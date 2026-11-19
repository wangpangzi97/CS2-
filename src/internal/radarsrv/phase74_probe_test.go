package radarsrv

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/uplink"
	"testing"
	"time"
)

// Independently constructed9/13 boundary: empty Cmd0(14bits)+Cmd16(18bits).
// No private captured messages are stored in this test or required to run it.
func phase74PrefixWire(body []byte, tick uint32) []byte {
	w := &emptyDeltaTestBits{}
	w.message(0, nil)
	w.message(16, nil)
	tickBody, _ := proto.Marshal(&msg.CNETMsg_Tick{Tick: proto.Uint32(tick)})
	w.message(4, tickBody)
	w.message(55, body)
	h := []byte{2, 1}
	h = binary.AppendUvarint(h, uint64(tick))
	for len(h) < 9 {
		h = append(h, 0)
	}
	return append(h, w.data...)
}
func phase74Bodies(t *testing.T) ([]byte, []byte) {
	t.Helper()
	dep, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	p := &msg.CSVCMsg_PacketEntities{}
	if proto.Unmarshal(emptyDeltaTestRead(t, "live-74522.pb"), p) != nil {
		t.Fatal("fixture invalid")
	}
	p.ServerTick = proto.Uint32(74524)
	p.DeltaFrom = proto.Int32(74521)
	future, _ := proto.Marshal(p)
	return dep, future
}
func TestPhase74ConsensusDependencyProbe(t *testing.T) {
	dep, future := phase74Bodies(t)
	wire := phase74PrefixWire(dep, 74521)
	strict, reason := gnsDecodeUnrelReason(wire)
	if strict != nil || reason != 6 {
		t.Fatal("fixture must preserve full-chain ambiguity rejection")
	}
	at := time.Now()
	store := NewStore(DefaultConfig())
	sess := store.Get("synthetic-phase74-dependency")
	sess.entityDecoder = emptyDeltaTestDecoder(t, at)
	sess.noteGNSUnrel(wire)
	admitted := sess.pipeline.unreliableEntities.Load() == 1
	sess.noteGNSUnrel(emptyDeltaTestWire(future, 74524))
	got, synced, _ := sess.entityDecoder.Snapshot(time.Now())
	appliedAt := at.Add(2 * time.Millisecond)
	if len(got) > 0 {
		appliedAt = got[0].UpdatedAt
	}
	reference := emptyDeltaTestDecoder(t, at)
	if reference.PacketEntities(dep, at.Add(time.Millisecond)) != nil || reference.PacketEntities(future, appliedAt) != nil {
		t.Fatal("reference invalid")
	}
	// Compare the same state at the same clock, including UpdatedAt and AgeMS.
	compareAt := appliedAt.Add(10 * time.Millisecond)
	got, synced, _ = sess.entityDecoder.Snapshot(compareAt)
	want, refSynced, _ := reference.Snapshot(compareAt)
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	same := bytes.Equal(a, b)
	fmt.Printf("PHASE74_STRICT_REASON=%d CHECKPOINT_PASSED=%t PLAYERS=%d SYNCED=%t EXACT_REFERENCE=%t SYNTHETIC_ONLY=true\n", reason, admitted, len(got), synced, same)
	if !admitted || !synced || !refSynced || len(got) != 9 || !same {
		t.Fatal("common entity checkpoint was lost before dependent delta")
	}
	if sess.pipeline.unrelRejectReasons[6].Load() != 1 {
		t.Fatal("strict rejection accounting changed")
	}
}
func TestPhase74ConsensusAuthenticatedGCMDependency(t *testing.T) {
	dep, future := phase74Bodies(t)
	wire := phase74PrefixWire(dep, 74521)
	at := time.Now()
	store := NewStore(DefaultConfig())
	sess := store.Get("synthetic-phase74-gcm")
	conn := []byte{31, 32, 33, 34}
	key := bytes.Repeat([]byte{0x35}, 32)
	iv := bytes.Repeat([]byte{0x28}, 12)
	sess.gns = &cs2crypto.GNSHandshake{ClientConnID: conn, ServerConnID: []byte{7, 8, 9, 10}}
	sess.entityDecoder = emptyDeltaTestDecoder(t, at)
	scheme, e := cs2crypto.SchemeFromGNS(key, iv)
	if e != nil {
		t.Fatal(e)
	}
	sess.setSchemeLocked("s2c", scheme)
	seal := func(seq uint16, body []byte) []byte {
		out := append([]byte{0x80}, conn...)
		out = binary.LittleEndian.AppendUint16(out, seq)
		return append(out, cs2crypto.SealWith(key, cs2crypto.GNSIVForSeq(iv, uint64(seq)), body, nil)...)
	}
	add := func(frame []byte) {
		n, e := store.Ingest(&uplink.Batch{Session: sess.id, Packets: []uplink.Packet{{Dir: "s2c", Data: base64.StdEncoding.EncodeToString(frame)}}})
		if e != nil || n != 1 {
			t.Fatal("synthetic authenticated ingress failed")
		}
		sess.decodeDir("s2c")
	}
	add(seal(1, append([]byte{0x27, 1, 0}, wire...)))
	add(seal(2, append([]byte{0x27, 2, 0}, emptyDeltaTestWire(future, 74524)...)))
	players, synced, _ := sess.entityDecoder.Snapshot(time.Now())
	if !synced || len(players) != 9 || sess.pipeline.unrelRejectReasons[6].Load() != 1 || sess.pipeline.decryptFailed.Load() != 0 {
		t.Fatal("authenticated common checkpoint recovery failed")
	}
	before := sess.pipeline.unreliableEntities.Load()
	bad := seal(3, append([]byte{0x27, 3, 0}, wire...))
	bad[len(bad)-1] ^= 1
	add(bad)
	if sess.pipeline.decryptFailed.Load() != 1 || sess.pipeline.unreliableEntities.Load() != before {
		t.Fatal("tampered GCM reached consensus dispatch")
	}
}
