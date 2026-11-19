package radarsrv

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/uplink"
)

// This is an independently constructed, authenticated test connection, NOT a
// replay of user packets. No key, connection ID or entity coordinate is printed.
func TestAuthenticatedGNSTakesPrecedenceOverPlaintextScore(t *testing.T) {
	at := time.Now()
	dep, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	wire := emptyDeltaTestWire(dep, 74521)
	snp := append([]byte{0x27, 1, 0}, wire...) // last unreliable fragment, lane0, size=remaining
	frameBytes := 7 + len(snp) + 16
	if frameBytes-3 >= 128 {
		t.Fatal("test frame must use single-byte coincident plaintext length")
	}
	conn := []byte{1, byte(frameBytes - 3), 0, 0}
	key := bytes.Repeat([]byte{0x35}, 32)
	iv := bytes.Repeat([]byte{0x28}, 12)
	seal := func(seq uint16, body []byte) []byte {
		out := append([]byte{0x80}, conn...)
		out = binary.LittleEndian.AppendUint16(out, seq)
		return append(out, cs2crypto.SealWith(key, cs2crypto.GNSIVForSeq(iv, uint64(seq)), body, nil)...)
	}
	frame := seal(1, snp)
	_, collision := cs2proto.Score(frame, cs2proto.MaxCmd)
	opened, e := cs2crypto.GNSOpen(key, iv, frame)
	if !collision || e != nil || !bytes.Equal(opened, snp) || !cs2crypto.GNSFrameForConn(frame, conn) {
		t.Fatal("fixture is not both authenticated GNS and a plaintext heuristic collision")
	}
	store := NewStore(DefaultConfig())
	sess := store.Get("controlled-ingress-collision")
	sess.gns = &cs2crypto.GNSHandshake{ClientConnID: conn, ServerConnID: []byte{7, 8, 9, 10}}
	sess.entityDecoder = emptyDeltaTestDecoder(t, at)
	scheme, e := cs2crypto.SchemeFromGNS(key, iv)
	if e != nil {
		t.Fatal(e)
	}
	sess.setSchemeLocked("s2c", scheme)
	add := func(raw []byte) int {
		n, e := store.Ingest(&uplink.Batch{Session: sess.id, Packets: []uplink.Packet{{Dir: "s2c", Data: base64.StdEncoding.EncodeToString(raw)}}})
		if e != nil {
			t.Fatal(e)
		}
		sess.decodeDir("s2c")
		return n
	}
	n := add(frame)
	// A later real entity payload now acknowledges the state carried by the
	// filtered test packet. The no-change dependency has the exact full state.
	future := &msg.CSVCMsg_PacketEntities{}
	if e := proto.Unmarshal(emptyDeltaTestRead(t, "live-74522.pb"), future); e != nil {
		t.Fatal(e)
	}
	future.ServerTick = proto.Uint32(74524)
	future.DeltaFrom = proto.Int32(74521)
	body, _ := proto.Marshal(future)
	second := seal(2, append([]byte{0x27, 2, 0}, emptyDeltaTestWire(body, 74524)...))
	if _, looksPlain := cs2proto.Score(second, cs2proto.MaxCmd); looksPlain {
		t.Fatal("control frame unexpectedly also collides")
	}
	if add(second) != 1 {
		t.Fatal("noncolliding encrypted control frame lost")
	}
	players, synced, _ := sess.entityDecoder.Snapshot(time.Now())
	status := sess.entityDecoder.NumericStatus(time.Now())
	fmt.Printf("AUTHENTICATED_GNS=true PLAINTEXT_SCORE_COLLISION=%t DEPENDENCY_ACCEPTED=%d SYNCED=%t PLAYERS=%d FIRST_FAULT=%d DECRYPT_FAILED=%d SYNTHETIC_ONLY=true\n", collision, n, synced, len(players), status.FirstFaultCode, sess.pipeline.decryptFailed.Load())
	if n != 1 || !synced || len(players) != 9 || status.RejectedPackets != 0 || sess.pipeline.decryptFailed.Load() != 0 {
		t.Fatal("plaintext heuristic discarded an authenticated dependency before the GCM/SNP/entity path")
	}
}
