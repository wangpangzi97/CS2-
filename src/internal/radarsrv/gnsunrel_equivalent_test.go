package radarsrv

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/uplink"
)

func TestEquivalentNOPMessageBoundary(t *testing.T) {
	a := []gnsUnrelMsg{{Cmd: 4, Body: []byte{8, 1}}, {Cmd: 55, Body: []byte{8, 2}}}
	n := gnsUnrelMsg{}
	if !gnsUnrelEquivalentMessages(a, []gnsUnrelMsg{n, a[0], n, a[1], n}) {
		t.Fatal("empty NOPs altered message identity")
	}
	cases := [][]gnsUnrelMsg{
		{a[1], a[0]}, {a[0]}, {a[0], a[1], {Cmd: 8}},
		{{Cmd: 4, Body: []byte{8, 2}}, a[1]}, {a[0], {Cmd: 55, Body: []byte{8, 2, 8, 2}}},
		{a[0], a[1], {Cmd: 0, Body: []byte{8, 1}}},
	}
	for _, b := range cases {
		if gnsUnrelEquivalentMessages(a, b) || gnsUnrelEquivalentMessages(b, a) {
			t.Fatal("non-NOP difference incorrectly normalized")
		}
	}
}

func TestEquivalentNOPDoesNotResolveGenuineAmbiguity(t *testing.T) {
	body, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	wire := phase64ProbeWire(body, 74521)
	// An unhandled non-NOP command is not padding: do not silently drop it.
	// Changing the first14-bit message from Cmd0 to Cmd8 retains byte alignment.
	wire[11] = 8
	a, _, okA := gnsParseUnrelChain(wire, 11*8)
	b, _, okB := gnsParseUnrelChain(wire, 18*8)
	sa, va := gnsUnrelCandidateScore(a)
	sb, vb := gnsUnrelCandidateScore(b)
	if !okA || !okB || !va || !vb || sa != sb || gnsUnrelEquivalentMessages(a, b) {
		t.Fatal("genuine ambiguity fixture invalid")
	}
	if got, reason := gnsDecodeUnrelReason(wire); got != nil || reason != 6 {
		t.Fatal("different equally scored chains must still fail closed")
	}
}

func TestEquivalentNOPStructuredCandidates(t *testing.T) {
	for i := 0; i < 512; i++ {
		body, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(uint32(74521 + i)), MaxEntries: proto.Int32(int32(i % 400))})
		wire := phase64ProbeWire(body, uint32(74521+i))
		// Independent parsing proof for the two selected offsets: all non-NOP
		// messages compare byte-for-byte; entity acceptance rules are unchanged.
		a, la, oa := gnsParseUnrelChain(wire, 11*8)
		b, lb, ob := gnsParseUnrelChain(wire, 18*8)
		if !oa || !ob || la != lb || !reflect.DeepEqual(phase64ProbeNonNOP(a), phase64ProbeNonNOP(b)) {
			t.Fatal("structured fixture changed non-NOP bytes")
		}
		d, reason := gnsDecodeUnrelReason(wire)
		if d == nil || reason != 0 || !reflect.DeepEqual(phase64ProbeNonNOP(d.Msgs), phase64ProbeNonNOP(a)) {
			t.Fatal("equivalent top-score candidate not retained")
		}
		if originalUnrelForOriginTest(wire) != nil {
			t.Fatal("baseline no longer reproduces false ambiguity")
		}
	}
}

func TestEquivalentNOPAuthenticatedGNSDependency(t *testing.T) {
	at := time.Now()
	dep, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	wire := phase64ProbeWire(dep, 74521)
	conn := []byte{31, 32, 33, 34}
	key := bytes.Repeat([]byte{0x35}, 32)
	iv := bytes.Repeat([]byte{0x28}, 12)
	seal := func(seq uint16, body []byte) []byte {
		out := append([]byte{0x80}, conn...)
		out = binary.LittleEndian.AppendUint16(out, seq)
		return append(out, cs2crypto.SealWith(key, cs2crypto.GNSIVForSeq(iv, uint64(seq)), body, nil)...)
	}
	store := NewStore(DefaultConfig())
	sess := store.Get("synthetic-equivalent-nop")
	sess.gns = &cs2crypto.GNSHandshake{ClientConnID: conn, ServerConnID: []byte{7, 8, 9, 10}}
	sess.entityDecoder = emptyDeltaTestDecoder(t, at)
	scheme, e := cs2crypto.SchemeFromGNS(key, iv)
	if e != nil {
		t.Fatal(e)
	}
	sess.setSchemeLocked("s2c", scheme)
	add := func(frame []byte) {
		n, e := store.Ingest(&uplink.Batch{Session: sess.id, Packets: []uplink.Packet{{Dir: "s2c", Data: base64.StdEncoding.EncodeToString(frame)}}})
		if e != nil || n != 1 {
			t.Fatal("authenticated controlled frame lost")
		}
		sess.decodeDir("s2c")
	}
	add(seal(1, append([]byte{0x27, 1, 0}, wire...)))
	future := &msg.CSVCMsg_PacketEntities{}
	if e := proto.Unmarshal(emptyDeltaTestRead(t, "live-74522.pb"), future); e != nil {
		t.Fatal(e)
	}
	future.ServerTick = proto.Uint32(74524)
	future.DeltaFrom = proto.Int32(74521)
	body, _ := proto.Marshal(future)
	add(seal(2, append([]byte{0x27, 2, 0}, emptyDeltaTestWire(body, 74524)...)))
	players, synced, _ := sess.entityDecoder.Snapshot(time.Now())
	st := sess.entityDecoder.NumericStatus(time.Now())
	if !synced || len(players) != 9 || st.FirstFaultCode != 0 || sess.pipeline.decryptFailed.Load() != 0 || sess.pipeline.unrelRejected.Load() != 0 {
		t.Fatal("equivalent NOP dependency failed through authenticated GCM/SNP path")
	}
	// Matching connection ID does not replace authentication.
	bad := seal(3, append([]byte{0x27, 3, 0}, emptyDeltaTestWire(body, 74524)...))
	bad[len(bad)-1] ^= 1
	add(bad)
	if sess.pipeline.decryptFailed.Load() != 1 {
		t.Fatal("GCM tamper protection changed")
	}
}
