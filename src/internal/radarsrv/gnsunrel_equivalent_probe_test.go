package radarsrv

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
)

// Independently constructed valid padding before an existing entity payload.
// This does not replay any user game session or print its data.
func phase64ProbeWire(body []byte, tick uint32) []byte {
	w := &emptyDeltaTestBits{}
	for i := 0; i < 4; i++ {
		w.message(0, nil)
	} // four empty NOPs =56bits =7bytes
	tb, _ := proto.Marshal(&msg.CNETMsg_Tick{Tick: proto.Uint32(tick)})
	w.message(4, tb)
	w.message(55, body)
	h := []byte{2, 1}
	h = binary.AppendUvarint(h, uint64(tick))
	for len(h) < 11 {
		h = append(h, 0)
	}
	return append(h, w.data...)
}
func phase64ProbeNonNOP(ms []gnsUnrelMsg) []gnsUnrelMsg {
	out := make([]gnsUnrelMsg, 0, len(ms))
	for _, m := range ms {
		if m.Cmd != 0 || len(m.Body) != 0 {
			out = append(out, m)
		}
	}
	return out
}
func TestPhase64EquivalentDependencyProbe(t *testing.T) {
	at := time.Unix(100, 0)
	dep, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	wire := phase64ProbeWire(dep, 74521)
	a, leftA, okA := gnsParseUnrelChain(wire, 11*8)
	b, leftB, okB := gnsParseUnrelChain(wire, 18*8)
	sa, va := gnsUnrelCandidateScore(a)
	sb, vb := gnsUnrelCandidateScore(b)
	ca, _ := json.Marshal(phase64ProbeNonNOP(a))
	cb, _ := json.Marshal(phase64ProbeNonNOP(b))
	identical := okA && okB && leftA <= 8 && leftB <= 8 && va && vb && sa == sb && bytes.Equal(ca, cb)
	if !identical {
		t.Fatal("independent equivalent-candidate fixture is invalid")
	}
	d := emptyDeltaTestDecoder(t, at)
	chosen, reason := gnsDecodeUnrelReason(wire)
	accepted := false
	if chosen != nil {
		for _, m := range chosen.Msgs {
			if m.Cmd == 55 {
				if e := d.PacketEntities(m.Body, at.Add(time.Millisecond)); e != nil {
					t.Fatal(e)
				}
				accepted = true
			}
		}
	}
	future := &msg.CSVCMsg_PacketEntities{}
	if e := proto.Unmarshal(emptyDeltaTestRead(t, "live-74522.pb"), future); e != nil {
		t.Fatal(e)
	}
	future.ServerTick = proto.Uint32(74524)
	future.DeltaFrom = proto.Int32(74521)
	body, _ := proto.Marshal(future)
	_ = d.PacketEntities(body, at.Add(2*time.Millisecond))
	got, synced, _ := d.Snapshot(at.Add(2 * time.Millisecond))
	gotBytes, _ := json.Marshal(got)
	ref := emptyDeltaTestDecoder(t, at)
	future.DeltaFrom = proto.Int32(74515)
	expectedBody, _ := proto.Marshal(future)
	if e := ref.PacketEntities(expectedBody, at.Add(2*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	want, refSynced, _ := ref.Snapshot(at.Add(2 * time.Millisecond))
	wantBytes, _ := json.Marshal(want)
	same := synced && refSynced && bytes.Equal(gotBytes, wantBytes)
	st := d.NumericStatus(at.Add(2 * time.Millisecond))
	fmt.Printf("EQUIVALENT_NON_NOP_MESSAGES=%t CLASSIFIER_REASON=%d DEPENDENCY_ACCEPTED=%t PLAYERS=%d SYNCED=%t EXACT_REFERENCE_MATCH=%t FIRST_FAULT=%d SYNTHETIC_ONLY=true\n", identical, reason, accepted, len(got), synced, same, st.FirstFaultCode)
	if !accepted || !synced || len(got) != 9 || !same || st.FirstFaultCode != 0 {
		t.Fatal("identical messages behind valid empty NOP padding were falsely rejected as ambiguous")
	}
}
