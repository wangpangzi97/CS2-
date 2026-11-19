package entitycodec

import (
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"reflect"
	"testing"
	"time"
	"unsafe"
)

func TestInputTraceIsBoundedAndKeepsFirstMissingAcrossRingEviction(t *testing.T) {
	if traceGap(74522, 0) != 0 || traceGap(0, 74515) != 0 || traceGap(74522, 74515) != 7 || traceGap(1<<31, 1) != 1<<20 {
		t.Fatal("raw absolute tick or unbounded relative distance escaped")
	}
	var p entityInputTrace
	if unsafe.Sizeof(p) > 2048 {
		t.Fatal("diagnostic metadata budget exceeded")
	}
	p.remember(10, 1, 0)
	p.remember(11, 2, 5)
	p.remember(12, 1, 0)
	p.missing(11, 4)
	if p.missingKind != 2 || p.missingCode != 5 || p.firstMissingKind != 2 || p.firstMissingCode != 5 {
		t.Fatal("known failed receipt not distinguished")
	}
	for i := uint32(13); i < 400; i++ {
		p.remember(i, 2, 1)
	}
	p.missing(11, 400)
	if p.count != 128 || p.missingKind != 5 || p.firstMissingKind != 2 || p.firstMissingCode != 5 || p.firstMissingInput != 4 {
		t.Fatal("bounded ring lost first provenance or claimed unseen packet")
	}
	p = entityInputTrace{}
	p.remember(100, 1, 0)
	p.remember(102, 1, 0)
	p.missing(101, 3)
	if p.missingKind != 4 {
		t.Fatal("inside-horizon absence misclassified")
	}
	p.missing(99, 4)
	if p.missingKind != 5 {
		t.Fatal("outside ring represented as proven absent")
	}
}

func TestFirstCauseAndReceiptsResetOnlyAtSignonOrSuccessfulFull(t *testing.T) {
	at := time.Unix(100, 0)
	d := lateBuild(t, at)
	if e := d.PacketEntities([]byte{0xff}, at.Add(time.Millisecond)); e == nil {
		t.Fatal("corrupt proto accepted")
	}
	if d.NumericStatus(at).FirstFaultCode != 1 {
		t.Fatal("malformed first cause lost")
	}
	if e := d.PacketEntities(lateRead(t, "live-full.pb"), at.Add(2*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	if s := d.NumericStatus(at); s.FirstFaultCode != 0 || s.FirstMissingInputKind != 0 || d.inputTrace.count != 1 {
		t.Fatal("successful full did not reanchor trace")
	}
	if e := d.ServerInfo(lateRead(t, "live-serverinfo.pb")); e != nil {
		t.Fatal(e)
	}
	if s := d.NumericStatus(at); s.FirstFaultCode != 0 || s.FirstFaultInput != 0 || d.inputTrace.count != 0 {
		t.Fatal("old signon provenance retained")
	}
}

func TestBlockedMissingDependenciesCountButNeverPublish(t *testing.T) {
	at := time.Unix(100, 0)
	d := lateBuild(t, at)
	for i := uint32(0); i < 5; i++ {
		b, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74514), ServerTick: proto.Uint32(74522 + i)})
		if e := d.PacketEntities(b, at.Add(time.Duration(i+1)*time.Millisecond)); e == nil {
			t.Fatal("unknown dependency accepted")
		}
	}
	s := d.NumericStatus(at.Add(5 * time.Millisecond))
	ps, ok, _ := d.Snapshot(at.Add(5 * time.Millisecond))
	if s.CacheMisses != 5 || s.FirstFaultCode != 3 || s.FirstFaultInput != 2 || s.FirstMissingInput != 2 || ok || len(ps) != 0 {
		t.Fatal("gated rejects lost or failclosed changed")
	}
}

func causeTestNumber(s NumericEntityStatus, n string) uint64 {
	v := reflect.ValueOf(s).FieldByName(n)
	if !v.IsValid() {
		return 0
	}
	return v.Uint()
}
func TestFirstCauseSurvivesLaterMissingBase(t *testing.T) {
	at := time.Unix(100, 0)
	d := lateBuild(t, at)
	bad := &msg.CSVCMsg_PacketEntities{}
	if e := proto.Unmarshal(lateRead(t, "live-74522.pb"), bad); e != nil {
		t.Fatal(e)
	}
	bad.UpdatedEntries = proto.Int32(bad.GetUpdatedEntries() + 100)
	body, _ := proto.Marshal(bad)
	if e := d.PacketEntities(body, at.Add(time.Millisecond)); e == nil {
		t.Fatal("control corruption not rejected")
	}
	if d.NumericStatus(at.Add(time.Millisecond)).FaultCode != 5 {
		t.Fatal("control did not reach parser failure")
	}
	if e := d.PacketEntities(lateRead(t, "live-74523.pb"), at.Add(2*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	// Later dependent frame references the tick whose decode failed. The current
	// diagnostic keeps only code3, losing the earlier parser failure code5.
	missing, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74522), ServerTick: proto.Uint32(74524)})
	if e := d.PacketEntities(missing, at.Add(3*time.Millisecond)); e == nil {
		t.Fatal("missing exact base accepted")
	}
	ps, ok, _ := d.Snapshot(at.Add(3 * time.Millisecond))
	s := d.NumericStatus(at.Add(3 * time.Millisecond))
	first := causeTestNumber(s, "FirstFaultCode")
	origin := causeTestNumber(s, "MissingInputKind")
	code := causeTestNumber(s, "MissingInputCode")
	seq := causeTestNumber(s, "FirstFaultInput")
	fmt.Printf("LATEST_CODE=%d FIRST_CODE=%d FIRST_INPUT=%d MISSING_INPUT_KIND=%d MISSING_INPUT_CODE=%d PLAYERS=%d FAIL_CLOSED=%t SYNTHETIC_CAUSE_ONLY=true\n", s.FaultCode, first, seq, origin, code, len(ps), !ok && len(ps) == 0)
	if s.FaultCode != 3 || first != 5 || seq != 2 || origin != 2 || code != 5 || ok || len(ps) != 0 {
		t.Fatal("first cause or failed-input provenance lost; diagnostic-only test does not claim game repair")
	}
}
