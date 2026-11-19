package entitycodec

import (
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"testing"
	"time"
	"unsafe"
)

func TestIngressOriginBoundedStickyAndNoUnknownClaims(t *testing.T) {
	var o ingressOrigin
	if unsafe.Sizeof(o) > 3072 {
		t.Fatal("metadata budget exceeded")
	}
	o.observe(0, 1, 1, 0)
	o.observe(1, 3, 1, 0)
	o.observe(1, 1, 128, 0)
	o.observe(1, 1, 1, 7)
	if o.count != 0 {
		t.Fatal("invalid trace accepted")
	}
	o.observe(10, 1, 1, 0)
	o.observe(10, 1, 2, 0)
	o.observe(10, 1, 8, 6)
	o.observe(10, 2, 16|4|32, 0)
	o.capture(10)
	if o.captured != 1 || o.outerFlags != 11 || o.outerReason != 6 || o.netFlags != 52 {
		t.Fatal("layered receipt missing")
	}
	for i := uint32(20); i < 2000; i++ {
		o.observe(i, 1, 4, 0)
	}
	o.capture(1999)
	if o.count != 256 || o.outerFlags != 11 || o.outerReason != 6 {
		t.Fatal("first evidence overwritten or unbounded")
	}
	o = ingressOrigin{}
	o.capture(77)
	if o.captured != 1 || o.outerFlags != 0 || o.netFlags != 0 {
		t.Fatal("unknown converted into claimed receipt")
	}
}
func TestIngressOriginResetsAnchorButCountsSinceSignon(t *testing.T) {
	at := time.Unix(100, 0)
	d := lateBuild(t, at)
	d.RecordIngressTick(74521, 1, 11, 6)
	d.RecordEntityContext(5, 5, 6)
	body, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74521), ServerTick: proto.Uint32(74524)})
	if d.PacketEntities(body, at) == nil {
		t.Fatal("missing dependency accepted")
	}
	if d.NumericStatus(at).FirstMissingOuterFlags != 11 {
		t.Fatal("source lost")
	}
	full := &msg.CSVCMsg_PacketEntities{}
	if proto.Unmarshal(lateRead(t, "live-full.pb"), full) != nil {
		t.Fatal("fixture")
	}
	full.ServerTick = nil
	wire, _ := proto.Marshal(full)
	if e := d.PacketEntities(wire, at.Add(time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	s := d.NumericStatus(at)
	if s.FirstMissingOriginCaptured != 0 || s.FirstMissingOuterFlags != 0 || s.ZeroTickBodies != 1 || s.IngressOuterMatches != 1 || s.IngressNetMismatches != 1 {
		t.Fatal("anchor or since-ServerInfo scope incorrect")
	}
	if e := d.ServerInfo(lateRead(t, "live-serverinfo.pb")); e != nil {
		t.Fatal(e)
	}
	if s := d.NumericStatus(at); s.ZeroTickBodies != 0 || s.IngressOuterMatches != 0 || d.origin.count != 0 {
		t.Fatal("old generation retained")
	}
}
