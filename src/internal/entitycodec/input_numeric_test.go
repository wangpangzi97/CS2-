package entitycodec

import (
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"testing"
	"time"
)

func TestNumericInputCountsRejectedAndEmptyFramesAndResets(t *testing.T) {
	now := time.Unix(100, 0)
	d := lateBuild(t, now)
	b, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	if e := d.PacketEntities(b, now.Add(time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	if e := d.PacketEntities([]byte{0xff}, now.Add(2*time.Millisecond)); e == nil {
		t.Fatal("bad proto accepted")
	}
	s := d.NumericStatus(now.Add(2 * time.Millisecond))
	if s.InputPackets != 3 || s.EmptyDeltas != 1 || s.RejectedPackets != 1 {
		t.Fatal("input counters lost rejected envelope")
	}
	if e := d.ServerInfo(lateRead(t, "live-serverinfo.pb")); e != nil {
		t.Fatal(e)
	}
	s = d.NumericStatus(now)
	if s.InputPackets != 0 || s.EmptyDeltas != 0 || s.RejectedPackets != 0 {
		t.Fatal("old generation counters retained")
	}
}
