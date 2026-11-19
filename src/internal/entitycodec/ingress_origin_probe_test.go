package entitycodec

import (
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"reflect"
	"testing"
	"time"
)

func TestFirstMissingOriginRetainedWithoutPlayers(t *testing.T) {
	at := time.Unix(100, 0)
	d := lateBuild(t, at)
	fn := reflect.ValueOf(d).MethodByName("RecordIngressTick")
	if fn.IsValid() {
		for _, event := range []struct{ flags, reason uint8 }{{1, 0}, {2, 0}, {8, 6}} {
			fn.Call([]reflect.Value{reflect.ValueOf(uint32(74521)), reflect.ValueOf(uint8(1)), reflect.ValueOf(event.flags), reflect.ValueOf(event.reason)})
		}
	}
	b, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74521), ServerTick: proto.Uint32(74524)})
	if e := d.PacketEntities(b, at.Add(time.Millisecond)); e == nil {
		t.Fatal("missing dependency accepted")
	}
	s := d.NumericStatus(at.Add(time.Millisecond))
	p, ok, _ := d.Snapshot(at.Add(time.Millisecond))
	n := func(name string) uint64 {
		v := reflect.ValueOf(s).FieldByName(name)
		if !v.IsValid() {
			return 0
		}
		return v.Uint()
	}
	captured, flags, reason := n("FirstMissingOriginCaptured"), n("FirstMissingOuterFlags"), n("FirstMissingOuterReason")
	fmt.Printf("FIRST_FAULT=%d ORIGIN_CAPTURED=%d OUTER_FLAGS=%d OUTER_REASON=%d PLAYERS=%d FAIL_CLOSED=%t SYNTHETIC_TRACE_ONLY=true\n", s.FirstFaultCode, captured, flags, reason, len(p), !ok && len(p) == 0)
	if captured != 1 || flags != 11 || reason != 6 || ok || len(p) != 0 {
		t.Fatal("first missing origin lost; diagnostic test is not a character fix")
	}
}
