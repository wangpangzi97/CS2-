package entitycodec

import (
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"reflect"
	"testing"
	"time"
)

func TestPhase67CurrentEpisodeProbe(t *testing.T) {
	at := time.Unix(100, 0)
	d := recoveryBuild(t, at)
	recoveryDamage(t, d, at.Add(time.Millisecond))
	if e := d.PacketEntities(recoveryRead(t, "live-74523.pb"), at.Add(2*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	ps, ok, _ := d.Snapshot(at.Add(2 * time.Millisecond))
	if !ok || len(ps) != 9 {
		t.Fatal("controlled recovery failed")
	}
	d.RecordIngressTick(74524, 1, 2|8, 6)
	m := &msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), ServerTick: proto.Uint32(74525), DeltaFrom: proto.Int32(74524)}
	body, _ := proto.Marshal(m)
	rejected := d.PacketEntities(body, at.Add(3*time.Millisecond)) != nil
	n := d.NumericStatus(at.Add(3 * time.Millisecond))
	ps, ok, _ = d.Snapshot(at.Add(3 * time.Millisecond))
	current := uint64(n.FirstFaultCode)
	var generation, outer, reason uint64
	// Test-only compatibility: baseline has no new method. No production fallback.
	method := reflect.ValueOf(d).MethodByName("EpisodeStatus")
	if method.IsValid() {
		v := method.Call(nil)[0]
		current = v.FieldByName("Code").Uint()
		generation = v.FieldByName("Number").Uint()
		outer = v.FieldByName("OuterFlags").Uint()
		reason = v.FieldByName("OuterReason").Uint()
	}
	exact := current == 3 && generation == 2 && outer == 10 && reason == 6
	fmt.Printf("CURRENT_EPISODE=%t HISTORICAL_CODE=%d CURRENT_CODE=%d SNAPSHOT_CODE=%d GENERATION=%d ORIGIN_FLAGS=%d ORIGIN_REASON=%d UNKNOWN_BASE_REJECTED=%t PLAYERS=%d SYNCED=%t\n", exact, n.FirstFaultCode, n.FaultCode, current, generation, outer, reason, rejected, len(ps), ok)
	if !exact || n.FirstFaultCode != 5 || !rejected || len(ps) != 0 || ok {
		t.Fatal("current fault must not reuse recovered history or draw stale players")
	}
}
