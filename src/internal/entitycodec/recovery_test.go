package entitycodec

import (
	"encoding/json"
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"os"
	"testing"
	"time"
)

func recoveryRead(t *testing.T, n string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + n)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func recoveryBuild(t *testing.T, now time.Time) *Decoder {
	t.Helper()
	d := New()
	if e := d.ServerInfo(recoveryRead(t, "live-serverinfo.pb")); e != nil {
		t.Fatal(e)
	}
	if e := d.PacketEntities(recoveryRead(t, "live-full.pb"), now); e != nil {
		t.Fatal(e)
	}
	return d
}
func recoveryDamage(t *testing.T, d *Decoder, now time.Time) {
	t.Helper()
	m := &msg.CSVCMsg_PacketEntities{}
	if e := proto.Unmarshal(recoveryRead(t, "live-74522.pb"), m); e != nil {
		t.Fatal(e)
	}
	m.UpdatedEntries = proto.Int32(m.GetUpdatedEntries() + 100)
	b, _ := proto.Marshal(m)
	if e := d.PacketEntities(b, now); e == nil {
		t.Fatal("corrupt entity suffix accepted")
	}
	if ps, ok, _ := d.Snapshot(now); ok || len(ps) != 0 {
		t.Fatal("failed parser published entities")
	}
}

func TestExactCachedDeltaRecovery(t *testing.T) {
	now := time.Unix(100, 0)
	d := recoveryBuild(t, now)
	recoveryDamage(t, d, now.Add(100*time.Millisecond))
	// The following genuine fixture names the exact still-retained full tick74515.
	// Restoration must discard partial mutations from the failed prior update.
	b := recoveryRead(t, "live-74523.pb")
	e := d.PacketEntities(b, now.Add(200*time.Millisecond))
	ps, ok, _ := d.Snapshot(now.Add(200 * time.Millisecond))
	ref := recoveryBuild(t, now)
	if e := ref.PacketEntities(b, now.Add(200*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	want, wok, _ := ref.Snapshot(now.Add(200 * time.Millisecond))
	a, _ := json.Marshal(ps)
	w, _ := json.Marshal(want)
	equal := ok && wok && string(a) == string(w)
	fmt.Printf("FAILED_STATE_HIDDEN=true RECOVERED=%t PLAYERS=%d EXACT_REFERENCE_MATCH=%t\n", ok, len(ps), equal)
	if e != nil || !equal || len(ps) != 9 {
		t.Fatal("exact cached delta did not safely recover")
	}
}

func TestCachedDeltaRecoveryStillFailsClosed(t *testing.T) {
	now := time.Unix(100, 0)
	b := recoveryRead(t, "live-74523.pb")
	for _, kind := range []string{"no_initial_full", "missing_base", "expired_base", "new_generation", "zero_tick", "zero_base", "unknown_base", "old_tick", "second_bad_packet"} {
		t.Run(kind, func(t *testing.T) {
			d := recoveryBuild(t, now)
			recoveryDamage(t, d, now.Add(100*time.Millisecond))
			at := now.Add(200 * time.Millisecond)
			candidate := b
			switch kind {
			case "no_initial_full", "new_generation":
				if e := d.ServerInfo(recoveryRead(t, "live-serverinfo.pb")); e != nil {
					t.Fatal(e)
				}
			case "missing_base":
				d.history = nil
				d.historyOrder = nil
				d.historyBytes = 0
			case "expired_base":
				at = now.Add(11 * time.Second)
			case "zero_tick", "zero_base", "unknown_base", "old_tick":
				m := &msg.CSVCMsg_PacketEntities{}
				_ = proto.Unmarshal(b, m)
				switch kind {
				case "zero_tick":
					m.ServerTick = proto.Uint32(0)
				case "zero_base":
					m.DeltaFrom = proto.Int32(0)
				case "unknown_base":
					m.DeltaFrom = proto.Int32(999999)
				case "old_tick":
					m.ServerTick = proto.Uint32(74514)
				}
				candidate, _ = proto.Marshal(m)
			case "second_bad_packet":
				recoveryDamage(t, d, at)
				return
			}
			_ = d.PacketEntities(candidate, at)
			if ps, ok, _ := d.Snapshot(at); ok || len(ps) > 0 {
				t.Fatal("unsafe recovery published entities")
			}
		})
	}
	fmt.Println("RECOVERY_FAIL_CLOSED_INITIAL_MISSING_EXPIRED_GENERATION_TICK_AND_CORRUPT=true")
}

func TestRecoveryNumericReasonAndLongConnection(t *testing.T) {
	now := time.Unix(100, 0)
	d := recoveryBuild(t, now)
	recoveryDamage(t, d, now.Add(time.Millisecond))
	if s := d.NumericStatus(now); s.Stage != 6 || s.FaultCode != 5 {
		t.Fatal("bounded parser failure reason missing", s.Stage, s.FaultCode)
	}
	b := recoveryRead(t, "live-74523.pb")
	if e := d.PacketEntities(b, now.Add(2*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	if s := d.NumericStatus(now); s.Stage != 9 || s.FaultCode != 0 {
		t.Fatal("recovery did not clear current failure enum")
	}
	// Synthetic zero-change frames exercise >16384 accepted snapshots and
	// repeated damaged suffixes without reconnecting. Not a real match replay.
	for i := uint32(1); i <= 17000; i++ {
		m := &msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(int32(d.lastTick)), ServerTick: proto.Uint32(d.lastTick + 1)}
		at := now.Add(time.Duration(i) * time.Second / 64)
		if i%1024 == 0 {
			bad := proto.Clone(m).(*msg.CSVCMsg_PacketEntities)
			bad.UpdatedEntries = proto.Int32(1)
			bad.EntityData = []byte{255}
			bb, _ := proto.Marshal(bad)
			if e := d.PacketEntities(bb, at); e == nil {
				t.Fatal("corruption accepted")
			}
			if ps, ok, _ := d.Snapshot(at); ok || len(ps) != 0 {
				t.Fatal("failed state leaked")
			}
		}
		body, _ := proto.Marshal(m)
		if e := d.PacketEntities(body, at); e != nil {
			t.Fatal("continuous exact-base recovery failed", i, e)
		}
	}
	ps, ok, _ := d.Snapshot(now.Add(17000 * time.Second / 64))
	if !ok || len(ps) != 9 || len(d.history) > 128 || d.historyBytes > 128<<20 {
		t.Fatal("long connection lost synchronization or bounds")
	}
	fmt.Printf("SYNTHETIC_CONTINUOUS_FRAMES=17000 INJECTED_FAULTS=16 NO_RECONNECT=true FINAL_PLAYERS=%d HISTORY_BOUNDS_UNCHANGED=true\n", len(ps))
}
