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

func lateRead(t *testing.T, n string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + n)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func lateBuild(t *testing.T, now time.Time) *Decoder {
	t.Helper()
	d := New()
	if e := d.ServerInfo(lateRead(t, "live-serverinfo.pb")); e != nil {
		t.Fatal(e)
	}
	if e := d.PacketEntities(lateRead(t, "live-full.pb"), now); e != nil {
		t.Fatal(e)
	}
	return d
}
func lateFuture(tick uint32) []byte {
	b, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74522), ServerTick: proto.Uint32(tick)})
	return b
}
func lateJSON(d *Decoder, at time.Time) (string, bool, int) {
	ps, ok, _ := d.Snapshot(at)
	b, _ := json.Marshal(ps)
	return string(b), ok, len(ps)
}
func TestLateFrameBecomesExactFutureBase(t *testing.T) {
	now := time.Unix(100, 0)
	a, b := lateRead(t, "live-74522.pb"), lateRead(t, "live-74523.pb")
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint("missing_before_late=", pending), func(t *testing.T) {
			d := lateBuild(t, now)
			if e := d.PacketEntities(b, now.Add(time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			before, _, _ := lateJSON(d, now.Add(3*time.Millisecond))
			if pending {
				if e := d.PacketEntities(lateFuture(74524), now.Add(2*time.Millisecond)); e == nil {
					t.Fatal("missing base accepted")
				}
				if _, ok, n := lateJSON(d, now.Add(2*time.Millisecond)); ok || n != 0 {
					t.Fatal("failed state leaked")
				}
			}
			if e := d.PacketEntities(a, now.Add(3*time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			unchanged := true
			if !pending {
				after, ok, _ := lateJSON(d, now.Add(3*time.Millisecond))
				unchanged = ok && before == after
			} else {
				_, ok, n := lateJSON(d, now.Add(3*time.Millisecond))
				unchanged = !ok && n == 0
			}
			future := lateFuture(74525)
			e := d.PacketEntities(future, now.Add(4*time.Millisecond))
			got, ok, n := lateJSON(d, now.Add(4*time.Millisecond))
			ref := lateBuild(t, now)
			if e := ref.PacketEntities(a, now.Add(3*time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			if e := ref.PacketEntities(future, now.Add(4*time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			want, wok, _ := lateJSON(ref, now.Add(4*time.Millisecond))
			equal := ok && wok && got == want
			fmt.Printf("PENDING=%t LATE_DID_NOT_PUBLISH_OR_REWIND=%t FUTURE_RECOVERED=%t PLAYERS=%d EXACT_REFERENCE_MATCH=%t\n", pending, unchanged, ok, n, equal)
			if e != nil || !unchanged || !equal || n != 9 {
				t.Fatal("valid late frame was lost as a later declared dependency")
			}
		})
	}
}

func TestLateCacheRejectsUnsafeWithoutTouchingLive(t *testing.T) {
	now := time.Unix(100, 0)
	for _, kind := range []string{"corrupt_suffix", "missing_base", "expired", "old_full", "outside_window"} {
		t.Run(kind, func(t *testing.T) {
			d := lateBuild(t, now)
			if e := d.PacketEntities(lateRead(t, "live-74523.pb"), now.Add(time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			m := &msg.CSVCMsg_PacketEntities{}
			_ = proto.Unmarshal(lateRead(t, "live-74522.pb"), m)
			at := now.Add(3 * time.Millisecond)
			switch kind {
			case "corrupt_suffix":
				m.UpdatedEntries = proto.Int32(m.GetUpdatedEntries() + 100)
			case "missing_base":
				m.DeltaFrom = proto.Int32(74514)
			case "expired":
				at = now.Add(11 * time.Second)
			case "old_full":
				m.LegacyIsDelta = proto.Bool(false)
			case "outside_window":
				m.ServerTick = proto.Uint32(74300)
				m.DeltaFrom = proto.Int32(74299)
			}
			before, was, n := lateJSON(d, at)
			tick, packets := d.lastTick, d.packets
			body, _ := proto.Marshal(m)
			if e := d.PacketEntities(body, at); e != nil {
				t.Fatal(e)
			}
			after, ok, count := lateJSON(d, at)
			if before != after || was != ok || n != count || d.lastTick != tick || d.packets != packets || d.cacheTrace.lateCached != 0 || d.cacheTrace.lateRejected != 1 {
				t.Fatal("unsafe late input changed current live state", kind)
			}
			if kind == "expired" && ok {
				t.Fatal("expired live frame published")
			}
		})
	}
}

func TestLateHistoryBudgetAndNumericProvenance(t *testing.T) {
	now := time.Unix(100, 0)
	d := lateBuild(t, now)
	source := d.history[d.lastTick]
	d.history = map[uint32]historicalFrame{}
	d.historyOrder = nil
	d.historyBytes = 0
	for tick := uint32(1); tick <= 200; tick++ {
		d.history[tick] = source
		d.historyOrder = append(d.historyOrder, tick)
		d.historyBytes += source.checkpoint.Bytes()
	}
	d.lastTick = 200
	d.activeBase = 1
	if e := d.pruneHistoryKeeping(1, 100, 200); e != nil {
		t.Fatal(e)
	}
	for _, id := range []uint32{1, 100, 200} {
		if _, ok := d.history[id]; !ok {
			t.Fatal("protected current/active/late base evicted")
		}
	}
	if len(d.history) > 128 || d.historyBytes > 128<<20 {
		t.Fatal("existing cache bounds widened")
	}
	d.recordMissingBase(2)
	if d.cacheTrace.missingKind != 1 {
		t.Fatal("recorded eviction not distinguished")
	}
	delete(d.history, 199)
	d.recordMissingBase(199)
	if d.cacheTrace.missingKind != 2 {
		t.Fatal("inside-horizon gap misclassified")
	}
	d.recordMissingBase(201)
	if d.cacheTrace.missingKind != 4 {
		t.Fatal("future base misclassified")
	}
	d.history = nil
	d.historyOrder = nil
	d.historyBytes = 0
	d.recordMissingBase(199)
	if d.cacheTrace.missingKind != 5 {
		t.Fatal("empty cache misclassified")
	}
	if e := d.ServerInfo(lateRead(t, "live-serverinfo.pb")); e != nil {
		t.Fatal(e)
	}
	s := d.NumericStatus(now)
	if s.CacheMisses != 0 || s.MissingKind != 0 || s.LateSeen != 0 || d.activeBase != 0 {
		t.Fatal("trace crossed signon generation")
	}
	fmt.Println("LATE_INVALID_CORRUPT_EXPIRED_FULL_WINDOW_AND_GENERATION_GUARDS=true BUDGET=128frames/128MiB NUMERIC_PROVENANCE_BOUNDED=true")
}
