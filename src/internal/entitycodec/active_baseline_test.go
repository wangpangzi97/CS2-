package entitycodec

import (
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"os"
	"strings"
	"testing"
	"time"
)

func TestActiveAcknowledgedBaseSurvivesByteBudget(t *testing.T) {
	d := New()
	info, _ := os.ReadFile("testdata/live-serverinfo.pb")
	full, _ := os.ReadFile("testdata/live-full.pb")
	if e := d.ServerInfo(info); e != nil {
		t.Fatal(e)
	}
	if e := d.PacketEntities(full, time.Unix(100, 0)); e != nil {
		t.Fatal(e)
	}
	var source historicalFrame
	for _, h := range d.history {
		source = h
		break
	}
	if source.checkpoint == nil {
		t.Fatal("missing actual checkpoint")
	}
	d.history = map[uint32]historicalFrame{}
	d.historyOrder = nil
	d.historyBytes = 0
	// Reuse this immutable checkpoint solely to exercise eviction/accounting.
	// Synthetic labels are not claimed to be a real entity timeline.
	for id := uint32(1); id <= 200; id++ {
		d.history[id] = source
		d.historyOrder = append(d.historyOrder, id)
		d.historyBytes += source.checkpoint.Bytes()
	}
	before := d.historyBytes
	if e := d.pruneHistory(1, 200); e != nil {
		t.Fatal(e)
	}
	if _, ok := d.history[1]; !ok {
		t.Fatal("active base evicted")
	}
	if _, ok := d.history[200]; !ok {
		t.Fatal("newest snapshot evicted")
	}
	if len(d.historyOrder) > 128 || d.historyBytes > 128<<20 {
		t.Fatal("bounds disabled")
	}
	total := 0
	for _, h := range d.history {
		total += h.checkpoint.Bytes()
	}
	if total != d.historyBytes {
		t.Fatal("accounting mismatch")
	}
	// Move acknowledgement to an actually retained checkpoint and add pressure.
	newBase := d.historyOrder[len(d.historyOrder)-2]
	d.history[201] = source
	d.historyOrder = append(d.historyOrder, 201)
	d.historyBytes += source.checkpoint.Bytes()
	if e := d.pruneHistory(newBase, 201); e != nil {
		t.Fatal(e)
	}
	if _, ok := d.history[1]; ok {
		t.Fatal("former base remained permanently pinned")
	}
	if _, ok := d.history[newBase]; !ok {
		t.Fatal("new active base evicted")
	}
	fmt.Printf("ACTIVE_BASE_BUDGET before=%d after=%d frames=%d active_base_retained=true previous_base_released=true\n", before, d.historyBytes, len(d.historyOrder))
}
func TestRootDecodeFailureSurvivesLaterDeltas(t *testing.T) {
	d := New()
	info, _ := os.ReadFile("testdata/live-serverinfo.pb")
	full, _ := os.ReadFile("testdata/live-full.pb")
	delta, _ := os.ReadFile("testdata/live-74522.pb")
	_ = d.ServerInfo(info)
	if e := d.PacketEntities(full, time.Now()); e != nil {
		t.Fatal(e)
	}
	d.history = nil
	d.historyOrder = nil
	d.historyBytes = 0
	d.lastTick = 74516
	if e := d.PacketEntities(delta, time.Now()); e == nil || !strings.Contains(e.Error(), "缺少delta指定基线") {
		t.Fatal(e)
	}
	root := d.syncFault
	for i := 0; i < 100; i++ {
		if e := d.PacketEntities(delta, time.Now()); e == nil || !strings.Contains(e.Error(), root) {
			t.Fatal("root failure lost", e)
		}
	}
	if d.syncFault != root || len(d.fault) > len(root)+100 {
		t.Fatal("unbounded nested failure text")
	}
	// The original fixture's tick is older than lastTick and must stay ignored.
	// Stamp a fresh full tick for this synthetic recovery test; do not weaken
	// production's out-of-order snapshot protection.
	fresh := &msg.CSVCMsg_PacketEntities{}
	_ = proto.Unmarshal(full, fresh)
	fresh.ServerTick = proto.Uint32(74530)
	freshBody, _ := proto.Marshal(fresh)
	if e := d.PacketEntities(freshBody, time.Now()); e != nil || d.syncFault != "" {
		t.Fatal("fresh full did not recover", e)
	}
}
