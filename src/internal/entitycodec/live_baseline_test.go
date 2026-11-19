package entitycodec

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestFollowupAcknowledgedBaselineNotLastPacket(t *testing.T) {
	read := func(n string) []byte {
		b, e := os.ReadFile("testdata/" + n)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	info, full := read("live-serverinfo.pb"), read("live-full.pb")
	a, b := read("live-74522.pb"), read("live-74523.pb")
	tm := time.Unix(100, 0)
	build := func() *Decoder {
		d := New()
		if e := d.ServerInfo(info); e != nil {
			t.Fatal(e)
		}
		if e := d.PacketEntities(full, tm); e != nil {
			t.Fatal(e)
		}
		return d
	}
	actual := build()
	if e := actual.PacketEntities(a, tm.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if e := actual.PacketEntities(b, tm.Add(2*time.Second)); e != nil {
		t.Fatalf("second delta refers to old acknowledged base: %v", e)
	}
	want := build()
	if e := want.PacketEntities(b, tm.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	ps, ok, status := actual.Snapshot(tm.Add(2 * time.Second))
	ref, rok, _ := want.Snapshot(tm.Add(2 * time.Second))
	if !ok || !rok || len(ps) != 9 {
		t.Fatal("live players", len(ps), status)
	}
	gotJSON, _ := json.Marshal(ps)
	refJSON, _ := json.Marshal(ref)
	if !reflect.DeepEqual(gotJSON, refJSON) {
		t.Fatal("branch leaked changes from the other delta")
	}
	if len(actual.history) < 3 || actual.historyBytes <= 0 || actual.historyBytes > 128<<20 {
		t.Fatal("baseline cache bound/accounting")
	}
	// Restore the full checkpoint again after two mutations: saved states must be detached.
	if e := actual.parser.RestoreRadarCheckpoint(actual.history[74515].checkpoint); e != nil {
		t.Fatal(e)
	}
	actual.ents = actual.parser.RadarEntities()
	actual.departed = copyDeparted(actual.history[74515].departed)
	actual.last = tm
	restored, ok, _ := actual.Snapshot(tm)
	baseline := build()
	original, _, _ := baseline.Snapshot(tm)
	x, _ := json.Marshal(restored)
	y, _ := json.Marshal(original)
	if !ok || !reflect.DeepEqual(x, y) {
		t.Fatal("checkpoint aliasing changed pristine baseline")
	}
}
