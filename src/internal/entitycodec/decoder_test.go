package entitycodec

import (
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"os"
	"testing"
	"time"
)

func TestFullAndDeltaFromSuppliedDemo(t *testing.T) {
	d := New()
	info, e := os.ReadFile("testdata/serverinfo.pb")
	if e != nil {
		t.Fatal(e)
	}
	if e = d.ServerInfo(info); e != nil {
		t.Fatal(e)
	}
	tm := time.Unix(100, 0)
	for k := 0; k < 5; k++ {
		b, e := os.ReadFile(fmt.Sprintf("testdata/entities-%02d.pb", k))
		if e != nil {
			t.Fatal(e)
		}
		if e = d.PacketEntities(b, tm.Add(time.Duration(k)*time.Second/64)); e != nil {
			t.Fatal(e)
		}
		ps, ok, status := d.Snapshot(tm.Add(time.Duration(k) * time.Second / 64))
		if !ok || len(ps) != 10 {
			t.Fatalf("frame %d players=%d synced=%v %s", k, len(ps), ok, status)
		}
		team2, team3 := 0, 0
		ids := map[int]bool{}
		for _, p := range ps {
			if ids[p.ID] || p.Name == "" || p.SteamID == "" || p.PawnID <= 0 || p.Health != 100 || !p.Alive {
				t.Fatalf("invalid typed player: %+v", p)
			}
			ids[p.ID] = true
			if p.Team == 2 {
				team2++
			}
			if p.Team == 3 {
				team3++
			}
			if p.Pos.X == 0 && p.Pos.Y == 0 && p.Pos.Z == 0 {
				t.Fatal("invented zero coordinate")
			}
		}
		if team2 != 5 || team3 != 5 {
			t.Fatal(team2, team3)
		}
	}
	if _, ok, _ := d.Snapshot(tm.Add(20 * time.Second)); ok {
		t.Fatal("stale stream still synchronized")
	}
}
func TestDeltaCannotInventInitialPlayers(t *testing.T) {
	d := New()
	info, _ := os.ReadFile("testdata/serverinfo.pb")
	if e := d.ServerInfo(info); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile("testdata/entities-02.pb")
	if d.PacketEntities(b, time.Now()) == nil {
		t.Fatal("delta accepted without full")
	}
	if ps, ok, _ := d.Snapshot(time.Now()); ok || len(ps) > 0 {
		t.Fatal("invented players")
	}
}

func TestMalformedDeltaRequiresFreshFullResync(t *testing.T) {
	d := New()
	info, _ := os.ReadFile("testdata/serverinfo.pb")
	full, _ := os.ReadFile("testdata/entities-00.pb")
	if e := d.ServerInfo(info); e != nil {
		t.Fatal(e)
	}
	tm := time.Now()
	if e := d.PacketEntities(full, tm); e != nil {
		t.Fatal(e)
	}
	bad, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), UpdatedEntries: proto.Int32(1), EntityData: []byte{255}})
	if d.PacketEntities(bad, tm) == nil {
		t.Fatal("truncated field path accepted")
	}
	if _, ok, _ := d.Snapshot(tm); ok {
		t.Fatal("failed state published")
	}
	if e := d.PacketEntities(full, tm); e != nil {
		t.Fatal(e)
	}
	if ps, ok, _ := d.Snapshot(tm); !ok || len(ps) != 10 {
		t.Fatal("fresh full did not recover")
	}
}
