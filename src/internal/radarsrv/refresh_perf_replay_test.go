package radarsrv

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestRefreshPerfReplay(t *testing.T) {
	root := os.Getenv("PERF_TRACE")
	if root == "" {
		t.Skip("explicit offline trace required")
	}
	b, e := os.ReadFile(root)
	if e != nil {
		t.Fatal(e)
	}
	s := NewStore(DefaultConfig()).Get("ancient-perf")
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	n, synced, lost, maxPlayers := 0, false, 0, 0
	h := sha256.New()
	for len(b) > 0 {
		if len(b) < 5 {
			t.Fatal("trace header")
		}
		k := b[0]
		l := int(binary.LittleEndian.Uint32(b[1:5]))
		b = b[5:]
		if l > len(b) {
			t.Fatal("trace size")
		}
		p := b[:l]
		b = b[l:]
		if k == 1 {
			s.feedMsg(s.decoder, "s2c", p)
		} else if k == 2 {
			s.noteGNSUnrel(p)
		} else {
			t.Fatal("trace kind")
		}
		sn := s.Snapshot()
		if sn.Synced {
			synced = true
		} else if synced {
			lost++
		}
		if len(sn.Players) > maxPlayers {
			maxPlayers = len(sn.Players)
		}
		// Hash only semantic state, excluding timing, age and instrumentation.
		for _, p := range sn.Players {
			v := []any{p.ID, p.SteamID, p.PawnID, p.Serial, p.Name, p.Team, p.Health, p.Alive, p.Pos, p.Stale}
			vbytes, _ := json.Marshal(v)
			h.Write(vbytes)
		}
		n++
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	sn := s.Snapshot()
	row := map[string]any{"records": n, "players": len(sn.Players), "synced": sn.Synced, "lost_after_sync": lost, "max_players": maxPlayers, "semantic_sha256": fmt.Sprintf("%x", h.Sum(nil)), "elapsed_ms": float64(elapsed) / float64(time.Millisecond), "allocated_bytes": after.TotalAlloc - before.TotalAlloc, "mallocs": after.Mallocs - before.Mallocs, "gc_cycles": after.NumGC - before.NumGC, "gc_pause_ms": float64(after.PauseTotalNs-before.PauseTotalNs) / 1e6, "snapshot": sn}
	if out := os.Getenv("PERF_OUTPUT"); out != "" {
		raw, _ := json.MarshalIndent(row, "", "  ")
		if e := os.WriteFile(out, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	fmt.Printf("REPLAY records=%d players=%d synced=%v lost=%d elapsed_ms=%.3f allocated_bytes=%d mallocs=%d gc=%d semantic_sha=%x\n", n, len(sn.Players), sn.Synced, lost, row["elapsed_ms"], row["allocated_bytes"], row["mallocs"], row["gc_cycles"], h.Sum(nil))
	if n != 5031 || len(sn.Players) != 8 || !sn.Synced || lost != 0 {
		t.Fatal("continuity regression")
	}
}
