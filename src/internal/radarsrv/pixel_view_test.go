package radarsrv

import (
	"encoding/json"
	"io"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/mapdata"
	"local/cs2-radar/internal/viewframe"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

func pixelFixture() cs2proto.Snapshot {
	return cs2proto.Snapshot{Synced: true, MapState: "ready", Map: &mapdata.MapDef{ID: "fixture", RefWidth: 100, RefHeight: 100, OriginWorldX: 100, OriginWorldY: 200, UnitsPerPixel: 2, ImageURI: "/mapimg/fixture/overview.png"}, Players: []cs2proto.Player{{ID: 42, PawnID: 43, Serial: 3, SteamID: "private-player", Name: "private-name", Health: 100, Alive: true, Pos: cs2proto.Vec3{X: 120, Y: 160, Z: 888}}}, Sounds: []cs2proto.Sound{{Ent: 777, Pos: cs2proto.Vec3{X: 160, Y: 100, Z: 999}}}}
}
func TestPixelProjectionAndNoRawFields(t *testing.T) {
	v := &pixelState{}
	f, e := v.project(pixelFixture())
	if e != nil {
		t.Fatal(e)
	}
	if len(f.Players) != 1 || len(f.Sounds) != 1 || f.Players[0].PX != 10 || f.Players[0].PY != 20 || f.Sounds[0].PX != 30 || f.Sounds[0].PY != 50 {
		t.Fatal(f)
	}
	raw, _ := json.Marshal(f)
	for _, s := range []string{`"pos"`, `"ent"`, `"serial"`, `"pawn_id"`, `"steam_id"`, `"origin_world_x"`, `"units_per_pixel"`, `"z"`, `"health"`, `private-player`, `private-name`, `"scheme"`, `"session"`} {
		if strings.Contains(string(raw), s) {
			t.Fatal("private field leaked", s)
		}
	}
	if _, e = viewframe.Decode(raw); e != nil {
		t.Fatal(e)
	}
}
func TestPixelRandomIDLifecycle(t *testing.T) {
	v := &pixelState{}
	raw := pixelFixture()
	a, _ := v.project(raw)
	again, _ := v.project(raw)
	if a.Generation != again.Generation || a.Players[0].ID != again.Players[0].ID || a.Sounds[0].ID != again.Sounds[0].ID {
		t.Fatal("unstable IDs")
	}
	other, _ := (&pixelState{}).project(raw)
	if a.Generation == other.Generation || a.Players[0].ID == other.Players[0].ID {
		t.Fatal("cross-session ID reuse")
	}
	raw.Players[0].Serial++
	serial, _ := v.project(raw)
	if serial.Players[0].ID == a.Players[0].ID {
		t.Fatal("serial reuse")
	}
	absent := raw
	absent.Players = nil
	absent.Sounds = nil
	v.project(absent)
	back, _ := v.project(raw)
	if back.Players[0].ID == serial.Players[0].ID || back.Sounds[0].ID == a.Sounds[0].ID {
		t.Fatal("departed ID revived")
	}
	raw.Map.ID = "other_map"
	raw.Map.ImageURI = ""
	changed, _ := v.project(raw)
	if changed.Generation == back.Generation || changed.Players[0].ID == back.Players[0].ID {
		t.Fatal("map ID reuse")
	}
}
func TestPixelUnknownStaleInvalidAndReset(t *testing.T) {
	raw := pixelFixture()
	raw.Synced = false
	f, _ := (&pixelState{}).project(raw)
	if len(f.Players) != 0 || len(f.Sounds) != 1 {
		t.Fatal("sound/player semantics mixed")
	}
	raw.MapState = "unknown"
	f, _ = (&pixelState{}).project(raw)
	if len(f.Sounds) != 0 || f.MapID != "" {
		t.Fatal("world fallback")
	}
	raw = pixelFixture()
	raw.Players[0].Stale = true
	raw.Sounds[0].AgeMS = 60000
	f, _ = (&pixelState{}).project(raw)
	if len(f.Players)+len(f.Sounds) != 0 {
		t.Fatal("stale points")
	}
	raw = pixelFixture()
	raw.Players[0].Pos.X = float32(math.NaN())
	raw.Sounds[0].Pos.Y = float32(math.Inf(1))
	f, e := (&pixelState{}).project(raw)
	if e != nil || len(f.Players)+len(f.Sounds) != 0 {
		t.Fatal("nonfinite coordinates")
	}
	sess := NewStore(DefaultConfig()).Get("synthetic")
	sess.pixelView = &pixelState{generation: "old"}
	sess.resetGNSGenerationLocked()
	if sess.pixelView != nil {
		t.Fatal("reset kept IDs")
	}
	sess.mapName = "de_dust2"
	sess.pendingEntitySignon = true
	reset, e := sess.PixelView()
	if e != nil || reset.MapID != "" || reset.Image != "" || len(reset.Players)+len(reset.Sounds) != 0 {
		t.Fatal("pending signon retained old view", e)
	}
}
func TestPixelHTTPSessionBoundaryAndRevoke(t *testing.T) {
	s, b, srv, ca := secureStoreFixture(t)
	c := nativeClient(t, srv, ca, strings.Repeat("ab", 32))
	s.SetMapName(c.SessionID(), "de_dust2")
	sess := s.Get(c.SessionID())
	sess.mu.Lock()
	sess.gnsPos = map[uint32]gnsPosEntry{777: {Pos: cs2proto.Vec3{}, At: time.Now()}}
	sess.mu.Unlock()
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/radar", nil)
	resp, e := c.DoBody(req, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	f, e := viewframe.Decode(raw)
	if e != nil || len(f.Sounds) != 1 || len(f.Players) != 0 {
		t.Fatal(string(raw), e)
	}
	other := nativeClient(t, srv, ca, strings.Repeat("ac", 32))
	resp, e = other.DoBody(req, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	empty, e := viewframe.Decode(raw)
	if e != nil || len(empty.Sounds) != 0 || empty.Generation == f.Generation {
		t.Fatal("other session read existing points", e)
	}
	b.Revoke(c.SessionID())
	if _, e = c.DoBody(req, nil); e == nil {
		t.Fatal("revoked view allowed")
	}
	if len(s.SessionIDs()) != 1 {
		t.Fatal("revocation did not drop own session")
	}
}
