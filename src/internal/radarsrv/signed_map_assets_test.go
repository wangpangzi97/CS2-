package radarsrv

import (
	"bytes"
	"encoding/json"
	"image/png"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/mapdata"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedMapAssetsAll17PixelProjection(t *testing.T) {
	r, err := mapdata.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	r.SetExternalDir(filepath.Join("..", "..", "dist", "maps"))
	if len(r.IDs()) != 17 {
		t.Fatal(r.IDs())
	}
	for _, id := range r.IDs() {
		t.Run(id, func(t *testing.T) {
			m, state, reason := r.Resolve(id)
			if state != mapdata.StateReady || m.ImageKind != "external-overview" {
				t.Fatal(state, reason)
			}
			image, mime, ok := r.ImageBytes(id, "overview.png")
			if !ok || mime != "image/png" {
				t.Fatal("map missing")
			}
			cfg, e := png.DecodeConfig(bytes.NewReader(image))
			if e != nil || cfg.Width < 1 {
				t.Fatal(e)
			}
			raw := pixelFixture()
			raw.Map = m
			raw.MapState = string(state)
			raw.Players[0].Pos = cs2proto.Vec3{X: float32(m.OriginWorldX + 20*m.UnitsPerPixel), Y: float32(m.OriginWorldY - 30*m.UnitsPerPixel)}
			raw.Sounds = nil
			view := &pixelState{}
			f, e := view.project(raw)
			if e != nil || f.State != "ready" || len(f.Players) != 1 || f.Players[0].PX != 20 || f.Players[0].PY != 30 {
				t.Fatal(f, e)
			}
			again, e := view.project(raw)
			if e != nil || again.Players[0].ID != f.Players[0].ID {
				t.Fatal("unstable random ID")
			}
			other, e := (&pixelState{}).project(raw)
			if e != nil || other.Players[0].ID == f.Players[0].ID {
				t.Fatal("cross-session ID reuse")
			}
			b, _ := json.Marshal(f)
			for _, field := range []string{"\"origin_world_x\"", "\"units_per_pixel\"", "\"steam_id\"", "\"pawn_id\"", "\"pos\""} {
				if strings.Contains(string(b), field) {
					t.Fatal("private field", field)
				}
			}
		})
	}
}
func TestSignedMapAssetsMissingRemainFailClosed(t *testing.T) {
	r, e := mapdata.NewRegistry()
	if e != nil {
		t.Fatal(e)
	}
	missing := 0
	for _, id := range r.IDs() {
		if id == "de_dust2" {
			continue
		}
		m, state, _ := r.Resolve(id)
		raw := pixelFixture()
		raw.Map = m
		raw.MapState = string(state)
		f, e := (&pixelState{}).project(raw)
		if e != nil || f.State != "map_required" || len(f.Players) != 0 || len(f.Sounds) != 0 {
			t.Fatal(id, f, e)
		}
		missing++
	}
	if missing != 16 {
		t.Fatal(missing)
	}
}
