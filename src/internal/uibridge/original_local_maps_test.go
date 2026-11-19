package uibridge

import (
	"bytes"
	"context"
	"encoding/json"
	"local/cs2-radar/internal/viewframe"
	"os"
	"path/filepath"
	"testing"
)

func TestOriginalLocalMapIgnoresRemoteEmptyAndDensity(t *testing.T) {
	for _, pointer := range []string{"", "/mapimg/fixture/density.png", "/mapimg/fixture/overview.png"} {
		t.Run(pointer, func(t *testing.T) {
			f := fixture()
			f.frame.Image = pointer
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "fixture"), 0755)
			os.WriteFile(filepath.Join(dir, "fixture", "overview.png"), f.png, 0600)
			b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", f, dir)
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close()
			c := bootstrap(t, b)
			_, raw := local(t, b, c, "GET", "/view", "")
			var out struct {
				View viewframe.Frame `json:"view"`
			}
			if json.Unmarshal(raw, &out) != nil || out.View.Image != "/mapimg/fixture/overview.png" {
				t.Fatal("canonical image not bound")
			}
			f.mu.Lock()
			before := f.calls
			f.mu.Unlock()
			code, png := local(t, b, c, "GET", "/mapimg/fixture/overview.png", "")
			f.mu.Lock()
			after := f.calls
			f.mu.Unlock()
			if code != 200 || !bytes.Equal(png, f.png) || after != before {
				t.Fatal("local original bytes not served without remote fetch", code)
			}
			if out.View.State != "sounds_only" || len(out.View.Players) != 0 || len(out.View.Sounds) != 2 {
				t.Fatal("map fix fabricated players or changed state")
			}
			if code, _ = local(t, b, nil, "GET", "/mapimg/fixture/overview.png", ""); code != 403 {
				t.Fatal("auth weakened")
			}
			if code, _ = local(t, b, c, "GET", "/mapimg/fixture/density.png", ""); code != 403 {
				t.Fatal("unbound remote pointer exposed")
			}
		})
	}
}
func TestOriginalLocalMapPreservesReadyPlayers(t *testing.T) {
	f := fixture()
	f.frame.State = "ready"
	f.frame.Image = ""
	f.frame.Players = []viewframe.Point{{ID: f.frame.Sounds[0].ID, PX: 200, PY: 300}}
	f.frame.Sounds = nil
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "fixture"), 0755)
	os.WriteFile(filepath.Join(dir, "fixture", "overview.png"), f.png, 0600)
	b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", f, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	c := bootstrap(t, b)
	_, raw := local(t, b, c, "GET", "/view", "")
	var out struct {
		View viewframe.Frame `json:"view"`
	}
	if json.Unmarshal(raw, &out) != nil || out.View.State != "ready" || len(out.View.Players) != 1 || out.View.Players[0].PX != 200 {
		t.Fatal("real drawing primitives modified")
	}
}
func TestOriginalLocalMapCorruptAssetDoesNotRevokeLease(t *testing.T) {
	f := fixture()
	f.frame.Image = ""
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "fixture"), 0755)
	os.WriteFile(filepath.Join(dir, "fixture", "overview.png"), []byte("not a png"), 0600)
	b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", f, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	c := bootstrap(t, b)
	if code, _ := local(t, b, c, "GET", "/mapimg/fixture/overview.png", ""); code != 503 {
		t.Fatal("corrupt PNG accepted")
	}
	select {
	case <-b.Failed():
		t.Fatal("drawing failure revoked data lease")
	default:
	}
	if code, raw := local(t, b, c, "GET", "/view", ""); code != 200 || !bytes.Contains(raw, []byte(`"state":"active"`)) {
		t.Fatal("valid view removed")
	}
	b.Invalidate()
	if code, _ := local(t, b, c, "GET", "/mapimg/fixture/overview.png", ""); code != 403 {
		t.Fatal("revocation lost")
	}
}
func TestOriginalLocalMapRequiresValidatedMap(t *testing.T) {
	f := fixture()
	f.frame.MapID = ""
	f.frame.Image = ""
	f.frame.State = "map_required"
	f.frame.Sounds = nil
	b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", f, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	c := bootstrap(t, b)
	if code, _ := local(t, b, c, "GET", "/mapimg/fixture/overview.png", ""); code != 403 {
		t.Fatal("unknown map exposed")
	}
}
