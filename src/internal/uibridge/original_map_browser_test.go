package uibridge

import (
	"context"
	"encoding/base64"
	"local/cs2-radar/internal/viewframe"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Explicit synthetic QA only. No capture, credentials, game access or remote HTTP.
func TestOriginalLocalBrowserFixture(t *testing.T) {
	out := os.Getenv("GS_ORIGINAL_MAP_QA_URL")
	src := os.Getenv("GS_ORIGINAL_MAP_QA_PNG")
	if out == "" || src == "" {
		t.Skip("original-map browser QA not requested")
	}
	if !filepath.IsAbs(out) || !filepath.IsAbs(src) {
		t.Fatal("absolute fixture paths required")
	}
	png, e := os.ReadFile(src)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "fixture"), 0755)
	os.WriteFile(filepath.Join(root, "fixture", "overview.png"), png, 0600)
	f := fixture()
	f.frame.Image = ""
	f.frame.State = "ready"
	f.frame.Players = []viewframe.Point{{ID: base64.RawURLEncoding.EncodeToString(make([]byte, 16)), PX: 512, PY: 512}}
	b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", f, root)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if e = os.WriteFile(out, []byte(b.URL()), 0600); e != nil {
		t.Fatal(e)
	}
	until := time.Now().Add(3 * time.Minute)
	for time.Now().Before(until) {
		if _, e = os.Stat(out + ".stop"); e == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("browser QA completion marker not received")
}
