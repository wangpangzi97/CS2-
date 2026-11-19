package uibridge

import (
	"context"
	"encoding/base64"
	"local/cs2-radar/internal/viewframe"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApprovedUIBrowserFixture(t *testing.T) {
	out := os.Getenv("GAMESENSE_ATLAS_PREVIEW_FILE")
	if out == "" {
		t.Skip("explicit synthetic browser QA only")
	}
	maps := os.Getenv("GAMESENSE_ATLAS_PREVIEW_MAPS")
	data := os.Getenv("GAMESENSE_ATLAS_PREVIEW_DATA")
	if !filepath.IsAbs(out) || !filepath.IsAbs(maps) || !filepath.IsAbs(data) {
		t.Fatal("absolute isolated fixture paths required")
	}
	f := fixture()
	f.frame.Version = 3
	f.frame.MapID = "de_dust2"
	f.frame.Image = "/mapimg/de_dust2/overview.png"
	f.frame.State = "ready"
	id := func(x string) string { return base64.RawURLEncoding.EncodeToString([]byte(x)) }
	f.frame.Players = []viewframe.Point{{ID: id("fixture-player01"), PX: 500, PY: 440, Team: 2, Name: "彩色测试人物"}, {ID: id("fixture-player02"), PX: 630, PY: 320, Team: 3, Name: "Test player"}}
	b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", &atlasPreviewRemote{f}, maps)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	b.atlasDir = data
	if e = os.WriteFile(out, []byte(b.URL()), 0600); e != nil {
		t.Fatal(e)
	}
	end := time.Now().Add(60 * time.Minute)
	revoked := false
	for time.Now().Before(end) {
		if _, e := os.Stat(out + ".stop"); e == nil {
			return
		}
		if _, e := os.Stat(out + ".revoke"); e == nil && !revoked {
			close(f.failure)
			revoked = true
		}
		if raw, e := os.ReadFile(out + ".map"); e == nil {
			id := strings.TrimSpace(string(raw))
			if id == "de_ancient" || id == "de_dust2" {
				f.mu.Lock()
				f.frame.MapID = id
				f.frame.Image = "/mapimg/" + id + "/overview.png"
				f.mu.Unlock()
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}
