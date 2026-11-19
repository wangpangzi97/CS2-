package uibridge

import (
	"context"
	"encoding/base64"
	"local/cs2-radar/internal/viewframe"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type movingNameRemote struct {
	*atlasPreviewRemote
	started time.Time
}

func (f *movingNameRemote) DoBody(r *http.Request, b []byte) (*http.Response, error) {
	if r.URL.Path == "/api/v1/radar" {
		f.mu.Lock()
		if len(f.frame.Players) > 0 {
			f.frame.Players[0].PX = 500 + int(math.Sin(time.Since(f.started).Seconds()/3)*180)
			f.frame.Players[0].PY = 440 + int(math.Cos(time.Since(f.started).Seconds()/3)*120)
		}
		f.mu.Unlock()
	}
	return f.atlasPreviewRemote.DoBody(r, b)
}
func TestPhase77NamesBrowserFixture(t *testing.T) {
	out := os.Getenv("GAMESENSE_NAMES_PREVIEW_FILE")
	if out == "" {
		t.Skip("explicit isolated names browser QA only")
	}
	maps := os.Getenv("GAMESENSE_NAMES_PREVIEW_MAPS")
	data := os.Getenv("GAMESENSE_NAMES_PREVIEW_DATA")
	if !filepath.IsAbs(out) || !filepath.IsAbs(maps) || !filepath.IsAbs(data) {
		t.Fatal("isolated absolute paths required")
	}
	f := fixture()
	f.frame.Version = 3
	f.frame.MapID = "de_dust2"
	f.frame.Image = "/mapimg/de_dust2/overview.png"
	f.frame.State = "ready"
	id := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	f.frame.Players = []viewframe.Point{{ID: id("fixture-player01"), PX: 500, PY: 440, Team: 2, Name: "测试T <文字>"}, {ID: id("fixture-player02"), PX: 650, PY: 320, Team: 3, Name: "测试CT"}}
	b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", &movingNameRemote{&atlasPreviewRemote{f}, time.Now()}, maps)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	b.atlasDir = data
	if e = os.WriteFile(out, []byte(b.URL()), 0600); e != nil {
		t.Fatal(e)
	}
	until := time.Now().Add(30 * time.Minute)
	revoked := false
	for time.Now().Before(until) {
		if _, e := os.Stat(out + ".stop"); e == nil {
			return
		}
		if _, e := os.Stat(out + ".revoke"); e == nil && !revoked {
			close(f.failure)
			revoked = true
		}
		time.Sleep(100 * time.Millisecond)
	}
}
