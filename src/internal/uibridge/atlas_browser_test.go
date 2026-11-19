package uibridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"local/cs2-radar/internal/viewframe"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type atlasPreviewRemote struct{ *fixtureRemote }

func (f *atlasPreviewRemote) DoBody(r *http.Request, body []byte) (*http.Response, error) {
	if r.URL.Path == "/api/v1/maps" {
		raw := []byte(`{"ids":["de_dust2","de_ancient","de_inferno","de_nuke","de_mirage","de_anubis","de_vertigo","de_overpass","de_train","cs_office","de_cache"]}`)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	}
	if r.URL.Path == "/api/v1/map" {
		var v struct {
			Name string `json:"name"`
		}
		json.Unmarshal(body, &v)
		if v.Name != "" {
			f.mu.Lock()
			f.frame.MapID = v.Name
			f.frame.Image = "/mapimg/" + v.Name + "/overview.png"
			f.mu.Unlock()
		}
	}
	return f.fixtureRemote.DoBody(r, body)
}
func TestPhase76AtlasBrowserFixture(t *testing.T) {
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
	f.frame.Version = 2
	f.frame.MapID = "de_dust2"
	f.frame.Image = "/mapimg/de_dust2/overview.png"
	f.frame.State = "ready"
	id := func(x string) string { return base64.RawURLEncoding.EncodeToString([]byte(x)) }
	f.frame.Players = []viewframe.Point{{ID: id("fixture-player01"), PX: 500, PY: 440, Team: 2}, {ID: id("fixture-player02"), PX: 630, PY: 320, Team: 3}}
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
		time.Sleep(100 * time.Millisecond)
	}
}
