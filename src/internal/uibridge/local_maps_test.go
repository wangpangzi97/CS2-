package uibridge

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalMapAssetsNeverFetchRemotePNG(t *testing.T) {
	f := fixture()
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "fixture"), 0700)
	os.WriteFile(filepath.Join(dir, "fixture", "overview.png"), f.png, 0600)
	b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", f, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	c := bootstrap(t, b)
	f.mu.Lock()
	before := f.calls
	f.mu.Unlock()
	code, raw := local(t, b, c, "GET", "/mapimg/fixture/overview.png", "")
	if code != 200 || !bytes.Equal(raw, f.png) {
		t.Fatal("local PNG not served", code)
	}
	f.mu.Lock()
	after := f.calls
	f.mu.Unlock()
	if after != before {
		t.Fatal("PNG requested from remote")
	}
	os.Remove(filepath.Join(dir, "fixture", "overview.png"))
	code, _ = local(t, b, c, "GET", "/mapimg/fixture/overview.png", "")
	if code != 503 {
		t.Fatal("missing local map silently fell back", code)
	}
	code, _ = local(t, b, nil, "GET", "/mapimg/fixture/overview.png", "")
	if code != 403 {
		t.Fatal("image authorization lost")
	}
}
func TestLocalMapsRejectWrongFrameAndTraversal(t *testing.T) {
	f := fixture()
	b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", f, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	c := bootstrap(t, b)
	for _, path := range []string{"/mapimg/other/overview.png", "/mapimg/fixture/../../license.json"} {
		code, _ := local(t, b, c, "GET", path, "")
		if code == 200 {
			t.Fatal("unbound image allowed", path)
		}
	}
	id, state, _, sounds := b.ViewState()
	if id != "fixture" || state != "sounds_only" || sounds != 2 {
		t.Fatal("public UI state missing")
	}
	b.Invalidate()
	id, _, _, sounds = b.ViewState()
	if id != "" || sounds != 0 {
		t.Fatal("stale metadata exposed")
	}
}
func TestLocalMapMissingDoesNotKillValidDataLease(t *testing.T) {
	f := fixture()
	b, e := StartWithLocalMaps(context.Background(), "https://fixture.invalid/api/v1/ingest", f, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	c := bootstrap(t, b)
	req, _ := http.NewRequest("GET", b.local+"/mapimg/fixture/overview.png", nil)
	req.AddCookie(c)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	r, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != 503 {
		t.Fatal(r.StatusCode)
	}
	select {
	case <-b.Failed():
		t.Fatal("missing drawing asset terminated data authorization")
	default:
	}
}
