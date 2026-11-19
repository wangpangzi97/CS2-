package uibridge

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func atlasFixture(t *testing.T) (*Bridge, *http.Cookie) {
	t.Helper()
	b, _ := startFixture(t)
	b.atlasDir = t.TempDir()
	return b, bootstrap(t, b)
}
func atlasRequest(t *testing.T, b *Bridge, c *http.Cookie, path string, v any, origin string) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(v)
	method := "GET"
	if v != nil {
		method = "POST"
	}
	r, _ := http.NewRequest(method, b.local+path, bytes.NewReader(raw))
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Gamesense-View", "1")
	if c != nil {
		r.AddCookie(c)
	}
	if v != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	q, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Body.Close()
	x, _ := io.ReadAll(q.Body)
	return q.StatusCode, x
}
func atlasLoad(t *testing.T, b *Bridge, c *http.Cookie) atlasCatalog {
	t.Helper()
	code, raw := atlasRequest(t, b, c, "/atlas/data", nil, "")
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	var v atlasCatalog
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("invalid response")
	}
	return v
}
func TestAtlasImportContract(t *testing.T) {
	b, c := atlasFixture(t)
	v := atlasLoad(t, b, c)
	n, refs := 0, 0
	for _, s := range v.Spots {
		n += len(s.Props)
		for _, p := range s.Props {
			refs += len(p.Imgs)
		}
	}
	if len(v.Spots) != 38 || n != 52 || refs != 63 || len(v.Images) != 56 || len(v.Labels) != 11 || len(v.Features) != 6 {
		t.Fatal("incomplete packaged reference")
	}
}
func TestAtlasDurableSaveBackupRestoreAndRevision(t *testing.T) {
	b, c := atlasFixture(t)
	v := atlasLoad(t, b, c)
	oldName := v.Spots[0].Props[0].Name
	v.Spots[0].Props[0].Name = "本地编辑<img src=x onerror=alert(1)>"
	request := map[string]any{"revision": v.Revision, "spots": v.Spots}
	if code, raw := atlasRequest(t, b, c, "/atlas/save", request, b.local); code != 200 {
		t.Fatal(code, string(raw))
	}
	raw, e := os.ReadFile(filepath.Join(b.atlasDir, "data.json"))
	if e != nil {
		t.Fatal(e)
	}
	unchanged := string(raw)
	if code, _ := atlasRequest(t, b, c, "/atlas/save", request, b.local); code != 409 {
		t.Fatal("stale revision accepted", code)
	}
	after, _ := os.ReadFile(filepath.Join(b.atlasDir, "data.json"))
	if string(after) != unchanged {
		t.Fatal("conflict overwrote file")
	}
	other, _ := startFixture(t)
	other.atlasDir = b.atlasDir
	cookie := bootstrap(t, other)
	read := atlasLoad(t, other, cookie)
	if read.Revision != 1 || read.Spots[0].Props[0].Name != v.Spots[0].Props[0].Name {
		t.Fatal("new bridge did not persist across port")
	}
	if code, raw := atlasRequest(t, other, cookie, "/atlas/restore", map[string]any{"revision": read.Revision}, other.local); code != 200 {
		t.Fatal(code, string(raw))
	}
	restored := atlasLoad(t, other, cookie)
	if restored.Revision != 2 || restored.Spots[0].Props[0].Name != oldName {
		t.Fatal("backup restore failed")
	}
	t.Log("PERSISTED_ACROSS_BRIDGE_PORT=true BACKUP_RESTORED=true STALE_REVISION_REJECTED=true")
}
func TestAtlasBrowserOriginRevocationAndNoRemoteEdits(t *testing.T) {
	b, f := startFixture(t)
	b.atlasDir = t.TempDir()
	c := bootstrap(t, b)
	v := atlasLoad(t, b, c)
	for _, test := range []struct {
		cookie *http.Cookie
		origin string
	}{{nil, b.local}, {c, ""}, {c, "https://evil.invalid"}} {
		if code, _ := atlasRequest(t, b, test.cookie, "/atlas/save", map[string]any{"revision": 0, "spots": v.Spots}, test.origin); code != 403 {
			t.Fatal("foreign edit accepted", code)
		}
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if code, _ := atlasRequest(t, b, c, "/atlas/save", map[string]any{"revision": 0, "spots": v.Spots}, b.local); code != 200 {
		t.Fatal(code)
	}
	f.mu.Lock()
	after := f.calls
	f.mu.Unlock()
	if after != calls {
		t.Fatal("local edit reached remote")
	}
	b.Invalidate()
	if code, _ := atlasRequest(t, b, c, "/atlas/data", nil, ""); code != 403 {
		t.Fatal("revoked reference exposed", code)
	}
	if code, _ := atlasRequest(t, b, c, "/atlas/save", map[string]any{"revision": 1, "spots": v.Spots}, b.local); code != 403 {
		t.Fatal("revoked write accepted", code)
	}
}
func TestAtlasCorruptFileIsPreserved(t *testing.T) {
	b, c := atlasFixture(t)
	_ = atlasLoad(t, b, c)
	bad := []byte(`{"schema":1,"revision":7,"spots":[],"unknown":"never overwrite"}`)
	path := filepath.Join(b.atlasDir, "data.json")
	os.WriteFile(path, bad, 0600)
	if code, _ := atlasRequest(t, b, c, "/atlas/data", nil, ""); code != 503 {
		t.Fatal(code)
	}
	if code, _ := atlasRequest(t, b, c, "/atlas/save", map[string]any{"revision": 7, "spots": []atlasSpot{}}, b.local); code != 400 {
		t.Fatal(code)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, bad) {
		t.Fatal("corrupt original replaced")
	}
}
func TestAtlasRejectsInvalidAndArbitraryAssets(t *testing.T) {
	b, c := atlasFixture(t)
	v := atlasLoad(t, b, c)
	s, _ := b.atlasStore()
	for _, change := range []func(*atlasState){func(v *atlasState) { v.Spots[0].X = 101 }, func(v *atlasState) { v.Spots[0].Map = "../escape" }, func(v *atlasState) { v.Spots[0].Props[0].Imgs = []string{"../secret"} }, func(v *atlasState) { v.Spots[0].Props[0].Type = "unknown" }, func(v *atlasState) { v.Spots[0].Props[0].Name = "bad\x00" }, func(v *atlasState) { v.Spots[0].Props[0].ID = v.Spots[0].ID }} {
		raw, _ := json.Marshal(v.atlasState)
		var x atlasState
		json.Unmarshal(raw, &x)
		change(&x)
		if s.valid(x) {
			t.Fatal("invalid edit accepted")
		}
	}
	for _, path := range []string{"/atlas/map/unknown", "/atlas/map/../secret", "/atlas/image/nope", "/atlas/data?token=bad"} {
		if code, _ := atlasRequest(t, b, c, path, nil, ""); code == 200 {
			t.Fatal("arbitrary path accepted", path)
		}
	}
	request := map[string]any{"revision": 0, "spots": v.Spots, "path": "../escape"}
	if code, _ := atlasRequest(t, b, c, "/atlas/save", request, b.local); code != 400 {
		t.Fatal("unknown request field accepted", code)
	}
}
func TestAtlasFileLockPreventsConcurrentLostUpdate(t *testing.T) {
	b, c := atlasFixture(t)
	v := atlasLoad(t, b, c)
	first, _ := b.atlasStore()
	second := &atlasStore{root: first.root, seed: first.seed}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for _, s := range []*atlasStore{first, second} {
		wg.Add(1)
		go func(s *atlasStore) {
			defer wg.Done()
			_, e := s.commit(0, v.Spots, false)
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				success++
			} else if e != errAtlasConflict {
				t.Errorf("unexpected error %v", e)
			}
		}(s)
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("concurrent edits lost revision", success)
	}
}
func TestAtlasDrawingValidatorUnchanged(t *testing.T) {
	raw, _ := assets.ReadFile("ui.js")
	for _, s := range []string{"function valid(f)", "keys(p,pointKeys)", "now>=deadline", "tracks.clear()", "textContent=prop.name"} {
		if !strings.Contains(string(raw), s) {
			t.Fatal("drawing boundary or safe text missing", s)
		}
	}
}
