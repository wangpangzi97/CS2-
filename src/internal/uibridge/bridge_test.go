package uibridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"local/cs2-radar/internal/viewframe"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureRemote struct {
	mu         sync.Mutex
	failure    chan struct{}
	bad, stall bool
	calls      int
	frame      viewframe.Frame
	png        []byte
}

func fixture() *fixtureRemote {
	id := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	f := &fixtureRemote{failure: make(chan struct{}), frame: viewframe.Frame{Version: 1, Generation: id("fixture-view-gen"), Width: 1024, Height: 1024, MapID: "fixture", Image: "/mapimg/fixture/overview.png", State: "sounds_only", Players: []viewframe.Point{}, Sounds: []viewframe.Point{{ID: id("fixture-sound-id"), PX: 350, PY: 420}, {ID: id("second-sound-id!"), PX: 700, PY: 600}}}}
	img := image.NewRGBA(image.Rect(0, 0, 1024, 1024))
	for y := 0; y < 1024; y++ {
		for x := 0; x < 1024; x++ {
			c := color.RGBA{R: 24, G: 32, B: 27, A: 255}
			if (x/100+y/100)%2 == 0 {
				c = color.RGBA{R: 33, G: 46, B: 37, A: 255}
			}
			img.SetRGBA(x, y, c)
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	f.png = buf.Bytes()
	return f
}
func (f *fixtureRemote) Failed() <-chan struct{} { return f.failure }
func (f *fixtureRemote) DoBody(r *http.Request, body []byte) (*http.Response, error) {
	f.mu.Lock()
	f.calls++
	bad, stall, frame := f.bad, f.stall, f.frame
	f.mu.Unlock()
	if stall {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	var raw []byte
	ctype := "application/json"
	switch r.URL.Path {
	case "/api/v1/maps":
		raw = []byte(`{"ids":["fixture"]}`)
	case "/api/v1/radar":
		raw, _ = json.Marshal(frame)
		if bad {
			raw = []byte(`{"access_token":"MUST_NOT_REACH_BROWSER","pos":{"x":1000}}`)
		}
	case "/api/v1/map":
		raw = []byte(`{"ok":true,"state":"ready"}`)
	case "/mapimg/fixture/overview.png":
		raw = f.png
		ctype = "image/png"
	default:
		return nil, io.EOF
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{ctype}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
}
func startFixture(t *testing.T) (*Bridge, *fixtureRemote) {
	t.Helper()
	f := fixture()
	b, e := Start(context.Background(), "https://fixture.invalid/api/v1/ingest", f)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(b.Close)
	return b, f
}
func bootstrap(t *testing.T, b *Bridge) *http.Cookie {
	t.Helper()
	r, _ := http.NewRequest("GET", b.URL(), nil)
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	resp, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(resp.Cookies()) != 1 || !bytes.Contains(raw, []byte("gamesense")) {
		t.Fatal("bootstrap failed", resp.StatusCode)
	}
	c := resp.Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	return c
}
func local(t *testing.T, b *Bridge, c *http.Cookie, method, path, origin string) (int, []byte) {
	t.Helper()
	body := strings.NewReader(`{"name":"fixture"}`)
	r, _ := http.NewRequest(method, b.local+path, body)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Gamesense-View", "1")
	if c != nil {
		r.AddCookie(c)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("cache permitted")
	}
	return resp.StatusCode, raw
}
func TestBridgeBrowserOriginAndCookieGate(t *testing.T) {
	b, _ := startFixture(t)
	c := bootstrap(t, b)
	for _, v := range []struct {
		method, path, origin string
		c                    *http.Cookie
	}{{"GET", "/view", "", nil}, {"GET", "/view", "https://evil.invalid", c}, {"POST", "/map", "", c}, {"POST", "/map", "https://evil.invalid", c}, {"GET", "/view?session=other", "", c}, {"GET", "/api/v1/ingest", "", c}, {"OPTIONS", "/view", "https://evil.invalid", c}} {
		if code, _ := local(t, b, v.c, v.method, v.path, v.origin); code != 403 {
			t.Fatal(v, code)
		}
	}
	for _, site := range []string{"cross-site", "same-site", "same-origin", ""} {
		r, _ := http.NewRequest("GET", b.URL(), nil)
		r.Header.Set("Sec-Fetch-Site", site)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		resp, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatal("foreign bootstrap admitted", site)
		}
	}
	r, _ := http.NewRequest("GET", b.local+"/view", nil)
	r.Host = "rebinding.invalid"
	r.AddCookie(c)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Gamesense-View", "1")
	resp, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("DNS rebinding host admitted")
	}
	if code, raw := local(t, b, c, "GET", "/view", ""); code != 200 || !bytes.Contains(raw, []byte(`"state":"active"`)) {
		t.Fatal(code, string(raw))
	}
	if code, _ := local(t, b, c, "POST", "/map", b.local); code != 200 {
		t.Fatal("same-origin map denied", code)
	}
}
func TestBridgeWhitelistAndImage(t *testing.T) {
	b, _ := startFixture(t)
	c := bootstrap(t, b)
	code, raw := local(t, b, c, "GET", "/view", "")
	if code != 200 {
		t.Fatal(code)
	}
	for _, secret := range []string{`"pos"`, `"session"`, `"token"`, `"origin_world_x"`, `"ent"`} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("raw/credential leak", secret)
		}
	}
	if code, _ = local(t, b, c, "GET", "/mapimg/fixture/overview.png", ""); code != 200 {
		t.Fatal(code)
	}
	if code, _ = local(t, b, c, "GET", "/mapimg/other/overview.png", ""); code != 403 {
		t.Fatal("arbitrary proxy image")
	}
	for _, p := range []string{"/ui.js", "/ui.css"} {
		code, raw = local(t, b, c, "GET", p, "")
		if code != 200 {
			t.Fatal(p, code)
		}
		for _, s := range []string{"X-Data-Proof", "Authorization:", "access_token", "private_key", "/api/v1/ingest", "worldToImage"} {
			if bytes.Contains(raw, []byte(s)) {
				t.Fatal("native boundary leaked into assets", s)
			}
		}
	}
}
func TestBridgeRevocationMalformedAndCancellationClear(t *testing.T) {
	for _, kind := range []string{"revoke", "malformed", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := fixture()
			b, e := Start(ctx, "https://fixture.invalid/api/v1/ingest", f)
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close()
			c := bootstrap(t, b)
			switch kind {
			case "revoke":
				close(f.failure)
			case "malformed":
				f.mu.Lock()
				f.bad = true
				f.mu.Unlock()
			case "cancel":
				cancel()
			}
			select {
			case <-b.Failed():
			case <-time.After(2 * time.Second):
				t.Fatal("view did not fail closed")
			}
			code, raw := local(t, b, c, "GET", "/view", "")
			if code != 200 || !bytes.Contains(raw, []byte(`"view":null`)) || bytes.Contains(raw, []byte(`"px"`)) {
				t.Fatal("stale view retained", string(raw))
			}
			b.mu.Lock()
			retained := b.frame != nil || len(b.maps) != 0
			b.mu.Unlock()
			if retained {
				t.Fatal("native cache retained")
			}
		})
	}
}
func TestBridgeHungRemoteExpiresCachedFrame(t *testing.T) {
	b, f := startFixture(t)
	c := bootstrap(t, b)
	f.mu.Lock()
	f.stall = true
	f.mu.Unlock()
	time.Sleep(1100 * time.Millisecond)
	_, raw := local(t, b, c, "GET", "/view", "")
	if !bytes.Contains(raw, []byte(`"view":null`)) {
		t.Fatal("hung remote replayed cached view", string(raw))
	}
}
func TestBridgeRejectsUnfilteredServerPayload(t *testing.T) {
	f := fixture()
	f.bad = true
	b, e := Start(context.Background(), "https://fixture.invalid/api/v1/ingest", f)
	if e == nil || b != nil {
		if b != nil {
			b.Close()
		}
		t.Fatal("raw server payload admitted")
	}
}

// Explicit environment-gated local fixture for real-browser QA. It has only
// synthetic drawing primitives, no GuYi credentials, capture or live game data.
func TestBridgeBrowserFixture(t *testing.T) {
	out := os.Getenv("GAMESENSE_VIEW_PREVIEW_FILE")
	if out == "" {
		t.Skip("manual synthetic browser fixture not requested")
	}
	if !filepath.IsAbs(out) {
		t.Fatal("absolute fixture output required")
	}
	b, f := startFixture(t)
	if e := os.WriteFile(out, []byte(b.URL()), 0600); e != nil {
		t.Fatal(e)
	}
	stop := out + ".revoke"
	end := out + ".stop"
	deadline := time.Now().Add(10 * time.Minute)
	revoked := false
	for time.Now().Before(deadline) {
		if _, e := os.Stat(end); e == nil {
			return
		}
		if _, e := os.Stat(stop); e == nil && !revoked {
			close(f.failure)
			revoked = true
		}
		time.Sleep(100 * time.Millisecond)
	}
}
