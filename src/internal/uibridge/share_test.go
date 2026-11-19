package uibridge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/cs2-radar/internal/viewframe"
)

func shareFixture(t *testing.T) *Bridge {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "fixture"), 0700)
	os.WriteFile(filepath.Join(root, "fixture/overview.png"), fixture().png, 0600)
	opaque := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	frame := &viewframe.Frame{Version: 3, Generation: opaque, Width: 1024, Height: 1024, MapID: "fixture", Image: "/mapimg/fixture/overview.png", State: "ready", Players: []viewframe.Point{{ID: opaque, PX: 123, PY: 456, Team: 2, Name: "测试 <纯文本>"}}, Sounds: []viewframe.Point{}}
	if e := frame.Validate(); e != nil {
		t.Fatal(e)
	}
	b := &Bridge{ctx: ctx, cancel: cancel, mapRoot: root, active: true, frame: frame, at: time.Now(), failure: make(chan struct{}), local: "http://127.0.0.1:31999", cookieName: "owner", cookie: "OWNER_ONLY"}
	t.Cleanup(b.Close)
	return b
}
func startTestShare(t *testing.T, b *Bridge) *readonlyShare {
	t.Helper()
	if e := b.startShare(shareConfig{Mode: "tunnel", BindIP: "127.0.0.1", Minutes: 15, PublicOrigin: "https://viewer.example.invalid"}); e != nil {
		t.Fatal(e)
	}
	return b.share
}
func shareRequest(s *readonlyShare, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, s.origin+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Origin", s.origin)
	r.Header.Set("X-Gamesense-Viewer", "1")
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.serve(w, r)
	return w
}
func joinTestShare(t *testing.T, s *readonlyShare) *http.Cookie {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"invite": strings.Split(s.link, "#")[1]})
	w := shareRequest(s, "POST", "/session", string(raw), nil)
	if w.Code != 200 {
		t.Fatalf("join code %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing viewer cookie")
	}
	return cookies[0]
}
func TestReadonlyBoundaryAndRevocation(t *testing.T) {
	b := shareFixture(t)
	if b.share != nil {
		t.Fatal("must default off")
	}
	s := startTestShare(t, b)
	for _, p := range []string{"/view", "/mapimg/fixture/overview.png"} {
		if w := shareRequest(s, "GET", p, "", nil); w.Code != 403 {
			t.Fatalf("unauthorized %s %d", p, w.Code)
		}
	}
	if w := shareRequest(s, "POST", "/session", `{"invite":"`+strings.Repeat("x", 43)+`"}`, nil); w.Code != 403 {
		t.Fatal("wrong invitation accepted")
	}
	c := joinTestShare(t, s)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("weak cookie")
	}
	if c.Name == b.cookieName || c.Value == b.cookie {
		t.Fatal("owner credential reused")
	}
	if w := shareRequest(s, "GET", "/view", "", c); w.Code != 200 || !strings.Contains(w.Body.String(), `"px":123`) || strings.Contains(w.Body.String(), "OWNER_ONLY") {
		t.Fatal("valid view contract failed")
	}
	if w := shareRequest(s, "GET", "/mapimg/fixture/overview.png", "", c); w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatal("current local map unavailable")
	}
	for _, p := range []string{"/map", "/atlas/save", "/atlas/restore", "/share/start", "/share/stop", "/api/v1/ingest", "/admin/cards.php"} {
		for _, m := range []string{"GET", "POST", "DELETE", "OPTIONS"} {
			if w := shareRequest(s, m, p, `{}`, c); w.Code != 403 {
				t.Fatalf("privileged route %s %s %d", m, p, w.Code)
			}
		}
	}
	if w := shareRequest(s, "GET", "/mapimg/other/overview.png", "", c); w.Code != 403 {
		t.Fatal("non-current map exposed")
	}
	if w := shareRequest(s, "GET", "/view?invite=forbidden", "", c); w.Code != 403 {
		t.Fatal("query credential accepted")
	}
	if w := shareRequest(s, "GET", "/view", "", &http.Cookie{Name: b.cookieName, Value: b.cookie}); w.Code != 403 {
		t.Fatal("owner cookie became viewer")
	}
	// A viewer cookie cannot bootstrap or mutate the original native bridge.
	r := httptest.NewRequest("POST", b.local+"/share/stop", strings.NewReader(`{}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Origin", b.local)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Gamesense-View", "1")
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	b.serve(w, r)
	if w.Code != 403 {
		t.Fatal("viewer crossed owner boundary")
	}
	b.mu.Lock()
	b.at = time.Now().Add(-2 * time.Second)
	b.mu.Unlock()
	if w := shareRequest(s, "GET", "/view", "", c); w.Code != 503 || strings.Contains(w.Body.String(), "123") {
		t.Fatal("stale frame leaked")
	}
	b.mu.Lock()
	b.at = time.Now()
	b.mu.Unlock()
	if shareRequest(s, "GET", "/view", "", c).Code != 200 {
		t.Fatal("fresh recovery failed")
	}
	oldLink := s.link
	b.stopShare()
	if shareRequest(s, "GET", "/view", "", c).Code != 403 {
		t.Fatal("stopped credential survived")
	}
	newer := startTestShare(t, b)
	if newer.link == oldLink {
		t.Fatal("invitation reused")
	}
	if shareRequest(newer, "GET", "/view", "", c).Code != 403 {
		t.Fatal("old cookie survived restart")
	}
	fmt.Println("READONLY=AUTHORIZED_PIXELS_ONLY MUTATIONS=403 STALE=503 STOP=REVOKED RESTART=NEW_GRANT")
}
func TestReadonlyOriginHostSourceAndLimit(t *testing.T) {
	b := shareFixture(t)
	s := startTestShare(t, b)
	c := joinTestShare(t, s)
	for _, kind := range []string{"host", "origin", "source", "fetch", "iframe", "missing-origin", "encoded-path"} {
		r := httptest.NewRequest("POST", s.origin+"/session", strings.NewReader(`{}`))
		r.RemoteAddr = "127.0.0.1:123"
		r.Header.Set("Origin", s.origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Gamesense-Viewer", "1")
		r.AddCookie(c)
		switch kind {
		case "host":
			r.Host = "attacker.invalid"
		case "origin":
			r.Header.Set("Origin", "https://attacker.invalid")
		case "source":
			r.RemoteAddr = "8.8.8.8:123"
		case "fetch":
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		case "iframe":
			r.Header.Set("Sec-Fetch-Dest", "iframe")
		case "missing-origin":
			r.Header.Del("Origin")
		case "encoded-path":
			r.URL.RawPath = "/%73ession"
		}
		w := httptest.NewRecorder()
		s.serve(w, r)
		if w.Code != 403 {
			t.Fatalf("%s allowed", kind)
		}
	}
	for i := 1; i < viewerLimit; i++ {
		joinTestShare(t, s)
	}
	raw, _ := json.Marshal(map[string]string{"invite": strings.Split(s.link, "#")[1]})
	if shareRequest(s, "POST", "/session", string(raw), nil).Code != 429 {
		t.Fatal("viewer cap not enforced")
	}
	if s.status().Viewers != viewerLimit {
		t.Fatal("wrong count")
	}
	s.mu.Lock()
	for k := range s.sessions {
		s.sessions[k] = time.Now().Add(-3 * time.Minute)
	}
	s.mu.Unlock()
	if shareRequest(s, "GET", "/view", "", c).Code != 403 {
		t.Fatal("idle session accepted")
	}
	joinTestShare(t, s)
	s.mu.Lock()
	s.tokens = 0
	s.rateAt = time.Now()
	s.mu.Unlock()
	if shareRequest(s, "GET", "/view", "", c).Code != 429 {
		t.Fatal("rate bound missing")
	}
	fmt.Println("ORIGIN_HOST_SOURCE_CSRF=DENIED VIEWERS=5 IDLE=RECLAIMED RATE=BOUNDED")
}
func TestReadonlyExpiryAndHostLoss(t *testing.T) {
	for _, mode := range []string{"expire", "invalidate", "context"} {
		t.Run(mode, func(t *testing.T) {
			b := shareFixture(t)
			s := startTestShare(t, b)
			c := joinTestShare(t, s)
			switch mode {
			case "expire":
				s.mu.Lock()
				s.expires = time.Now().Add(-time.Second)
				s.mu.Unlock()
			case "invalidate":
				b.Invalidate()
			case "context":
				b.cancel()
				select {
				case <-s.done:
				case <-time.After(time.Second):
					t.Fatal("context did not close share")
				}
			}
			if w := shareRequest(s, "GET", "/view", "", c); w.Code != 403 {
				t.Fatalf("%s data survived %d", mode, w.Code)
			}
		})
	}
	fmt.Println("EXPIRY_HOST_AUTH_LOSS_EXIT=REVOKED")
}
func TestReadonlyConfigAndLANSource(t *testing.T) {
	b := shareFixture(t)
	bad := []shareConfig{{Mode: "lan", BindIP: "0.0.0.0", Minutes: 15, AcceptPlainLAN: true}, {Mode: "lan", BindIP: "127.0.0.1", Minutes: 15, AcceptPlainLAN: true}, {Mode: "tunnel", BindIP: "0.0.0.0", Minutes: 15, PublicOrigin: "https://viewer.invalid"}}
	for _, u := range []string{"http://viewer.invalid", "https://u:p@viewer.invalid", "https://viewer.invalid/api", "https://viewer.invalid?token=x", "https://viewer.invalid#x", "https://127.0.0.1", "https://192.168.1.1", "https://viewer.invalid:0"} {
		bad = append(bad, shareConfig{Mode: "tunnel", BindIP: "127.0.0.1", Minutes: 15, PublicOrigin: u})
	}
	for _, c := range bad {
		if b.startShare(c) == nil {
			t.Fatal("invalid config accepted")
		}
	}
	s := &readonlyShare{bridge: b, mode: "lan", cookieName: "fixture_lan_only", origin: "http://192.168.1.2:18083", listen: "192.168.1.2:18083", expires: time.Now().Add(time.Minute), done: make(chan struct{}), sessions: map[[32]byte]time.Time{}, tokens: 200, rateAt: time.Now()}
	for _, peer := range []string{"192.168.1.3:1234", "8.8.8.8:1234"} {
		r := httptest.NewRequest("GET", s.origin+"/", nil)
		r.RemoteAddr = peer
		w := httptest.NewRecorder()
		s.serve(w, r)
		expected := 200
		if strings.HasPrefix(peer, "8.") {
			expected = 403
		}
		if w.Code != expected {
			t.Fatalf("LAN source %d", w.Code)
		}
	}
	// A LAN cookie is intentionally not claimed confidential or Secure over HTTP.
	secret, _ := viewerSecret()
	s.invitation = sha256.Sum256([]byte(secret))
	s.link = s.origin + "/#" + secret
	c := joinTestShare(t, s)
	if c.Secure {
		t.Fatal("LAN HTTP cookie cannot require TLS")
	}
	fmt.Println("CONFIG=PRIVATE_INTERFACE_OR_LOOPBACK_ONLY LAN_PUBLIC_SOURCE=403")
}
func TestReadonlyRealLoopbackHTTP(t *testing.T) {
	b := shareFixture(t)
	s := startTestShare(t, b)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	do := func(path string, c *http.Cookie) *http.Response {
		r, _ := http.NewRequest("GET", "http://"+s.listen+path, nil)
		r.Host = "viewer.example.invalid"
		r.Header.Set("X-Gamesense-Viewer", "1")
		if c != nil {
			r.AddCookie(c)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		return resp
	}
	resp := do("/view", nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("real listener anonymous access")
	}
	c := joinTestShare(t, s)
	resp = do("/view", c)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var result struct {
		View viewframe.Frame `json:"view"`
		TTL  int             `json:"valid_for_ms"`
	}
	if json.Unmarshal(raw, &result) != nil || result.View.Validate() != nil || result.TTL < 1 || result.TTL > 1000 {
		t.Fatal("real listener invalid DTO")
	}
	b.stopShare()
	_, e := client.Get("http://" + s.listen + "/view")
	if e == nil {
		t.Fatal("stop left TCP listener open")
	}
	fmt.Println("REAL_LOOPBACK_HTTP=403_THEN_AUTHORIZED_V3 STOP=LISTENER_CLOSED NO_EXTERNAL_NETWORK=true")
}

func TestReadonlyOwnerControlGate(t *testing.T) {
	b := shareFixture(t)
	body := `{"mode":"tunnel","bind_ip":"127.0.0.1","port":0,"minutes":15,"public_origin":"https://viewer.example.invalid","accept_plain_lan":false}`
	call := func(path, raw, kind string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", b.local+path, strings.NewReader(raw))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Cookie", b.cookieName+"="+b.cookie)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Origin", b.local)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Gamesense-View", "1")
		switch kind {
		case "anonymous":
			r.Header.Del("Cookie")
		case "cross-origin":
			r.Header.Set("Origin", "https://other.invalid")
		case "missing-origin":
			r.Header.Del("Origin")
		case "lan-owner":
			r.RemoteAddr = "192.168.1.2:1234"
		case "missing-marker":
			r.Header.Del("X-Gamesense-View")
		}
		w := httptest.NewRecorder()
		b.serve(w, r)
		return w
	}
	for _, kind := range []string{"anonymous", "cross-origin", "missing-origin", "lan-owner", "missing-marker"} {
		if call("/share/start", body, kind).Code != 403 {
			t.Fatal("owner gate failed", kind)
		}
	}
	if call("/share/start", strings.Replace(body, `"mode":`, `"unknown":true,"mode":`, 1), "").Code != 400 {
		t.Fatal("unknown config field accepted")
	}
	if call("/share/start", body, "").Code != 200 {
		t.Fatal("owner start failed")
	}
	if b.share == nil || !strings.HasPrefix(b.share.listen, "127.0.0.1:") {
		t.Fatal("wrong tunnel bind")
	}
	if call("/share/start", body, "").Code != 400 {
		t.Fatal("active share replaced without stop")
	}
	if call("/share/stop", `{}`, "").Code != 200 || b.share != nil {
		t.Fatal("owner stop failed")
	}
	if call("/share/start", strings.Repeat("x", 4096), "").Code != 400 {
		t.Fatal("oversized control body accepted")
	}
	fmt.Println("OWNER_CONTROL=LOOPBACK_COOKIE_ORIGIN_REQUIRED DEFAULT_OFF=true TUNNEL_BIND=LOOPBACK")
}
