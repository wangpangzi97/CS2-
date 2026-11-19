// Package uibridge is a native-process credential boundary, not a decoder. Only
// validated drawing primitives cross into the browser. Local OS users remain
// trusted: an owner-controlled process can forge HTTP browser metadata.
package uibridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"local/cs2-radar/internal/dataauth"
	"local/cs2-radar/internal/startupdiag"
	"local/cs2-radar/internal/viewframe"
)

//go:embed ui.html ui.css ui.js atlas-core.js atlas_seed.json viewer.html viewer.css viewer.js viewer-core.js share-control.js
var assets embed.FS

type Remote interface {
	DoBody(*http.Request, []byte) (*http.Response, error)
	Failed() <-chan struct{}
}
type Bridge struct {
	mu                                sync.Mutex
	op                                sync.Mutex
	ctx                               context.Context
	cancel                            context.CancelFunc
	mapRoot                           string
	remote                            Remote
	origin, local, cookieName, cookie string
	server                            *http.Server
	failure                           chan struct{}
	once                              sync.Once
	active                            bool
	frame                             *viewframe.Frame
	at                                time.Time
	maps                              []string
	atlasOnce                         sync.Once
	atlas                             *atlasStore
	atlasErr                          error
	atlasDir                          string
	viewVersion                       int
	shareOp                           sync.Mutex
	share                             *readonlyShare
}

// Start is retained for synthetic remote-image fixtures. Production uses local maps.
func Start(parent context.Context, ingest string, remote Remote) (*Bridge, error) {
	return StartWithLocalMaps(parent, ingest, remote, "")
}
func StartWithLocalMaps(parent context.Context, ingest string, remote Remote, mapRoot string) (*Bridge, error) {
	origin, e := dataauth.Audience(ingest)
	if e != nil || remote == nil {
		return nil, errors.New("view bridge configuration invalid")
	}
	u, _ := url.Parse(ingest)
	if u.Path != "/api/v1/ingest" {
		return nil, errors.New("view bridge endpoint invalid")
	}
	ctx, cancel := context.WithCancel(parent)
	b := &Bridge{viewVersion: viewframe.NameVersion, mapRoot: mapRoot, ctx: ctx, cancel: cancel, remote: remote, origin: origin, failure: make(chan struct{}), active: true}
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		cancel()
		return nil, e
	}
	b.cookie = base64.RawURLEncoding.EncodeToString(secret)
	b.cookieName = "gs_view_" + base64.RawURLEncoding.EncodeToString(secret[:8])
	if e = b.loadMaps(); e != nil {
		e = startupdiag.Wrap(startupdiag.ViewMaps, e)
	} else if e = b.refresh(); e != nil {
		e = startupdiag.Wrap(startupdiag.ViewFrame, e)
	}
	if e != nil {
		b.Invalidate()
		return nil, e
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		b.Invalidate()
		return nil, startupdiag.Wrap(startupdiag.ViewListener, e)
	}
	b.local = "http://" + ln.Addr().String()
	b.server = &http.Server{Handler: http.HandlerFunc(b.serve), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	go func() {
		if e := b.server.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
			b.Invalidate()
		}
	}()
	go b.poll()
	return b, nil
}
func (b *Bridge) URL() string             { return b.local + "/radar" }
func (b *Bridge) Failed() <-chan struct{} { return b.failure }
func (b *Bridge) Invalidate() {
	b.once.Do(func() {
		b.mu.Lock()
		b.active = false
		b.frame = nil
		b.maps = nil
		b.at = time.Time{}
		b.mu.Unlock()
		b.stopShare()
		b.cancel()
		close(b.failure)
	})
}
func (b *Bridge) Close() {
	b.Invalidate()
	if b.server != nil {
		_ = b.server.Close()
	}
}
func (b *Bridge) request(method, path string, body []byte, limit int) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 1500*time.Millisecond)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, method, b.origin+path, bytes.NewReader(body))
	if e != nil {
		return nil, "", e
	}
	if method == "GET" && path == "/api/v1/radar" {
		req.Header.Set("X-Gamesense-View-Version", strconv.Itoa(b.viewVersion))
	}
	resp, e := b.remote.DoBody(req, body)
	if e != nil {
		return nil, "", e
	}
	defer resp.Body.Close()
	// Only the exact old protocol rejection may negotiate to v2. Authorization,
	// malformed replies, timeouts and other errors remain terminal/fail-closed.
	if method == "GET" && path == "/api/v1/radar" && b.viewVersion == viewframe.NameVersion && resp.StatusCode == 400 {
		rejected, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		if readErr == nil && string(rejected) == "unsupported drawing version\n" {
			resp.Body.Close()
			b.viewVersion = viewframe.TeamVersion
			return b.request(method, path, body, limit)
		}
		return nil, "", errors.New("remote view rejected")
	}
	if resp.StatusCode != 200 {
		return nil, "", errors.New("remote view rejected")
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if e != nil || len(raw) > limit {
		return nil, "", errors.New("remote view response limit")
	}
	return raw, resp.Header.Get("Content-Type"), nil
}
func decode(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func (b *Bridge) loadMaps() error {
	raw, _, e := b.request("GET", "/api/v1/maps", nil, 16384)
	if e != nil {
		return e
	}
	var v struct {
		IDs []string `json:"ids"`
	}
	if decode(raw, &v) != nil || len(v.IDs) > 128 {
		return errors.New("invalid map list")
	}
	seen := map[string]bool{}
	for _, id := range v.IDs {
		if !viewframe.MapID(id) || seen[id] {
			return errors.New("invalid map ID")
		}
		seen[id] = true
	}
	sort.Strings(v.IDs)
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.active {
		return errors.New("view stopped")
	}
	b.maps = v.IDs
	return nil
}
func (b *Bridge) refresh() error {
	raw, _, e := b.request("GET", "/api/v1/radar", nil, viewframe.MaxBytes)
	if e != nil {
		return e
	}
	frame, e := viewframe.Decode(raw)
	if e != nil {
		return e
	}
	if b.viewVersion == viewframe.NameVersion && frame.Version == viewframe.TeamVersion {
		b.viewVersion = viewframe.TeamVersion
	}
	// Production drawing assets come only from the original local maps directory.
	// A validated map ID binds the PNG; remote density/empty pointers must not
	// suppress the local overview. No coordinates or authorization are changed.
	if b.mapRoot != "" && frame.MapID != "" {
		frame.Image = "/mapimg/" + frame.MapID + "/overview.png"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.active {
		return errors.New("view stopped")
	}
	b.frame = &frame
	b.at = time.Now()
	return nil
}
func (b *Bridge) poll() {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-b.ctx.Done():
			b.Invalidate()
			return
		case <-b.remote.Failed():
			b.Invalidate()
			return
		case <-t.C:
			b.op.Lock()
			e := b.refresh()
			b.op.Unlock()
			if e != nil {
				b.Invalidate()
				return
			}
		}
	}
}
func (b *Bridge) freshLocked() bool {
	return b.active && b.frame != nil && time.Since(b.at) < time.Second
}
func deny(w http.ResponseWriter) { http.Error(w, "local view access denied", 403) }
func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (b *Bridge) authenticated(r *http.Request) bool {
	c, e := r.Cookie(b.cookieName)
	return e == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(b.cookie)) == 1
}
func (b *Bridge) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || host != "127.0.0.1" || "http://"+r.Host != b.local || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
		deny(w)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/radar" {
		// Only a top-level native/user navigation can bootstrap an HttpOnly cookie.
		// A link/iframe/fetch from any web origin must not mint a local grant.
		site := r.Header.Get("Sec-Fetch-Site")
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Mode") != "navigate" || r.Header.Get("Sec-Fetch-Dest") != "document" || (site != "none" && !(site == "same-origin" && b.authenticated(r))) {
			deny(w)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: b.cookieName, Value: b.cookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		raw, _ := assets.ReadFile("ui.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(raw)
		return
	}
	if !b.authenticated(r) || r.Header.Get("Sec-Fetch-Site") != "same-origin" || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != b.local) {
		deny(w)
		return
	}
	if b.serveShareControl(w, r) {
		return
	}
	if b.serveAtlas(w, r) {
		return
	}
	if r.Method == "GET" && (r.URL.Path == "/ui.js" || r.URL.Path == "/ui.css" || r.URL.Path == "/atlas-core.js") {
		name := r.URL.Path[1:]
		raw, _ := assets.ReadFile(name)
		ctype := "text/javascript; charset=utf-8"
		if name == "ui.css" {
			ctype = "text/css; charset=utf-8"
		}
		w.Header().Set("Content-Type", ctype)
		w.Write(raw)
		return
	}
	if r.Method == "GET" && viewframe.ImagePath(r.URL.Path) {
		b.image(w, r)
		return
	}
	if r.Header.Get("X-Gamesense-View") != "1" {
		deny(w)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/view":
		b.mu.Lock()
		var f *viewframe.Frame
		ttl := 0
		if b.freshLocked() {
			v := *b.frame
			f = &v
			ttl = int((time.Second - time.Since(b.at)) / time.Millisecond)
		}
		b.mu.Unlock()
		state := "disconnected"
		if f != nil {
			state = "active"
		}
		reply(w, struct {
			State      string           `json:"state"`
			View       *viewframe.Frame `json:"view"`
			ValidForMS int              `json:"valid_for_ms"`
		}{state, f, ttl})
	case r.Method == "GET" && r.URL.Path == "/maps":
		b.mu.Lock()
		ids := []string{}
		if b.freshLocked() {
			ids = append(ids, b.maps...)
		}
		b.mu.Unlock()
		reply(w, struct {
			IDs []string `json:"ids"`
		}{ids})
	case r.Method == "POST" && r.URL.Path == "/map":
		if r.Header.Get("Origin") != b.local || r.Header.Get("Content-Type") != "application/json" {
			deny(w)
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		var v struct {
			Name string `json:"name"`
		}
		if e != nil || decode(raw, &v) != nil {
			http.Error(w, "invalid selection", 400)
			return
		}
		b.op.Lock()
		defer b.op.Unlock()
		b.mu.Lock()
		valid := b.active && v.Name == ""
		for _, id := range b.maps {
			if b.active && id == v.Name {
				valid = true
			}
		}
		if valid {
			b.frame = nil
			b.at = time.Time{}
		}
		b.mu.Unlock()
		if !valid {
			http.Error(w, "invalid selection", 400)
			return
		}
		body, _ := json.Marshal(v)
		raw, _, e = b.request("POST", "/api/v1/map", body, 2048)
		var result struct {
			OK    bool   `json:"ok"`
			State string `json:"state"`
		}
		if e != nil || decode(raw, &result) != nil || !result.OK {
			b.Invalidate()
			http.Error(w, "view unavailable", 503)
			return
		}
		if e = b.refresh(); e != nil {
			b.Invalidate()
			http.Error(w, "view unavailable", 503)
			return
		}
		reply(w, map[string]bool{"ok": true})
	default:
		deny(w)
	}
}
func (b *Bridge) image(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	valid := b.freshLocked() && b.frame.Image == r.URL.Path
	generation := ""
	if valid {
		generation = b.frame.Generation
	}
	b.mu.Unlock()
	if !valid {
		deny(w)
		return
	}
	var raw []byte
	var ctype string
	var e error
	if b.mapRoot != "" {
		// The strict ImagePath and current-frame gate ran before this lookup.
		parts := strings.Split(r.URL.Path, "/")
		root, err := filepath.Abs(b.mapRoot)
		if err != nil {
			http.Error(w, "local map unavailable", 503)
			return
		}
		for _, p := range []string{root, filepath.Join(root, parts[2]), filepath.Join(root, parts[2], parts[3])} {
			st, err := os.Lstat(p)
			if err != nil || st.Mode()&os.ModeSymlink != 0 {
				http.Error(w, "local map missing; reinstall maps folder", 503)
				return
			}
		}
		file := filepath.Join(root, parts[2], parts[3])
		st, err := os.Stat(file)
		if err != nil || !st.Mode().IsRegular() || st.Size() > 8<<20 {
			http.Error(w, "invalid local map", 503)
			return
		}
		raw, e = os.ReadFile(file)
		ctype = "image/png"
	} else {
		raw, ctype, e = b.request("GET", r.URL.Path, nil, 8<<20)
	}
	if e != nil || !strings.HasPrefix(ctype, "image/png") {
		if b.mapRoot == "" {
			b.Invalidate()
		}
		http.Error(w, "image unavailable", 503)
		return
	}
	cfg, e := png.DecodeConfig(bytes.NewReader(raw))
	if e != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 4096 || cfg.Height > 4096 {
		if b.mapRoot == "" {
			b.Invalidate()
		}
		http.Error(w, "image unavailable", 503)
		return
	}
	b.mu.Lock()
	valid = b.freshLocked() && b.frame.Image == r.URL.Path && b.frame.Generation == generation
	b.mu.Unlock()
	if !valid {
		deny(w)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(raw)
}

// ViewState exports only non-sensitive UI stage metadata, never raw packets/keys.
func (b *Bridge) ViewState() (mapID, state string, players, sounds int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.freshLocked() {
		return "", "disconnected", 0, 0
	}
	return b.frame.MapID, b.frame.State, len(b.frame.Players), len(b.frame.Sounds)
}
