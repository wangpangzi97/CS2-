package uibridge

// A separate, opt-in drawing-only listener. It has no Remote, device credential,
// filesystem editing, map-selection, ingest, or administration route.
import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"local/cs2-radar/internal/viewframe"
)

const viewerLimit = 5

type shareConfig struct {
	Mode           string `json:"mode"`
	BindIP         string `json:"bind_ip"`
	Port           int    `json:"port"`
	Minutes        int    `json:"minutes"`
	PublicOrigin   string `json:"public_origin"`
	AcceptPlainLAN bool   `json:"accept_plain_lan"`
}
type shareStatus struct {
	Active  bool   `json:"active"`
	Mode    string `json:"mode"`
	Listen  string `json:"listen"`
	Link    string `json:"link"`
	Expires string `json:"expires"`
	Viewers int    `json:"viewers"`
	Limit   int    `json:"limit"`
}
type readonlyShare struct {
	mu                                     sync.Mutex
	bridge                                 *Bridge
	server                                 *http.Server
	mode, origin, listen, link, cookieName string
	invitation                             [32]byte
	expires                                time.Time
	sessions                               map[[32]byte]time.Time
	dead                                   bool
	done                                   chan struct{}
	rateAt                                 time.Time
	tokens                                 float64
	joinAt                                 time.Time
	joins                                  int
}

func viewerSecret() (string, error) {
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func privateLAN(ip net.IP) bool {
	return ip != nil && ip.To4() != nil && ip.IsPrivate() && !ip.IsLoopback()
}
func lanAddresses() []string {
	out := []string{}
	seen := map[string]bool{}
	interfaces, _ := net.Interfaces()
	for _, in := range interfaces {
		if in.Flags&net.FlagUp == 0 || in.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := in.Addrs()
		for _, a := range addrs {
			ip, _, e := net.ParseCIDR(a.String())
			if e == nil && privateLAN(ip) && !seen[ip.String()] {
				seen[ip.String()] = true
				out = append(out, ip.String())
			}
		}
	}
	return out
}
func (b *Bridge) stopShare() {
	b.shareOp.Lock()
	defer b.shareOp.Unlock()
	if b.share != nil {
		b.share.close()
		b.share = nil
	}
}
func (s *readonlyShare) close() {
	s.mu.Lock()
	if s.dead {
		s.mu.Unlock()
		return
	}
	s.dead = true
	s.invitation = [32]byte{}
	s.link = ""
	clear(s.sessions)
	close(s.done)
	s.mu.Unlock()
	if s.server != nil {
		_ = s.server.Close()
	}
}
func (s *readonlyShare) status() shareStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	if s.dead || !time.Now().Before(s.expires) {
		return shareStatus{Limit: viewerLimit}
	}
	return shareStatus{true, s.mode, s.listen, s.link, s.expires.UTC().Format(time.RFC3339), len(s.sessions), viewerLimit}
}
func (b *Bridge) startShare(c shareConfig) error {
	b.shareOp.Lock()
	defer b.shareOp.Unlock()
	if b.share != nil && b.share.status().Active {
		return errors.New("stop current share first")
	}
	if c.Port < 0 || c.Port > 65535 || (c.Port > 0 && c.Port < 1024) || c.Minutes < 1 || c.Minutes > 60 {
		return errors.New("invalid port or duration")
	}
	origin := ""
	bind := c.BindIP
	switch c.Mode {
	case "lan":
		if !c.AcceptPlainLAN || c.PublicOrigin != "" {
			return errors.New("trusted LAN plaintext acknowledgement required")
		}
		found := false
		for _, a := range lanAddresses() {
			if a == bind {
				found = true
			}
		}
		if !found {
			return errors.New("select an active private IPv4 interface")
		}
	case "tunnel":
		if bind != "127.0.0.1" || c.AcceptPlainLAN {
			return errors.New("tunnel must bind loopback")
		}
		u, e := url.Parse(c.PublicOrigin)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(u.Host, "\\% \t\r\n") {
			return errors.New("exact HTTPS public origin required, without path or credentials")
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
			return errors.New("public HTTPS origin required")
		}
		if u.Port() != "" {
			p, e := strconv.Atoi(u.Port())
			if e != nil || p < 1 || p > 65535 {
				return errors.New("invalid HTTPS port")
			}
		}
		origin = "https://" + u.Host
	default:
		return errors.New("invalid sharing mode")
	}
	b.mu.Lock()
	fresh := b.freshLocked() && b.mapRoot != ""
	b.mu.Unlock()
	if !fresh {
		return errors.New("authorized local-map view required")
	}
	secret, e := viewerSecret()
	if e != nil {
		return e
	}
	cookie, e := viewerSecret()
	if e != nil {
		return e
	}
	ln, e := net.Listen("tcp4", net.JoinHostPort(bind, strconv.Itoa(c.Port)))
	if e != nil {
		return errors.New("viewer port unavailable")
	}
	if origin == "" {
		origin = "http://" + ln.Addr().String()
	}
	s := &readonlyShare{bridge: b, mode: c.Mode, origin: origin, listen: ln.Addr().String(), link: origin + "/#" + secret, cookieName: "gs_read_" + cookie[:12], invitation: sha256.Sum256([]byte(secret)), expires: time.Now().Add(time.Duration(c.Minutes) * time.Minute), sessions: map[[32]byte]time.Time{}, done: make(chan struct{}), tokens: 200, rateAt: time.Now()}
	s.server = &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	b.share = s
	go func() {
		if e := s.server.Serve(ln); e != nil && e != http.ErrServerClosed {
			s.close()
		}
	}()
	go func() {
		t := time.NewTimer(time.Until(s.expires))
		defer t.Stop()
		select {
		case <-b.ctx.Done():
		case <-s.done:
		case <-t.C:
		}
		s.close()
	}()
	return nil
}
func (b *Bridge) serveShareControl(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == "GET" && r.URL.Path == "/share-control.js" {
		raw, _ := assets.ReadFile("share-control.js")
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write(raw)
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/share/") {
		return false
	}
	if r.Header.Get("X-Gamesense-View") != "1" {
		deny(w)
		return true
	}
	if r.Method == "GET" && r.URL.Path == "/share/status" {
		b.shareOp.Lock()
		st := shareStatus{Limit: viewerLimit}
		if b.share != nil {
			st = b.share.status()
		}
		b.shareOp.Unlock()
		reply(w, struct {
			Share shareStatus `json:"share"`
			LAN   []string    `json:"lan"`
		}{st, lanAddresses()})
		return true
	}
	if r.Method != "POST" || r.Header.Get("Origin") != b.local || r.Header.Get("Content-Type") != "application/json" {
		deny(w)
		return true
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if e != nil {
		http.Error(w, "invalid share request", 400)
		return true
	}
	switch r.URL.Path {
	case "/share/start":
		var c shareConfig
		if decode(raw, &c) != nil {
			http.Error(w, "invalid share configuration", 400)
			return true
		}
		if e := b.startShare(c); e != nil {
			http.Error(w, e.Error(), 400)
			return true
		}
		reply(w, map[string]bool{"ok": true})
	case "/share/stop":
		var c struct{}
		if decode(raw, &c) != nil {
			http.Error(w, "invalid share request", 400)
			return true
		}
		b.stopShare()
		reply(w, map[string]bool{"ok": true})
	default:
		deny(w)
	}
	return true
}
func viewerDeny(w http.ResponseWriter) { http.Error(w, "viewer access denied", 403) }
func (s *readonlyShare) pruneLocked(now time.Time) {
	for k, last := range s.sessions {
		if now.Sub(last) > 2*time.Minute {
			delete(s.sessions, k)
		}
	}
}
func (s *readonlyShare) sessionLocked(r *http.Request, now time.Time) bool {
	c, e := r.Cookie(s.cookieName)
	if e != nil || len(c.Value) != 43 {
		return false
	}
	h := sha256.Sum256([]byte(c.Value))
	last, ok := s.sessions[h]
	if !ok || now.Sub(last) > 2*time.Minute {
		return false
	}
	s.sessions[h] = now
	return true
}
func (s *readonlyShare) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	u, _ := url.Parse(s.origin)
	if e != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || (r.Host != u.Host && !(s.mode == "tunnel" && r.Host == s.listen)) || (s.mode == "tunnel" && !ip.Equal(net.ParseIP("127.0.0.1"))) || (s.mode == "lan" && !privateLAN(ip) && !ip.IsLoopback()) || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != s.origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" || r.Header.Get("Sec-Fetch-Dest") == "iframe" {
		viewerDeny(w)
		return
	}
	now := time.Now()
	s.mu.Lock()
	if s.dead || !now.Before(s.expires) {
		s.mu.Unlock()
		viewerDeny(w)
		return
	}
	s.tokens += now.Sub(s.rateAt).Seconds() * 200
	if s.tokens > 200 {
		s.tokens = 200
	}
	s.rateAt = now
	if s.tokens < 1 {
		s.mu.Unlock()
		http.Error(w, "viewer rate limit", 429)
		return
	}
	s.tokens--
	s.bridge.mu.Lock()
	fresh := s.bridge.freshLocked()
	s.bridge.mu.Unlock()
	if !fresh {
		s.mu.Unlock()
		http.Error(w, "host view unavailable", 503)
		return
	}
	s.mu.Unlock()
	// Public shell has no data and no credential. Capability is read from URL
	// fragment, immediately removed, then exchanged over same-origin POST.
	if r.Method == "GET" {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "viewer.html"
		}
		ctype := ""
		switch name {
		case "viewer.html":
			ctype = "text/html; charset=utf-8"
		case "viewer.js", "viewer-core.js", "atlas-core.js":
			ctype = "text/javascript; charset=utf-8"
		case "viewer.css":
			ctype = "text/css; charset=utf-8"
		}
		if ctype != "" {
			raw, _ := assets.ReadFile(name)
			w.Header().Set("Content-Type", ctype)
			w.Write(raw)
			return
		}
	}
	if r.Method == "POST" && r.URL.Path == "/session" {
		if r.Header.Get("Origin") != s.origin || r.Header.Get("X-Gamesense-Viewer") != "1" || r.Header.Get("Content-Type") != "application/json" {
			viewerDeny(w)
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 256))
		var in struct {
			Invite string `json:"invite"`
		}
		if e != nil || decode(raw, &in) != nil || len(in.Invite) != 43 {
			viewerDeny(w)
			return
		}
		h := sha256.Sum256([]byte(in.Invite))
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.dead || !time.Now().Before(s.expires) {
			viewerDeny(w)
			return
		}
		if now.Sub(s.joinAt) >= time.Minute {
			s.joinAt = now
			s.joins = 0
		}
		s.joins++
		if s.joins > 10 {
			http.Error(w, "viewer join rate limit", 429)
			return
		}
		if subtle.ConstantTimeCompare(h[:], s.invitation[:]) != 1 {
			viewerDeny(w)
			return
		}
		s.pruneLocked(now)
		if s.sessionLocked(r, now) {
			reply(w, map[string]bool{"ok": true})
			return
		}
		if len(s.sessions) >= viewerLimit {
			http.Error(w, "viewer slots full", 429)
			return
		}
		credential, e := viewerSecret()
		if e != nil {
			http.Error(w, "viewer unavailable", 503)
			return
		}
		s.sessions[sha256.Sum256([]byte(credential))] = now
		http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: credential, Path: "/", HttpOnly: true, Secure: s.mode == "tunnel", SameSite: http.SameSiteStrictMode, Expires: s.expires})
		reply(w, map[string]bool{"ok": true})
		return
	}
	s.mu.Lock()
	authed := !s.dead && time.Now().Before(s.expires) && s.sessionLocked(r, now)
	s.mu.Unlock()
	if !authed {
		viewerDeny(w)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/view" && r.Header.Get("X-Gamesense-Viewer") == "1" {
		b := s.bridge
		b.mu.Lock()
		var f *viewframe.Frame
		ttl := 0
		if b.freshLocked() {
			v := *b.frame
			f = &v
			ttl = int(min(time.Second-time.Since(b.at), time.Until(s.expires)) / time.Millisecond)
		}
		b.mu.Unlock()
		s.mu.Lock()
		live := !s.dead && time.Now().Before(s.expires)
		s.mu.Unlock()
		if !live || ttl < 1 || f == nil {
			http.Error(w, "host view unavailable", 503)
			return
		}
		reply(w, struct {
			State string           `json:"state"`
			View  *viewframe.Frame `json:"view"`
			TTL   int              `json:"valid_for_ms"`
		}{"active", f, ttl})
		return
	}
	if r.Method == "GET" && viewframe.ImagePath(r.URL.Path) {
		s.bridge.image(w, r)
		return
	}
	// No forwarding fallback: /map, /atlas/*, /share/*, /api/* and /admin/* deny.
	viewerDeny(w)
}
