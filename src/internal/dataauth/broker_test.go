package dataauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureAuthority struct {
	mu                  sync.Mutex
	epoch, version      int64
	denied, unavailable bool
	enrolls, checks     int
	expires             int64
}

func (a *fixtureAuthority) Enroll(ctx context.Context, e Enrollment) (Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enrolls++
	if a.unavailable {
		return Identity{}, ErrUnavailable
	}
	if a.denied || e.MAC != digest([]byte(e.Text+"fixture-proof")) {
		return Identity{}, ErrDenied
	}
	return Identity{Subject: "fixture-entitlement", Device: e.Device, PublicKey: e.PublicKey, Binding: strings.Repeat("ab", 32), Epoch: a.epoch, Version: a.version, ExpiresAt: a.expires}, nil
}
func (a *fixtureAuthority) Check(ctx context.Context, i Identity, ip string) (Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.checks++
	if a.unavailable {
		return Identity{}, ErrUnavailable
	}
	if a.denied {
		return Identity{}, ErrDenied
	}
	i.Epoch = a.epoch
	i.Version = a.version
	i.ExpiresAt = a.expires
	return i, nil
}
func credential() Credential {
	return Credential{strings.Repeat("aa", 32), strings.Repeat("bb", 32), func(s string) (string, error) { return digest([]byte(s + "fixture-proof")), nil }}
}
func fixtureKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, e := ed25519.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func fixtureCA(t *testing.T, s *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	e := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func newHarness(t *testing.T) (*Broker, *fixtureAuthority, *Client) {
	t.Helper()
	authority := &fixtureAuthority{epoch: 1, version: 1, expires: time.Now().Add(24 * time.Hour).Unix()}
	var broker *Broker
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/challenge") || strings.HasSuffix(r.URL.Path, "/login") {
			broker.AuthHandler(w, r)
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		if e != nil {
			Deny(w)
			return
		}
		p, e := broker.Authorize(r, body)
		if e != nil {
			Deny(w)
			return
		}
		if r.URL.Path == "/api/v2/auth/heartbeat" {
			g, e := broker.Heartbeat(p)
			if e != nil {
				Deny(w)
				return
			}
			jsonReply(w, g)
			return
		}
		jsonReply(w, map[string]bool{"ok": true})
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	var e error
	broker, e = NewBroker(BrokerConfig{Audience: server.URL, Authority: authority})
	if e != nil {
		t.Fatal(e)
	}
	client, e := NewClient(server.URL+"/api/v1/ingest", fixtureCA(t, server), fixtureKey(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	if e = client.Login(context.Background(), credential()); e != nil {
		t.Fatal(e)
	}
	return broker, authority, client
}
func localSigned(t *testing.T, b *Broker, c *Client, path string, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", b.cfg.Audience+path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.TLS = &tls.ConnectionState{}
	c.mu.Lock()
	e := signRequest(r, b.cfg.Audience, c.grant.AccessToken, c.key, body, b.now())
	c.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestDataLoginHeartbeatRotation(t *testing.T) {
	b, _, c := newHarness(t)
	initial := c.grant
	if initial.AbsoluteExpiresAt > time.Now().Add(SessionTTL).Unix() || initial.AccessExpiresAt > time.Now().Add(AccessTTL).Unix() || initial.LeaseExpiresAt > time.Now().Add(LeaseTTL).Unix() {
		t.Fatal("TTL exceeded")
	}
	old := localSigned(t, b, c, "/api/v1/ingest", []byte("{}"))
	if e := c.Heartbeat(context.Background()); e != nil {
		t.Fatal(e)
	}
	if c.grant.SessionID != initial.SessionID || c.grant.AccessToken == initial.AccessToken || c.grant.AbsoluteExpiresAt != initial.AbsoluteExpiresAt {
		t.Fatal("rotation extended absolute session or kept token")
	}
	if _, e := b.Authorize(old, []byte("{}")); e == nil {
		t.Fatal("old token survived rotation")
	}
	req, _ := http.NewRequest("POST", c.audience+"/api/v1/ingest", nil)
	resp, e := c.DoBody(req, []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
}
func TestDataProofBindingAndReplay(t *testing.T) {
	b, _, c := newHarness(t)
	body := []byte(`{"session":"synthetic"}`)
	for _, name := range []string{"body", "path", "method", "wrong-device-key", "stale-time", "future-time", "nonce", "query", "static-header"} {
		t.Run(name, func(t *testing.T) {
			r := localSigned(t, b, c, "/api/v1/ingest", body)
			actual := body
			switch name {
			case "body":
				actual = []byte("{}")
			case "path":
				r.URL.Path = "/api/v1/map"
			case "method":
				r.Method = "GET"
			case "wrong-device-key":
				r.Header.Set("X-Data-Proof", base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixtureKey(t), []byte("synthetic"))))
			case "stale-time":
				signRequest(r, b.cfg.Audience, c.grant.AccessToken, c.key, body, b.now().Add(-ProofSkew-time.Second))
			case "future-time":
				signRequest(r, b.cfg.Audience, c.grant.AccessToken, c.key, body, b.now().Add(ProofSkew+time.Second))
			case "nonce":
				r.Header.Set("X-Data-Nonce", "short")
			case "query":
				r.URL.RawQuery = "session=someone-else"
			case "static-header":
				r.Header.Set("X-Auth-Token", "synthetic")
			}
			if _, e := b.Authorize(r, actual); e == nil {
				t.Fatal("proof admitted after tampering")
			}
		})
	}
	r := localSigned(t, b, c, "/api/v1/ingest", body)
	if _, e := b.Authorize(r, body); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Authorize(r, body); e == nil {
		t.Fatal("request replay admitted")
	}
}
func TestDataConcurrentReplayAtomic(t *testing.T) {
	b, _, c := newHarness(t)
	body := []byte("{}")
	r := localSigned(t, b, c, "/api/v1/ingest", body)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := b.Authorize(r.Clone(context.Background()), body); e == nil {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("replay admitted %d times", admitted.Load())
	}
}
func TestDataExpiryAndAuthorityRevocation(t *testing.T) {
	for _, mode := range []string{"lease", "access", "absolute", "epoch", "version", "ban", "authority-failure", "ip-prefix", "restart"} {
		t.Run(mode, func(t *testing.T) {
			b, a, c := newHarness(t)
			now := b.now()
			advance := 3 * time.Second
			switch mode {
			case "lease":
				advance = LeaseTTL + time.Second
			case "access":
				advance = AccessTTL + time.Second
				b.mu.Lock()
				s := b.sessions[c.grant.SessionID]
				b.mu.Unlock()
				s.mu.Lock()
				s.lease = now.Add(time.Hour)
				s.mu.Unlock()
			case "absolute":
				advance = SessionTTL + time.Second
			case "epoch":
				a.mu.Lock()
				a.epoch++
				a.mu.Unlock()
			case "version":
				a.mu.Lock()
				a.version++
				a.mu.Unlock()
			case "ban":
				a.mu.Lock()
				a.denied = true
				a.mu.Unlock()
			case "authority-failure":
				a.mu.Lock()
				a.unavailable = true
				a.mu.Unlock()
			}
			b.now = func() time.Time { return now.Add(advance) }
			r := localSigned(t, b, c, "/api/v1/ingest", []byte("{}"))
			if mode == "ip-prefix" {
				r.RemoteAddr = "198.51.100.2:12345"
			}
			if mode == "restart" {
				fresh, e := NewBroker(b.cfg)
				if e != nil {
					t.Fatal(e)
				}
				b = fresh
			}
			if _, e := b.Authorize(r, []byte("{}")); e == nil {
				t.Fatal("expired/revoked/foreign request admitted")
			}
		})
	}
}
func TestDataKickCallbackAndNoRevival(t *testing.T) {
	b, a, c := newHarness(t)
	var count atomic.Int32
	b.cfg.OnRevoke = func(string) { count.Add(1) }
	a.mu.Lock()
	a.epoch++
	a.mu.Unlock()
	now := b.now()
	b.now = func() time.Time { return now.Add(3 * time.Second) }
	r := localSigned(t, b, c, "/api/v1/ingest", []byte("{}"))
	if _, e := b.Authorize(r, []byte("{}")); e == nil {
		t.Fatal("kick not observed")
	}
	b.Revoke(c.grant.SessionID)
	b.Revoke(c.grant.SessionID)
	if count.Load() != 1 {
		t.Fatal("callback not exactly once")
	}
	a.mu.Lock()
	a.epoch--
	a.mu.Unlock() // even an artificial state reversal cannot revive the token
	r = localSigned(t, b, c, "/api/v1/ingest", []byte("{}"))
	if _, e := b.Authorize(r, []byte("{}")); e == nil {
		t.Fatal("revoked token revived")
	}
}
func TestDataOneUseChallengeAndBounds(t *testing.T) {
	a := &fixtureAuthority{epoch: 1, version: 1, expires: time.Now().Add(time.Hour).Unix()}
	b, e := NewBroker(BrokerConfig{Audience: "https://example.invalid", Authority: a, MaxChallenges: 2})
	if e != nil {
		t.Fatal(e)
	}
	key := fixtureKey(t)
	cred := credential()
	bootstrap := Bootstrap{cred.SessionID, cred.Device, base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	raw, _ := json.Marshal(bootstrap)
	call := func(path string, raw []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", b.cfg.Audience+path, bytes.NewReader(raw))
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		b.AuthHandler(w, r)
		return w
	}
	w := call("/api/v2/auth/challenge", raw)
	var ch Challenge
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ch) != nil {
		t.Fatal("challenge failed")
	}
	text := EnrollmentText(b.cfg.Audience, bootstrap, ch)
	mac, _ := cred.MAC(text)
	login := Login{bootstrap, ch.ID, mac, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(text)))}
	loginRaw, _ := json.Marshal(login)
	if call("/api/v2/auth/login", loginRaw).Code != 200 || call("/api/v2/auth/login", loginRaw).Code != 403 {
		t.Fatal("challenge not one-use")
	}
	if call("/api/v2/auth/challenge", raw).Code != 200 || call("/api/v2/auth/challenge", raw).Code != 200 || call("/api/v2/auth/challenge", raw).Code != 503 {
		t.Fatal("challenge capacity unbounded")
	}
}
func TestDataPeerTrustAndNoPlaintext(t *testing.T) {
	a := &fixtureAuthority{}
	b, _ := NewBroker(BrokerConfig{Audience: "https://example.invalid", Authority: a, TrustLoopbackProxy: true})
	r := httptest.NewRequest("POST", "http://example.invalid/api/v2/auth/challenge", nil)
	r.RemoteAddr = "203.0.113.1:1234"
	r.Header.Set("X-GS-TLS", "1")
	r.Header.Set("X-GS-Client-IP", "198.51.100.2")
	if _, e := b.Peer(r); e == nil {
		t.Fatal("trusted attacker proxy headers")
	}
	r.RemoteAddr = "127.0.0.1:1234"
	if ip, e := b.Peer(r); e != nil || ip != "198.51.100.2" {
		t.Fatal("explicit proxy metadata rejected")
	}
	b.cfg.TrustLoopbackProxy = false
	if _, e := b.Peer(r); e == nil {
		t.Fatal("plaintext admitted")
	}
	r.TLS = &tls.ConnectionState{}
	if ip, e := b.Peer(r); e != nil || ip != "127.0.0.1" {
		t.Fatal("trusted forwarded header without proxy opt-in")
	}
}
func TestDataClientFailClosedAndCancellation(t *testing.T) {
	b, _, c := newHarness(t)
	b.Revoke(c.SessionID())
	if c.Heartbeat(context.Background()) == nil {
		t.Fatal("denial ignored")
	}
	select {
	case <-c.Failed():
	default:
		t.Fatal("failure not signaled")
	}
	if c.grant.AccessToken != "" || c.key != nil {
		t.Fatal("kept credential references")
	}
	if c.Heartbeat(context.Background()) == nil {
		t.Fatal("silently recovered")
	}
	_, _, c2 := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c2.Maintain(ctx) != nil {
		t.Fatal("cancel was not clean")
	}
	if HeartbeatInterval != 30*time.Second || AccessTTL != 120*time.Second || LeaseTTL != 90*time.Second || SessionTTL != 12*time.Hour {
		t.Fatal("unexpected policy")
	}
}

func TestDataInactiveLeaseSweep(t *testing.T) {
	b, _, c := newHarness(t)
	var dropped atomic.Int32
	b.cfg.OnRevoke = func(string) { dropped.Add(1) }
	now := b.now()
	b.now = func() time.Time { return now.Add(LeaseTTL + time.Second) }
	b.Sweep()
	b.Sweep()
	b.mu.Lock()
	n, tokens := len(b.sessions), len(b.tokens)
	b.mu.Unlock()
	if n != 0 || tokens != 0 || dropped.Load() != 1 {
		t.Fatal("expired lease retained state or repeated cleanup")
	}
	r := localSigned(t, b, c, "/api/v1/ingest", []byte("{}"))
	if _, e := b.Authorize(r, []byte("{}")); e == nil {
		t.Fatal("swept token survived")
	}
}
