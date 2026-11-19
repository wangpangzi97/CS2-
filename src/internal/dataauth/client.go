package dataauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"local/cs2-radar/internal/startupdiag"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Credential is native-process-only. MAC proves possession of a current GuYi
// session key without sending a card, that key, or an app secret to the broker.
type Credential struct {
	SessionID string
	Device    string
	MAC       func(string) (string, error)
}
type Client struct {
	runtimeFailure atomic.Uint32
	mu             sync.Mutex
	audience       string
	http           *http.Client
	key            ed25519.PrivateKey
	grant          Grant
	now            func() time.Time
	failure        chan struct{}
	failOnce       sync.Once
	terminal       error
}

func NewClient(ingest, ca string, key ed25519.PrivateKey) (*Client, error) {
	audience, e := Audience(ingest)
	if e != nil {
		return nil, e
	}
	u, _ := url.Parse(ingest)
	if u.Path != "/api/v1/ingest" || len(key) != ed25519.PrivateKeySize {
		return nil, ErrDenied
	}
	if derived := ed25519.NewKeyFromSeed(key.Seed()); !bytes.Equal(derived, key) {
		return nil, ErrDenied
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		pem, e := os.ReadFile(ca)
		if e != nil {
			return nil, errors.New("data CA unavailable")
		}
		pool, e := x509.SystemCertPool()
		if e != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid data CA")
		}
		cfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	tr.MaxConnsPerHost = 2
	return &Client{audience: audience, http: &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("data redirects forbidden") }}, key: append(ed25519.PrivateKey(nil), key...), now: time.Now, failure: make(chan struct{})}, nil
}
func (c *Client) request(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, e := http.NewRequestWithContext(ctx, "POST", c.audience+path, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
}
func decodeResponse(r *http.Response, v any) error {
	if r == nil {
		return ErrUnavailable
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return &startupdiag.HTTPFailure{Status: r.StatusCode, Cause: ErrDenied}
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 8193))
	if e != nil || len(raw) > 8192 {
		return ErrUnavailable
	}
	return strictJSON(raw, v)
}
func (c *Client) Login(ctx context.Context, credential Credential) (failure error) {
	stage := startupdiag.DataChallenge
	defer func() {
		if failure != nil {
			failure = startupdiag.Wrap(stage, failure)
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil || c.grant.SessionID != "" || credential.MAC == nil {
		return ErrDenied
	}
	in := Bootstrap{credential.SessionID, credential.Device, base64.RawURLEncoding.EncodeToString(c.key.Public().(ed25519.PublicKey))}
	if !validBootstrap(in) {
		return ErrDenied
	}
	raw, _ := json.Marshal(in)
	resp, e := c.request(ctx, "/api/v2/auth/challenge", raw)
	if e != nil {
		c.failLocked()
		return errors.Join(ErrUnavailable, startupdiag.Network(e))
	}
	var challenge Challenge
	if e = decodeResponse(resp, &challenge); e != nil {
		c.failLocked()
		return e
	}
	if challenge.ID == "" || challenge.Nonce == "" || challenge.ExpiresAt <= c.now().Unix() || challenge.ExpiresAt > c.now().Add(ChallengeTTL+ProofSkew).Unix() {
		c.failLocked()
		return ErrDenied
	}
	idBytes, e1 := base64.RawURLEncoding.Strict().DecodeString(challenge.ID)
	nonceBytes, e2 := base64.RawURLEncoding.Strict().DecodeString(challenge.Nonce)
	if e1 != nil || e2 != nil || len(idBytes) != 32 || len(nonceBytes) != 32 {
		c.failLocked()
		return ErrDenied
	}
	text := EnrollmentText(c.audience, in, challenge)
	mac, e := credential.MAC(text)
	if e != nil {
		c.failLocked()
		return e
	}
	login := Login{in, challenge.ID, mac, base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, []byte(text)))}
	raw, _ = json.Marshal(login)
	stage = startupdiag.DataLogin
	resp, e = c.request(ctx, "/api/v2/auth/login", raw)
	if e != nil {
		c.failLocked()
		return errors.Join(ErrUnavailable, startupdiag.Network(e))
	}
	var grant Grant
	if e = decodeResponse(resp, &grant); e != nil {
		c.failLocked()
		return e
	}
	if !c.validGrant(grant, true) {
		c.failLocked()
		return ErrDenied
	}
	c.grant = grant
	return nil
}
func (c *Client) validGrant(g Grant, initial bool) bool {
	now := c.now().Unix()
	t, e := base64.RawURLEncoding.Strict().DecodeString(g.AccessToken)
	id, e2 := base64.RawURLEncoding.Strict().DecodeString(g.SessionID)
	if e != nil || e2 != nil || len(t) != 32 || len(id) != 32 || g.AccessExpiresAt <= now || g.LeaseExpiresAt <= now || g.AbsoluteExpiresAt <= now || g.AccessExpiresAt > now+int64((AccessTTL+ProofSkew)/time.Second) || g.LeaseExpiresAt > now+int64((LeaseTTL+ProofSkew)/time.Second) || g.AbsoluteExpiresAt > now+int64((SessionTTL+ProofSkew)/time.Second) || g.LeaseExpiresAt > g.AbsoluteExpiresAt || g.AccessExpiresAt > g.AbsoluteExpiresAt {
		return false
	}
	return initial || (g.SessionID == c.grant.SessionID && g.AbsoluteExpiresAt <= c.grant.AbsoluteExpiresAt && g.AccessToken != c.grant.AccessToken)
}
func (c *Client) FailureInfo() (uint8, uint16) {
	v := c.runtimeFailure.Load()
	return uint8(v), uint16(v >> 8)
}
func (c *Client) failLocked(cause ...error) {
	kind, status := uint8(9), uint16(0)
	if len(cause) > 0 {
		kind, status = startupdiag.FailureInfo(cause[0])
		if kind == 0 {
			kind = 1
		}
	}
	c.runtimeFailure.CompareAndSwap(0, uint32(kind)|uint32(status)<<8)
	c.failOnce.Do(func() {
		c.terminal = ErrDenied
		c.grant.AccessToken = ""
		c.key = nil
		close(c.failure)
		c.http.CloseIdleConnections()
	})
}
func (c *Client) Failed() <-chan struct{} { return c.failure }
func (c *Client) Close()                  { c.mu.Lock(); defer c.mu.Unlock(); c.failLocked() }
func (c *Client) SessionID() string       { c.mu.Lock(); defer c.mu.Unlock(); return c.grant.SessionID }
func (c *Client) doLocked(req *http.Request, body []byte) (*http.Response, error) {
	origin, e := Audience(req.URL.String())
	if e != nil || origin != c.audience || req.URL.RawQuery != "" || req.URL.RawPath != "" || req.URL.ForceQuery || len(body) > MaxBody || c.terminal != nil || c.grant.AccessToken == "" || c.now().Unix() >= c.grant.LeaseExpiresAt || c.now().Unix() >= c.grant.AccessExpiresAt || c.now().Unix() >= c.grant.AbsoluteExpiresAt {
		c.failLocked()
		return nil, ErrDenied
	}
	// Rebuild the request rather than trusting caller-supplied credentials/body.
	signed, e := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	signed.Header.Set("Content-Type", "application/json")
	// Only the drawing-format hint is forwarded. It grants no authorization;
	// caller credentials, proxy metadata and all other headers remain discarded.
	if req.Method == "GET" && req.URL.Path == "/api/v1/radar" {
		if version := req.Header.Get("X-Gamesense-View-Version"); version == "1" || version == "2" || version == "3" {
			signed.Header.Set("X-Gamesense-View-Version", version)
		}
	}
	if e = signRequest(signed, c.audience, c.grant.AccessToken, c.key, body, c.now()); e != nil {
		c.failLocked()
		return nil, e
	}
	resp, e := c.http.Do(signed)
	if e != nil {
		c.failLocked(startupdiag.Network(e))
		return nil, errors.Join(ErrUnavailable, startupdiag.Network(e))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drawing-version negotiation is not an authorization fallback. Only
		// this exact v3-format rejection from the pinned HTTPS peer may retry
		// once as v2, with a fresh proof and nonce. All other failures stay terminal.
		if req.Method == "GET" && req.URL.Path == "/api/v1/radar" && req.Header.Get("X-Gamesense-View-Version") == "3" && resp.StatusCode == 400 {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			if readErr == nil && string(raw) == "unsupported drawing version\n" {
				retry := req.Clone(req.Context())
				retry.Header.Set("X-Gamesense-View-Version", "2")
				return c.doLocked(retry, body)
			}
		}
		resp.Body.Close()
		c.failLocked(&startupdiag.HTTPFailure{Status: resp.StatusCode, Cause: ErrDenied})
		return nil, &startupdiag.HTTPFailure{Status: resp.StatusCode, Cause: ErrDenied}
	}
	return resp, nil
}

// DoBody serializes sending with token rotation. No credential enters a URL,
// disk, JS, browser history or caller-visible error.
func (c *Client) DoBody(req *http.Request, body []byte) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.doLocked(req, body)
}
func (c *Client) Heartbeat(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, "POST", c.audience+"/api/v2/auth/heartbeat", strings.NewReader("{}"))
	resp, e := c.doLocked(req, []byte("{}"))
	if e != nil {
		return e
	}
	var g Grant
	if decodeResponse(resp, &g) != nil || !c.validGrant(g, false) {
		c.failLocked()
		return ErrDenied
	}
	c.grant = g
	return nil
}
func (c *Client) Maintain(ctx context.Context) error {
	t := time.NewTicker(HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.failure:
			return ErrDenied
		case <-t.C:
			if e := c.Heartbeat(ctx); e != nil {
				return e
			}
		}
	}
}
