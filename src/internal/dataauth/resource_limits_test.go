package dataauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Measures the old and new policies with identical, synthetic signed inputs.
// A fixed test clock compresses one minute; this is not production throughput.
func TestDataResourceBoundaryProbe(t *testing.T) {
	b, _, c := newHarness(t)
	base := time.Now().Truncate(time.Minute).Add(59 * time.Second)
	b.now = func() time.Time { return base }
	admitted := 0
	for i := 0; i < 1800; i++ {
		r := localSigned(t, b, c, "/api/v1/ingest", []byte("{}"))
		if _, e := b.Authorize(r, []byte("{}")); e == nil {
			admitted++
		}
	}
	b.mu.Lock()
	s := b.sessions[c.SessionID()]
	b.mu.Unlock()
	s.mu.Lock()
	nonces := len(s.nonces)
	s.mu.Unlock()
	// Known peers should not consume a new entry when the peer table is full.
	b.mu.Lock()
	b.rates = map[string]rateWindow{}
	for i := 0; i < 4096; i++ {
		b.rates[fmt.Sprintf("synthetic-peer-%d", i)] = rateWindow{window: base.Unix() / 60}
	}
	b.mu.Unlock()
	knownLimited := b.limited("synthetic-peer-0")
	b.now = func() time.Time { return base.Add(3 * time.Minute) }
	b.Sweep()
	b.mu.Lock()
	rates, sessions, tokens := len(b.rates), len(b.sessions), len(b.tokens)
	b.mu.Unlock()
	fmt.Printf("RESOURCE requested=1800 admitted=%d nonce_entries=%d known_peer_at_capacity_limited=%t idle_rates=%d sessions=%d tokens=%d\n", admitted, nonces, knownLimited, rates, sessions, tokens)
}

// Fixed-minute boundary simulation, not a 1800 RPS or wall-clock load claim.
// Heartbeats are signed and count toward the same per-minute admission quota.
func TestDataResourceNonceWindows(t *testing.T) {
	b, _, c := newHarness(t)
	base := time.Now().Truncate(time.Minute)
	start := time.Now()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	peak, admitted := 0, 0
	var old *http.Request
	for _, second := range []int{59, 60, 120} {
		now := base.Add(time.Duration(second) * time.Second)
		b.now = func() time.Time { return now }
		for i := 0; i < 1799; i++ {
			r := localSigned(t, b, c, "/api/v1/ingest", []byte("{}"))
			if _, e := b.Authorize(r, []byte("{}")); e != nil {
				t.Fatalf("under-quota request rejected at second=%d index=%d: %v", second, i, e)
			}
			admitted++
			if i == 0 {
				old = r
				if _, e := b.Authorize(r, []byte("{}")); e == nil {
					t.Fatal("replay admitted under load")
				}
			}
		}
		r := localSigned(t, b, c, "/api/v2/auth/heartbeat", []byte("{}"))
		p, e := b.Authorize(r, []byte("{}"))
		if e != nil {
			t.Fatal("heartbeat quota", e)
		}
		admitted++
		g, e := b.Heartbeat(p)
		if e != nil {
			t.Fatal("rotation", e)
		}
		c.mu.Lock()
		c.grant = g
		c.mu.Unlock()
		if _, e = b.Authorize(r, []byte("{}")); e == nil {
			t.Fatal("old token after rotation")
		}
		if _, e = b.Authorize(localSigned(t, b, c, "/api/v1/ingest", []byte("{}")), []byte("{}")); e == nil {
			t.Fatal("request 1801 admitted")
		}
		p.s.mu.Lock()
		n := len(p.s.nonces)
		p.s.mu.Unlock()
		if n > peak {
			peak = n
		}
		if n > maxSessionNonces {
			t.Fatal("nonce table exceeded bound")
		}
	}
	if peak != 3600 || maxSessionNonces != 3600 || admitted != 5400 {
		t.Fatalf("unexpected bound peak=%d admitted=%d", peak, admitted)
	}
	b.now = func() time.Time { return base.Add(181 * time.Second) }
	p, e := b.Authorize(localSigned(t, b, c, "/api/v1/ingest", []byte("{}")), []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	p.s.mu.Lock()
	retained := len(p.s.nonces)
	p.s.mu.Unlock()
	if retained != 1 {
		t.Fatalf("stale nonces retained: %d", retained)
	}
	if _, e = b.Authorize(old, []byte("{}")); e == nil {
		t.Fatal("expired signed request survived eviction")
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	fmt.Printf("SYNTHETIC_WINDOWS admitted=%d peak_nonces=%d after_expiry=%d elapsed_ms=%d heap_alloc_delta=%d (not RSS/SLA)\n", admitted, peak, retained, time.Since(start).Milliseconds(), int64(after.HeapAlloc)-int64(before.HeapAlloc))
}

func TestDataResourceRateTable(t *testing.T) {
	b, _, _ := newHarness(t)
	base := time.Now()
	b.now = func() time.Time { return base }
	b.mu.Lock()
	b.rates = map[string]rateWindow{}
	b.mu.Unlock()
	for i := 0; i < maxAuthPeers; i++ {
		if b.limited(fmt.Sprintf("synthetic-%d", i)) {
			t.Fatal("peer table rejected early")
		}
	}
	if !b.limited("new-over-capacity") {
		t.Fatal("peer table grew over cap")
	}
	for i := 1; i < authRequestsPerMinute; i++ {
		if b.limited("synthetic-0") {
			t.Fatal("known peer rejected before quota")
		}
	}
	if !b.limited("synthetic-0") {
		t.Fatal("known peer exceeded quota")
	}
	b.mu.Lock()
	n := len(b.rates)
	b.mu.Unlock()
	if n != 4096 {
		t.Fatalf("peer cap %d", n)
	}
	b.now = func() time.Time { return base.Add(2 * time.Minute) }
	b.Sweep()
	b.mu.Lock()
	n = len(b.rates)
	b.mu.Unlock()
	if n != 0 {
		t.Fatal("idle rate table retained stale entries")
	}
	if b.limited("new-over-capacity") {
		t.Fatal("expired capacity not recovered")
	}
	fmt.Println("RATE_TABLE peak=4096 unknown_refused=true known_quota=20 idle_entries=0 capacity_recovered=true")
}

type resourceHTTPResult struct {
	code int
	raw  []byte
	err  error
}

func resourcePost(client *http.Client, url string, raw []byte) resourceHTTPResult {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, e := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(raw))
	if e != nil {
		return resourceHTTPResult{err: e}
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := client.Do(r)
	if e != nil {
		return resourceHTTPResult{err: e}
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 8193))
	return resourceHTTPResult{response.StatusCode, body, e}
}

func TestDataResourceTLSChallengeBurst(t *testing.T) {
	a := &fixtureAuthority{}
	var b *Broker
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b.AuthHandler(w, r) }))
	defer s.Close()
	transport := s.Client().Transport.(*http.Transport)
	transport.MaxConnsPerHost = 32
	transport.MaxIdleConnsPerHost = 32
	// One bounded connection per request avoids speculative idle-pool dials
	// being cancelled during teardown of this short burst fixture.
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	var e error
	b, e = NewBroker(BrokerConfig{Audience: s.URL, Authority: a, MaxChallenges: 8})
	if e != nil {
		t.Fatal(e)
	}
	base := time.Now()
	b.now = func() time.Time { return base }
	key := fixtureKey(t)
	cred := credential()
	raw, _ := json.Marshal(Bootstrap{cred.SessionID, cred.Device, base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	results := make(chan resourceHTTPResult, 32)
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		go func() { <-start; results <- resourcePost(s.Client(), s.URL+"/api/v2/auth/challenge", raw) }()
	}
	close(start)
	counts := map[int]int{}
	for i := 0; i < 32; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		counts[r.code]++
	}
	if counts[200] != 8 || counts[503] != 12 || counts[429] != 12 || len(counts) != 3 {
		t.Fatalf("unexpected challenge burst: %v", counts)
	}
	b.mu.Lock()
	n := len(b.challenges)
	b.mu.Unlock()
	if n != 8 {
		t.Fatal("challenge cap exceeded")
	}
	b.now = func() time.Time { return base.Add(ChallengeTTL + time.Second) }
	b.Sweep()
	b.mu.Lock()
	n = len(b.challenges)
	b.mu.Unlock()
	if n != 0 {
		t.Fatal("idle challenges retained")
	}
	fmt.Println("TLS_CHALLENGES concurrent=32 accepted=8 capacity503=12 rate429=12 idle_challenges=0")
}

type resourceAuthority struct {
	gate                chan struct{}
	entered             chan struct{}
	active, peak, calls atomic.Int32
}

func (a *resourceAuthority) Enroll(ctx context.Context, e Enrollment) (Identity, error) {
	n := a.active.Add(1)
	defer a.active.Add(-1)
	a.calls.Add(1)
	for {
		old := a.peak.Load()
		if n <= old || a.peak.CompareAndSwap(old, n) {
			break
		}
	}
	a.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return Identity{}, ErrUnavailable
	case <-a.gate:
	}
	if e.MAC != digest([]byte(e.Text+"fixture-proof")) {
		return Identity{}, ErrDenied
	}
	return Identity{Subject: e.PublicKey, Device: e.Device, PublicKey: e.PublicKey, Binding: strings.Repeat("cd", 32), Epoch: 1, Version: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()}, nil
}
func (a *resourceAuthority) Check(_ context.Context, i Identity, _ string) (Identity, error) {
	return i, nil
}

func TestDataResourceTLSEnrollmentSlots(t *testing.T) {
	a := &resourceAuthority{gate: make(chan struct{}), entered: make(chan struct{}, 8)}
	var release sync.Once
	defer release.Do(func() { close(a.gate) })
	var b *Broker
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b.AuthHandler(w, r) }))
	defer s.Close()
	var drops atomic.Int32
	var e error
	b, e = NewBroker(BrokerConfig{Audience: s.URL, Authority: a, MaxSessions: 3, MaxChallenges: 8, OnRevoke: func(string) { drops.Add(1) }})
	if e != nil {
		t.Fatal(e)
	}
	base := time.Now()
	b.now = func() time.Time { return base }
	logins := [][]byte{}
	for i := 0; i < 8; i++ {
		key := fixtureKey(t)
		cred := credential()
		in := Bootstrap{cred.SessionID, cred.Device, base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
		raw, _ := json.Marshal(in)
		r := resourcePost(s.Client(), s.URL+"/api/v2/auth/challenge", raw)
		var ch Challenge
		if r.err != nil || r.code != 200 || json.Unmarshal(r.raw, &ch) != nil {
			t.Fatal("challenge", r.code, r.err)
		}
		text := EnrollmentText(b.cfg.Audience, in, ch)
		mac, _ := cred.MAC(text)
		raw, _ = json.Marshal(Login{in, ch.ID, mac, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(text)))})
		logins = append(logins, raw)
	}
	results := make(chan resourceHTTPResult, 8)
	start := make(chan struct{})
	for _, raw := range logins {
		go func(raw []byte) { <-start; results <- resourcePost(s.Client(), s.URL+"/api/v2/auth/login", raw) }(raw)
	}
	close(start)
	for i := 0; i < 4; i++ {
		select {
		case <-a.entered:
		case <-time.After(750 * time.Millisecond):
			t.Fatal("enrollment slots not entered")
		}
	}
	counts := map[int]int{}
	for i := 0; i < 4; i++ {
		select {
		case r := <-results:
			if r.err != nil || r.code != 503 {
				t.Fatal("over-capacity enrollment", r.code, r.err)
			}
			counts[r.code]++
		case <-time.After(750 * time.Millisecond):
			t.Fatal("over-capacity enrollment queued")
		}
	}
	release.Do(func() { close(a.gate) })
	for i := 0; i < 4; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		counts[r.code]++
	}
	if counts[200] != 3 || counts[503] != 5 || len(counts) != 2 || a.peak.Load() != 4 || a.calls.Load() != 4 || a.active.Load() != 0 {
		t.Fatalf("slot/session caps %v peak=%d calls=%d", counts, a.peak.Load(), a.calls.Load())
	}
	// A challenge is consumed even when its enrollment was refused as busy.
	if r := resourcePost(s.Client(), s.URL+"/api/v2/auth/login", logins[0]); r.err != nil || r.code != 403 {
		t.Fatal("busy/used challenge replay", r.code, r.err)
	}
	b.mu.Lock()
	sessions, tokens := len(b.sessions), len(b.tokens)
	b.mu.Unlock()
	if sessions != 3 || tokens != 3 {
		t.Fatal("session/token cap")
	}
	b.now = func() time.Time { return base.Add(3 * time.Minute) }
	b.Sweep()
	b.Sweep()
	b.mu.Lock()
	sessions, tokens = len(b.sessions), len(b.tokens)
	challenges, rates := len(b.challenges), len(b.rates)
	b.mu.Unlock()
	if sessions+tokens+challenges+rates != 0 || drops.Load() != 3 {
		t.Fatal("idle state or repeated callback")
	}
	fmt.Println("TLS_ENROLLMENT concurrent=8 authority_peak=4 calls=4 accepted=3 busy503=5 session_cap=3 callback_once=3 idle_state=0")
}

func TestDataResourcePermitConcurrency(t *testing.T) {
	b, _, c := newHarness(t)
	p, e := b.Authorize(localSigned(t, b, c, "/api/v1/ingest", []byte("{}")), []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var admitted atomic.Int32
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if p.Enter() {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatal("concurrent session work admitted", admitted.Load())
	}
	p.Leave()
	if !p.Enter() {
		t.Fatal("permit not reusable after work")
	}
	p.Leave()
	fmt.Println("PERMIT concurrent=32 admitted=1 released_reusable=true")
}

func TestDataResourceTLSAuthorityOutage(t *testing.T) {
	b, a, c := newHarness(t)
	var drops atomic.Int32
	b.cfg.OnRevoke = func(string) { drops.Add(1) }
	base := time.Now().Add(CheckTTL + time.Second)
	b.now = func() time.Time { return base }
	c.now = b.now
	a.mu.Lock()
	a.unavailable = true
	a.mu.Unlock()
	r, _ := http.NewRequest("POST", b.cfg.Audience+"/api/v1/ingest", nil)
	if response, e := c.DoBody(r, []byte("{}")); e == nil || response != nil {
		t.Fatal("authority outage admitted")
	}
	select {
	case <-c.Failed():
	default:
		t.Fatal("outage not terminal")
	}
	c.mu.Lock()
	cleared := c.grant.AccessToken == "" && c.key == nil
	c.mu.Unlock()
	if !cleared {
		t.Fatal("client kept credentials")
	}
	a.mu.Lock()
	a.unavailable = false
	before := a.checks
	a.mu.Unlock()
	if response, e := c.DoBody(r, []byte("{}")); e == nil || response != nil {
		t.Fatal("silent recovery")
	}
	a.mu.Lock()
	checks := a.checks
	a.mu.Unlock()
	b.Sweep()
	b.Sweep()
	b.mu.Lock()
	sessions, tokens := len(b.sessions), len(b.tokens)
	b.mu.Unlock()
	if checks != before || drops.Load() != 1 || sessions != 0 || tokens != 0 {
		t.Fatal("revival or retained revoked state")
	}
	fmt.Println("TLS_AUTHORITY_OUTAGE rejected=true client_terminal=true credentials_cleared=true silent_recovery=false callback=1 sessions=0 tokens=0")
}
