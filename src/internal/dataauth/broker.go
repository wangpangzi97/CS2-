package dataauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxAuthPeers          = 4096
	authRequestsPerMinute = 20
	dataRequestsPerMinute = 1800
	// Replay retention overlaps fixed-minute quota windows. The table must fit
	// every permitted request across those windows, not reject early at 1024.
	maxSessionNonces = (int((2*ProofSkew+time.Minute-time.Nanosecond)/time.Minute) + 1) * dataRequestsPerMinute
)

// Identity never crosses the public API. Epoch is the persistent GuYi card
// generation, changed on kick/ban/unbind; a new login cannot revive an old token.
type Identity struct {
	Subject   string `json:"subject"`
	Device    string `json:"device"`
	PublicKey string `json:"public_key"`
	Binding   string `json:"binding"`
	Epoch     int64  `json:"epoch"`
	Version   int64  `json:"version"`
	ExpiresAt int64  `json:"expires_at"`
}
type Enrollment struct {
	Bootstrap
	Text string `json:"text"`
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
}
type Authority interface {
	Enroll(context.Context, Enrollment) (Identity, error)
	Check(context.Context, Identity, string) (Identity, error)
}
type BrokerConfig struct {
	Audience  string
	Authority Authority
	// Only for a separately configured loopback TLS-terminating nginx listener
	// which OVERWRITES X-GS-Client-IP and X-GS-TLS. Never trust X-Forwarded-For.
	TrustLoopbackProxy bool
	MaxSessions        int
	MaxChallenges      int
	OnRevoke           func(string)
}
type challengeState struct {
	bootstrap Bootstrap
	challenge Challenge
	prefix    string
}
type session struct {
	mu                      sync.Mutex
	id                      string
	identity                Identity
	pub                     ed25519.PublicKey
	prefix                  string
	absolute, lease, access time.Time
	tokenHash               string
	nonces                  map[string]int64
	checked                 time.Time
	revoked                 bool
	notified                sync.Once
	busy                    atomic.Bool
	window                  int64
	hits                    int
}
type rateWindow struct {
	window int64
	hits   int
}
type Broker struct {
	cfg         BrokerConfig
	now         func() time.Time
	mu          sync.Mutex
	challenges  map[string]challengeState
	sessions    map[string]*session
	tokens      map[string]*session
	rates       map[string]rateWindow
	enrollSlots chan struct{}
}

func NewBroker(c BrokerConfig) (*Broker, error) {
	a, e := Audience(c.Audience)
	if e != nil || a != c.Audience || c.Authority == nil {
		return nil, ErrDenied
	}
	if c.MaxSessions <= 0 || c.MaxSessions > 1024 {
		c.MaxSessions = 64
	}
	if c.MaxChallenges <= 0 || c.MaxChallenges > 4096 {
		c.MaxChallenges = 512
	}
	return &Broker{cfg: c, now: time.Now, challenges: map[string]challengeState{}, sessions: map[string]*session{}, tokens: map[string]*session{}, rates: map[string]rateWindow{}, enrollSlots: make(chan struct{}, 4)}, nil
}
func prefix(ip string) string {
	a, e := netip.ParseAddr(ip)
	if e != nil {
		return ""
	}
	a = a.Unmap()
	bits := 56
	if a.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(a, bits).Masked().String()
}
func (b *Broker) Peer(r *http.Request) (string, error) {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return "", ErrDenied
	}
	a, e := netip.ParseAddr(host)
	if e != nil {
		return "", ErrDenied
	}
	if b.cfg.TrustLoopbackProxy && a.IsLoopback() && r.Header.Get("X-GS-TLS") == "1" {
		p, e := netip.ParseAddr(r.Header.Get("X-GS-Client-IP"))
		if e != nil {
			return "", ErrDenied
		}
		return p.Unmap().String(), nil
	}
	if r.TLS == nil {
		return "", ErrDenied
	}
	return a.Unmap().String(), nil
}
func strictJSON(raw []byte, v any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrDenied
	}
	return nil
}
func jsonReply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(v)
}
func Deny(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "data authorization required", http.StatusForbidden)
}
func (b *Broker) limited(ip string) bool {
	now := b.now().Unix() / 60
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range b.rates {
		if v.window < now {
			delete(b.rates, k)
		}
	}
	v, known := b.rates[ip]
	if !known && len(b.rates) >= maxAuthPeers {
		return true
	}
	if v.window != now {
		v = rateWindow{window: now}
	}
	v.hits++
	b.rates[ip] = v
	return v.hits > authRequestsPerMinute
}
func (b *Broker) AuthHandler(w http.ResponseWriter, r *http.Request) {
	ip, e := b.Peer(r)
	if e != nil || r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		Deny(w)
		return
	}
	if b.limited(ip) {
		http.Error(w, "rate limited", 429)
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if e != nil {
		http.Error(w, "request too large", 413)
		return
	}
	if r.URL.Path == "/api/v2/auth/challenge" {
		var in Bootstrap
		if strictJSON(raw, &in) != nil || !validBootstrap(in) {
			Deny(w)
			return
		}
		id, e := randomToken()
		if e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		nonce, e := randomToken()
		if e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		now := b.now()
		c := Challenge{id, nonce, now.Add(ChallengeTTL).Unix()}
		b.mu.Lock()
		for k, v := range b.challenges {
			if v.challenge.ExpiresAt <= now.Unix() {
				delete(b.challenges, k)
			}
		}
		if len(b.challenges) >= b.cfg.MaxChallenges {
			b.mu.Unlock()
			http.Error(w, "busy", 503)
			return
		}
		b.challenges[id] = challengeState{in, c, prefix(ip)}
		b.mu.Unlock()
		jsonReply(w, c)
		return
	}
	if r.URL.Path != "/api/v2/auth/login" {
		Deny(w)
		return
	}
	var in Login
	if strictJSON(raw, &in) != nil || !validBootstrap(in.Bootstrap) || !isHex(in.LicenseMAC, 32) {
		Deny(w)
		return
	}
	b.mu.Lock()
	c, ok := b.challenges[in.ChallengeID]
	delete(b.challenges, in.ChallengeID)
	b.mu.Unlock()
	if !ok || c.bootstrap != in.Bootstrap || c.prefix != prefix(ip) || c.challenge.ExpiresAt <= b.now().Unix() {
		Deny(w)
		return
	}
	text := EnrollmentText(b.cfg.Audience, in.Bootstrap, c.challenge)
	pub, _ := publicKey(in.PublicKey)
	if !ed25519.Verify(pub, []byte(text), signature(in.Signature)) {
		Deny(w)
		return
	}
	select {
	case b.enrollSlots <- struct{}{}:
		defer func() { <-b.enrollSlots }()
	default:
		http.Error(w, "busy", 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	identity, e := b.cfg.Authority.Enroll(ctx, Enrollment{in.Bootstrap, text, in.LicenseMAC, ip})
	if e != nil {
		if e == ErrUnavailable {
			http.Error(w, "authority unavailable", 503)
		} else {
			Deny(w)
		}
		return
	}
	now := b.now()
	if identity.Subject == "" || !isHex(identity.Binding, 32) || identity.Device != in.Device || identity.PublicKey != in.PublicKey || identity.Epoch < 1 || identity.Version < 1 || identity.ExpiresAt <= now.Unix() {
		Deny(w)
		return
	}
	id, e := randomToken()
	if e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	token, e := randomToken()
	if e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	absolute := now.Add(SessionTTL)
	if identity.ExpiresAt < absolute.Unix() {
		absolute = time.Unix(identity.ExpiresAt, 0)
	}
	s := &session{id: id, identity: identity, pub: pub, prefix: prefix(ip), absolute: absolute, lease: minTime(now.Add(LeaseTTL), absolute), access: minTime(now.Add(AccessTTL), absolute), tokenHash: digest([]byte(token)), nonces: map[string]int64{}, checked: now}
	b.mu.Lock()
	// One live session per entitlement. A reconnect revokes the old generation of
	// this broker's data session, rather than accidentally sharing its Store.
	expired := []*session{}
	for _, old := range b.sessions {
		old.mu.Lock()
		gone := old.revoked || !now.Before(old.absolute) || !now.Before(old.lease) || old.identity.Subject == identity.Subject
		old.mu.Unlock()
		if gone {
			expired = append(expired, old)
		}
	}
	for _, old := range expired {
		delete(b.sessions, old.id)
		delete(b.tokens, old.tokenHash)
	}
	if len(b.sessions) >= b.cfg.MaxSessions {
		b.mu.Unlock()
		http.Error(w, "busy", 503)
		return
	}
	b.sessions[id] = s
	b.tokens[s.tokenHash] = s
	b.mu.Unlock()
	for _, old := range expired {
		b.revoke(old)
	}
	jsonReply(w, s.grant(token))
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (s *session) grant(token string) Grant {
	return Grant{s.id, token, s.access.Unix(), s.lease.Unix(), s.absolute.Unix()}
}
func (b *Broker) revoke(s *session) {
	s.mu.Lock()
	s.revoked = true
	s.nonces = nil
	s.mu.Unlock()
	s.notified.Do(func() {
		if b.cfg.OnRevoke != nil {
			b.cfg.OnRevoke(s.id)
		}
	})
}
func (b *Broker) Revoke(id string) {
	b.mu.Lock()
	s := b.sessions[id]
	b.mu.Unlock()
	if s != nil {
		b.revoke(s)
	}
}

// Sweep drops inactive/expired/revoked state even when a disconnected client
// never makes another request. It does not claim to securely zero Go memory.
func (b *Broker) Sweep() {
	now := b.now()
	expired := []*session{}
	b.mu.Lock()
	for id, s := range b.sessions {
		s.mu.Lock()
		gone := s.revoked || !now.Before(s.lease) || !now.Before(s.absolute) || !now.Before(s.access)
		hash := s.tokenHash
		s.mu.Unlock()
		if gone {
			delete(b.sessions, id)
			delete(b.tokens, hash)
			expired = append(expired, s)
		}
	}
	for id, c := range b.challenges {
		if c.challenge.ExpiresAt <= now.Unix() {
			delete(b.challenges, id)
		}
	}
	for ip, v := range b.rates {
		if v.window < now.Unix()/60 {
			delete(b.rates, ip)
		}
	}
	b.mu.Unlock()
	for _, s := range expired {
		b.revoke(s)
	}
}
func (b *Broker) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.Sweep()
		}
	}
}

type Permit struct {
	broker *Broker
	s      *session
	ip     string
}

func (p *Permit) SessionID() string { return p.s.id }
func (p *Permit) Enter() bool       { return p.s.busy.CompareAndSwap(false, true) }
func (p *Permit) Leave()            { p.s.busy.Store(false) }
func (b *Broker) active(ctx context.Context, s *session, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := b.now()
	if s.revoked || !now.Before(s.absolute) || !now.Before(s.lease) || !now.Before(s.access) || s.prefix != prefix(ip) {
		s.revoked = true
		return ErrDenied
	}
	if now.Sub(s.checked) >= CheckTTL {
		next, e := b.cfg.Authority.Check(ctx, s.identity, ip)
		if e != nil || next.Subject != s.identity.Subject || next.Binding != s.identity.Binding || next.Device != s.identity.Device || next.PublicKey != s.identity.PublicKey || next.Epoch != s.identity.Epoch || next.Version != s.identity.Version || next.ExpiresAt <= now.Unix() {
			s.revoked = true
			if e == ErrUnavailable {
				return e
			}
			return ErrDenied
		}
		s.checked = now
		if next.ExpiresAt < s.absolute.Unix() {
			s.absolute = time.Unix(next.ExpiresAt, 0)
		}
	}
	return nil
}
func (p *Permit) Alive(ctx context.Context) error {
	e := p.broker.active(ctx, p.s, p.ip)
	if e != nil {
		p.broker.revoke(p.s)
	}
	return e
}
func (b *Broker) Authorize(r *http.Request, body []byte) (*Permit, error) {
	ip, e := b.Peer(r)
	if e != nil || len(body) > MaxBody || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.Header.Get("X-Auth-Token") != "" {
		return nil, ErrDenied
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "PoP ")
	decoded, e := base64.RawURLEncoding.Strict().DecodeString(token)
	if e != nil || len(decoded) != 32 || r.Header.Get("Authorization") != "PoP "+token {
		return nil, ErrDenied
	}
	hash := digest([]byte(token))
	b.mu.Lock()
	s := b.tokens[hash]
	b.mu.Unlock()
	if s == nil {
		return nil, ErrDenied
	}
	timestamp := r.Header.Get("X-Data-Time")
	ts, e := strconv.ParseInt(timestamp, 10, 64)
	now := b.now()
	nonce := r.Header.Get("X-Data-Nonce")
	n, e2 := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if e != nil || len(timestamp) != 10 || now.Unix()-ts > int64(ProofSkew/time.Second) || ts-now.Unix() > int64(ProofSkew/time.Second) || e2 != nil || len(n) != 32 {
		return nil, ErrDenied
	}
	if !ed25519.Verify(s.pub, []byte(ProofText(b.cfg.Audience, r.Method, r.URL.Path, token, timestamp, nonce, body)), signature(r.Header.Get("X-Data-Proof"))) {
		return nil, ErrDenied
	}
	s.mu.Lock()
	if s.revoked || s.tokenHash != hash {
		s.mu.Unlock()
		return nil, ErrDenied
	}
	for k, v := range s.nonces {
		if v < now.Unix() {
			delete(s.nonces, k)
		}
	}
	if _, ok := s.nonces[nonce]; ok || len(s.nonces) >= maxSessionNonces {
		s.mu.Unlock()
		return nil, ErrDenied
	}
	window := now.Unix() / 60
	if s.window != window {
		s.window = window
		s.hits = 0
	}
	s.hits++
	if s.hits > dataRequestsPerMinute {
		s.mu.Unlock()
		return nil, ErrDenied
	}
	s.nonces[nonce] = now.Add(2 * ProofSkew).Unix()
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	if e = b.active(ctx, s, ip); e != nil {
		b.revoke(s)
		return nil, e
	}
	return &Permit{b, s, ip}, nil
}
func (b *Broker) Heartbeat(p *Permit) (Grant, error) {
	token, e := randomToken()
	if e != nil {
		return Grant{}, ErrUnavailable
	}
	// Global -> session lock order matches enrollment cleanup.
	b.mu.Lock()
	defer b.mu.Unlock()
	s := p.s
	s.mu.Lock()
	defer s.mu.Unlock()
	now := b.now()
	if s.revoked || !now.Before(s.lease) || !now.Before(s.absolute) || !now.Before(s.access) {
		return Grant{}, ErrDenied
	}
	delete(b.tokens, s.tokenHash)
	s.tokenHash = digest([]byte(token))
	s.access = minTime(now.Add(AccessTTL), s.absolute)
	s.lease = minTime(now.Add(LeaseTTL), s.absolute)
	b.tokens[s.tokenHash] = s
	return s.grant(token), nil
}
