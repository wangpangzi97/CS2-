// Package dataauth is a versioned, device-held-key authorization boundary.
// It is NOT OAuth/DPoP: the explicit canonical form also signs the request body.
package dataauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	ChallengeTTL      = 60 * time.Second
	SessionTTL        = 12 * time.Hour
	AccessTTL         = 120 * time.Second
	HeartbeatInterval = 30 * time.Second
	LeaseTTL          = 90 * time.Second
	CheckTTL          = 2 * time.Second
	ProofSkew         = 30 * time.Second
	MaxBody           = 2 << 20
)

var ErrDenied = errors.New("data authorization denied; reauthentication required")
var ErrUnavailable = errors.New("license authority unavailable")

type Bootstrap struct {
	LicenseSession string `json:"license_session"`
	Device         string `json:"device"`
	PublicKey      string `json:"public_key"`
}
type Challenge struct {
	ID        string `json:"id"`
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
}
type Login struct {
	Bootstrap
	ChallengeID string `json:"challenge_id"`
	LicenseMAC  string `json:"license_mac"`
	Signature   string `json:"signature"`
}
type Grant struct {
	SessionID         string `json:"session_id"`
	AccessToken       string `json:"access_token"`
	AccessExpiresAt   int64  `json:"access_expires_at"`
	LeaseExpiresAt    int64  `json:"lease_expires_at"`
	AbsoluteExpiresAt int64  `json:"absolute_expires_at"`
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func isHex(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && s == strings.ToLower(s)
}
func publicKey(s string) (ed25519.PublicKey, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrDenied
	}
	return ed25519.PublicKey(b), nil
}
func signature(s string) []byte {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != ed25519.SignatureSize {
		return nil
	}
	return b
}
func validBootstrap(b Bootstrap) bool {
	_, e := publicKey(b.PublicKey)
	return e == nil && isHex(b.LicenseSession, 32) && isHex(b.Device, 32)
}

func Audience(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || strings.ContainsAny(raw, "\\\r\n\t ") {
		return "", ErrDenied
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return "", ErrDenied
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", ErrDenied
	}
	return u.Scheme + "://" + u.Host, nil
}
func EnrollmentText(audience string, b Bootstrap, c Challenge) string {
	return strings.Join([]string{"gamesense-data-enroll-v1", audience, c.ID, c.Nonce, strconv.FormatInt(c.ExpiresAt, 10), b.LicenseSession, b.Device, b.PublicKey}, "\n")
}
func ProofText(audience, method, path, token, timestamp, nonce string, body []byte) string {
	return strings.Join([]string{"gamesense-data-request-v1", audience, method, path, digest([]byte(token)), timestamp, nonce, digest(body)}, "\n")
}
func signRequest(r *http.Request, audience, token string, key ed25519.PrivateKey, body []byte, now time.Time) error {
	nonce, e := randomToken()
	if e != nil {
		return e
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	r.Header.Set("Authorization", "PoP "+token)
	r.Header.Set("X-Data-Time", timestamp)
	r.Header.Set("X-Data-Nonce", nonce)
	r.Header.Set("X-Data-Proof", base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(ProofText(audience, r.Method, r.URL.Path, token, timestamp, nonce, body)))))
	return nil
}
