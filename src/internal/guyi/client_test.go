package guyi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const fixtureSecret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const fixtureSID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func testClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	p := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := New(Config{Endpoint: s.URL + "/api/verify.php", AppKey: strings.Repeat("a", 64), AppID: 42, CAFile: p})
	if e != nil {
		t.Fatal(e)
	}
	return c, s
}

func fixtureSession() Session {
	return Session{ID: fixtureSID, Key: fixtureSecret, Version: 7, ExpiresAt: time.Now().Add(15 * time.Minute).Unix()}
}

func sealedResponse(t *testing.T, r *http.Request, payload any) envelope {
	t.Helper()
	b, e := json.Marshal(payload)
	if e != nil {
		t.Fatal(e)
	}
	key, e := derive(fixtureSecret, "response-encrypt")
	if e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		t.Fatal(e)
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	n := make([]byte, 12)
	if _, e = rand.Read(n); e != nil {
		t.Fatal(e)
	}
	aad := "v2:42:" + r.Header.Get("X-Key-Version") + ":" + r.Header.Get("X-Nonce") + ":200"
	c := g.Seal(nil, n, b, []byte(aad))
	wire := append(append(append([]byte{}, n...), c[len(c)-16:]...), c[:len(c)-16]...)
	return envelope{"v2", aad, base64.StdEncoding.EncodeToString(wire)}
}

func TestPHPInteroperabilityVector(t *testing.T) {
	b, e := os.ReadFile("testdata/php-vector.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Secret        string
		Canonical     string
		SigningKey    string `json:"signing_key"`
		EncryptionKey string `json:"encryption_key"`
		Signature     string
		Envelope      envelope
	}
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	for purpose, want := range map[string]string{"request-sign": v.SigningKey, "response-encrypt": v.EncryptionKey} {
		got, e := derive(v.Secret, purpose)
		if e != nil || hex.EncodeToString(got) != want {
			t.Fatalf("PHP HKDF mismatch: %s", purpose)
		}
	}
	k, _ := derive(v.Secret, "request-sign")
	m := hmac.New(sha256.New, k)
	m.Write([]byte(v.Canonical))
	if hex.EncodeToString(m.Sum(nil)) != v.Signature {
		t.Fatal("PHP HMAC mismatch")
	}
	k, _ = derive(v.Secret, "response-encrypt")
	block, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(block)
	wire, e := base64.StdEncoding.DecodeString(v.Envelope.Ciphertext)
	if e != nil {
		t.Fatal(e)
	}
	plain, e := g.Open(nil, wire[:12], append(append([]byte{}, wire[28:]...), wire[12:28]...), []byte(v.Envelope.AAD))
	if e != nil {
		t.Fatal("PHP GCM mismatch", e)
	}
	if !bytes.Contains(plain, []byte(`"code":200`)) {
		t.Fatal(string(plain))
	}
}

func TestTLSActivationHeartbeatUnbind(t *testing.T) {
	nonces := map[string]bool{}
	counts := map[string]int{}
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || r.URL.Path != "/api/verify.php" {
			t.Error("bad HTTP framing")
		}
		n := r.Header.Get("X-Nonce")
		nb, e := hex.DecodeString(n)
		if e != nil || len(nb) != 16 || nonces[n] {
			t.Error("nonce missing/reused")
		}
		nonces[n] = true
		ts, e := strconv.ParseInt(r.Header.Get("X-Timestamp"), 10, 64)
		if e != nil || time.Now().Unix()-ts > 5 {
			t.Error("timestamp missing")
		}
		body, _ := io.ReadAll(r.Body)
		var d map[string]string
		json.Unmarshal(body, &d)
		a := d["action"]
		counts[a]++
		if d["app_key"] != strings.Repeat("a", 64) {
			t.Error("app_key missing")
		}
		switch a {
		case "config":
			json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]int{"key_version": 7}})
		case "activate":
			if d["card_code"] != "fixture-card" || d["device_hash"] != "fixture-device" {
				t.Error("bad activation identity")
			}
			if r.Header.Get("X-Key-Version") != "7" {
				t.Error("did not discover rotated version")
			}
			json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": fixtureSession()})
		case "heartbeat", "unbind":
			if d["card_code"] != "" || d["device_hash"] != "fixture-device" {
				t.Error("card leaked in protected request")
			}
			if r.Header.Get("X-Session-Id") != fixtureSID {
				t.Error("bad session ID")
			}
			h := sha256.Sum256(body)
			canonical := strings.Join([]string{"v2", "POST", r.URL.Path, "session:" + fixtureSID, "7", r.Header.Get("X-Timestamp"), n, hex.EncodeToString(h[:])}, "\n")
			k, _ := derive(fixtureSecret, "request-sign")
			m := hmac.New(sha256.New, k)
			m.Write([]byte(canonical))
			if r.Header.Get("X-Signature") != hex.EncodeToString(m.Sum(nil)) {
				t.Error("signature mismatch")
			}
			data := map[string]any{"expire_time": "2099-01-01 00:00:00"}
			if a == "unbind" {
				data = map[string]any{"unbound": true}
			}
			json.NewEncoder(w).Encode(sealedResponse(t, r, map[string]any{"code": 200, "data": data}))
		default:
			t.Error("unexpected action")
			http.Error(w, "bad", 400)
		}
	})
	s, e := c.Activate(context.Background(), "fixture-card", "fixture-device")
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Heartbeat(context.Background(), s, "fixture-device"); e != nil {
		t.Fatal(e)
	}
	if e = c.Unbind(context.Background(), s, "fixture-device"); e != nil {
		t.Fatal(e)
	}
	if len(nonces) != 4 || len(counts) != 4 {
		t.Fatal("flow incomplete", counts)
	}
}

func TestProtectedResponseFailures(t *testing.T) {
	for _, kind := range []string{"plaintext", "wrong-app", "wrong-version", "old-nonce", "tag", "short", "bad-base64", "wrong-protocol", "bad-inner-code", "null-data", "empty-expiry", "oversize", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if kind == "revoked" {
					w.WriteHeader(401)
					return
				}
				if kind == "plaintext" {
					io.WriteString(w, `{"code":200,"data":{"expire_time":"2099"}}`)
					return
				}
				if kind == "oversize" {
					io.WriteString(w, strings.Repeat("a", (1<<20)+1))
					return
				}
				payload := map[string]any{"code": 200, "data": map[string]string{"expire_time": "2099"}}
				if kind == "bad-inner-code" {
					payload["code"] = 403
				}
				if kind == "null-data" {
					payload["data"] = nil
				}
				if kind == "empty-expiry" {
					payload["data"] = map[string]string{}
				}
				env := sealedResponse(t, r, payload)
				switch kind {
				case "wrong-app":
					env.AAD = strings.Replace(env.AAD, "42:", "43:", 1)
				case "wrong-version":
					env.AAD = strings.Replace(env.AAD, ":7:", ":8:", 1)
				case "old-nonce":
					env.AAD = "v2:42:7:" + strings.Repeat("0", 32) + ":200"
				case "tag":
					b, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
					b[12] ^= 1
					env.Ciphertext = base64.StdEncoding.EncodeToString(b)
				case "short":
					env.Ciphertext = "AA=="
				case "bad-base64":
					env.Ciphertext = "????"
				case "wrong-protocol":
					env.Protocol = "v1"
				}
				json.NewEncoder(w).Encode(env)
			})
			if e := c.Heartbeat(context.Background(), fixtureSession(), "fixture-device"); e == nil {
				t.Fatal("accepted", kind)
			}
		})
	}
}

func TestInvalidConfig(t *testing.T) {
	for _, endpoint := range []string{"http://example.com/api.php", "https://u:p@example.com/api.php", "https://example.com/api.php?q=1", "https://example.com/api.php#x", "https://example.com/%61pi.php", "https://example.com"} {
		if _, e := New(Config{Endpoint: endpoint, AppKey: strings.Repeat("a", 64), AppID: 42}); e == nil {
			t.Fatal("accepted", endpoint)
		}
	}
	for _, b := range []string{`{}`, `{"enabled":false}`, `{"insecure":true}`, `{} {}`} {
		p := filepath.Join(t.TempDir(), "license.json")
		os.WriteFile(p, []byte(b), 0600)
		if _, e := LoadConfig(p); e == nil {
			t.Fatal("accepted", b)
		}
	}
}

func TestRedirectAndUntrustedTLS(t *testing.T) {
	called := 0
	dest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++ }))
	defer dest.Close()
	c, s := testClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL, 302) })
	if _, e := c.Activate(context.Background(), "fixture-card", "fixture-device"); e == nil {
		t.Fatal("accepted redirect")
	}
	if called != 0 {
		t.Fatal("redirect followed")
	}
	untrusted, e := New(Config{Endpoint: s.URL + "/api/verify.php", AppKey: strings.Repeat("a", 64), AppID: 42})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = untrusted.Activate(context.Background(), "fixture-card", "fixture-device"); e == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestActivationAndSessionValidation(t *testing.T) {
	for _, kind := range []string{"wrong-key", "wrong-version", "expired", "far-future", "missing-data", "invalid-json", "denied"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				var d map[string]string
				json.Unmarshal(b, &d)
				if d["action"] == "config" {
					io.WriteString(w, `{"code":200,"data":{"key_version":7}}`)
					return
				}
				s := fixtureSession()
				switch kind {
				case "wrong-key":
					s.Key = "invalid"
				case "wrong-version":
					s.Version = 8
				case "expired":
					s.ExpiresAt = time.Now().Unix() - 1
				case "far-future":
					s.ExpiresAt = time.Now().Add(time.Hour).Unix()
				case "missing-data":
					io.WriteString(w, `{"code":200}`)
					return
				case "invalid-json":
					io.WriteString(w, `{`)
					return
				case "denied":
					w.WriteHeader(403)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": s})
			})
			if _, e := c.Activate(context.Background(), "fixture-card", "fixture-device"); e == nil {
				t.Fatal("accepted", kind)
			}
		})
	}
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("expired session reached network") })
	s := fixtureSession()
	s.ExpiresAt = 0
	if e := c.Heartbeat(context.Background(), s, "fixture-device"); e == nil {
		t.Fatal("expired accepted")
	}
}

func TestMaintainCancellationAndDenial(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := c.Maintain(ctx, fixtureSession(), "fixture-card", "fixture-device"); e != nil {
		t.Fatal(e)
	}
	s := fixtureSession()
	s.ExpiresAt = time.Now().Add(time.Second).Unix()
	start := time.Now()
	if e := c.maintain(context.Background(), s, "fixture-card", "fixture-device", time.Millisecond); e == nil {
		t.Fatal("denial ignored")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("denial did not terminate")
	}
}

func ExampleConfig() {
	c := Config{Endpoint: "https://license.example.invalid/api/verify.php", AppKey: strings.Repeat("a", 64), AppID: 42}
	fmt.Println(c.validate() == nil)
	// Output: true
}
