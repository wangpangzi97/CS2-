package guyi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"local/cs2-radar/internal/dataauth"
	"local/cs2-radar/internal/radarsrv"
	"local/cs2-radar/internal/viewframe"
)

const fullHTTPCard = "SYNTHETIC-HTTP-CARD"

type fullHTTPFixture struct {
	srv               *httptest.Server
	sdk               *Client
	key               ed25519.PrivateKey
	store             *radarsrv.Store
	authority         *dataauth.CommandAuthority
	ca, device        string
	mu                sync.Mutex
	lastHeartbeat     *http.Request
	lastHeartbeatBody []byte
	lastDataToken     string
}

func fullHTTPControl(t *testing.T, op string) []byte {
	t.Helper()
	cmd := exec.Command(os.Getenv("GAMESENSE_AUTH_PHP"), os.Getenv("GAMESENSE_HTTP_CONTROL"), op)
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("owned test control %s failed: %v (details not echoed)", op, e)
	}
	return b
}

func newFullHTTPFixture(t *testing.T) *fullHTTPFixture {
	t.Helper()
	if os.Getenv("GAMESENSE_HTTP_CONTROL") == "" {
		t.Skip("explicit isolated full HTTP/SQL fixture required")
	}
	u, e := url.Parse(os.Getenv("GAMESENSE_HTTP_PHP_ORIGIN"))
	if e != nil || u.String() != "http://127.0.0.1:33386" {
		t.Fatal("test upstream outside the bound fixture")
	}
	fullHTTPControl(t, "reset")
	f := &fullHTTPFixture{device: strings.Repeat("bb", 32)}
	_, f.key, e = ed25519.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) { http.Error(w, "fixture proxy unavailable", 502) }
	var dataHandler http.Handler
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/verify.php" {
			b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
			if e != nil {
				http.Error(w, "fixture read", 400)
				return
			}
			var action struct {
				Action string `json:"action"`
			}
			_ = json.Unmarshal(b, &action)
			if action.Action == "heartbeat" {
				f.mu.Lock()
				f.lastHeartbeat = r.Clone(context.Background())
				f.lastHeartbeat.Header = r.Header.Clone()
				f.lastHeartbeatBody = append([]byte(nil), b...)
				f.mu.Unlock()
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
			proxy.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/api/v1/ingest" && strings.HasPrefix(r.Header.Get("Authorization"), "PoP ") {
			f.mu.Lock()
			f.lastDataToken = strings.TrimPrefix(r.Header.Get("Authorization"), "PoP ")
			f.mu.Unlock()
		}
		dataHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	f.ca = filepath.Join(t.TempDir(), "fixture-ca.pem")
	if e = os.WriteFile(f.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	cfg := radarsrv.DefaultConfig()
	cfg.MapName = "de_dust2"
	f.store = radarsrv.NewStore(cfg)
	f.authority = &dataauth.CommandAuthority{PHP: os.Getenv("GAMESENSE_AUTH_PHP"), Script: os.Getenv("GAMESENSE_AUTH_SCRIPT"), Project: os.Getenv("GAMESENSE_AUTH_PROJECT"), AppID: 1}
	if e = f.authority.Ready(context.Background()); e != nil {
		t.Fatal("minimal authority readiness failed", e)
	}
	broker, e := dataauth.NewBroker(dataauth.BrokerConfig{Audience: f.srv.URL, Authority: f.authority, OnRevoke: f.store.DropAuthorizedSession})
	if e != nil {
		t.Fatal(e)
	}
	dataHandler = f.store.SecureHandler(broker)
	f.sdk, e = New(Config{Endpoint: f.srv.URL + "/api/verify.php", AppKey: strings.Repeat("22", 32), AppID: 1, CAFile: f.ca})
	if e != nil {
		t.Fatal(e)
	}
	if e = f.sdk.SetDeviceProofKey(f.key); e != nil {
		t.Fatal(e)
	}
	return f
}

func (f *fullHTTPFixture) activate(t *testing.T) Session {
	t.Helper()
	s, e := f.sdk.Activate(context.Background(), fullHTTPCard, f.device)
	if e != nil {
		t.Fatal("real PHP HTTP activation", e)
	}
	return s
}
func (f *fullHTTPFixture) data(t *testing.T, s Session) (*dataauth.Client, error) {
	t.Helper()
	c, e := dataauth.NewClient(f.srv.URL+"/api/v1/ingest", f.ca, f.key)
	if e != nil {
		return nil, e
	}
	t.Cleanup(c.Close)
	lease := &Lease{client: f.sdk, session: s, device: f.device}
	e = c.Login(context.Background(), lease.DataCredential())
	return c, e
}
func (f *fullHTTPFixture) unsigned(t *testing.T) int {
	t.Helper()
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/v1/ingest", strings.NewReader(`{"packets":[]}`))
	req.Header.Set("Content-Type", "application/json")
	res, e := f.srv.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	return res.StatusCode
}
func (f *fullHTTPFixture) ingest(t *testing.T, c *dataauth.Client) int {
	t.Helper()
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/v1/ingest", nil)
	req.Header.Set("Content-Type", "application/json")
	res, e := c.DoBody(req, []byte(`{"packets":[]}`))
	if e != nil {
		t.Fatal("signed empty ingest", e)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	return res.StatusCode
}
func expectHTTPAPI(t *testing.T, e error, status int) {
	t.Helper()
	var a *APIError
	if !errors.As(e, &a) || a.Status != status {
		t.Fatalf("expected PHP HTTP %d; got %v", status, e)
	}
}
func TestFullGuYiHTTPBoundaryProbe(t *testing.T) {
	f := newFullHTTPFixture(t)
	s := f.activate(t)
	denied := f.unsigned(t)
	if denied != 403 {
		t.Fatal("unsigned data admitted", denied)
	}
	c, e := f.data(t, s)
	login := e == nil
	admission := "not-attempted"
	if login {
		admission = strconv.Itoa(f.ingest(t, c))
	}
	fmt.Printf("HTTP_BOOTSTRAP=200 MINIMAL_DATA_LOGIN=%t SIGNED_EMPTY_INGEST=%s UNSIGNED=%d\n", login, admission, denied)
}

func (f *fullHTTPFixture) manage(t *testing.T, action string, authenticated bool) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"app_key": strings.Repeat("22", 32), "action": action, "card_code": fullHTTPCard})
	n := make([]byte, 16)
	if _, e := rand.Read(n); e != nil {
		t.Fatal(e)
	}
	nonce := hex.EncodeToString(n)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/verify.php", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Key-Version", "1")
	if authenticated {
		key, _ := derive(strings.Repeat("44", 32), "request-sign")
		sum := sha256.Sum256(body)
		text := strings.Join([]string{"v2", "POST", "/api/verify.php", "management:fixture-admin", "1", timestamp, nonce, hex.EncodeToString(sum[:])}, "\n")
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(text))
		req.Header.Set("X-Credential-Id", "fixture-admin")
		req.Header.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	res, e := f.srv.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 65537))
	if res.StatusCode == 200 {
		var env envelope
		if json.Unmarshal(b, &env) != nil || env.Protocol != "v2" || env.AAD != "v2:1:1:"+nonce+":200" {
			t.Fatal("management mutation response not protected")
		}
	}
	return res.StatusCode
}
func (f *fullHTTPFixture) oldTokenRequest(t *testing.T, token string) int {
	t.Helper()
	body := []byte(`{"packets":[]}`)
	n := make([]byte, 32)
	if _, e := rand.Read(n); e != nil {
		t.Fatal(e)
	}
	nonce := base64.RawURLEncoding.EncodeToString(n)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "PoP "+token)
	req.Header.Set("X-Data-Time", ts)
	req.Header.Set("X-Data-Nonce", nonce)
	req.Header.Set("X-Data-Proof", base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, []byte(dataauth.ProofText(f.srv.URL, "POST", "/api/v1/ingest", token, ts, nonce, body)))))
	res, e := f.srv.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	return res.StatusCode
}
func TestFullGuYiHTTPIntegration(t *testing.T) {
	for _, mode := range []string{"heartbeat-proof-replay", "kick", "ban-unban", "unbind"} {
		t.Run(mode, func(t *testing.T) {
			f := newFullHTTPFixture(t)
			s := f.activate(t)
			c, e := f.data(t, s)
			if e != nil {
				t.Fatal("real HTTP to minimal SQL enrollment", e)
			}
			if f.ingest(t, c) != 200 || f.unsigned(t) != 403 {
				t.Fatal("data admission boundary")
			}
			if e = f.sdk.Heartbeat(context.Background(), s, f.device); e != nil {
				t.Fatal("real PHP encrypted/device-signed heartbeat", e)
			}
			if e = c.Heartbeat(context.Background()); e != nil {
				t.Fatal("minimal SQL data heartbeat", e)
			}
			if f.ingest(t, c) != 200 {
				t.Fatal("rotated token failed")
			}
			f.mu.Lock()
			oldToken := f.lastDataToken
			f.mu.Unlock()
			if oldToken == "" {
				t.Fatal("old grant not observed")
			}
			if mode == "heartbeat-proof-replay" {
				f.mu.Lock()
				req := f.lastHeartbeat.Clone(context.Background())
				req.Header = f.lastHeartbeat.Header.Clone()
				body := append([]byte(nil), f.lastHeartbeatBody...)
				f.mu.Unlock()
				req.RequestURI = ""
				req.URL, _ = url.Parse(f.srv.URL + "/api/verify.php")
				req.Body = io.NopCloser(bytes.NewReader(body))
				req.ContentLength = int64(len(body))
				res, e := f.srv.Client().Do(req)
				if e != nil {
					t.Fatal(e)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode != 409 {
					t.Fatal("real PHP nonce replay not denied", res.StatusCode)
				}
				unsigned, e := New(f.sdk.config)
				if e != nil {
					t.Fatal(e)
				}
				before := fullHTTPControl(t, "state")
				_, e = unsigned.Activate(context.Background(), fullHTTPCard, f.device)
				expectHTTPAPI(t, e, 403)
				expectHTTPAPI(t, unsigned.Heartbeat(context.Background(), s, f.device), 403)
				expectHTTPAPI(t, unsigned.Unbind(context.Background(), s, f.device), 403)
				_, wrong, e := ed25519.GenerateKey(nil)
				if e != nil {
					t.Fatal(e)
				}
				if e = unsigned.SetDeviceProofKey(wrong); e != nil {
					t.Fatal(e)
				}
				_, e = unsigned.Activate(context.Background(), fullHTTPCard, f.device)
				expectHTTPAPI(t, e, 403)
				if f.manage(t, "kick", false) != 403 {
					t.Fatal("unsigned management admitted")
				}
				if !bytes.Equal(before, fullHTTPControl(t, "state")) {
					t.Fatal("rejected requests changed license/card state")
				}
				strict := os.Getenv("GAMESENSE_HTTP_STRICT_ORIGIN")
				if strict != "http://127.0.0.1:33387" {
					t.Fatal("strict fixture scope")
				}
				res, e = http.Post(strict+"/api/verify.php", "application/json", strings.NewReader(`{}`))
				if e != nil {
					t.Fatal(e)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode != 426 {
					t.Fatal("plain HTTP not refused by real controller", res.StatusCode)
				}
				r, _ := http.NewRequest("GET", f.srv.URL+"/api/v1/radar", nil)
				res, e = c.DoBody(r, nil)
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := io.ReadAll(io.LimitReader(res.Body, 65537))
				res.Body.Close()
				if res.StatusCode != 200 {
					t.Fatal("pixel view unavailable")
				}
				if _, e = viewframe.Decode(raw); e != nil {
					t.Fatal("pixel contract", e)
				}
				t.Log("real PHP activation/encrypted heartbeat; data login/rotation; replay409; missing/wrong device proof403; management403; plaintext426; signed pixel DTO verified")
				return
			}
			started := time.Now()
			switch mode {
			case "kick":
				if f.manage(t, "kick", true) != 200 {
					t.Fatal("signed HTTP kick failed")
				}
			case "ban-unban":
				if f.manage(t, "ban", true) != 200 {
					t.Fatal("signed HTTP ban failed")
				}
				_, e = f.sdk.Activate(context.Background(), fullHTTPCard, f.device)
				expectHTTPAPI(t, e, 403)
				if f.manage(t, "unban", true) != 200 {
					t.Fatal("signed HTTP unban failed")
				}
			case "unbind":
				if e = f.sdk.Unbind(context.Background(), s, f.device); e != nil {
					t.Fatal("signed HTTP unbind", e)
				}
			}
			// Real controller reactivation BEFORE probing old data token revival.
			fresh := f.activate(t)
			time.Sleep(dataauth.CheckTTL + 150*time.Millisecond)
			if status := f.oldTokenRequest(t, oldToken); status != 403 {
				t.Fatal("old token revived after real HTTP revoke/reactivation", status)
			}
			if len(f.store.SessionIDs()) != 0 {
				t.Fatal("revoked Store remains")
			}
			freshData, e := f.data(t, fresh)
			if e != nil {
				t.Fatal("new binding after permitted reset", e)
			}
			if f.ingest(t, freshData) != 200 {
				t.Fatal("fresh data session failed")
			}
			if f.oldTokenRequest(t, oldToken) != 403 {
				t.Fatal("old token revived after new enrollment")
			}
			if mode == "unbind" {
				expectHTTPAPI(t, f.sdk.Unbind(context.Background(), fresh, f.device), 409)
			}
			t.Logf("real HTTP %s: old fresh-signed request403, Store dropped, reactivated new session200, old token remains403; elapsed %.3fs includes explicit %.2fs cache wait", mode, time.Since(started).Seconds(), (dataauth.CheckTTL + 150*time.Millisecond).Seconds())
		})
	}
}
