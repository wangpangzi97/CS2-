package guyi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/cs2-radar/internal/dataauth"
	"local/cs2-radar/internal/radarsrv"
)

func TestDataDeviceDPAPIStateFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "device.bin")
	a, e := loadDataKey(p)
	if e != nil {
		t.Fatal(e)
	}
	b, e := loadDataKey(p)
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("device identity changed")
	}
	raw, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, a) {
		t.Fatal("private key stored as plaintext")
	}
	if e = os.WriteFile(p, []byte("corrupted-fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = loadDataKey(p); e == nil {
		t.Fatal("silently replaced damaged identity")
	}
	raw, _ = os.ReadFile(p)
	if string(raw) != "corrupted-fixture" {
		t.Fatal("overwrote damaged identity")
	}
}
func fixtureSessionSecret() string {
	secret, _ := hex.DecodeString(strings.Repeat("11", 32))
	sid := strings.Repeat("aa", 32)
	extract := hmac.New(sha256.New, []byte(sid))
	extract.Write(secret)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("guyi-v2/session"))
	expand.Write([]byte{1})
	return hex.EncodeToString(expand.Sum(nil))
}
func TestDataGuYiSQLIntegration(t *testing.T) {
	php, script, project, control := os.Getenv("GAMESENSE_AUTH_PHP"), os.Getenv("GAMESENSE_AUTH_SCRIPT"), os.Getenv("GAMESENSE_AUTH_PROJECT"), os.Getenv("GAMESENSE_AUTH_FIXTURE_CONTROL")
	if php == "" || script == "" || project == "" || control == "" {
		t.Skip("explicit isolated SQL fixture required")
	}
	run := func(op string) {
		t.Helper()
		cmd := exec.Command(php, control, op)
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("fixture operation %s: %v %s", op, e, b)
		}
	}
	for _, mode := range []string{"kick", "ban-unban", "changed-public-key", "wrong-license-mac", "unpatched-backend", "legacy-reset-proof"} {
		t.Run(mode, func(t *testing.T) {
			run("reset")
			authority := &dataauth.CommandAuthority{PHP: php, Script: script, Project: project, AppID: 1}
			ctx := context.Background()
			if mode == "unpatched-backend" {
				p := filepath.Join(project, "app/Infrastructure/Database/Database.php")
				original, e := os.ReadFile(p)
				if e != nil {
					t.Fatal(e)
				}
				changed := bytes.Replace(original, []byte("DATA_AUTH_EPOCH_VERSION=1"), []byte("DATA_AUTH_EPOCH_VERSION=0"), 1)
				if bytes.Equal(changed, original) {
					t.Fatal("guard fixture not found")
				}
				if e = os.WriteFile(p, changed, 0600); e != nil {
					t.Fatal(e)
				}
				defer os.WriteFile(p, original, 0600)
				if authority.Ready(ctx) == nil {
					t.Fatal("unpatched backend accepted despite migrated SQL")
				}
				return
			}
			if e := authority.Ready(ctx); e != nil {
				t.Fatal("patched authority/schema unavailable")
			}
			store := radarsrv.NewStore(radarsrv.DefaultConfig())
			var handler http.Handler
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/verify.php" {
					body, e := io.ReadAll(io.LimitReader(r.Body, 8193))
					if e != nil {
						http.Error(w, "fixture", 500)
						return
					}
					input, _ := json.Marshal(map[string]string{"path": r.URL.Path, "session": r.Header.Get("X-Session-Id"), "proof": r.Header.Get("X-Device-Proof"), "time": r.Header.Get("X-Timestamp"), "nonce": r.Header.Get("X-Nonce"), "version": r.Header.Get("X-Key-Version"), "body": string(body)})
					cmd := exec.Command(php, control, "device-proof")
					cmd.Stdin = bytes.NewReader(input)
					if _, e = cmd.CombinedOutput(); e != nil {
						http.Error(w, "device proof denied", 403)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, `{"code":200,"data":{"fixture":true}}`)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer srv.Close()
			broker, e := dataauth.NewBroker(dataauth.BrokerConfig{Audience: srv.URL, Authority: authority, OnRevoke: store.DropAuthorizedSession})
			if e != nil {
				t.Fatal(e)
			}
			handler = store.SecureHandler(broker)
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if e = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); e != nil {
				t.Fatal(e)
			}
			_, key, e := ed25519.GenerateKey(nil)
			if e != nil {
				t.Fatal(e)
			}
			lease := &Lease{session: Session{ID: strings.Repeat("aa", 32), Key: fixtureSessionSecret()}, device: strings.Repeat("bb", 32)}
			c, e := dataauth.NewClient(srv.URL+"/api/v1/ingest", ca, key)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if mode == "wrong-license-mac" {
				cred := lease.DataCredential()
				cred.MAC = func(string) (string, error) { return strings.Repeat("00", 32), nil }
				if c.Login(ctx, cred) == nil {
					t.Fatal("forged entitlement proof admitted")
				}
				return
			}
			if e = c.Login(ctx, lease.DataCredential()); e != nil {
				t.Fatal("GuYi MAC / Ed25519 enrollment failed", e)
			}
			req, _ := http.NewRequest("POST", srv.URL+"/api/v1/ingest", nil)
			resp, e := c.DoBody(req, []byte(`{"packets":[]}`))
			if e != nil {
				t.Fatal(e)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if len(store.SessionIDs()) != 1 {
				t.Fatal("signed native admission missing")
			}
			if mode == "legacy-reset-proof" {
				config := Config{Endpoint: srv.URL + "/api/verify.php", AppKey: strings.Repeat("22", 32), AppID: 1, CAFile: ca}
				sdk, e := New(config)
				if e != nil {
					t.Fatal(e)
				}
				for _, action := range []string{"activate", "unbind"} {
					if _, e = sdk.request(ctx, action, lease.device, "SYNTHETIC-DATA-CARD", 1, nil); e == nil {
						t.Fatal("registered device accepted unsigned legacy operation")
					}
				}
				if e = sdk.SetDeviceProofKey(key); e != nil {
					t.Fatal(e)
				}
				for _, action := range []string{"activate", "unbind"} {
					if _, e = sdk.request(ctx, action, lease.device, "SYNTHETIC-DATA-CARD", 1, nil); e != nil {
						t.Fatal("native device proof did not interoperate with PHP", e)
					}
				}
				return
			}
			if mode == "changed-public-key" {
				_, wrong, e := ed25519.GenerateKey(nil)
				if e != nil {
					t.Fatal(e)
				}
				other, e := dataauth.NewClient(srv.URL+"/api/v1/ingest", ca, wrong)
				if e != nil {
					t.Fatal(e)
				}
				defer other.Close()
				if other.Login(ctx, lease.DataCredential()) == nil {
					t.Fatal("same card/device registered a different key without reset")
				}
				return
			}
			start := time.Now()
			run(mode)
			// A positive result may be cached for at most 2 seconds. Test real wall time
			// here (no clock injection), against the patched PHP and real InnoDB state.
			time.Sleep(dataauth.CheckTTL + 100*time.Millisecond)
			if c.Heartbeat(ctx) == nil {
				t.Fatal("old token survived persistent revocation generation")
			}
			elapsed := time.Since(start)
			t.Logf("SQL revoke observed after %.3fs including deliberate cache-expiry wait", elapsed.Seconds())
			if elapsed > 5*time.Second {
				t.Fatal("isolated revocation check exceeded 5-second target")
			}
			if len(store.SessionIDs()) != 0 {
				t.Fatal("revoked Store remained addressable")
			}
		})
	}
}
