package uplink

import (
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

func caFile(t *testing.T, s *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func tlsFixture(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
func TestSecureEndpointPolicy(t *testing.T) {
	bad := []string{"", "http://127.0.0.1:1/api/v1/ingest", "https://x/api/v1/ingest?token=secret", "https://x/api/v1/ingest?", "https://x/api/v1/ingest#secret", "https://user:pass@x/api/v1/ingest", "https://x/wrong", " https://x/api/v1/ingest", "https://x:0/api/v1/ingest", "https://x:65536/api/v1/ingest", "https://x:/api/v1/ingest", "https://x/api/v1/%69ngest"}
	for _, x := range bad {
		if ValidateEndpoint(x) == nil {
			t.Errorf("accepted invalid endpoint %q", x)
		}
	}
	for _, x := range []string{"https://118.25.176.85/api/v1/ingest", "https://example.invalid:8443/api/v1/ingest", "https://[::1]:443/api/v1/ingest"} {
		if err := ValidateEndpoint(x); err != nil {
			t.Errorf("valid endpoint rejected: %v", err)
		}
	}
}
func TestSecureCAErrorsFailBeforeSender(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad-ca.pem")
	os.WriteFile(p, []byte("not a certificate"), 0600)
	for _, ca := range []string{p, p + ".missing"} {
		if s, err := NewRemote("https://127.0.0.1:1/api/v1/ingest", "fixture", "synthetic-fixture", ca); err == nil || s != nil {
			t.Fatal("CA error accepted")
		}
	}
	if s, err := NewRemote("https://127.0.0.1:1/api/v1/ingest", "fixture", "", ""); err == nil || s != nil {
		t.Fatal("empty credential accepted")
	}
}
func assertTerminal(t *testing.T, s *Sender) {
	t.Helper()
	select {
	case <-s.Failed():
	case <-time.After(time.Second):
		t.Fatal("missing terminal failure signal")
	}
	if s.Err() == nil {
		t.Fatal("missing terminal error")
	}
	s.Push(Packet{Data: "AA=="})
	s.SetKey(make([]byte, 32))
	s.mu.Lock()
	clean := len(s.buf) == 0 && s.key == "" && s.gns == nil && s.gnsKeys == nil && s.gnsIVs == nil
	s.mu.Unlock()
	if !clean {
		t.Fatal("retained protected buffer after failure")
	}
	if s.Flush(true) == nil || s.Close() == nil {
		t.Fatal("failed sender resumed")
	}
}
func TestSecureUntrustedTLSIsTerminal(t *testing.T) {
	var calls atomic.Int32
	srv := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) })
	s, err := NewRemote(srv.URL+"/api/v1/ingest", "fixture", "synthetic-fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Push(Packet{Data: "AA=="})
	if s.Flush(false) == nil {
		t.Fatal("accepted untrusted certificate")
	}
	assertTerminal(t, s)
	if calls.Load() != 0 {
		t.Fatal("sent body despite TLS failure")
	}
}
func TestSecureTrustedTLSDelivery(t *testing.T) {
	var calls atomic.Int32
	srv := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Auth-Token") != "synthetic-fixture" {
			t.Error("missing migration fixture credential")
		}
		if r.URL.RawQuery != "" || r.TLS == nil {
			t.Error("credential URL or plaintext")
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(202)
	})
	s, err := NewRemote(srv.URL+"/api/v1/ingest", "fixture", "synthetic-fixture", caFile(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Push(Packet{Data: "AA=="})
	if err := s.Flush(false); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || s.Stats()["packets"] != uint64(1) {
		t.Fatal("missing TLS delivery")
	}
}
func TestSecureForbiddenIsTerminal(t *testing.T) {
	var calls atomic.Int32
	srv := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(403) })
	s, err := NewRemote(srv.URL+"/api/v1/ingest", "fixture", "synthetic-fixture", caFile(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetKey(make([]byte, 32))
	s.Push(Packet{Data: "AA=="})
	if err := s.Flush(false); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatal("missing denial")
	}
	assertTerminal(t, s)
	if calls.Load() != 1 {
		t.Fatal("retried after denial")
	}
}

func TestSecureConcurrentFailureNoRetry(t *testing.T) {
	var calls atomic.Int32
	srv := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(403) })
	s, err := NewRemote(srv.URL+"/api/v1/ingest", "fixture", "synthetic-fixture", caFile(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Push(Packet{Data: "AA=="})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Flush(true) == nil {
				t.Error("failure resumed")
			}
		}()
	}
	wg.Wait()
	assertTerminal(t, s)
	if calls.Load() != 1 {
		t.Fatalf("retried after terminal failure: %d", calls.Load())
	}
	select {
	case <-s.doneCh:
	case <-time.After(time.Second):
		t.Fatal("failed background worker leaked")
	}
}
func TestSecureRedirectNeverForwards(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer target.Close()
	srv := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/ingest", http.StatusTemporaryRedirect)
	})
	s, err := NewRemote(srv.URL+"/api/v1/ingest", "fixture", "synthetic-fixture", caFile(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Push(Packet{Data: "AA=="})
	if s.Flush(false) == nil {
		t.Fatal("accepted redirect")
	}
	assertTerminal(t, s)
	if calls.Load() != 0 {
		t.Fatal("forwarded secret to redirect target")
	}
}
func TestSecureDirectConstructorCannotSendHTTP(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	s := New(srv.URL+"/api/v1/ingest", "fixture")
	s.Token = "synthetic-fixture"
	defer s.Close()
	s.Push(Packet{Data: "AA=="})
	if s.Flush(false) == nil {
		t.Fatal("accepted HTTP")
	}
	assertTerminal(t, s)
	if calls.Load() != 0 {
		t.Fatal("sent plaintext")
	}
}
func TestSecureIdentityMismatchAndDisconnect(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(map[bool]string{false: "identity", true: "disconnect"}[disconnect], func(t *testing.T) {
			srv := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected request") })
			s, err := NewRemote(srv.URL+"/api/v1/ingest", "fixture", "synthetic-fixture", caFile(t, srv))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if disconnect {
				srv.Close()
			} else {
				s.hc.Transport.(*http.Transport).TLSClientConfig.ServerName = "wrong.invalid"
			}
			s.Push(Packet{Data: "AA=="})
			if s.Flush(false) == nil {
				t.Fatal("accepted unavailable/untrusted endpoint")
			}
			assertTerminal(t, s)
		})
	}
}
