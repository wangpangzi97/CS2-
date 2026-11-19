package radarsrv

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/cs2-radar/internal/dataauth"
	"local/cs2-radar/internal/uplink"
)

type admissionAuthority struct{}

func (admissionAuthority) Enroll(_ context.Context, e dataauth.Enrollment) (dataauth.Identity, error) {
	return dataauth.Identity{Subject: e.Device, Device: e.Device, PublicKey: e.PublicKey, Binding: strings.Repeat("ab", 32), Epoch: 1, Version: 1, ExpiresAt: time.Now().Add(24 * time.Hour).Unix()}, nil
}
func (admissionAuthority) Check(_ context.Context, i dataauth.Identity, _ string) (dataauth.Identity, error) {
	return i, nil
}

type panicRead struct{}

func (panicRead) Read([]byte) (int, error) { panic("unauthorized body read") }
func (panicRead) Close() error             { return nil }

func TestDataHTTPAdmissionBeforeBodyAndLegacyDisabled(t *testing.T) {
	for _, token := range []string{"", "synthetic-static-token"} {
		s := NewStore(DefaultConfig())
		h := s.Handler(token)
		for _, path := range []string{"/api/v1/ingest", "/api/v1/radar?token=synthetic-static-token", "/api/v1/probe", "/radar"} {
			r := httptest.NewRequest("POST", "http://127.0.0.1"+path, nil)
			r.Body = panicRead{}
			r.Header.Set("X-Auth-Token", "synthetic-static-token")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal("legacy entrance admitted")
			}
		}
		n, p, b := s.Stats()
		if n != 0 || p != 0 || b != 0 {
			t.Fatal("legacy denial changed store")
		}
	}
	s := NewStore(DefaultConfig())
	b, _ := dataauth.NewBroker(dataauth.BrokerConfig{Audience: "https://example.invalid", Authority: admissionAuthority{}})
	h := s.SecureHandler(b)
	r := httptest.NewRequest("POST", "https://example.invalid/api/v1/ingest", nil)
	r.Body = panicRead{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing token not rejected")
	}
	if n, p, b := s.Stats(); n != 0 || p != 0 || b != 0 {
		t.Fatal("business work began without token")
	}
}
func secureStoreFixture(t *testing.T) (*Store, *dataauth.Broker, *httptest.Server, string) {
	t.Helper()
	s := NewStore(DefaultConfig())
	var h http.Handler
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	b, e := dataauth.NewBroker(dataauth.BrokerConfig{Audience: srv.URL, Authority: admissionAuthority{}, OnRevoke: s.DropAuthorizedSession})
	if e != nil {
		t.Fatal(e)
	}
	h = s.SecureHandler(b)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	return s, b, srv, ca
}
func nativeClient(t *testing.T, srv *httptest.Server, ca, device string) *dataauth.Client {
	t.Helper()
	_, key, e := ed25519.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	c, e := dataauth.NewClient(srv.URL+"/api/v1/ingest", ca, key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	e = c.Login(context.Background(), dataauth.Credential{SessionID: strings.Repeat("aa", 32), Device: device, MAC: func(string) (string, error) { return strings.Repeat("aa", 32), nil }})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestDataHTTPOwnershipAndNativeUplink(t *testing.T) {
	s, b, srv, ca := secureStoreFixture(t)
	a := nativeClient(t, srv, ca, strings.Repeat("ab", 32))
	other := nativeClient(t, srv, ca, strings.Repeat("ac", 32))
	sender, e := uplink.NewAuthenticatedRemote(srv.URL+"/api/v1/ingest", a.SessionID(), ca, a.DoBody)
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Abort()
	// A final empty synthetic batch verifies the real native sender, proof gate,
	// ownership rewrite, and Store admission without running any decoder/capture.
	if e = sender.Flush(true); e != nil {
		t.Fatal(e)
	}
	ids := s.SessionIDs()
	if len(ids) != 1 || ids[0] != a.SessionID() {
		t.Fatal("client selected an arbitrary store session")
	}
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/map", nil)
	if _, e = other.DoBody(req, []byte(`{"session":"`+a.SessionID()+`","name":"de_dust2"}`)); e == nil {
		t.Fatal("cross-account map mutation admitted")
	}
	b.Revoke(a.SessionID())
	if len(s.SessionIDs()) != 0 {
		t.Fatal("revoked store not removed")
	}
	if e = sender.Flush(true); e == nil {
		t.Fatal("sender continued after server revocation")
	}
}
func TestDataHTTPNoRawFallbackOrEnumeration(t *testing.T) {
	for _, path := range []string{"/api/v1/probe", "/api/v1/sessions", "/radar"} {
		t.Run(path, func(t *testing.T) {
			s, _, srv, ca := secureStoreFixture(t)
			c := nativeClient(t, srv, ca, strings.Repeat("ab", 32))
			req, _ := http.NewRequest("GET", srv.URL+path, nil)
			if resp, e := c.DoBody(req, nil); e == nil {
				resp.Body.Close()
				t.Fatal("raw/diagnostic route exposed")
			}
			if len(s.SessionIDs()) != 0 {
				t.Fatal("read denial created a session")
			}
		})
	}
}
func TestDataHTTPBatchQuotaAndCrossSession(t *testing.T) {
	for _, body := range []string{`{"session":"someone-else","packets":[]}`, `{"packets":[{"dir":"bad","data":"AA=="}]}`, `{"packets":[{"dir":"s2c","data":"not-base64"}]}`, `{"packets":[],"admin":true}`} {
		s, _, srv, ca := secureStoreFixture(t)
		c := nativeClient(t, srv, ca, strings.Repeat("ab", 32))
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/ingest", nil)
		if r, e := c.DoBody(req, []byte(body)); e == nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			t.Fatal("invalid or foreign batch admitted")
		}
		if n, p, b := s.Stats(); n != 0 || p != 0 || b != 0 {
			t.Fatal("rejected batch reached Store")
		}
	}
}
