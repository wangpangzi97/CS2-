package guyi

import (
	"context"
	"encoding/json"
	"errors"
	"local/cs2-radar/internal/startupdiag"
	"net/http"
	"strings"
	"testing"
)

func TestPublicConnectionCheckNoCredentials(t *testing.T) {
	calls := 0
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["action"] != "config" || body["app_key"] != strings.Repeat("a", 64) {
			t.Error("diagnostic used non-public payload")
		}
		for _, h := range []string{"X-Session-Id", "X-Signature", "X-Device-Proof", "Authorization", "X-Auth-Token"} {
			if r.Header.Get(h) != "" {
				t.Errorf("diagnostic leaked credential header %s", h)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"code":200,"data":{"key_version":1}}`))
	})
	if e := c.CheckConnection(context.Background()); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal("unexpected request count")
	}
}
func TestRejectedConnectionShowsStatusWithoutResponseBody(t *testing.T) {
	const secret = "FAKE_CARD_TOKEN_SECRET_SERVER_ERROR"
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403); w.Write([]byte(secret)) })
	e := c.CheckConnection(context.Background())
	var api *APIError
	if !errors.As(e, &api) || api.Status != 403 {
		t.Fatalf("missing numeric status: %v", e)
	}
	got := startupdiag.Format(e)
	if !strings.Contains(got, "GS-A01/HTTP-403") || strings.Contains(got, secret) {
		t.Fatal(got)
	}
}

func TestConnectionCertificateFailureIsTypedNotWeakened(t *testing.T) {
	_, server := testClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS reached HTTP") })
	c, e := New(Config{Endpoint: server.URL + "/api/verify.php", AppKey: strings.Repeat("a", 64), AppID: 42})
	if e != nil {
		t.Fatal(e)
	}
	e = c.CheckConnection(context.Background())
	if e == nil || !strings.Contains(startupdiag.Format(e), "GS-A01/NET-TLS") {
		t.Fatalf("untrusted TLS not correctly rejected: %v", e)
	}
}
