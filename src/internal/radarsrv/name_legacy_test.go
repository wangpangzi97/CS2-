package radarsrv

import (
	"context"
	"local/cs2-radar/internal/uibridge"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNamesOldTLSBackendNegotiatesOnceAndRevokeStillFails(t *testing.T) {
	_, broker, srv, ca := secureStoreFixture(t)
	original := srv.Config.Handler
	var mu sync.Mutex
	v3, v2 := 0, 0
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/radar" {
			mu.Lock()
			if r.Header.Get("X-Gamesense-View-Version") == "3" {
				v3++
				mu.Unlock()
				http.Error(w, "unsupported drawing version", 400)
				return
			}
			v2++
			mu.Unlock()
		}
		original.ServeHTTP(w, r)
	})
	c := nativeClient(t, srv, ca, strings.Repeat("cd", 32))
	b, e := uibridge.Start(context.Background(), srv.URL+"/api/v1/ingest", c)
	if e != nil {
		t.Fatal("old service did not negotiate", e)
	}
	defer b.Close()
	time.Sleep(220 * time.Millisecond)
	mu.Lock()
	once := v3 == 1 && v2 >= 2
	mu.Unlock()
	if !once {
		t.Fatal("repeated downgrade exceeds original polling budget")
	}
	broker.Revoke(c.SessionID())
	select {
	case <-b.Failed():
	case <-time.After(time.Second):
		t.Fatal("downgrade revived authorization")
	}
	t.Log("OLD_BACKEND_COMPATIBLE=true V3_NEGOTIATED_ONCE=true REVOKE_STILL_TERMINAL=true")
}
