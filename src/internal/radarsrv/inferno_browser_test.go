package radarsrv

import (
	"encoding/json"
	"fmt"
	"local/cs2-radar/internal/cs2proto"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestInfernoMarkerBrowserFixture(t *testing.T) {
	if os.Getenv("INFERNO_BROWSER_FIXTURE") != "1" {
		t.Skip("opt-in recorded browser fixture")
	}
	b, e := os.ReadFile(os.Getenv("INFERNO_BROWSER_SNAPSHOT"))
	if e != nil {
		t.Fatal(e)
	}
	var sn cs2proto.Snapshot
	if e = json.Unmarshal(b, &struct {
		Snapshot *cs2proto.Snapshot `json:"snapshot"`
	}{Snapshot: &sn}); e != nil {
		t.Fatal(e)
	}
	if len(sn.Players) != 8 || !sn.Synced {
		t.Fatal("not a decoded live snapshot")
	}
	cfg := DefaultConfig()
	cfg.MapImageDir = os.Getenv("INFERNO_INPUT") + "/maps"
	base := NewStore(cfg).fixtureHandler("inferno-marker-fixture")
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/radar" && r.URL.Query().Get("token") == "inferno-marker-fixture" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sn)
			return
		}
		base.ServeHTTP(w, r)
	})
	listener, e := net.Listen("tcp", "127.0.0.1:18769")
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(listener)
	defer srv.Close()
	fmt.Println("INFERNO_BROWSER_READY http://127.0.0.1:18769/radar?session=runtime&token=inferno-marker-fixture")
	time.Sleep(240 * time.Second)
}
