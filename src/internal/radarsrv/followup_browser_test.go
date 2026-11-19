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

func TestFollowupBrowserFixture(t *testing.T) {
	if os.Getenv("CS2_FOLLOWUP_BROWSER") != "1" {
		t.Skip("opt-in recorded browser fixture")
	}
	b, e := os.ReadFile(os.Getenv("CS2_FOLLOWUP_SNAPSHOT"))
	if e != nil {
		t.Fatal(e)
	}
	var sn cs2proto.Snapshot
	if e = json.Unmarshal(b, &struct {
		Snapshot *cs2proto.Snapshot `json:"snapshot"`
	}{Snapshot: &sn}); e != nil {
		t.Fatal(e)
	}
	if len(sn.Players) != 9 || !sn.Synced {
		t.Fatal("not a decoded live snapshot")
	}
	cfg := DefaultConfig()
	cfg.MapImageDir = os.Getenv("CS2_FOLLOWUP_DIR") + "/maps"
	base := NewStore(cfg).fixtureHandler("followup-fixture")
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/radar" && r.URL.Query().Get("token") == "followup-fixture" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sn)
			return
		}
		base.ServeHTTP(w, r)
	})
	listener, e := net.Listen("tcp", "127.0.0.1:18767")
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(listener)
	defer srv.Close()
	fmt.Println("FOLLOWUP_BROWSER_READY http://127.0.0.1:18767/radar?session=runtime&token=followup-fixture")
	time.Sleep(100 * time.Second)
}
