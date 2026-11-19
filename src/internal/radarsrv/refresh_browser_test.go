package radarsrv

import (
	"encoding/json"
	"fmt"
	"local/cs2-radar/internal/cs2proto"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRefreshBrowserFixture(t *testing.T) {
	if os.Getenv("REFRESH_BROWSER") != "1" {
		t.Skip("explicit local offline browser fixture")
	}
	var row struct{ Snapshot cs2proto.Snapshot }
	raw, e := os.ReadFile(os.Getenv("REFRESH_BROWSER_SNAPSHOT"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &row); e != nil {
		t.Fatal(e)
	}
	sn := row.Snapshot
	cfg := DefaultConfig()
	cfg.MapImageDir = os.Getenv("REFRESH_BROWSER_MAPS")
	st := NewStore(cfg)
	st.SetMapName("preview-map", "de_ancient")
	mi := st.Get("preview-map").Snapshot()
	sn.Map = mi.Map
	sn.MapState = mi.MapState
	sn.MapStatus = mi.MapStatus
	base := st.fixtureHandler("qa-local")
	stop := make(chan struct{}, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "qa-local" {
			base.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/qa-stop" {
			select {
			case stop <- struct{}{}:
			default:
			}
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/radar" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, strings.Replace(RadarPage, "<h1>CS2 雷达</h1>", "<h1>CS2 雷达 · 离线功能验证</h1>", 1))
			return
		}
		if r.URL.Path == "/api/v1/radar" {
			cp := sn
			cp.Players = append([]cs2proto.Player(nil), sn.Players...)
			for i := range cp.Players {
				p := &cp.Players[i]
				p.Name = fmt.Sprintf("离线玩家%d", i+1)
				if i < 2 {
					p.Name = "同名昵称"
				}
				if i == 2 {
					p.Name = "这是一个超长的中文昵称用于检查截断"
				}
				p.AgeMS = 0
				p.Stale = false
				if i == 3 {
					p.Stale = true
					p.AgeMS = 1500
				}
				p.UpdatedAt = time.Now()
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, cp)
			return
		}
		base.ServeHTTP(w, r)
	})
	ln, e := net.Listen("tcp", "127.0.0.1:18771")
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: h}
	defer srv.Close()
	go srv.Serve(ln)
	fmt.Println("REFRESH_BROWSER_READY http://127.0.0.1:18771/radar?session=refresh-fixture&token=qa-local")
	select {
	case <-stop:
	case <-time.After(10 * time.Minute):
	}
}
