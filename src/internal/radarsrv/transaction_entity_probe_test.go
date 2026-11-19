package radarsrv

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type txnBits struct {
	b []byte
	p int
}

func (w *txnBits) put(v uint32, n int) {
	for i := 0; i < n; i++ {
		if w.p/8 >= len(w.b) {
			w.b = append(w.b, 0)
		}
		w.b[w.p/8] |= byte((v>>uint(i))&1) << uint(w.p&7)
		w.p++
	}
}
func txnPayload(cmd uint32, body []byte) []byte {
	w := txnBits{}
	if cmd < 16 {
		w.put(cmd, 6)
	} else if cmd < 256 {
		w.put((cmd&15)|16, 6)
		w.put(cmd>>4, 4)
	} else {
		w.put((cmd&15)|32, 6)
		w.put(cmd>>4, 8)
	}
	n := uint32(len(body))
	for n >= 128 {
		w.put((n&127)|128, 8)
		n >>= 7
	}
	w.put(n, 8)
	for _, b := range body {
		w.put(uint32(b), 8)
	}
	return append([]byte{1, 0}, w.b...)
}
func TestTransactionEntityProbe(t *testing.T) {
	root := os.Getenv("BUNDLE_FIXTURE_DIR")
	if root == "" {
		t.Skip("set BUNDLE_FIXTURE_DIR")
	}
	st := NewStore(DefaultConfig())
	s := st.Get("transaction")
	a, e := os.ReadFile(root + "/serverinfo.pb")
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(root + "/entities-00.pb")
	if e != nil {
		t.Fatal(e)
	}
	s.feedMsg(s.decoder, "s2c", txnPayload(40, a))
	s.feedMsg(s.decoder, "s2c", txnPayload(55, b))
	sn := s.Snapshot()
	mapID := ""
	if sn.Map != nil {
		mapID = sn.Map.ID
	}
	fmt.Printf("ENTITY_PROBE players=%d synced=%v map=%s source=%s\n", len(sn.Players), sn.Synced, mapID, sn.MapSource)
	if len(sn.Players) != 10 || !sn.Synced || mapID != "de_dust2" || sn.MapSource != "serverinfo" {
		t.Fatal("typed entity/map decoding acceptance not met")
	}
}

// Opt-in local-only browser fixture. It replays one recorded frame, not a live game.
func TestBrowserFixture(t *testing.T) {
	if os.Getenv("CS2_BROWSER_FIXTURE") != "1" {
		t.Skip("opt-in browser fixture")
	}
	root := os.Getenv("BUNDLE_FIXTURE_DIR")
	a, e := os.ReadFile(root + "/serverinfo.pb")
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(root + "/entities-00.pb")
	if e != nil {
		t.Fatal(e)
	}
	cfg := DefaultConfig()
	cfg.MapImageDir = filepath.Join("..", "..", "dist", "maps")
	store := NewStore(cfg)
	s := store.Get("browsercheck")
	s.feedMsg(s.decoder, "s2c", txnPayload(40, a))
	s.feedMsg(s.decoder, "s2c", txnPayload(55, b))
	srv := &http.Server{Addr: "127.0.0.1:18766", Handler: store.fixtureHandler("browser-fixture")}
	go srv.ListenAndServe()
	defer srv.Close()
	fmt.Println("BROWSER_FIXTURE_READY http://127.0.0.1:18766/radar?session=browsercheck&token=browser-fixture")
	end := time.NewTimer(100 * time.Second)
	defer end.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-end.C:
			return
		case <-tick.C:
			_ = s.entityDecoder.PacketEntities(b, time.Now())
		}
	}
}
