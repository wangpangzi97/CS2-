package radarsrv

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/uibridge"
	"local/cs2-radar/internal/viewframe"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPixelNativeBridgeEndToEnd(t *testing.T) {
	s, broker, srv, ca := secureStoreFixture(t)
	c := nativeClient(t, srv, ca, strings.Repeat("ab", 32))
	s.SetMapName(c.SessionID(), "de_dust2")
	sess := s.Get(c.SessionID())
	sess.mu.Lock()
	sess.gnsPos = map[uint32]gnsPosEntry{777: {Pos: cs2proto.Vec3{}, At: time.Now()}}
	sess.mu.Unlock()
	bridge, e := uibridge.Start(context.Background(), srv.URL+"/api/v1/ingest", c)
	if e != nil {
		t.Fatal(e)
	}
	defer bridge.Close()
	r, _ := http.NewRequest("GET", bridge.URL(), nil)
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	resp, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || len(resp.Cookies()) != 1 {
		t.Fatal("local bootstrap", resp.StatusCode)
	}
	cookie := resp.Cookies()[0]
	local := strings.TrimSuffix(bridge.URL(), "/radar")
	get := func(path string) []byte {
		t.Helper()
		r, _ := http.NewRequest("GET", local+path, nil)
		r.AddCookie(cookie)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("X-Gamesense-View", "1")
		resp, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode, string(raw))
		}
		return raw
	}
	var result struct {
		State      string           `json:"state"`
		View       *viewframe.Frame `json:"view"`
		ValidForMS int              `json:"valid_for_ms"`
	}
	raw := get("/view")
	if json.Unmarshal(raw, &result) != nil || result.View == nil || len(result.View.Sounds) != 1 || result.View.Validate() != nil || result.ValidForMS < 1 {
		t.Fatal(string(raw))
	}
	if bytes.Contains(raw, []byte(c.SessionID())) || bytes.Contains(raw, []byte(`"pos"`)) || bytes.Contains(raw, []byte(`"ent"`)) {
		t.Fatal("private native/server fields leaked")
	}
	if len(get(result.View.Image)) == 0 {
		t.Fatal("signed native asset request failed")
	}
	broker.Revoke(c.SessionID())
	select {
	case <-bridge.Failed():
	case <-time.After(2 * time.Second):
		t.Fatal("native bridge did not clear after remote revocation")
	}
	raw = get("/view")
	if !bytes.Contains(raw, []byte(`"view":null`)) || bytes.Contains(raw, []byte(`"px"`)) {
		t.Fatal("old view remained", string(raw))
	}
}
