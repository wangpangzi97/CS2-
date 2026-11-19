package radarsrv

import (
	"context"
	"encoding/json"
	"io"
	"local/cs2-radar/internal/entitycodec"
	"local/cs2-radar/internal/uibridge"
	"local/cs2-radar/internal/viewframe"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNameProjectionVersionBoundary(t *testing.T) {
	raw := pixelFixture()
	raw.Players[0].Team = 2
	raw.Players[0].Name = "  测试  人物\u202e\x00  "
	v := &pixelState{}
	for _, version := range []int{1, 2, 3} {
		f, e := v.projectVersion(raw, version)
		if e != nil || len(f.Players) != 1 {
			t.Fatal(e)
		}
		if version == 3 && f.Players[0].Name != "测试 人物" {
			t.Fatal("name not projected")
		}
		if version != 3 && f.Players[0].Name != "" {
			t.Fatal("name leaked to old version")
		}
		b, _ := json.Marshal(f)
		if strings.Contains(string(b), "private-player") || strings.Contains(string(b), "pawn_id") || strings.Contains(string(b), "steam_id") {
			t.Fatal("private identity leaked")
		}
	}
	raw.Players[0].Stale = true
	f, e := v.projectVersion(raw, 3)
	if e != nil || len(f.Players) > 0 {
		t.Fatal("stale named player exposed")
	}
}
func TestNamesDecodedEntityThroughTLSAndNativeBridge(t *testing.T) {
	store, broker, srv, ca := secureStoreFixture(t)
	client := nativeClient(t, srv, ca, strings.Repeat("bc", 32))
	store.SetMapName(client.SessionID(), "de_dust2")
	sess := store.Get(client.SessionID())
	sess.entityDecoder = entitycodec.New()
	info, e := os.ReadFile("../entitycodec/testdata/serverinfo.pb")
	if e != nil {
		t.Fatal(e)
	}
	full, e := os.ReadFile("../entitycodec/testdata/entities-00.pb")
	if e != nil {
		t.Fatal(e)
	}
	if e = sess.entityDecoder.ServerInfo(info); e != nil {
		t.Fatal(e)
	}
	if e = sess.entityDecoder.PacketEntities(full, time.Now()); e != nil {
		t.Fatal(e)
	}
	bridge, e := uibridge.Start(context.Background(), srv.URL+"/api/v1/ingest", client)
	if e != nil {
		t.Fatal(e)
	}
	defer bridge.Close()
	req, _ := http.NewRequest("GET", bridge.URL(), nil)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	cookie := res.Cookies()[0]
	req, _ = http.NewRequest("GET", strings.TrimSuffix(bridge.URL(), "/radar")+"/view", nil)
	req.AddCookie(cookie)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-Gamesense-View", "1")
	res, e = http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var out struct {
		View viewframe.Frame `json:"view"`
	}
	if json.Unmarshal(raw, &out) != nil || out.View.Version != 3 || len(out.View.Players) == 0 {
		t.Fatal("name view unavailable", res.StatusCode)
	}
	names := 0
	for _, p := range out.View.Players {
		if p.Name != "" {
			names++
		}
	}
	if names == 0 {
		t.Fatal("entity fixture did not expose real decoded names")
	}
	t.Logf("DECODED_NAMES_THROUGH_TLS_NATIVE_BRIDGE=%d PLAYER_VALUES_NOT_LOGGED=true", names)
	broker.Revoke(client.SessionID())
	select {
	case <-bridge.Failed():
	case <-time.After(time.Second):
		t.Fatal("revoke not cleared")
	}
}
