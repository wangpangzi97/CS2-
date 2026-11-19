package radarsrv

import (
	"encoding/json"
	"fmt"
	"io"
	"local/cs2-radar/internal/entitycodec"
	"local/cs2-radar/internal/uplink"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLowLatencyAndTeamDrawingCompatibility(t *testing.T) {
	sent := make(chan struct{}, 4)
	sender, e := uplink.NewAuthenticatedRemote("https://example.invalid/api/v1/ingest", "synthetic", "", func(*http.Request, []byte) (*http.Response, error) {
		select {
		case sent <- struct{}{}:
		default:
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Abort()
	sender.Push(uplink.Packet{Dir: "s2c", Data: "AA=="})
	timely := false
	select {
	case <-sent:
		timely = true
	case <-time.After(900 * time.Millisecond):
	}
	store, _, server, ca := secureStoreFixture(t)
	client := nativeClient(t, server, ca, strings.Repeat("ab", 32))
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
	request := func(version string) map[string]any {
		req, _ := http.NewRequest("GET", server.URL+"/api/v1/radar", nil)
		if version != "" {
			req.Header.Set("X-Gamesense-View-Version", version)
		}
		res, e := client.DoBody(req, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		var m map[string]any
		if e = json.NewDecoder(res.Body).Decode(&m); e != nil {
			t.Fatal(e)
		}
		return m
	}
	v2 := request("2")
	teamOK := v2["v"] == float64(2)
	points, _ := v2["players"].([]any)
	teamOK = teamOK && len(points) > 0
	for _, p := range points {
		v := p.(map[string]any)
		teamOK = teamOK && (v["team"] == float64(2) || v["team"] == float64(3))
	}
	v1 := request("")
	legacy := v1["v"] == float64(1)
	for _, p := range v1["players"].([]any) {
		_, present := p.(map[string]any)["team"]
		legacy = legacy && !present
	}
	fmt.Printf("FLUSH_MS=%d FLUSH_BEFORE_900MS=%t TEAM_DRAWING_V2=%t LEGACY_V1_UNCHANGED=%t\n", sender.FlushInterval.Milliseconds(), timely, teamOK, legacy)
	if sender.FlushInterval > 250*time.Millisecond || !timely || !teamOK || !legacy {
		t.Fatal("cadence or team drawing contract missing")
	}
}
