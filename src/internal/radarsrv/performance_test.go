package radarsrv

import (
	"encoding/json"
	"local/cs2-radar/internal/uplink"
	"net/http/httptest"
	"testing"
)

func TestPerformanceAPIAndNoCache(t *testing.T) {
	store := NewStore(DefaultConfig())
	if _, e := store.Ingest(&uplink.Batch{Session: "perf"}); e != nil {
		t.Fatal(e)
	}
	store.Process("perf")
	rr := httptest.NewRecorder()
	store.fixtureHandler("").ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/radar?session=perf", nil))
	if rr.Code != 200 || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(rr.Code, rr.Header())
	}
	var out map[string]any
	if e := json.Unmarshal(rr.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	p, ok := out["performance"].(map[string]any)
	if !ok || p["ingest"].(map[string]any)["count"].(float64) != 1 || p["process"].(map[string]any)["count"].(float64) != 1 {
		t.Fatal(p)
	}
}
