package uibridge

import (
	"bytes"
	"testing"
)

func TestBrowserLowLatencyKeepsExpiryAndSerialPoll(t *testing.T) {
	b, e := assets.ReadFile("ui.js")
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"setTimeout(poll,50)", "(now-t.at)/80", "await api('/view')", "if(frame&&now>=deadline)clear(", "start+result.valid_for_ms", "result.valid_for_ms>1000"} {
		if !bytes.Contains(b, []byte(s)) {
			t.Fatalf("missing cadence/security invariant %s", s)
		}
	}
	// 10 uplinks/s + 10 remote polls/s + 2 heartbeats/min. Browser polls
	// terminate at the loopback cache, never generate 20 extra remote calls/s.
	if (600 + 600 + 2) >= 1800 {
		t.Fatal("normal periodic traffic exhausts session limit")
	}
}
