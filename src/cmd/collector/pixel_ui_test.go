package main

import (
	"testing"
)

func TestPixelNoPreauthorizationRemoteBrowserURL(t *testing.T) {
	old := *flagUplink
	defer func() { *flagUplink = old }()
	*flagUplink = "https://127.0.0.1:1/api/v1/ingest"
	if u, e := radarURL(); e == nil || u != "" {
		t.Fatal("unauthed remote HTML still advertised", u)
	}
	s := &captureSession{stopCh: make(chan struct{})}
	if s.ViewURL() != "" {
		t.Fatal("UI URL exists without native bridge")
	}
	s.Stop()
	if s.ViewURL() != "" {
		t.Fatal("stopped UI URL still returned")
	}
}
