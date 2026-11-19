package main

import (
	"path/filepath"
	"testing"
)

func TestLicenseGateBeforeCapture(t *testing.T) {
	old := *flagLicenseConfig
	defer func() { *flagLicenseConfig = old }()
	*flagLicenseConfig = filepath.Join(t.TempDir(), "missing-license.json")
	s, e := startCapture(&emitter{ipc: false})
	if s != nil {
		t.Fatal("capture started without authorization")
	}
	if _, ok := e.(*authorizationError); !ok {
		t.Fatalf("did not fail at authorization boundary: %T %v", e, e)
	}
}
