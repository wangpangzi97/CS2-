package main

import (
	"bytes"
	"log"
	"path/filepath"
	"strings"
	"testing"
)

func TestOptionalReplayRejectedConfigDoesNotAbort(t *testing.T) {
	var output bytes.Buffer
	old := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(old)
	if optionalReplay("") != nil || output.Len() != 0 {
		t.Fatal("default-off diagnostics changed")
	}
	private := filepath.Join(t.TempDir(), "synthetic-missing-consent.json")
	if optionalReplay(private) != nil {
		t.Fatal("invalid optional scope armed capture")
	}
	if !strings.Contains(output.String(), "restricted replay not armed; continuing normal authorized service") || strings.Contains(output.String(), private) {
		t.Fatal("wrong or sensitive rejection log")
	}
	t.Log("OPTIONAL_REJECTED_CAPTURE_DISABLED=true NORMAL_PATH_CONTINUES=true DEFAULT_OFF_UNCHANGED=true")
}
