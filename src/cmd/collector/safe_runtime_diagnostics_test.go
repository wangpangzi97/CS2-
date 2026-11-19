package main

import (
	"bytes"
	"local/cs2-radar/internal/runtimereport"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeRuntimeSampleCannotSerializePrivateState(t *testing.T) {
	const secret = "FAKE_CARD_TOKEN_IP_KEY_MEMORY_MUST_NOT_EXPORT"
	s := &captureSession{stopCh: make(chan struct{}), foundKey: []byte(secret), foundTag: secret, keyErr: secret, gnsC2S: [][]byte{[]byte(secret)}}
	s.keyPhase.Store("冻结 " + secret)
	s.pkts = 42
	s.keySearching.Store(true)
	j, e := runtimereport.New(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	p := s.safeDiagnosticSample()
	if p.Packets != 42 || p.Phase != runtimereport.Freezing {
		t.Fatal("phase/counters missing")
	}
	j.Record(p)
	if e = j.Flush(); e != nil {
		t.Fatal(e)
	}
	files, _ := filepath.Glob(filepath.Join(j.Dir(), "*"))
	for _, f := range files {
		b, e := os.ReadFile(f)
		if e != nil || bytes.Contains(b, []byte(secret)) {
			t.Fatal("private state leaked")
		}
	}
	if safeCounter(map[string]any{"packets": secret, "last_error": secret}, "packets") != 0 {
		t.Fatal("string counter accepted")
	}
}
func TestSafePhaseReadyIsBooleanAndErrorsAreEnums(t *testing.T) {
	if safeKeyPhase("冻结", true) != runtimereport.Ready || safeKeyPhase("冻结失败 SECRET", false) != runtimereport.Failed {
		t.Fatal("phase mapping")
	}
}
