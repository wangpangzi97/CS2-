package main

import (
	"local/cs2-radar/internal/startupdiag"
	"testing"
)

func TestSafeStopFirstObservedCauseSurvivesCleanup(t *testing.T) {
	s := &captureSession{stopCh: make(chan struct{})}
	s.recordErrorStop(2, &startupdiag.HTTPFailure{Status: 403})
	s.Stop()
	s.recordStop(5, 3, 0)
	p := s.safeDiagnosticSample()
	if p.StopReason != 2 || p.FailureKind != 2 || p.HTTPStatus != 403 {
		t.Fatal("cleanup overwrote first stop")
	}
}
