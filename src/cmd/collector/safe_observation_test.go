package main

import (
	"local/cs2-radar/internal/capturefilter"
	"testing"
)

func TestSafeObservationCountersAndSnapshotValidity(t *testing.T) {
	s := &captureSession{stopCh: make(chan struct{}), cfilter: capturefilter.New()}
	s.keyPhase.Store("等待握手包")
	s.observeSafeFlow(10)
	s.cfilter.Set(123, []uint16{10})
	s.observeSafeFlow(10)
	s.observeSafeFlow(20)
	s.cfilter.AutoAdmit(20, 30)
	s.observeSafeFlow(20)
	s.observeSafeGNS(false, false)
	s.observeSafeGNS(true, false)
	s.observeSafeGNS(true, true)
	s.diag.filterState.Store(1)
	s.gnsMu.Lock()
	p := s.safeDiagnosticSample()
	s.gnsMu.Unlock()
	if p.PeerSnapshot != 2 || p.OwnedUDP != 1 || p.HeuristicUDP != 1 || p.UnfilteredUDP != 1 || p.UnmatchedUDP != 1 || p.OwnedPorts != 1 || p.FilterState != 1 {
		t.Fatal("flow or validity")
	}
	if p.GNSAttempts != 3 || p.GNSCandidate != 2 || p.GNSParsed != 1 || p.GNSRejected != 1 {
		t.Fatal("parser counters")
	}
	if s.safeDiagnosticSample().PeerSnapshot != 1 {
		t.Fatal("valid snapshot")
	}
}
