package main

import "testing"

func TestOwnedTargetSafeCounterMapping(t *testing.T) {
	s := ownedFixture()
	s.diag.directionUnknown.Store(2)
	s.diag.ownershipRejected.Store(7)
	s.diag.ownershipRefreshes.Store(1)
	p := s.safeDiagnosticSample()
	if p.DirectionUnknown != 2 || p.OwnershipRejected != 7 || p.OwnershipRefreshes != 1 {
		t.Fatal("numeric ownership counters lost")
	}
}
