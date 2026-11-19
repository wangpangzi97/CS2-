package main

import (
	"local/cs2-radar/internal/capturefilter"
	"local/cs2-radar/internal/handshake"
	"local/cs2-radar/internal/transport"
	"time"
)

// A structural handshake may request rediscovery, but NEVER grants a port.
// Only a successful guarded Discover plus a new local ownership match admits it.
func ownedRefreshCandidate(data []byte) bool {
	if len(data) == 0 || len(data) > 65535 {
		return false
	}
	if handshake.IsHelloType(data[0]) {
		p, e := handshake.ParseHello(data)
		return e == nil && len(p.PublicKey) == 32
	}
	if handshake.IsGNSType(data[0]) {
		p, e := handshake.ParseGNSHandshake(data)
		return e == nil && (p.Type == handshake.TypeGNSConnectRequest || p.Type == handshake.TypeGNSConnectOK)
	}
	return false
}
func (s *captureSession) reserveOwnerRefresh(now time.Time) bool {
	s.filterMu.Lock()
	defer s.filterMu.Unlock()
	if s.ownerRefreshStart.IsZero() || now.Sub(s.ownerRefreshStart) >= time.Second {
		s.ownerRefreshStart = now
		s.ownerRefreshBudget = 0
	}
	if s.ownerRefreshBudget >= 8 {
		return false
	}
	s.ownerRefreshBudget++
	return true
}
func (s *captureSession) refreshOwnedTargetForHandshake() bool {
	return s.refreshCaptureFilter(resolvePID, capturefilter.Discover)
}
func (s *captureSession) admitOwnedTargetUDP(u *transport.UDPPacket, dir string, refresh func() bool) bool {
	if u == nil || !s.captureFilterAvailable() || dir != direction(s.locals, u) {
		return false
	}
	var local uint16
	switch dir {
	case "c2s":
		local = u.SrcPort
	case "s2c":
		local = u.DstPort
	default:
		return false
	}
	if s.cfilter.MatchOwnedLocal(local) {
		return true
	}
	if refresh == nil || !ownedRefreshCandidate(u.Data) || !s.reserveOwnerRefresh(time.Now()) {
		return false
	}
	s.diag.ownershipRefreshes.Add(1)
	if !refresh() {
		return false
	}
	return s.captureFilterAvailable() && s.cfilter.MatchOwnedLocal(local)
}
