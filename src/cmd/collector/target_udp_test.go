package main

import (
	"local/cs2-radar/internal/capturefilter"
	"local/cs2-radar/internal/transport"
	"os"
	"strings"
	"testing"
	"time"
)

func ownedFixture() *captureSession {
	s := &captureSession{cfilter: capturefilter.NewStrict(), locals: map[string]bool{"192.0.2.10": true}}
	s.cfilter.Set(42, []uint16{27015})
	s.diag.filterState.Store(1)
	return s
}
func udpFixture() *transport.UDPPacket {
	return &transport.UDPPacket{SrcIP: [4]byte{192, 0, 2, 10}, DstIP: [4]byte{198, 51, 100, 20}, SrcPort: 5353, DstPort: 5354, Data: append([]byte{0x80}, make([]byte, 63)...)}
}
func fakeOwnedHello() []byte {
	return append([]byte{0x22, 0x3a, 36, 0x0a, 34, 0x12, 32}, make([]byte, 32)...)
}
func TestOwnedTargetNoHeuristicAndRemotePortCollision(t *testing.T) {
	s := ownedFixture()
	u := udpFixture()
	calls := 0
	refresh := func() bool { calls++; return true }
	for i := 0; i < 100; i++ {
		s.cfilter.Set(42, []uint16{27015})
		s.cfilter.AutoAdmit(u.SrcPort, u.DstPort)
		s.cfilter.AddPort(u.SrcPort)
		if s.admitOwnedTargetUDP(u, "c2s", refresh) {
			t.Fatal("heuristic admitted")
		}
	}
	if calls != 0 || s.cfilter.ClassifyLocal(u.SrcPort) != 3 {
		t.Fatal("cipher shape triggered refresh")
	}
	u.DstPort = 27015
	if s.admitOwnedTargetUDP(u, "c2s", refresh) {
		t.Fatal("remote number used as local ownership")
	}
	u.SrcPort = 27015
	if !s.admitOwnedTargetUDP(u, "c2s", nil) {
		t.Fatal("owned outgoing lost")
	}
	u.SrcIP, u.DstIP = u.DstIP, u.SrcIP
	u.SrcPort, u.DstPort = u.DstPort, u.SrcPort
	if !s.admitOwnedTargetUDP(u, "s2c", nil) {
		t.Fatal("owned incoming lost")
	}
}
func TestOwnedTargetDirectionRejectsAmbiguousAndSpoofed(t *testing.T) {
	s := ownedFixture()
	u := udpFixture()
	u.SrcPort = 27015
	if s.admitOwnedTargetUDP(u, "s2c", nil) {
		t.Fatal("caller supplied false direction")
	}
	u.DstIP = u.SrcIP
	if direction(s.locals, u) != "unknown" || s.admitOwnedTargetUDP(u, "unknown", nil) {
		t.Fatal("both local admitted")
	}
	u.SrcIP = [4]byte{203, 0, 113, 5}
	u.DstIP = [4]byte{203, 0, 113, 6}
	if direction(s.locals, u) != "unknown" || s.admitOwnedTargetUDP(u, "unknown", nil) {
		t.Fatal("neither local admitted")
	}
}
func TestOwnedTargetHandshakeRefreshRequiresRealOwnership(t *testing.T) {
	s := ownedFixture()
	u := udpFixture()
	u.Data = fakeOwnedHello()
	if !ownedRefreshCandidate(u.Data) {
		t.Fatal("synthetic structured handshake fixture invalid")
	}
	if s.admitOwnedTargetUDP(u, "c2s", func() bool { return true }) {
		t.Fatal("handshake authorizes itself")
	}
	if !s.admitOwnedTargetUDP(u, "c2s", func() bool {
		return s.refreshCaptureFilter(func() (uint32, error) { return 42, nil }, func(uint32) ([]uint16, error) { return []uint16{27015, 5353}, nil })
	}) {
		t.Fatal("newly discovered owned handshake lost")
	}
	s = ownedFixture()
	if s.admitOwnedTargetUDP(u, "c2s", func() bool { s.publishFilterState(8); s.cfilter.Clear(); return false }) {
		t.Fatal("blocked refresh admitted")
	}
	s = ownedFixture()
	now := time.Now()
	for i := 0; i < 8; i++ {
		if !s.reserveOwnerRefresh(now) {
			t.Fatal("budget early")
		}
	}
	if s.reserveOwnerRefresh(now) {
		t.Fatal("unbounded refresh")
	}
	if !s.reserveOwnerRefresh(now.Add(time.Second)) {
		t.Fatal("budget did not recover")
	}
}
func TestOwnedTargetProductionGateOrder(t *testing.T) {
	b, e := os.ReadFile("main.go")
	if e != nil {
		t.Fatal(e)
	}
	text := strings.SplitN(string(b), "func (s *captureSession) run()", 2)[1]
	gate := strings.Index(text, "s.admitOwnedTargetUDP(udp, dir,")
	for _, after := range []string{"s.noteGNSPeer(", "s.thr.Allow(", "s.sender.Push("} {
		if gate < 0 || gate > strings.Index(text, after) {
			t.Fatal("ownership not before sensitive work")
		}
	}
	if strings.Contains(text, "s.cfilter.AutoAdmit(") || strings.Contains(text, "s.cfilter.AddPort(") || strings.Contains(text, "s.cfilter.Match(") {
		t.Fatal("broad production path retained")
	}
	if !strings.Contains(text, "s.cfilter.MatchOwnedLocal(localPort)") {
		t.Fatal("no final recheck")
	}
}
