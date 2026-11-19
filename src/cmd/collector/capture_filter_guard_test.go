package main

import (
	"errors"
	"local/cs2-radar/internal/capturefilter"
	"local/cs2-radar/internal/memscan"
	"os"
	"strings"
	"testing"
)

func TestTargetFilterFailureStatesNoForward(t *testing.T) {
	for _, state := range []uint8{2, 3, 4, 6, 7, 8} {
		t.Run(filterStatusText(state), func(t *testing.T) {
			s := &captureSession{cfilter: capturefilter.NewStrict()}
			s.cfilter.Set(42, []uint16{27015})
			s.diag.filterState.Store(1)
			if !s.captureFilterAvailable() {
				t.Fatal("healthy fixture unavailable")
			}
			resolve := func() (uint32, error) { return 42, nil }
			discover := func(uint32) ([]uint16, error) { return []uint16{27015}, nil }
			if state == 3 {
				discover = func(uint32) ([]uint16, error) { return nil, errors.New("FAKE_PRIVATE") }
			}
			if state == 4 {
				discover = func(uint32) ([]uint16, error) { return []uint16{0}, nil }
			}
			if state == 2 || state >= 6 {
				resolve = func() (uint32, error) { return 0, &targetResolveError{state: state, cause: errors.New("FAKE_PRIVATE")} }
			}
			if s.refreshCaptureFilter(resolve, discover) {
				t.Fatal("failure admitted")
			}
			if s.captureFilterAvailable() || s.cfilter.Match(27015, 5353) || s.cfilter.PID() != 0 {
				t.Fatal("stale target retained")
			}
			s.cfilter.AddPort(5353)
			if s.cfilter.Match(5353, 5353) || s.captureFilterAvailable() {
				t.Fatal("handshake admission bypassed ownership")
			}
			if got := uint8(s.diag.filterState.Load()); got != state {
				t.Fatalf("state %d != %d", got, state)
			}
			if strings.Contains(filterStatusText(state), "FAKE_PRIVATE") {
				t.Fatal("error text leaked")
			}
		})
	}
}
func TestTargetFilterRecoveryAndGateOrder(t *testing.T) {
	s := &captureSession{cfilter: capturefilter.NewStrict()}
	resolve := func() (uint32, error) { return 42, nil }
	if s.captureFilterAvailable() {
		t.Fatal("unpolled open")
	}
	if !s.refreshCaptureFilter(resolve, func(uint32) ([]uint16, error) { return []uint16{27015}, nil }) {
		t.Fatal("discovery failed")
	}
	if !s.captureFilterAvailable() || !s.cfilter.Match(27015, 5353) || s.cfilter.Match(5353, 5353) {
		t.Fatal("ownership filter wrong")
	}
	b, e := os.ReadFile("main.go")
	if e != nil {
		t.Fatal(e)
	}
	text := strings.SplitN(string(b), "func (s *captureSession) run()", 2)[1]
	gate := strings.Index(text, "if !s.captureFilterAvailable()")
	if strings.Contains(text, "s.cfilter.AutoAdmit(") || strings.Contains(text, "s.cfilter.AddPort(") || gate < 0 || gate > strings.Index(text, "handshake.ParseGNSHandshake") || gate > strings.Index(text, "s.sender.Push(") {
		t.Fatal("gate not ahead of sensitive work")
	}
	if !strings.Contains(string(b), "cfilter:  capturefilter.NewStrict(),") {
		t.Fatal("production factory not strict")
	}
}
func TestTargetFilterLookupTypedCause(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code uint8
	}{{memscan.ErrProcessNotFound, 6}, {errors.New("FAKE_PRIVATE"), 7}} {
		_, e := lookupTargetPID("fake", func(string) (uint32, error) { return 0, tc.err })
		if filterFailureState(e) != tc.code {
			t.Fatal("wrong typed lookup cause")
		}
	}
	forceACHit(t, "FAKE_PRIVATE")
	setAllowAC(t, false)
	old := *flagPID
	*flagPID = 4242
	defer func() { *flagPID = old }()
	_, e := resolvePID()
	if filterFailureState(e) != 8 {
		t.Fatal("guard did not precede explicit PID")
	}
}
func TestTargetFilterProductionNoBypass(t *testing.T) {
	oldNo, oldAC := *flagNoFilter, *flagAllowAC
	defer func() { *flagNoFilter, *flagAllowAC = oldNo, oldAC }()
	for _, pair := range [][2]bool{{true, false}, {false, true}} {
		*flagNoFilter, *flagAllowAC = pair[0], pair[1]
		if productionDiagnosticsPolicy() == nil {
			t.Fatal("production bypass allowed")
		}
	}
	s := &captureSession{cfilter: capturefilter.NewStrict(), noFilter: true}
	if s.refreshCaptureFilter(func() (uint32, error) { t.Fatal("lookup called"); return 42, nil }, func(uint32) ([]uint16, error) { t.Fatal("discover called"); return nil, nil }) || s.captureFilterAvailable() {
		t.Fatal("no-filter bypass")
	}
}
