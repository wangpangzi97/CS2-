package main

import (
	"fmt"
	"local/cs2-radar/internal/startupdiag"
	"os"
)

// First observed stop request wins; later cleanup cancellation cannot overwrite
// it. This is an observed trigger, not proof of an external root cause.
func (s *captureSession) recordStop(reason, kind uint8, status uint16) {
	if reason < 1 || reason > 6 {
		reason = 1
	}
	if kind > 9 {
		kind = 1
	}
	if status != 0 && (status < 100 || status > 599) {
		status = 0
	}
	packed := uint32(reason) | uint32(kind)<<8 | uint32(status)<<16
	if s.diag.stopPacked.CompareAndSwap(0, packed) {
		fmt.Fprintf(os.Stderr, "[GS-STOP] reason=%d failure=%d http=%d\n", reason, kind, status)
	}
}
func (s *captureSession) recordErrorStop(reason uint8, e error) {
	k, h := startupdiag.FailureInfo(e)
	s.recordStop(reason, k, h)
}
func (s *captureSession) recordDataStop(reason uint8, c interface{ FailureInfo() (uint8, uint16) }, fallback error) {
	k, h := c.FailureInfo()
	if k == 0 {
		k, h = startupdiag.FailureInfo(fallback)
		if k == 0 {
			k = 1
		}
	}
	s.recordStop(reason, k, h)
}
func (s *captureSession) stopAs(reason uint8, e error) { s.recordErrorStop(reason, e); s.Stop() }
