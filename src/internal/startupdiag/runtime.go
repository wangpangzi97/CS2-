package startupdiag

import (
	"context"
	"errors"
	"net"
)

// FailureInfo returns fixed numeric classifications only, never Error() text.
// 0 none,1 unknown,2 HTTP,3 cancel,4 timeout,5 TLS,6 DNS,7 network,
// 8 backpressure,9 denied/invalid data session.
func FailureInfo(err error) (uint8, uint16) {
	if err == nil {
		return 0, 0
	}
	var code interface{ DiagnosticFailureCode() uint8 }
	if errors.As(err, &code) && code.DiagnosticFailureCode() == 8 {
		return 8, 0
	}
	var h interface{ HTTPStatus() int }
	if errors.As(err, &h) {
		if n := safeStatus(h.HTTPStatus()); n != 0 {
			return 2, uint16(n)
		}
	}
	var n *networkError
	if errors.As(err, &n) {
		switch n.kind {
		case "CANCEL":
			return 3, 0
		case "TIMEOUT":
			return 4, 0
		case "TLS":
			return 5, 0
		case "DNS":
			return 6, 0
		default:
			return 7, 0
		}
	}
	if errors.Is(err, context.Canceled) {
		return 3, 0
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return 4, 0
	}
	wrapped := Network(err)
	if errors.As(wrapped, &n) && n.kind != "NETWORK" {
		return FailureInfo(wrapped)
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return 7, 0
	}
	return 1, 0
}
