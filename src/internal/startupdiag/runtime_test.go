package startupdiag

import (
	"context"
	"errors"
	"testing"
)

func TestRuntimeFailureInfoOnlyTypedCodes(t *testing.T) {
	for _, x := range []struct {
		e error
		k uint8
		h uint16
	}{{nil, 0, 0}, {errors.New("FAKE_TOKEN HTTP 403 timeout"), 1, 0}, {&HTTPFailure{Status: 403}, 2, 403}, {context.Canceled, 3, 0}, {context.DeadlineExceeded, 4, 0}} {
		k, h := FailureInfo(x.e)
		if k != x.k || h != x.h {
			t.Fatal("typed classification")
		}
	}
}
