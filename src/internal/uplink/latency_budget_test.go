package uplink

import (
	"errors"
	"testing"
	"time"
)

func TestRemoteLatencyBudgetDoesNotChangeLocalDiagnostic(t *testing.T) {
	remote := New("https://fixture.invalid/api/v1/ingest", "synthetic")
	remote.fail(errors.New("synthetic stop"))
	defer remote.Close()
	if remote.FlushInterval != 100*time.Millisecond || remote.MaxPackets != 256 {
		t.Fatal("remote cadence/batch budget changed")
	}
	local := NewLocal("synthetic", func(*Batch) error { return nil })
	defer local.Close()
	if local.FlushInterval != 200*time.Millisecond || local.MaxPackets != 64 {
		t.Fatal("local diagnostic mode changed")
	}
}
