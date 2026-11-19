package uplink

import (
	"errors"
	"testing"
)

func TestRepairExplicitFlushLossAccounting(t *testing.T) {
	s := NewLocal("x", func(*Batch) error { return errors.New("fixture failure") })
	s.FlushInterval = 1000000000
	s.Push(Packet{Dir: "s2c", Data: "AA=="})
	if s.Flush(false) == nil {
		t.Fatal("missing failure")
	}
	m := s.Stats()
	if m["failed"].(uint64) != 1 || m["dropped_packets"].(uint64) != 1 {
		t.Fatal(m)
	}
	_ = s.Close()
	s.Push(Packet{})
	if s.Stats()["dropped_packets"].(uint64) != 2 {
		t.Fatal("post-close packet unaccounted")
	}
}
