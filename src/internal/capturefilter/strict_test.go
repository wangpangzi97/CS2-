package capturefilter

import (
	"sync"
	"testing"
)

func TestStrictUnavailableTarget(t *testing.T) {
	f := NewStrict()
	if f.Match(1, 2) {
		t.Fatal("empty open")
	}
	f.AddPort(1)
	if f.Match(1, 2) {
		t.Fatal("admission creates ownership")
	}
	f.Set(42, []uint16{27015})
	if !f.Match(27015, 2) || f.Match(1, 2) {
		t.Fatal("wrong target match")
	}
	f.Clear()
	if f.Match(27015, 2) {
		t.Fatal("stale target open")
	}
	f.Set(0, []uint16{27015})
	if f.Match(27015, 2) {
		t.Fatal("zero PID open")
	}
}
func TestStrictConcurrentClearNeverOpensAllUDP(t *testing.T) {
	f := NewStrict()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			f.Set(42, []uint16{27015})
			f.Clear()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			if f.Match(5353, 5353) {
				t.Error("unrelated packet admitted")
				return
			}
		}
	}()
	wg.Wait()
}
