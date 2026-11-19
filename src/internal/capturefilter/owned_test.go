package capturefilter

import (
	"sync"
	"testing"
)

func TestOwnedStrictCannotExpandAcrossRefresh(t *testing.T) {
	f := NewStrict()
	for i := 0; i < 100; i++ {
		f.Set(42, []uint16{27015})
		if len(f.AutoAdmit(5353, 5354)) != 0 || f.AddPort(5353) || f.MatchOwnedLocal(5353) || !f.MatchOwnedLocal(27015) {
			t.Fatal("strict expansion")
		}
	}
	f.Clear()
	if f.MatchOwnedLocal(27015) {
		t.Fatal("stale owner")
	}
}
func TestOwnedStrictConcurrentRefresh(t *testing.T) {
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
			f.AutoAdmit(5353, 5354)
			f.AddPort(5353)
			if f.MatchOwnedLocal(5353) {
				t.Error("unowned admitted")
				return
			}
		}
	}()
	wg.Wait()
}
