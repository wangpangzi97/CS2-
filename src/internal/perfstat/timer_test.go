package perfstat

import (
	"sync"
	"testing"
	"time"
)

func TestBoundedConcurrentTimer(t *testing.T) {
	var x Timer
	var w sync.WaitGroup
	for i := 0; i < 8; i++ {
		w.Add(1)
		go func() {
			defer w.Done()
			for j := 0; j < 1000; j++ {
				x.Observe(2 * time.Millisecond)
			}
		}()
	}
	w.Wait()
	s := x.Snapshot()
	if s.Count != 8000 || s.MeanMS != 2 || s.MaxMS != 2 || s.P50UpperMS != 2 || s.P95UpperMS != 2 {
		t.Fatalf("%+v", s)
	}
	var empty Timer
	if empty.Snapshot().Count != 0 {
		t.Fatal("empty")
	}
	x.Observe(3 * time.Second)
	if x.Snapshot().MaxMS != 3000 {
		t.Fatal("overflow bucket")
	}
}
