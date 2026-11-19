package uplink

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestLocalBatchPerformance(t *testing.T) {
	delivered := make(chan int, 8)
	s := NewLocal("timing-fixture", func(b *Batch) error {
		if len(b.Packets) > 0 {
			delivered <- len(b.Packets)
		}
		return nil
	})
	defer s.Close()
	start := time.Now()
	s.Push(Packet{Data: "AA=="})
	select {
	case n := <-delivered:
		if n != 1 {
			t.Fatal(n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timer did not flush")
	}
	sparse := time.Since(start)
	start = time.Now()
	for i := 0; i < 64; i++ {
		s.Push(Packet{Data: "AA=="})
	}
	select {
	case n := <-delivered:
		if n != 64 {
			t.Fatal(n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("full did not flush")
	}
	burst := time.Since(start)
	raw, _ := json.Marshal(s.Stats())
	fmt.Printf("BATCH sparse_one_ms=%.3f full64_ms=%.3f stats=%s\n", float64(sparse)/1e6, float64(burst)/1e6, raw)
	if sparse < 100*time.Millisecond {
		t.Fatal("unexpected sparse flush before default timer")
	}
	if s.Stats()["performance"] == nil {
		t.Fatal("performance missing")
	}
}
