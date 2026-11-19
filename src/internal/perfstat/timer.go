// Package perfstat provides bounded, lock-free cumulative duration histograms.
package perfstat

import (
	"sync/atomic"
	"time"
)

var upper = [...]int64{50000, 100000, 250000, 500000, 1000000, 2000000, 5000000, 10000000, 20000000, 50000000, 100000000, 250000000, 500000000, 1000000000, 2000000000}

type Timer struct {
	buckets [16]atomic.Uint64
	total   atomic.Uint64
	max     atomic.Uint64
}
type Summary struct {
	Count      uint64  `json:"count"`
	MeanMS     float64 `json:"mean_ms"`
	TotalMS    float64 `json:"total_ms"`
	MaxMS      float64 `json:"max_ms"`
	P50UpperMS float64 `json:"p50_upper_ms"`
	P95UpperMS float64 `json:"p95_upper_ms"`
}

func (t *Timer) Observe(d time.Duration) {
	if d < 0 {
		d = 0
	}
	n := uint64(d)
	t.total.Add(n)
	for old := t.max.Load(); n > old; old = t.max.Load() {
		if t.max.CompareAndSwap(old, n) {
			break
		}
	}
	i := 0
	for i < len(upper) && int64(n) > upper[i] {
		i++
	}
	t.buckets[i].Add(1)
}
func (t *Timer) Snapshot() Summary {
	var bins [16]uint64
	var count uint64
	for i := range bins {
		bins[i] = t.buckets[i].Load()
		count += bins[i]
	}
	s := Summary{Count: count, TotalMS: float64(t.total.Load()) / 1e6, MaxMS: float64(t.max.Load()) / 1e6}
	if count == 0 {
		return s
	}
	s.MeanMS = s.TotalMS / float64(count)
	quant := func(percent uint64) float64 {
		need := (count*percent + 99) / 100
		var n uint64
		for i, c := range bins {
			n += c
			if n >= need {
				if i < len(upper) {
					return float64(upper[i]) / 1e6
				}
				return s.MaxMS
			}
		}
		return s.MaxMS
	}
	s.P50UpperMS = quant(50)
	s.P95UpperMS = quant(95)
	return s
}
