package main

import (
	"crypto/rand"
	"testing"
	"time"
)

// TestClampPassRateMeasured 在真随机字节上量出「clamp 那一遍」省了多少 X25519。
//
// 为什么要实测：976 MB 逐字节校验的耗时几乎全部是 X25519 标量乘（约 5 µs/次），
// 所以「省了多少次校验」就等于「省了多少时间」。这个比值决定了
// 「要不要在关窗之前多等十几秒」，不能拍脑袋。
func TestClampPassRateMeasured(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过（-short）")
	}
	const size = 8 << 20
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("填充随机字节: %v", err)
	}

	count := func(pf privFilter) (int, time.Duration) {
		n := 0
		t0 := time.Now()
		filterScan(buf, pf, func(int) bool {
			n++
			return false
		})
		return n, time.Since(t0)
	}

	full := DefaultPrivFilter
	clamp := DefaultPrivFilter
	clamp.RequireClamp = true

	nFull, dFull := count(full)
	nClamp, dClamp := count(clamp)

	offsets := float64(size - 31)
	t.Logf("随机字节 %d MB（近似堆里的高熵段）", size>>20)
	t.Logf("  完整预筛：通过 %d 个窗口（%.2f%%）｜耗时 %s", nFull, float64(nFull)*100/offsets, dFull)
	t.Logf("  只测 clamp：通过 %d 个窗口（%.3f%%）｜耗时 %s", nClamp, float64(nClamp)*100/offsets, dClamp)
	if nClamp == 0 {
		t.Fatal("clamp 那一遍一个窗口都没通过 —— 判断条件写错了")
	}
	ratio := float64(nFull) / float64(nClamp)
	t.Logf("  X25519 次数减少 %.1f 倍", ratio)
	if ratio < 20 {
		t.Fatalf("clamp 优先只省了 %.1f 倍，达不到预期（应接近 32 倍）", ratio)
	}
}
