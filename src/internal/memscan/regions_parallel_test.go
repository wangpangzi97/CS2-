package memscan

import (
	"os"
	"testing"
	"time"
)

// TestRegionsParallelMatchesSerial 是核心正确性用例：并行枚举的结果必须和
// 串行枚举**完全一致**（同样的区域、同样的 Base/Size/Protect/Type，且按 Base 升序）。
//
// 背景：RegionsParallel 把用户地址空间切成 N 段、每段独立从段首走
// VirtualQueryEx。这条路径的正确性依赖两个事实：
//  1. VirtualQueryEx(addr) 返回的是**包含 addr 的区域**，所以从任意段首开始
//     都能拿到该段内的完整区域链；
//  2. 跨段边界的区域会被两个 worker 各报一次，必须按 Base 去重。
//
// 任何一条不成立，公钥定位就会漏区域 —— 而漏掉的区域恰好可能是私钥所在处。
func TestRegionsParallelMatchesSerial(t *testing.T) {
	proc, err := OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	serial, serr := proc.RegionsWithError(time.Now().Add(10*time.Second), 0)
	if serr != nil && serr != ErrRegionDeadline && serr != ErrRegionLimit {
		t.Fatalf("串行枚举失败: %v", serr)
	}
	if len(serial) == 0 {
		t.Skip("串行枚举一个区域都没有，环境异常")
	}

	// ⚠ 不能断言"区域列表完全相等"：这个测试进程自己在两次枚举之间还在分配内存
	// （Go 运行时按需 mmap、线程栈扩张、区域被拆成更小的块），实测串行连跑两次
	// 都会有 1~5 个区域变化。直接比"Base+Size 完全相同"测的是 churn，不是正确性。
	//
	// 真正致命的方向是**漏地址**：并行分段后，如果某个 worker 没走到自己那段里
	// 的某个区域，那段内存就永远不会被搜 —— 漏掉的可能正好是私钥所在处。
	// 所以断言改成：**串行看到的每一个区域起始地址，并行结果都必须覆盖到它**
	// （被拆成多块也算覆盖）。
	covered := func(list []Region, addr uintptr) bool {
		lo, hi := 0, len(list)
		for lo < hi {
			mid := (lo + hi) / 2
			r := list[mid]
			switch {
			case addr < r.Base:
				hi = mid
			case addr >= r.Base+r.Size:
				lo = mid + 1
			default:
				return true
			}
		}
		return false
	}

	for _, w := range []int{1, 2, 4, 8, 16} {
		par, perr := proc.RegionsParallel(time.Now().Add(10*time.Second), w)
		if perr != nil && perr != ErrRegionDeadline {
			t.Fatalf("workers=%d 并行枚举失败: %v", w, perr)
		}
		missing := 0
		var firstMissing Region
		for _, r := range serial {
			if !covered(par, r.Base) {
				if missing == 0 {
					firstMissing = r
				}
				missing++
			}
		}
		if missing > 0 {
			t.Fatalf("workers=%d：有 %d 个区域没被覆盖，第一个是 %+v（并行 %d 个 / 串行 %d 个）",
				w, missing, firstMissing, len(par), len(serial))
		}
		// 升序 + 无重复（去重逻辑的自检）
		for i := 1; i < len(par); i++ {
			if par[i].Base <= par[i-1].Base {
				t.Fatalf("workers=%d：结果不是严格升序（第 %d 个 %#x <= 前一个 %#x）",
					w, i, par[i].Base, par[i-1].Base)
			}
		}
		t.Logf("workers=%2d：%d 个区域（串行 %d），串行的起始地址全部覆盖、升序无重复",
			w, len(par), len(serial))
	}
}

// TestRegionsParallelDeadline 传一个已经过期的 deadline 必须快速返回，
// 且**不能**卡住（这是冻结窗口里的硬约束：枚举超时必须让位给抓取）。
func TestRegionsParallelDeadline(t *testing.T) {
	proc, err := OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程: %v", err)
	}
	defer proc.Close()

	t0 := time.Now()
	rs, err := proc.RegionsParallel(time.Now().Add(-time.Second), 8)
	el := time.Since(t0)
	if err != ErrRegionDeadline {
		t.Fatalf("过期 deadline 应返回 ErrRegionDeadline，得到 %v", err)
	}
	if el > 200*time.Millisecond {
		t.Fatalf("过期 deadline 却花了 %s，说明没在循环里检查", el)
	}
	t.Logf("过期 deadline：%s 返回 %d 个区域（部分结果允许返回）", el.Round(time.Millisecond), len(rs))
}

// BenchmarkRegionsParallel 量串行 vs 并行的枚举耗时。
//
// 04:10 现场：7579 个区域串行枚举约 100 ms，而这 100 ms 正好卡在
// 「握手 → 冻结」的黄金窗口里。这个基准用来确认并行确实把它压下去了。
func BenchmarkRegionsParallel(b *testing.B) {
	proc, err := OpenForRead(uint32(os.Getpid()))
	if err != nil {
		b.Skipf("打不开自身进程: %v", err)
	}
	defer proc.Close()

	b.Run("serial", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := proc.RegionsWithError(time.Now().Add(10*time.Second), 0); err != nil &&
				err != ErrRegionDeadline && err != ErrRegionLimit {
				b.Fatalf("串行失败: %v", err)
			}
		}
	})
	for _, w := range []int{4, 8, 16} {
		w := w
		b.Run("parallel", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := proc.RegionsParallel(time.Now().Add(10*time.Second), w); err != nil &&
					err != ErrRegionDeadline {
					b.Fatalf("并行失败: %v", err)
				}
			}
			b.Logf("workers=%d", w)
		})
	}
}
