package main

import (
	"testing"

	"local/cs2-radar/internal/memscan"
	"local/cs2-radar/internal/winapi"
)

// TestSplitPubScanRegions 盯住公钥定位第一级的分档规则。
//
// 这个分档是「把 2.45 秒压进 700 毫秒」的全部依据：
// 只扫 MEM_PRIVATE 且 ≤1MB（实测 868.8 MB / 约 276 ms），
// 其余留给兜底级。分错档要么拖慢第一级，要么漏掉公钥。
func TestSplitPubScanRegions(t *testing.T) {
	reg := func(base uintptr, size uintptr, typ uint32) memscan.Region {
		return memscan.Region{Base: base, Size: size, Type: typ}
	}

	all := []memscan.Region{
		reg(0x1000, 0x3000, winapi.MEM_PRIVATE),   // 小堆 → small
		reg(0x10000, 0x10000, winapi.MEM_PRIVATE), // 64KB 堆 → small
		reg(0x20000, 1<<20, winapi.MEM_PRIVATE),   // 恰好 1MB → small（含边界）
		reg(0x30000, 1<<20+1, winapi.MEM_PRIVATE), // 1MB+1 → rest
		reg(0x40000, 5<<30, winapi.MEM_PRIVATE),   // 5GB 大堆 → rest
		reg(0x50000, 0x1000, winapi.MEM_IMAGE),    // PE 映像 → rest（再小也不要）
		reg(0x60000, 0x1000, winapi.MEM_MAPPED),   // 映射 → rest
	}

	small, rest := splitPubScanRegions(all)

	if len(small) != 3 {
		t.Fatalf("小区域 %d 个，期望 3", len(small))
	}
	for _, r := range small {
		if r.Type != winapi.MEM_PRIVATE {
			t.Errorf("小区域里混进了非 MEM_PRIVATE：Type=%#x", r.Type)
		}
		if r.Size > 1<<20 {
			t.Errorf("小区域里混进了 >1MB 的区域：Size=%#x", r.Size)
		}
	}
	// 边界：恰好 1MB 必须在小区域里
	if small[2].Base != 0x20000 {
		t.Errorf("恰好 1MB 的区域应进小区域，实际小区域第 3 个 base=%#x", small[2].Base)
	}

	if len(rest) != 4 {
		t.Fatalf("其余区域 %d 个，期望 4", len(rest))
	}

	// 一个都不能丢：两级加起来必须等于原始总量。
	if got, want := totalMemBytes(small)+totalMemBytes(rest), totalMemBytes(all); got != want {
		t.Fatalf("两级总量 %d，原始 %d —— 有区域被丢掉或重复", got, want)
	}
}

// TestSplitPubScanRegionsEmpty 空输入不能 panic（进程刚启动时可能枚举不到）。
func TestSplitPubScanRegionsEmpty(t *testing.T) {
	small, rest := splitPubScanRegions(nil)
	if len(small) != 0 || len(rest) != 0 {
		t.Fatalf("空输入应返回两个空切片，实际 %d / %d", len(small), len(rest))
	}
}

// TestPubScanSmallMaxIsOneMB 钉住第一级上限 = 1 MB。
//
// 依据：cs2.exe 实测「MEM_PRIVATE 且 ≤1MB」= 868.8 MB（约 276 ms），
// 而公钥的 6 处命中所在区域全部 ≤256 KB。改大这个值会直接拖慢第一级，
// 改小则可能漏掉公钥。
func TestPubScanSmallMaxIsOneMB(t *testing.T) {
	if pubScanSmallMax != 1<<20 {
		t.Fatalf("pubScanSmallMax = %#x，期望 1MB（0x100000）", pubScanSmallMax)
	}
}
