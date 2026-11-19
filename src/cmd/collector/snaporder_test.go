package main

// 快照抓取顺序（2026-10-19 02:52 现场驱动）
//
// ── 为什么要专门测顺序 ──────────────────────────────────────────────
//
// takeSnapshot 严格按 ranges 顺序抄，撞到 -snap-mb 上限就停。
// 所以**顺序 = 预算分配**，排序错了就等于把 512 MB 花在最没希望的地方。
//
// 02:52 现场就是这么错的：rest 走的是 `writableRanges(ordered)`，
// 而 writableRanges 内部调用 mergeRanges —— 按**地址**重排。
// 结果 453.8 MB 全抄在低地址的 5 GB 大堆上，而同一份日志里 7 处公钥命中
// 的 RegionSize 是 0x5000 / 0x8000 / 0x8000 / 0x10000 / 0x15000 / 0x15000 / 0x30000
// —— **七处全在 ≤192 KB 的小区域**，一处大堆都没有。
//
// 这组用例钉死三件事：
//   1. 小私有区域排在大私有区域前面（哪怕大区域地址更低）；
//   2. 32 KB 的 MEM_IMAGE 不能插到 5 MB 的 MEM_PRIVATE 前面；
//   3. 邻域（primary）被扣掉，且总字节数守恒。

import (
	"testing"

	"local/cs2-radar/internal/memscan"
	"local/cs2-radar/internal/winapi"
)

func snapTestRegions() []memscan.Region {
	const rw = 0x04
	return []memscan.Region{
		// 故意让最大的区域地址最低 —— 按地址排的话它一定排第一。
		{Base: 0x10000000, Size: 5 << 20, Protect: rw, Type: winapi.MEM_PRIVATE},
		{Base: 0x20000000, Size: 64 << 10, Protect: rw, Type: winapi.MEM_PRIVATE},
		{Base: 0x30000000, Size: 200 << 10, Protect: rw, Type: winapi.MEM_PRIVATE},
		{Base: 0x40000000, Size: 2 << 20, Protect: rw, Type: winapi.MEM_PRIVATE},
		{Base: 0x50000000, Size: 32 << 10, Protect: rw, Type: winapi.MEM_IMAGE},
	}
}

func indexOfRange(rs []scanRange, lo uintptr) int {
	for i, r := range rs {
		if r.lo == lo {
			return i
		}
	}
	return -1
}

func TestSnapRangesSmallPrivateFirst(t *testing.T) {
	regions := snapTestRegions()
	// 邻域落在 64 KB 那个区域里，切成两半。
	primary := []scanRange{{lo: 0x20001000, hi: 0x20002000, tag: "snap-near"}}

	got := snapRanges(regions, primary)
	if len(got) == 0 {
		t.Fatal("snapRanges 返回空")
	}

	// ① 最大区域（地址最低、5 MB）绝不能排在前面。
	iBig := indexOfRange(got, 0x10000000)
	iSmall := indexOfRange(got, 0x30000000)
	if iBig < 0 || iSmall < 0 {
		t.Fatalf("区间丢了：5MB 在 %d，200KB 在 %d", iBig, iSmall)
	}
	if iBig < iSmall {
		t.Fatalf("5 MB 大堆（#%d）排到了 200 KB 小区域（#%d）前面 —— 顺序退化回按地址了",
			iBig, iSmall)
	}

	// ② 32 KB 的 MEM_IMAGE 是最后一名，不能插到大堆前面。
	iImg := indexOfRange(got, 0x50000000)
	if iImg < 0 {
		t.Fatal("MEM_IMAGE 区间丢了")
	}
	if iImg < iBig {
		t.Fatalf("32 KB 的 MEM_IMAGE（#%d）排到了 5 MB 私有堆（#%d）前面", iImg, iBig)
	}

	// ③ 第一个区间必须是"最小的那半块"（0x20000000 起的 4 KB）。
	if got[0].lo != 0x20000000 || got[0].hi != 0x20001000 {
		t.Fatalf("第一个区间应为 [0x20000000,0x20001000)，实际 [%#x,%#x)", got[0].lo, got[0].hi)
	}

	// ④ 邻域被扣掉了。
	for _, r := range got {
		if r.lo < 0x20002000 && r.hi > 0x20001000 {
			t.Fatalf("邻域没被扣掉：[%#x,%#x) 盖住了 [0x20001000,0x20002000)", r.lo, r.hi)
		}
	}

	// ⑤ 总字节守恒：可写总量 - 邻域量。
	var total, want uintptr
	for _, r := range got {
		total += r.hi - r.lo
	}
	for _, r := range regions {
		if winapi.WritableProtect(r.Protect) && r.Size >= 32 {
			want += r.Size
		}
	}
	want -= 0x1000 // primary
	if total != want {
		t.Fatalf("字节不守恒：got %d，want %d", total, want)
	}
}

// TestSnapRangesEmptyAndNoPrimary 覆盖两个边界：没有邻域、没有可写区。
func TestSnapRangesEmptyAndNoPrimary(t *testing.T) {
	if got := snapRanges(nil, nil); got != nil {
		t.Fatalf("空输入应返回 nil，得到 %d 个区间", len(got))
	}

	regions := snapTestRegions()
	got := snapRanges(regions, nil)
	var total uintptr
	for _, r := range got {
		total += r.hi - r.lo
	}
	var want uintptr
	for _, r := range regions {
		if winapi.WritableProtect(r.Protect) && r.Size >= 32 {
			want += r.Size
		}
	}
	if total != want {
		t.Fatalf("没有邻域时字节应全保留：got %d，want %d", total, want)
	}
}

// TestSnapTierBytesReportsBudget 钉死日志里的"预算花在哪一档"能算出来。
func TestSnapTierBytesReportsBudget(t *testing.T) {
	regions := snapTestRegions()
	got := snapTierBytes(regions, snapRanges(regions, nil))
	if len(got) == 0 {
		t.Fatal("snapTierBytes 返回空")
	}
	// 至少要有"小区域"和"私有大堆"两档 —— 否则日志说明不了预算分配。
	var hasSmall, hasBig bool
	for _, s := range got {
		if len(s) > len("小区域≤256KB") && s[:len("小区域")] == "小区域" {
			hasSmall = true
		}
		if len(s) > len("私有大堆") && s[:len("私有大堆")] == "私有大堆" {
			hasBig = true
		}
	}
	if !hasSmall || !hasBig {
		t.Fatalf("档位汇总不完整：%v", got)
	}
}

// TestSnapTierRanking 钉死分档边界：256 KB 算小区域，256 KB+1 算中区域。
func TestSnapTierRanking(t *testing.T) {
	const rw = 0x04
	cases := []struct {
		r    memscan.Region
		want int
	}{
		{memscan.Region{Size: snapSmallMax, Protect: rw, Type: winapi.MEM_PRIVATE}, 0},
		{memscan.Region{Size: snapSmallMax + 1, Protect: rw, Type: winapi.MEM_PRIVATE}, 1},
		{memscan.Region{Size: 1 << 20, Protect: rw, Type: winapi.MEM_PRIVATE}, 1},
		{memscan.Region{Size: 1<<20 + 1, Protect: rw, Type: winapi.MEM_PRIVATE}, 2},
		{memscan.Region{Size: 4 << 10, Protect: rw, Type: winapi.MEM_MAPPED}, 3},
		{memscan.Region{Size: 4 << 10, Protect: rw, Type: winapi.MEM_IMAGE}, 4},
	}
	for _, c := range cases {
		if got := snapTier(c.r); got != c.want {
			t.Fatalf("size=%#x type=%#x：tier got %d，want %d", c.r.Size, c.r.Type, got, c.want)
		}
	}
}

// TestSnapRangesQuotaReservesHeapShare 锁死「私有大堆必须有保底配额」。
//
// 🔴 2026-10-20 07:29 现场：原来的「按档位严格排序、先到先得」让
// 小区域 + 中区域吃掉 952 MB，**私有大堆只拿到 71.8 MB（自己 1.1%）**，
// 于是 `[room1] GNS 握手材料已齐，但没有客户端私钥` —— 新分配的 32 字节
// 密钥对象正是住在私有大堆里，根本没被读到。
//
// 这个用例构造「小区域总量远超预算」的极端情形，要求撞到上限之前
// 私有大堆至少拿到 40% 的预算。
func TestSnapRangesQuotaReservesHeapShare(t *testing.T) {
	const rw = 0x04
	var regions []memscan.Region
	// 小区域（tier 0）：3000 块 × 256 KB = 750 MB。
	// 750 MB 已经超过 70% 预算 —— 按老逻辑它会先把预算吃光。
	for i := 0; i < 3000; i++ {
		regions = append(regions, memscan.Region{
			Base:    0x10000000 + uintptr(i)*(256<<10),
			Size:    256 << 10,
			Protect: rw,
			Type:    winapi.MEM_PRIVATE,
		})
	}
	// 私有大堆（tier 2）：4 块 × 1 GB，地址故意放在高处。
	for i := 0; i < 4; i++ {
		regions = append(regions, memscan.Region{
			Base:    0x90000000 + uintptr(i)*(1<<30),
			Size:    1 << 30,
			Protect: rw,
			Type:    winapi.MEM_PRIVATE,
		})
	}

	got := snapRanges(regions, nil)
	if len(got) == 0 {
		t.Fatal("snapRanges 返回空")
	}

	// 按顺序累计到 -snap-mb 上限，统计各档拿到的字节。
	var small, heap uintptr
	capBytes := snapshotCapBytes
	for _, r := range got {
		if small+heap >= capBytes {
			break
		}
		n := r.hi - r.lo
		if r.lo >= 0x90000000 {
			heap += n
		} else {
			small += n
		}
	}
	if heap < capBytes*4/10 {
		t.Fatalf("上限 %d MB 内私有大堆只拿到 %d MB（小区域 %d MB）—— "+
			"配额没生效，小区域又独吞了预算",
			capBytes>>20, heap>>20, small>>20)
	}
	if small == 0 {
		t.Fatal("小区域一个字节都没拿到 —— 配额调过头了，公钥就在小区域里")
	}
}
