package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"local/cs2-radar/internal/memscan"
)

// TestPrivFilterPassRate 在本进程的真实内存上量出预筛通过率。
//
// 为什么必须实测而不是估算：预筛的阈值直接决定全内存兜底能不能在预算内跑完。
// 通过率如果是 1%，7.5 GB 就是 7500 万次 X25519 校验（约 8 分钟，超预算）；
// 如果是 0.1%，只有 750 万次（约 45 秒，可接受）。差一个数量级，只能靠量。
//
// 这个测试只读本进程内存，不冻结、不写、不改任何东西，跑完就退出。
func TestPrivFilterPassRate(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过（-short）")
	}
	const budgetMB = 600 // 采样量：够稳定，又不至于跑太久

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	regions, err := proc.RegionsWithError(time.Now().Add(30*time.Second), 0)
	if err != nil && err != memscan.ErrRegionDeadline && err != memscan.ErrRegionLimit {
		t.Fatalf("RegionsWithError: %v", err)
	}

	// 收集可写区，取前 budgetMB。
	var ranges []scanRange
	var total uintptr
	for _, r := range sortRegionsForScan(regions) {
		if total >= budgetMB<<20 {
			break
		}
		ranges = append(ranges, scanRange{lo: r.Base, hi: r.Base + r.Size, tag: "self"})
		total += r.Size
	}
	ranges = mergeRanges(ranges)
	if len(ranges) == 0 {
		t.Skip("没有可写区域")
	}

	// 并行统计：每个 worker 拿一块 1 MB，逐字节滑窗，统计
	// "总偏移数" 和 "各阈值下的通过数"。
	type bucket struct {
		offsets uint64
		pass    []uint64 // 与 thresholds 等长
	}
	thresholds := []privFilter{
		{MinDistinct: 0, MaxZeros: -1}, // 不筛（基线）
		{MinDistinct: 22, MaxZeros: 1},
		{MinDistinct: 22, MaxZeros: 2},
		{MinDistinct: 24, MaxZeros: 2},
		{MinDistinct: 28, MaxZeros: 0},
	}
	var (
		aggOffsets uint64
		aggPass    = make([]uint64, len(thresholds))
	)
	var mu sync.Mutex

	blocks := make(chan scanRange, 64)
	go func() {
		defer close(blocks)
		for _, r := range splitRanges(ranges) {
			blocks <- r
		}
	}()

	workers := runtime.NumCPU()
	if workers > 16 {
		workers = 16
	}
	var wg sync.WaitGroup
	var stopAll atomic.Bool
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, scanBlock)
			local := bucket{pass: make([]uint64, len(thresholds))}
			for r := range blocks {
				if stopAll.Load() {
					continue
				}
				want := int(r.hi - r.lo)
				if want > scanBlock {
					want = scanBlock
				}
				n, rerr := proc.ReadAt(r.lo, buf[:want])
				if rerr != nil || n < 32 {
					continue
				}
				b := buf[:n]
				local.offsets += uint64(n - 31)
				for ti, f := range thresholds {
					if ti == 0 {
						continue // 基线恒等于 offsets
					}
					f := f
					ti := ti
					filterScan(b, f, func(int) bool {
						local.pass[ti]++
						return false
					})
				}
			}
			mu.Lock()
			aggOffsets += local.offsets
			for i := 1; i < len(thresholds); i++ {
				aggPass[i] += local.pass[i]
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	offs := aggOffsets
	if offs == 0 {
		t.Skip("采样为 0")
	}
	t.Logf("采样 %.1f MB，逐字节偏移 %d 个", float64(offs+31*uint64(len(ranges)))/(1<<20), offs)
	for i, f := range thresholds {
		if i == 0 {
			t.Logf("  %-40s 通过 %d（100%%）", f.String(), offs)
			continue
		}
		p := aggPass[i]
		t.Logf("  %-40s 通过 %d（%.4f%%）→ 7.5 GB 预计 %s 次校验",
			f.String(), p, float64(p)*100/float64(offs),
			estimateChecks(float64(p)/float64(offs)))
	}
}

// estimateChecks 把通过率换算成"7.5 GB 全量会做多少次 X25519 校验"，
// 按 6.1 µs/次 折成可读时长，方便判断是否超预算。
func estimateChecks(rate float64) string {
	const totalBytes = 7572 << 20 // 用户机器实测可读区域 7572.8 MB
	checks := rate * float64(totalBytes)
	secs := checks * 6.1e-6
	if secs < 90 {
		return itoa(int(checks)) + "（约 " + itoa(int(secs)) + " 秒）"
	}
	return itoa(int(checks)) + "（约 " + itoa(int(secs/60)) + " 分钟）"
}

// TestPrivFilterKeepsRealKeys 用大量真实 X25519 私钥验证预筛**不会漏掉密钥**。
//
// 这是预筛的安全底线：预筛再快，只要会漏真密钥就是负优化。所以必须有测试
// 拿真实随机私钥去撞，而不是靠概率公式说服自己。
func TestPrivFilterKeepsRealKeys(t *testing.T) {
	const n = 20000
	cases := []privFilter{
		DefaultPrivFilter,
		{MinDistinct: 24, MaxZeros: 2},
		{MinDistinct: 28, MaxZeros: 0}, // 故意过严，看它到底漏多少
	}
	keys := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		keys = append(keys, k.Bytes())
	}
	for _, f := range cases {
		miss := 0
		for _, k := range keys {
			if !filterScan(k, f, func(int) bool { return true }) {
				miss++
			}
		}
		// 预筛是概率性的，不可能零漏检；但默认阈值必须把漏检压到 0.1% 以下，
		// 否则"扫完却没找到"的可信度就没了。实测约 0.03%。
		if f == DefaultPrivFilter && float64(miss)/n > 0.001 {
			t.Errorf("默认预筛漏掉了 %d/%d（%.3f%%）个真实私钥 —— 超过 0.1%% 上限，阈值不能用",
				miss, n, float64(miss)*100/n)
		}
		t.Logf("%-40s 漏 %d/%d（%.3f%%）", f.String(), miss, n, float64(miss)*100/n)
	}
}

// TestFilterScanFindsUnalignedKey 钉死"逐字节滑动"这个性质。
//
// 旧实现用 `off += 8`，只能检查 8 字节对齐的窗口。测试当时仍然通过，
// 因为它在 Go 结构体里命中了另一个**对齐**的内部副本 —— 埋进去的未对齐副本
// 从没被检查过。这个测试专门把密钥埋在未对齐偏移上，且要求只存在这一份。
func TestFilterScanFindsUnalignedKey(t *testing.T) {
	buf := make([]byte, 4096)
	// 填成"结构化"内容（低熵），确保预筛真的在起作用
	for i := range buf {
		buf[i] = byte(i % 7)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	want := key.Bytes()
	const off = 1001 // 不是 8 的倍数
	copy(buf[off:], want)

	var got int
	if !filterScan(buf, DefaultPrivFilter, func(o int) bool {
		if o == off {
			got = o
			return true
		}
		return false
	}) {
		t.Fatalf("未对齐偏移 %d 上的密钥没被扫到", off)
	}
	if got != off {
		t.Fatalf("偏移不对：%d != %d", got, off)
	}
}

// TestClampFilterOnlyCallsClampedWindows 锁死「clamp 那一遍不许放过非 clamp 窗口」。
//
// 这条是第一遍快扫的正确性基础：如果 clamp 判断写反（比如 `b[31]&0xC0 == 0xC0`），
// 快扫会一个窗口都不试，然后「快扫没命中」这个结论就变成假阴性，
// 而日志上只会看到耗时很短、什么都没找到。
func TestClampFilterOnlyCallsClampedWindows(t *testing.T) {
	buf := make([]byte, 512)
	for i := range buf {
		buf[i] = byte(i*37 + 11) // 高熵填充，保证不会被 DefaultPrivFilter 挡掉
	}
	// 强行造一个 clamp 形态的窗口在 off=64，一个非 clamp 的窗口在 off=200。
	clampOff, plainOff := 64, 200
	buf[clampOff] &^= 7
	buf[clampOff+31] = (buf[clampOff+31] &^ 0xC0) | 0x40
	buf[plainOff] |= 1 // 破坏 clamp 形态
	buf[plainOff+31] &^= 0x40

	pf := DefaultPrivFilter
	pf.RequireClamp = true

	var seen []int
	filterScan(buf, pf, func(off int) bool {
		seen = append(seen, off)
		return false
	})
	for _, off := range seen {
		if off == plainOff {
			t.Fatalf("非 clamp 窗口 %d 不该进 X25519 校验", off)
		}
	}
	found := false
	for _, off := range seen {
		if off == clampOff {
			found = true
		}
	}
	if !found {
		t.Fatalf("clamp 窗口 %d 没被扫到（seen=%v）", clampOff, seen)
	}
}

// TestClampFirstMissesUnclampedKey 证明「clamp 那一遍不能当唯一一遍」。
//
// 生成一把**不 clamp** 的私钥（BoringSSL 风格的存法），塞进缓冲区：
//   - 带 RequireClamp 的预筛扫不到它（所以必须有第二遍）；
//   - 完整预筛扫得到（所以两遍合起来零漏检）。
//
// 这两条同时成立，才说明「clamp 优先」是优先级而不是过滤器 ——
// 上一轮就是因为把形态当过滤器用，把真私钥漏掉了。
func TestClampFirstMissesUnclampedKey(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	priv := key.Bytes()

	// 强行抹掉 clamp 形态：首字节低 3 位和末字节高 2 位都改成非标准值。
	unclamped := append([]byte(nil), priv...)
	unclamped[0] |= 1
	unclamped[31] = (unclamped[31] &^ 0xC0) | 0x80

	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(i*91 + 7)
	}
	const off = 777
	copy(buf[off:], unclamped)

	pf := DefaultPrivFilter
	pf.RequireClamp = true
	var hitClamp bool
	filterScan(buf, pf, func(o int) bool {
		if o == off {
			hitClamp = true
			return true
		}
		return false
	})
	if hitClamp {
		t.Fatal("构造的私钥本来就不带 clamp 形态，快扫不该命中 —— 测试自身有问题")
	}

	var hitFull bool
	filterScan(buf, DefaultPrivFilter, func(o int) bool {
		if o == off {
			hitFull = true
			return true
		}
		return false
	})
	if !hitFull {
		t.Fatal("完整预筛必须能扫到非 clamp 形态的私钥，否则两遍扫会漏检")
	}
}
