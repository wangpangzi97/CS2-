package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
)

// testKeyPair 把私钥和公钥放在**同一个结构体**里，模拟真实进程里的布局
// （两个值通常是相邻字段）。放在包级变量上，保证它活在堆里、不会被优化掉。
type testKeyPair struct {
	Priv [32]byte
	Pub  [32]byte
}

var testKP testKeyPair

// TestScanPubThenFindPrivNear 验证「先定位公钥、再在附近找私钥」这条新路径。
//
// 为什么要有这个测试：本轮把盲扫私钥换成了"公钥定位 + 邻域搜索"。盲扫的问题
// 是候选量随内存大小线性爆炸（用户机器 7 GB / 8 字节 ≈ 9 亿候选，预算 400 万
// 只够覆盖 0.6%），而新路径的假设是"私钥就在公钥附近"。**这个假设必须被验证**，
// 否则又是一轮靠猜。
//
// 做法：用本进程当目标，往堆上放一对真实生成的 X25519 密钥，然后完整跑一遍
// scanPub（真实 ReadProcessMemory）→ findPrivNear（真实 X25519 比对）。
func TestScanPubThenFindPrivNear(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	copy(testKP.Priv[:], k.Bytes())
	copy(testKP.Pub[:], k.PublicKey().Bytes())

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	regions, err := proc.RegionsWithError(time.Now().Add(20*time.Second), 0)
	if err != nil && err != memscan.ErrRegionDeadline && err != memscan.ErrRegionLimit {
		t.Fatalf("枚举区域: %v", err)
	}
	if len(regions) == 0 {
		t.Fatal("没枚举到可读区域")
	}

	ordered := sortRegionsForScan(regions)
	t0 := time.Now()
	hits, scanned := scanPub(proc, ordered, testKP.Pub[:], 16, time.Now().Add(90*time.Second))
	el := time.Since(t0)
	mbps := 0.0
	if el > 0 {
		mbps = float64(scanned) / (1 << 20) / el.Seconds()
	}
	t.Logf("区域 %d 个｜扫了 %.1f MB｜耗时 %s｜吞吐 %.0f MB/s｜公钥命中 %d 处",
		len(regions), float64(scanned)/(1<<20), el.Truncate(time.Millisecond), mbps, len(hits))
	if len(hits) == 0 {
		t.Fatal("没在自身内存里找到刚写进去的公钥 —— scanPub 有问题")
	}

	// 命中点必须带着上下文（报告靠它判断私钥是否与公钥相邻）。
	for _, h := range hits {
		if len(h.Dump) == 0 {
			t.Fatalf("公钥命中点 %#x 没采集到上下文 dump", h.Addr)
		}
		if h.DumpAt < 0 || h.DumpAt+32 > len(h.Dump) {
			t.Fatalf("dump 偏移越界: DumpAt=%d len=%d", h.DumpAt, len(h.Dump))
		}
		if string(h.Dump[h.DumpAt:h.DumpAt+32]) != string(testKP.Pub[:]) {
			t.Fatalf("dump 里 DumpAt 位置不是公钥: %x", h.Dump[h.DumpAt:h.DumpAt+32])
		}
	}

	kf := keyfind.New(proc, testKP.Pub[:], time.Now().Add(2*time.Minute))
	var (
		got     []byte
		gotAddr uintptr
	)
	kf.OnFound = func(p []byte, _ string, addr uintptr) {
		got, gotAddr = append([]byte(nil), p...), addr
	}
	// 64 KB 窗口不开 clamp 过滤 —— 和 searchKey 里第一级一致。
	st := new(scanStat)
	if !scanRangesStat(kf, proc, nearRanges(hits, 64<<10, "near-pub"),
		time.Now().Add(time.Minute), st) {
		t.Fatal("公钥命中了，但附近 64 KB 内没找到对应私钥")
	}
	t.Logf("邻域扫描统计: %s", st.summary())
	if string(got) != string(testKP.Priv[:]) {
		t.Fatalf("私钥不匹配:\n got=%x\nwant=%x", got, testKP.Priv[:])
	}

	// 报一下命中点与公钥的距离，确认"相邻字段"这个假设确实成立。
	var nearest uintptr
	for _, h := range hits {
		d := gotAddr - h.Addr
		if gotAddr < h.Addr {
			d = h.Addr - gotAddr
		}
		if nearest == 0 || d < nearest {
			nearest = d
		}
	}
	t.Logf("命中私钥 @%#x，最近的公钥命中点距它 %d 字节", gotAddr, nearest)
}

// TestFormatPubDump 确认命中点上下文能正确排版，且 ▶ 标记盖住公钥。
func TestFormatPubDump(t *testing.T) {
	dump := make([]byte, 128)
	for i := range dump {
		dump[i] = byte(i)
	}
	// 公钥放在偏移 64 处（scanPub 里 dlo=pos-64，所以 DumpAt=64 就是标准位置）。
	pub := make([]byte, 32)
	copy(dump[64:], pub)

	h := pubHit{
		Addr:   0x1000,
		Region: memscan.Region{Base: 0x1000, Size: 4096, Type: 0x20000},
		Dump:   dump,
		DumpAt: 64,
	}
	out := formatPubDump(h)
	if out == "" {
		t.Fatal("formatPubDump 返回空")
	}
	for _, want := range []string{"0x1000", "PRIVATE", "▶", "-64", "+0", "+48"} {
		if !strings.Contains(out, want) {
			t.Errorf("输出里缺少 %q:\n%s", want, out)
		}
	}
	// 只有覆盖公钥的那两行（+0、+16）带标记，其余行不带。
	marked := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "▶") {
			marked++
		}
	}
	if marked != 2 {
		t.Errorf("应只有 2 行被标记（公钥 32 字节 = 2 行），实际 %d:\n%s", marked, out)
	}
}

// TestFormatPubDumpEmpty 确认没采集到上下文时不会 panic。
func TestFormatPubDumpEmpty(t *testing.T) {
	out := formatPubDump(pubHit{Addr: 0x10, Region: memscan.Region{Type: 0x40000}})
	if !strings.Contains(out, "未采集到上下文") {
		t.Errorf("空 dump 应给出提示，实际:\n%s", out)
	}
}

// TestHumanSize 确认区域大小的可读化（报告里到处在用）。
func TestHumanSize(t *testing.T) {
	cases := []struct {
		in   uintptr
		want string
	}{
		{512, "512 B"},
		{4096, "4 KB"},
		{2 << 20, "2.0 MB"},
		{3 << 30, "3.0 GB"},
	}
	for _, c := range cases {
		if got := humanSize(c.in); got != c.want {
			t.Errorf("humanSize(%d)=%q, want %q", c.in, got, c.want)
		}
	}
}

// TestSortRegionsForScan 确认排序把 MEM_PRIVATE 排在 MEM_IMAGE 前面、
// 同类里大的在前 —— 这是"预算花在正确的地方"的前提。
func TestSortRegionsForScan(t *testing.T) {
	in := []memscan.Region{
		{Base: 0x1000, Size: 100, Type: 0x1000000}, // MEM_IMAGE
		{Base: 0x2000, Size: 50, Type: 0x20000},    // MEM_PRIVATE，小
		{Base: 0x3000, Size: 900, Type: 0x20000},   // MEM_PRIVATE，大
		{Base: 0x4000, Size: 700, Type: 0x40000},   // MEM_MAPPED
	}
	got := sortRegionsForScan(in)
	if got[0].Size != 900 || got[1].Size != 50 {
		t.Fatalf("PRIVATE 未排在最前或未按大小降序: %+v", got[:2])
	}
	if got[2].Type != 0x40000 {
		t.Fatalf("MAPPED 应排在 PRIVATE 之后: %+v", got[2])
	}
	if got[3].Type != 0x1000000 {
		t.Fatalf("IMAGE 应排最后: %+v", got[3])
	}
	// 不能改动入参（调用方还在用它算总量）
	if in[0].Type != 0x1000000 {
		t.Fatal("sortRegionsForScan 不应修改入参切片")
	}
}

// TestScanRangesFindsPlantedKey 端到端验证并行扫描器本身。
//
// 覆盖的是"兜底二"那条路径：给定一段区间，块读 + 8 字节步长 + 多核并行，
// 能不能把埋在中间的真实私钥挖出来。**不按 clamp 形态过滤**是这里的关键 ——
// 植入的私钥多半不是 clamp 形态（31/32 概率），加了过滤这条测试就会挂。
func TestScanRangesFindsPlantedKey(t *testing.T) {
	const size = 256 << 10
	buf := make([]byte, size)
	for i := range buf { // 填充成非零，避免整段全零候选
		buf[i] = byte(i*7 + 13)
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const at = 0x1E000 // 8 字节对齐
	copy(buf[at:], k.Bytes())
	// 公钥紧跟其后（真实实现最常见的布局），顺带让命中点落在同一段里。
	copy(buf[at+32:], k.PublicKey().Bytes())

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	kf := keyfind.New(proc, k.PublicKey().Bytes(), time.Now().Add(time.Minute))
	var gotAddr uintptr
	kf.OnFound = func(_ []byte, tag string, addr uintptr) {
		gotAddr, _ = addr, tag
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	st := new(scanStat)
	found := scanRangesStat(kf, proc,
		[]scanRange{{lo: base, hi: base + size, tag: "test"}},
		time.Now().Add(time.Minute), st)
	runtime.KeepAlive(buf)
	t.Logf("扫描统计: %s", st.summary())

	if !found {
		t.Fatalf("256 KB 区间里埋了真实私钥却没找到（%s）", st.summary())
	}
	if want := base + at; gotAddr != want {
		t.Fatalf("命中的地址不对: got=%#x want=%#x", gotAddr, want)
	}
}

// TestMergeRanges 确认重叠区间被合并 —— 否则 6 个命中点会把同一段内存扫 6 遍。
func TestMergeRanges(t *testing.T) {
	in := []scanRange{
		{lo: 100, hi: 200},
		{lo: 150, hi: 260}, // 与上一条重叠
		{lo: 260, hi: 300}, // 与上一条相邻
		{lo: 500, hi: 600}, // 独立
		{lo: 520, hi: 550}, // 被完全包含
	}
	got := mergeRanges(in)
	want := []scanRange{{lo: 100, hi: 300}, {lo: 500, hi: 600}}
	if len(got) != len(want) {
		t.Fatalf("合并后应有 %d 段，实际 %d: %+v", len(want), len(got), got)
	}
	for i := range want {
		if got[i].lo != want[i].lo || got[i].hi != want[i].hi {
			t.Fatalf("第 %d 段不符: got=%+v want=%+v", i, got[i], want[i])
		}
	}
	// 入参不能被改乱（调用方可能复用）。
	if in[0].hi != 200 {
		t.Fatalf("mergeRanges 不应修改入参: %+v", in[0])
	}
}

// TestNearAndRegionRanges 确认两种区间构造都按区域边界裁剪。
func TestNearAndRegionRanges(t *testing.T) {
	reg := memscan.Region{Base: 0x10000, Size: 0x1000, Type: 0x20000}
	hits := []pubHit{
		{Addr: 0x10100, Region: reg}, // 靠近区域头
		{Addr: 0x10F00, Region: reg}, // 靠近区域尾
		{Addr: 0x10180, Region: reg}, // 与前一个很近，窗口重叠
	}
	near := nearRanges(hits, 0x800, "near-pub")
	for _, r := range near {
		if r.lo < reg.Base || r.hi > reg.Base+reg.Size {
			t.Fatalf("区间越出区域边界: %+v", r)
		}
	}
	// 三个命中点 + 0x800 窗口在 4 KB 区域里应当被合并成 1 段（整区）。
	if len(near) != 1 {
		t.Fatalf("重叠窗口应合并成 1 段，实际 %d 段: %+v", len(near), near)
	}

	full := fullRegionRanges(hits, "full-region")
	if len(full) != 1 || full[0].lo != reg.Base || full[0].hi != reg.Base+reg.Size {
		t.Fatalf("同一区域的多个命中点应只产生 1 段整区: %+v", full)
	}
}

// TestWritableRanges 确认只保留可写页（跳过只读映像，省掉无意义的校验）。
func TestWritableRanges(t *testing.T) {
	in := []memscan.Region{
		{Base: 0x1000, Size: 0x1000, Protect: 0x04, Type: 0x20000},  // READWRITE
		{Base: 0x3000, Size: 0x1000, Protect: 0x02, Type: 0x20000},  // READONLY
		{Base: 0x5000, Size: 0x1000, Protect: 0x40, Type: 0x20000},  // EXECUTE_READWRITE
		{Base: 0x7000, Size: 0x10, Protect: 0x04, Type: 0x20000},    // 太小，跳过
		{Base: 0x9000, Size: 0x1000, Protect: 0x104, Type: 0x20000}, // READWRITE|GUARD，跳过
	}
	got := writableRanges(in)
	if len(got) != 2 {
		t.Fatalf("应只保留 2 段可写区域，实际 %d: %+v", len(got), got)
	}
	if got[0].lo != 0x1000 || got[1].lo != 0x5000 {
		t.Fatalf("保留的区域不对: %+v", got)
	}
}

// TestSplitRanges 确认区间被切成"够多"的小块 —— 否则只有少数 worker 在干活。
//
// 2026-10-19 03:27 现场：`邻域搜索：读 0.3 MB｜校验 323522 次｜耗时 8.985s`。
// 0.3 MB 走逐字节全量校验本来就要 32 万次 X25519（≈12 秒串行），
// 但按固定 1 MB 切只切出 1~2 段，16 个核里只有 1~2 个在跑，于是真跑了 9 秒。
// 现在改成「按总量/核数算段长，夹在 [32 KB, 1 MB]」。
//
// 这条用例钉死三条不变量，不再钉具体块数（块数随核数变，钉死会让测试绑死在机器上）：
//  1. 每块不超过 scanChunk；
//  2. 总字节守恒、tag 保留（命中时靠 tag 区分是哪一级找到的）；
//  3. **小总量也要切出足够多的块**，能喂满多核。
func TestSplitRanges(t *testing.T) {
	check := func(name string, in []scanRange) []scanRange {
		t.Helper()
		got := splitRanges(in)
		var total uintptr
		for _, r := range got {
			if r.hi-r.lo > scanChunk {
				t.Fatalf("%s: 切出来的块超过 scanChunk: %+v", name, r)
			}
			if r.hi-r.lo < 32 {
				t.Fatalf("%s: 切出了小于 32 字节的块: %+v", name, r)
			}
			if r.tag == "" {
				t.Fatalf("%s: 切分后丢了 tag: %+v", name, r)
			}
			total += r.hi - r.lo
		}
		if total != totalRangeBytes(in) {
			t.Fatalf("%s: 切分后总字节数变了: got=%d want=%d", name, total, totalRangeBytes(in))
		}
		return got
	}

	// ① 大总量：段长应该顶到 scanChunk（行为与改造前一致）。
	//    注意要真的"大"：段长 = clamp(总量/核数, 32KB, 1MB)，
	//    3 MB / 16 核 = 196 KB，那种量级本来就该细分。
	const bigSize = 64 << 20
	big := []scanRange{{lo: 0, hi: bigSize, tag: "a"}}
	gotBig := check("big", big)
	if len(gotBig) != bigSize/scanChunk {
		t.Fatalf("64 MB 应仍按 1 MB 切成 %d 块，实际 %d 块（首块 %d 字节）",
			bigSize/scanChunk, len(gotBig), gotBig[0].hi-gotBig[0].lo)
	}

	// ② 小总量：必须切出足够多的块，否则多核闲置。
	const small = 300 << 10
	smallIn := []scanRange{{lo: 0x20000000, hi: 0x20000000 + small, tag: "near"}}
	gotSmall := check("small", smallIn)
	w := numWorkers()
	if w > 16 {
		w = 16
	}
	if w < 2 {
		t.Skip("单核机器，跳过并行度断言")
	}
	if len(gotSmall) < 4 {
		t.Fatalf("0.3 MB 只切成 %d 块，多核用不上（%d 个 worker）: %+v", len(gotSmall), w, gotSmall)
	}

	// ③ 极小/零长度区间不能切出垃圾块（31 字节的窗口连一个私钥都放不下，直接丢）。
	if got := splitRanges([]scanRange{{lo: 1000, hi: 1031, tag: "b"}}); len(got) != 0 {
		t.Fatalf("31 字节的区间应被丢弃，实际 %+v", got)
	}
}

// BenchmarkScanRanges 量出并行扫描的等效吞吐（校验次数/秒）。
//
// 用途：把"全内存兜底"的时间预算算成实数，而不是拍脑袋。已知单次 X25519
// 校验约 38.8 µs，若并行后能到 ~5 µs 等效，7 GB 全量（约 9.2 亿候选）需要
// 一小时以上，这就是为什么兜底必须限时、并把"扫了多少/是否截断"写进报告。
func BenchmarkScanRanges(b *testing.B) {
	const size = 8 << 20
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(i*11 + 5)
	}
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		b.Skipf("打不开自身进程: %v", err)
	}
	defer proc.Close()
	base := uintptr(unsafe.Pointer(&buf[0]))
	// 目标公钥设成一段随便的字节，保证一个候选都命中不了、跑满整段。
	target := make([]byte, 32)
	for i := range target {
		target[i] = byte(0xA0 + i)
	}
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kf := keyfind.New(proc, target, time.Now().Add(5*time.Minute))
		st := new(scanStat)
		scanRangesStat(kf, proc, []scanRange{{lo: base, hi: base + size, tag: "bench"}},
			time.Now().Add(5*time.Minute), st)
		if i == 0 {
			b.Logf("校验 %d 次，耗时 %s", st.cand.Load(), st.elapsed.Truncate(time.Millisecond))
		}
	}
	runtime.KeepAlive(buf)
}

// plantKeyPair 在一块独立缓冲里埋一对真实密钥，返回缓冲区与命中点。
// 调用方负责 runtime.KeepAlive(buf)。
func plantKeyPair(t *testing.T, size int, privOff, pubOff int) ([]byte, []pubHit, []byte) {
	t.Helper()
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(i*13 + 7)
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(buf[privOff:], k.Bytes())
	copy(buf[pubOff:], k.PublicKey().Bytes())
	base := uintptr(unsafe.Pointer(&buf[0]))
	reg := memscan.Region{Base: base, Size: uintptr(size), Protect: 0x04, Type: 0x20000}
	hits := []pubHit{{Addr: base + uintptr(pubOff), Region: reg}}
	return buf, hits, k.PublicKey().Bytes()
}

// TestRunKeySearchAdjacent 验证最常见的布局：私钥紧跟公钥（实测距离 32 字节）。
// 这一级必须命中，因为它是真实客户端最可能的情形，也是唯一"秒级完成"的路径。
func TestRunKeySearchAdjacent(t *testing.T) {
	const size = 64 << 10
	buf, hits, pub := plantKeyPair(t, size, 0x4000, 0x4000+32)

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	kf := keyfind.New(proc, pub, time.Now().Add(2*time.Minute))
	var got []byte
	kf.OnFound = func(p []byte, _ string, _ uintptr) { got = append([]byte(nil), p...) }

	var phases []string
	ok, rep := runKeySearch(kf, proc, []memscan.Region{hits[0].Region}, hits,
		func(p string) { phases = append(phases, p) }, 30*time.Second, 0, nil, nil)
	runtime.KeepAlive(buf)

	if !ok {
		t.Fatalf("相邻布局没找到私钥（邻域=%s 兜底=%s）", rep.Near, rep.Full)
	}
	if string(got) != string(buf[0x4000:0x4000+32]) {
		t.Fatalf("搜到的私钥不对: %x", got)
	}
	// 相邻布局必须只走第一级就结束 —— 否则"秒级完成"这个前提不成立。
	// 第一级是哪个窗口由 nearStages[0] 决定（第九轮按原版补了 ±8 KB），
	// 这里不写死，免得以后调阶梯又假失败。
	if len(phases) != 1 || !strings.Contains(phases[0], nearStages[0].desc) {
		t.Fatalf("相邻布局应在第一级（%s）就命中，实际阶段: %v", nearStages[0].desc, phases)
	}
	if rep.Full != "" {
		t.Fatalf("第一级命中后不应再跑兜底，实际兜底=%q", rep.Full)
	}
	t.Logf("相邻布局：阶段=%v 邻域=%s", phases, rep.Near)
}

// TestRunKeySearchFarInSameRegion 验证"私钥在同一块内存但离公钥 200 KB"。
// 64 KB 那一级必然搜不到，必须靠放大到 1 MB 才命中 —— 这条测试钉住的是
// **分级放大真的会继续往下走**，而不是第一级失败就放弃。
func TestRunKeySearchFarInSameRegion(t *testing.T) {
	const size = 2 << 20
	privOff, pubOff := 0x10000, 0x10000+200*1024
	buf, hits, pub := plantKeyPair(t, size, privOff, pubOff)

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	kf := keyfind.New(proc, pub, time.Now().Add(2*time.Minute))
	var gotAddr uintptr
	kf.OnFound = func(_ []byte, tag string, addr uintptr) { gotAddr, _ = addr, tag }

	var phases []string
	ok, rep := runKeySearch(kf, proc, []memscan.Region{hits[0].Region}, hits,
		func(p string) { phases = append(phases, p) }, 60*time.Second, 0, nil, nil)
	runtime.KeepAlive(buf)

	if !ok {
		t.Fatalf("同区 200 KB 距离没找到私钥（阶段=%v 邻域=%s 兜底=%s）", phases, rep.Near, rep.Full)
	}
	if want := hits[0].Region.Base + uintptr(privOff); gotAddr != want {
		t.Fatalf("命中地址不对: got=%#x want=%#x", gotAddr, want)
	}
	if len(phases) < 2 {
		t.Fatalf("200 KB 距离应跨过第一级，实际阶段: %v", phases)
	}
	t.Logf("同区 200 KB：阶段=%v 邻域=%s", phases, rep.Near)
}

// TestRunKeySearchNotFound 确认搜不到时会正常返回 false，且不超预算。
func TestRunKeySearchNotFound(t *testing.T) {
	const size = 64 << 10
	buf, hits, _ := plantKeyPair(t, size, 0x4000, 0x4000+32)
	// 换一个完全不相干的公钥去搜 —— 必然搜不到。
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	kf := keyfind.New(proc, other.PublicKey().Bytes(), time.Now().Add(2*time.Minute))
	begin := time.Now()
	ok, rep := runKeySearch(kf, proc, []memscan.Region{hits[0].Region}, hits, nil, 3*time.Second, 0, nil, nil)
	el := time.Since(begin)
	runtime.KeepAlive(buf)

	if ok {
		t.Fatal("用不相干的公钥不应搜到私钥")
	}
	if el > 20*time.Second {
		t.Fatalf("预算 3 秒却跑了 %s —— 预算没生效", el)
	}
	if rep.Near == "" {
		t.Fatal("报告里必须有邻域搜索的覆盖统计")
	}
	t.Logf("未命中：耗时 %s 邻域=%s", el.Truncate(time.Millisecond), rep.Near)
}

// TestSubtractRanges 确认兜底阶段不会重复扫已扫过的区间（预算很贵）。
func TestSubtractRanges(t *testing.T) {
	all := []scanRange{{lo: 0, hi: 1000}}
	done := []scanRange{{lo: 200, hi: 300}, {lo: 600, hi: 700}}
	got := subtractRanges(all, done)
	want := []scanRange{{lo: 0, hi: 200}, {lo: 300, hi: 600}, {lo: 700, hi: 1000}}
	if len(got) != len(want) {
		t.Fatalf("应剩 %d 段，实际 %d: %+v", len(want), len(got), got)
	}
	for i := range want {
		if got[i].lo != want[i].lo || got[i].hi != want[i].hi {
			t.Fatalf("第 %d 段不符: got=%+v want=%+v", i, got[i], want[i])
		}
	}

	// 完全被覆盖 → 什么都不剩。
	if r := subtractRanges([]scanRange{{lo: 100, hi: 200}}, []scanRange{{lo: 0, hi: 1000}}); len(r) != 0 {
		t.Fatalf("完全覆盖时应返回空，实际 %+v", r)
	}
	// 头部被覆盖。
	got = subtractRanges([]scanRange{{lo: 100, hi: 200}}, []scanRange{{lo: 0, hi: 150}})
	if len(got) != 1 || got[0].lo != 150 || got[0].hi != 200 {
		t.Fatalf("头部覆盖后应剩 [150,200]，实际 %+v", got)
	}
	// 尾部被覆盖。
	got = subtractRanges([]scanRange{{lo: 100, hi: 200}}, []scanRange{{lo: 150, hi: 300}})
	if len(got) != 1 || got[0].lo != 100 || got[0].hi != 150 {
		t.Fatalf("尾部覆盖后应剩 [100,150]，实际 %+v", got)
	}
	// 无重叠 → 原样返回。
	got = subtractRanges([]scanRange{{lo: 100, hi: 200}}, []scanRange{{lo: 500, hi: 600}})
	if len(got) != 1 || got[0].lo != 100 || got[0].hi != 200 {
		t.Fatalf("无重叠应原样返回，实际 %+v", got)
	}
}

// TestRunKeySearchStartStage 确认可以从第 2 级开始（冻结窗口已做过第 1 级）。
//
// 为什么重要：searchKey 在冻结窗口内做掉 ±64 KB 那一级，解冻后再调
// runKeySearch 从第 2 级继续。如果 startStage 没生效，就会把同一段内存
// 再扫一遍 —— 在 3 分钟预算下这是实打实的浪费。
func TestRunKeySearchStartStage(t *testing.T) {
	const size = 2 << 20
	privOff, pubOff := 0x10000, 0x10000+200*1024
	buf, hits, pub := plantKeyPair(t, size, privOff, pubOff)

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	kf := keyfind.New(proc, pub, time.Now().Add(2*time.Minute))
	var phases []string
	// 从 ±1 MB 那一级开始（跳过 8 KB / 64 KB）。下标按 nearStages 算，
	// 不写死数字 —— 第九轮补了 ±8 KB 之后 1 已经不再是"1 MB"了。
	startStage := 0
	for i, s := range nearStages {
		if s.desc == "1 MB" {
			startStage = i
		}
	}
	ok, rep := runKeySearch(kf, proc, []memscan.Region{hits[0].Region}, hits,
		func(p string) { phases = append(phases, p) }, 60*time.Second, startStage, nil, nil)
	runtime.KeepAlive(buf)

	if !ok {
		t.Fatalf("从第 %d 级开始也应能找到（阶段=%v 邻域=%s）", startStage, phases, rep.Near)
	}
	for _, p := range phases {
		if strings.Contains(p, "8 KB") || strings.Contains(p, "64 KB") {
			t.Fatalf("startStage=%d 不该再跑 8 KB / 64 KB 那一级，实际阶段: %v", startStage, phases)
		}
	}
	if len(phases) == 0 {
		t.Fatal("应至少跑过一级")
	}
	t.Logf("从第 %d 级开始：阶段=%v 邻域=%s", startStage, phases, rep.Near)
}
