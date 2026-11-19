package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
)

// TestSnapshotThenVerify 验证"冻结期间抓取 → 解冻后校验"这条新链路。
//
// 为什么必须有这条测试：第七轮把 X25519 校验从冻结窗口里搬了出来，改成
// "冻结只读、解冻才算"。这个改动一旦有地址算错或缓冲复用的问题，
// 表现是"扫了但永远找不到"，而且报告里看不出异常 —— 必须有端到端用例盯着。
func TestSnapshotThenVerify(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	const size = 512 << 10
	buf := make([]byte, size)
	fillRealistic(buf) // 真实堆内存的形态：零填充 + 指针表
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := key.PublicKey().Bytes()
	priv := append([]byte(nil), key.Bytes()...)

	const off = 77777 // 未对齐（77777 % 8 == 1）
	copy(buf[off:], priv)

	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	base := hdr.Data
	ranges := []scanRange{{lo: base, hi: base + uintptr(size), tag: "snap-test"}}

	// ① 抓取（真实使用中这一步在冻结窗口内）
	snap := takeSnapshot(proc, ranges, len(ranges), snapshotDefaultMax, time.Now().Add(10*time.Second))
	if snap == nil || snap.bytes != uint64(size) {
		t.Fatalf("快照字节数不对：%v（期望 %d）", snap, size)
	}
	if snap.truncated {
		t.Fatalf("不该被截断")
	}

	// ② 校验（真实使用中这一步在解冻之后）
	kf := keyfind.New(proc, pub, time.Now().Add(30*time.Second))
	var (
		found []byte
		at    uintptr
	)
	kf.OnFound = func(p []byte, tag string, a uintptr) {
		found = append([]byte(nil), p...)
		at = a
	}
	st := new(scanStat)
	if !snap.verify(kf, time.Now().Add(30*time.Second), st) {
		t.Fatalf("副本里没找到私钥（%s）", st.summary())
	}
	if want := base + off; at != want {
		t.Fatalf("命中地址 %#x，期望 %#x", at, want)
	}
	if string(found) != string(priv) {
		t.Fatalf("命中的字节不是埋进去的私钥")
	}
	runtime.KeepAlive(buf)
}

// TestSnapshotRespectsMax 验证上限真的生效并且如实标记截断。
//
// 上限存在的意义是防止"命中点很多 + 区域很大"时把内存吃爆；
// 一旦被截断，调用方会退回从第 1 级重新走，所以这个标志必须准确。
func TestSnapshotRespectsMax(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	buf := make([]byte, 4<<20)
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	base := hdr.Data
	ranges := []scanRange{{lo: base, hi: base + uintptr(len(buf)), tag: "cap-test"}}

	snap := takeSnapshot(proc, ranges, 0, 1<<20, time.Now().Add(10*time.Second))
	if snap.bytes > 1<<20 {
		t.Fatalf("超过上限：%d > %d", snap.bytes, 1<<20)
	}
	if !snap.truncated {
		t.Fatalf("被上限截断时必须标记 truncated")
	}
	runtime.KeepAlive(buf)
}

// TestSnapshotNilSafe 钉死空输入不 panic（没命中公钥时就是这个路径）。
func TestSnapshotNilSafe(t *testing.T) {
	if s := takeSnapshot(nil, nil, 0, 0, time.Time{}); s == nil || s.bytes != 0 {
		t.Fatalf("空输入应返回空快照")
	}
	var s *memSnapshot
	st := new(scanStat)
	if s.verify(nil, time.Time{}, st) {
		t.Fatalf("nil 快照不该命中")
	}
	if s.summary() != "未抓取" {
		t.Fatalf("nil 快照的摘要不对：%s", s.summary())
	}
}

// TestSnapshotSplitNearRest 验证"邻域优先、其余随后"的分段确实按 primary 切开。
//
// 为什么必须有这条：第八轮把校验拆成 verifyNear / verifyRest 两段，
// 如果 primary 记错了（比如一直记成 0），verifyNear 会退化成"校验全部"，
// 表现是"邻域校验耗时几十分钟"，而且日志上看不出错 —— 只是慢，慢到被关窗口。
func TestSnapshotSplitNearRest(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	mk := func(n int) []byte {
		b := make([]byte, n)
		fillRealistic(b)
		return b
	}
	near := mk(32 << 10)
	rest := mk(32 << 10)

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := key.PublicKey().Bytes()
	priv := append([]byte(nil), key.Bytes()...)

	// 私钥只埋在"其余"那段里，邻域里没有。
	const off = 4097
	copy(rest[off:], priv)

	nh := (*reflect.SliceHeader)(unsafe.Pointer(&near))
	rh := (*reflect.SliceHeader)(unsafe.Pointer(&rest))
	ranges := []scanRange{
		{lo: nh.Data, hi: nh.Data + uintptr(len(near)), tag: "split-near"},
		{lo: rh.Data, hi: rh.Data + uintptr(len(rest)), tag: "split-rest"},
	}
	snap := takeSnapshot(proc, ranges, 1, snapshotDefaultMax, time.Now().Add(10*time.Second))
	if snap.bytes != uint64(len(near)+len(rest)) {
		t.Fatalf("快照字节数 %d，期望 %d", snap.bytes, len(near)+len(rest))
	}
	if snap.primary != 1 {
		t.Fatalf("primary=%d，期望 1（只有第 1 段属于邻域）", snap.primary)
	}
	if got, want := snap.primaryBytes(), uint64(len(near)); got != want {
		t.Fatalf("primaryBytes=%d，期望 %d", got, want)
	}

	kf := keyfind.New(proc, pub, time.Now().Add(30*time.Second))
	var at uintptr
	kf.OnFound = func(p []byte, _ string, a uintptr) { at = a }

	// 邻域段必须找不到（埋点不在里面）
	if snap.verifyNear(kf, time.Now().Add(30*time.Second), new(scanStat)) {
		t.Fatalf("邻域段不该命中")
	}
	// 其余段必须找到，且地址精确
	if !snap.verifyRest(kf, time.Now().Add(30*time.Second), new(scanStat)) {
		t.Fatalf("其余段没找到私钥")
	}
	if want := rh.Data + off; at != want {
		t.Fatalf("命中地址 %#x，期望 %#x", at, want)
	}
	runtime.KeepAlive(near)
	runtime.KeepAlive(rest)
}

// TestSnapshotParallelKeepsOrderAndSplit 钉死并行抓取之后的两条不变量：
//
//	takeSnapshot 原来是顺序读，副本天然是地址升序，`primary` 就是"邻域段的条数"。
//	改成多线程之后顺序变成随机的 —— 而下游 verifyNear/verifyRest/coveredRanges
//	全都假定「chunks[0:primary] 是邻域、且各自按地址升序」。
//	一旦这条不变量破了，表现是"扫了但找不到"，而且日志上完全看不出来。
func TestSnapshotParallelKeepsOrderAndSplit(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	const mb = 1 << 20
	nearBuf := make([]byte, 3*mb)
	restBuf := make([]byte, 4*mb)
	for i := range nearBuf {
		nearBuf[i] = byte(i)
	}
	for i := range restBuf {
		restBuf[i] = byte(i * 7)
	}
	nearBase := (*reflect.SliceHeader)(unsafe.Pointer(&nearBuf)).Data
	restBase := (*reflect.SliceHeader)(unsafe.Pointer(&restBuf)).Data

	ranges := []scanRange{
		{lo: nearBase, hi: nearBase + uintptr(len(nearBuf)), tag: "near"},
		{lo: restBase, hi: restBase + uintptr(len(restBuf)), tag: "rest"},
	}
	s := takeSnapshot(proc, ranges, 1, 64*mb, time.Time{})
	runtime.KeepAlive(nearBuf)
	runtime.KeepAlive(restBuf)

	if s.bytes != uint64(3*mb+4*mb) {
		t.Fatalf("抓取字节不对：got %d，want %d", s.bytes, 3*mb+4*mb)
	}
	if s.primary <= 0 || s.primary >= len(s.chunks) {
		t.Fatalf("primary 越界：%d / %d 段", s.primary, len(s.chunks))
	}
	// 邻域段必须全部落在 nearBuf 里，其余必须全部落在 restBuf 里。
	for i, c := range s.chunks {
		inNear := c.addr >= nearBase && c.addr < nearBase+uintptr(len(nearBuf))
		inRest := c.addr >= restBase && c.addr < restBase+uintptr(len(restBuf))
		if i < s.primary && !inNear {
			t.Fatalf("第 %d 段被判成邻域，但地址 %#x 不在邻域区间", i, c.addr)
		}
		if i >= s.primary && !inRest {
			t.Fatalf("第 %d 段被判成其余，但地址 %#x 不在其余区间", i, c.addr)
		}
	}
	// 两个区间内部都必须按地址升序。
	for _, seg := range [][]snapChunk{s.chunks[:s.primary], s.chunks[s.primary:]} {
		for i := 1; i < len(seg); i++ {
			if seg[i-1].addr >= seg[i].addr {
				t.Fatalf("副本没有按地址升序：%#x 后面跟了 %#x", seg[i-1].addr, seg[i].addr)
			}
		}
	}
	if s.truncated {
		t.Fatalf("预算 64 MB 远大于 7 MB，不该截断")
	}
}

// BenchmarkTakeSnapshot 量出"冻结期间抄内存"的实际吞吐。
//
// 为什么要有这个基准：冻结时长 = 反作弊风险。抄 512 MB 要多久，
// 直接决定 NtSuspendProcess 挂多久。改造前是单线程顺序读，实测 540 ms；
// 改造后应该贴着 ReadProcessMemory 的并行上限走。
//
// 用法：go test ./cmd/collector/ -run XXX -bench BenchmarkTakeSnapshot -benchtime 3x
func BenchmarkTakeSnapshot(b *testing.B) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		b.Skipf("打不开自身进程: %v", err)
	}
	defer proc.Close()

	const size = 128 << 20
	buf := make([]byte, size)
	for i := 0; i < size; i += 4096 {
		buf[i] = byte(i)
	}
	base := (*reflect.SliceHeader)(unsafe.Pointer(&buf)).Data
	// 切成 128 个 1 MB 的段，模拟真实区域列表（小区域多、不连续）。
	var ranges []scanRange
	for off := 0; off < size; off += 1 << 20 {
		ranges = append(ranges, scanRange{lo: base + uintptr(off), hi: base + uintptr(off+(1<<20)), tag: "bench"})
	}

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := takeSnapshot(proc, ranges, len(ranges), size, time.Time{})
		if s.bytes != uint64(size) {
			b.Fatalf("抓取字节不对: %d", s.bytes)
		}
	}
	runtime.KeepAlive(buf)
}

// BenchmarkTakeSnapshotRealRegions 用**真实区域列表**跑快照，量的才是现场那个数。
//
// 为什么要有它：BenchmarkTakeSnapshot 用的是 128 段连续 1 MB 的热缓冲，
// 测出 6.69 GB/s；而 freezeE.log 现场是「1024 MB / 474 ms」≈ 2.2 GB/s。
// 差 3 倍的来源是现场的区域形态 —— 约 8000 个区域、大量 100~256 KB 的小块，
// 每个小块都要一次 ReadProcessMemory，调用开销和缺页都摊不薄。
// 这个基准直接读本进程的可写区（形态和 cs2.exe 同类），
// 用来看「冻结窗口能不能再压」这件事的天花板在哪。
func BenchmarkTakeSnapshotRealRegions(b *testing.B) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		b.Skipf("打不开自身进程: %v", err)
	}
	defer proc.Close()

	regions, err := proc.RegionsWithError(time.Now().Add(10*time.Second), 0)
	if err != nil {
		b.Skipf("枚举区域失败: %v", err)
	}
	ranges := writableRanges(regions)
	if len(ranges) == 0 {
		b.Skipf("没有可写区")
	}
	all := totalRangeBytes(ranges)
	b.Logf("本进程：区域 %d 个｜可写区合并成 %d 段｜共 %.1f MB",
		len(regions), len(ranges), float64(all)/(1<<20))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t0 := time.Now()
		s := takeSnapshot(proc, ranges, 0, snapshotCapBytes, time.Time{})
		el := time.Since(t0)
		if i == 0 {
			b.Logf("抓取 %.1f MB｜段 %d｜短读 %d｜耗时 %s｜%.2f GB/s",
				float64(s.bytes)/(1<<20), s.regions, s.shortRead,
				el.Truncate(time.Millisecond),
				float64(s.bytes)/float64(1<<30)/el.Seconds())
		}
	}
}
