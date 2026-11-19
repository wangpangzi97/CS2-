package main

// ── 候选收集的「静默窗口」（2026-10-17 第十四轮）──
//
// 这一段逻辑看起来只是个超时，实际上决定了「私钥还活不活着」：
// 它在 freeze **之前**，每多等 1 ms，客户端就多 1 ms 去把私钥算成共享密钥
// 并清零。原来这里是固定 1500 ms（一个保守猜测），19:46 现场实测
// 握手 → 冻结之间整整 1.5 秒完全不受保护。
//
// 所以这些测试断言的不是"能不能收齐"，而是**收齐的代价有多小**。

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"local/cs2-radar/internal/memscan"
)

// TestCollectBatchDoesNotWaitFixedTimeout 钉死「不再白等 1.5 秒」。
//
// 这是本轮最重要的一条：只有一个候选时，必须在几十毫秒内返回，
// 而不是等满一个固定超时。用 200 ms 做上限 —— 比 1500 ms 宽松一个数量级，
// 又足以容纳调度抖动（CI 机器负载高时 12 ms 的 timer 可能拖到几十毫秒）。
func TestCollectBatchDoesNotWaitFixedTimeout(t *testing.T) {
	ch := make(chan []byte, 16)
	stop := make(chan struct{})
	ch <- []byte("only-one")

	t0 := time.Now()
	got := collectBatch(ch, stop, 12*time.Millisecond)
	el := time.Since(t0)

	if len(got) != 1 {
		t.Fatalf("收到 %d 个候选，期望 1", len(got))
	}
	if el > 200*time.Millisecond {
		t.Fatalf("单候选花了 %s，说明还在等固定超时（上限 200 ms）", el)
	}
	t.Logf("单候选 %s 返回（旧的固定超时是 1500 ms）", el.Round(time.Millisecond))
}

// TestCollectBatchGetsAllBackToBack 钉死「同一个回调连续投的候选一个都不漏」。
//
// 真实投递形态：收包回调里先投主公钥，紧接着 for 循环投包里其它 32 字节字段，
// 全部在几微秒内完成（通道有 16 个缓冲，投递方不阻塞）。
func TestCollectBatchGetsAllBackToBack(t *testing.T) {
	ch := make(chan []byte, 16)
	stop := make(chan struct{})
	for i := 0; i < 5; i++ {
		ch <- []byte(fmt.Sprintf("cand-%d", i))
	}

	got := collectBatch(ch, stop, 12*time.Millisecond)
	if len(got) != 5 {
		t.Fatalf("收到 %d 个候选，期望 5（连续投递不能漏）", len(got))
	}
}

// TestCollectBatchResetsOnNewItem 钉死「每来一个新的就重置静默计时」。
//
// 如果实现写成了"固定等 quietGap 就收工"，间隔投递的候选会被漏掉。
// 这里每 5 ms 投一个、静默窗口 40 ms，5 个都应该收到。
func TestCollectBatchResetsOnNewItem(t *testing.T) {
	ch := make(chan []byte, 16)
	stop := make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ {
			ch <- []byte(fmt.Sprintf("slow-%d", i))
			time.Sleep(5 * time.Millisecond)
		}
	}()

	got := collectBatch(ch, stop, 40*time.Millisecond)
	if len(got) != 5 {
		t.Fatalf("收到 %d 个候选，期望 5（静默计时必须在收到新候选时重置）", len(got))
	}
}

// TestCollectBatchStopReturnsNil 钉死「关窗口立刻退出」。
func TestCollectBatchStopReturnsNil(t *testing.T) {
	ch := make(chan []byte, 16)
	stop := make(chan struct{})
	close(stop)

	done := make(chan [][]byte, 1)
	go func() { done <- collectBatch(ch, stop, 5*time.Second) }()
	select {
	case got := <-done:
		if got != nil {
			t.Fatalf("stop 关闭时应返回 nil，实际 %d 个", len(got))
		}
	case <-time.After(time.Second):
		t.Fatal("stop 关闭后 collectBatch 没有立刻返回")
	}
}

// TestCollectBatchZeroGapUsesDefault 钉死「quietGap 传 0 不会立刻返回空」。
func TestCollectBatchZeroGapUsesDefault(t *testing.T) {
	ch := make(chan []byte, 16)
	stop := make(chan struct{})
	ch <- []byte("a")
	ch <- []byte("b")

	got := collectBatch(ch, stop, 0)
	if len(got) != 2 {
		t.Fatalf("收到 %d 个候选，期望 2", len(got))
	}
}

// ── 指针槽位的 dump 渲染 ──

// slotProbe 是本进程里一块真实可读的内存，用来验证槽位 dump。
var slotProbe [8]uintptr

// TestFormatSlotDumpMarksOnlyPointer 钉死「▶ 只标 8 字节 + 打出槽位值」。
//
// 19:46 报告里这一段有两个毛病：
//  1. 头部写成 `TYPE_0x0　区域 0x21840afe000 + 0 B` —— 用的是伪造的
//     `Region{Base: addr &^ 0xFFF}`，Size/Type 都是 0；
//  2. ▶ 标了 32 字节（沿用公钥的渲染函数），后半截其实是邻居字段。
//
// 槽位是 8 字节的指针，标 32 字节会让人以为"槽位是 32 字节"。
func TestFormatSlotDumpMarksOnlyPointer(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	regions, rerr := proc.RegionsWithError(time.Now().Add(20*time.Second), 0)
	if rerr != nil && rerr != memscan.ErrRegionDeadline && rerr != memscan.ErrRegionLimit {
		t.Skipf("枚举区域失败: %v", rerr)
	}
	if len(regions) == 0 {
		t.Skip("没枚举到区域")
	}

	const fakeTarget = uintptr(0x12345000)
	slotProbe[1] = fakeTarget
	addr := uintptr(unsafe.Pointer(&slotProbe[1]))

	out := formatSlotDump(proc, nil, addr, 64, regions)

	if n := strings.Count(out, "▶"); n != 1 {
		t.Fatalf("▶ 应该只标 1 行（8 字节），实际 %d 行：\n%s", n, out)
	}
	want := fmt.Sprintf("槽位值 = %#x", fakeTarget)
	if !strings.Contains(out, want) {
		t.Fatalf("没有打出槽位值（期望含 %q）：\n%s", want, out)
	}
	if strings.Contains(out, "TYPE_0x0") {
		t.Fatalf("区域头还是伪造的（TYPE_0x0）：\n%s", out)
	}
	if strings.Contains(out, "+ 0 B") {
		t.Fatalf("区域大小还是 0：\n%s", out)
	}
}

// TestRegionOf 钉死区间判定（左闭右开）。
func TestRegionOf(t *testing.T) {
	regions := []memscan.Region{
		{Base: 0x1000, Size: 0x1000, Type: 0x20000},
		{Base: 0x3000, Size: 0x2000, Type: 0x40000},
	}
	cases := []struct {
		addr uintptr
		want uintptr
	}{
		{0x0FFF, 0},      // 区域前
		{0x1000, 0x1000}, // 首字节（闭）
		{0x1FFF, 0x1000}, // 末字节
		{0x2000, 0},      // 右开边界 → 不属于第一块
		{0x3000, 0x3000},
		{0x4FFF, 0x3000},
		{0x5000, 0}, // 右开边界
	}
	for _, c := range cases {
		if got := regionOf(regions, c.addr).Base; got != c.want {
			t.Fatalf("regionOf(%#x) = %#x，期望 %#x", c.addr, got, c.want)
		}
	}
}

// ── 公钥邻域的自动判读 ──

// TestJudgeNeighborhoodZeroPrivSlot 钉死「+32 全 0 = 私钥已被擦除」这条判读。
//
// 19:10 和 19:46 两次现场的命中点 dump 都是这个形状：
// 公钥 32 字节，紧跟 32 字节全 0。两次不同公钥、不同地址、同样形状 ——
// 这是「pub[32]+priv[32] 布局里私钥被 SecureZeroMemory」的特征。
// 报告必须自己把这句话说出来，而不是让人去盯十六进制。
func TestJudgeNeighborhoodZeroPrivSlot(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i*7 + 3)
	}
	dump := append(append([]byte(nil), pub...), make([]byte, 32)...)
	out := judgeNeighborhood(pubHit{Dump: dump, DumpAt: 0, Judge: true})

	if !strings.Contains(out, "全为 0") {
		t.Fatalf("没识别出 +32 全 0 这个形状：\n%s", out)
	}
	// ⚠ 这条断言在 21:01 之后反过来了。
	//
	// 原来断言「必须给出『让冻结更早发生』这个对策」。21:01 把冻结压到 6ms
	// （ClientHello 刚上网、还没收到 ServerHello）时 `+32` 仍然全 0 ——
	// 时间上不可能是擦除，所以「让冻结更早」这个建议是**错的**，
	// 它会让人继续在已经走到头的路上加码（还顺带增加封号风险）。
	// 现在必须断言：不许再给这个建议，并且要说明"这个结构体本来就不放私钥"。
	if strings.Contains(out, "让冻结更早发生") {
		t.Fatalf("判读还在建议「让冻结更早发生」—— 6ms 时仍然全 0，这个建议已被推翻：\n%s", out)
	}
	if !strings.Contains(out, "本来就不放私钥") {
		t.Fatalf("判读没有说明「这个结构体本来就不放私钥」：\n%s", out)
	}
}

// TestJudgeNeighborhoodRealPriv 钉死「+32 高熵 = 疑似私钥」。
func TestJudgeNeighborhoodRealPriv(t *testing.T) {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i*11 + 5) // 32 个不同值 → 满足 distinct>=24
	}
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(255 - i)
	}
	dump := append(append([]byte(nil), pub...), priv...)
	out := judgeNeighborhood(pubHit{Dump: dump, DumpAt: 0, Judge: true})

	if !strings.Contains(out, "高熵") {
		t.Fatalf("没识别出疑似私钥：\n%s", out)
	}
}

// TestJudgeNeighborhoodPlain 钉死「既不全 0 也不像私钥」不会误报。
func TestJudgeNeighborhoodPlain(t *testing.T) {
	blk := make([]byte, 64)
	for i := range blk {
		blk[i] = 0x01 // distinct=1
	}
	out := judgeNeighborhood(pubHit{Dump: blk, DumpAt: 0, Judge: true})
	if !strings.Contains(out, "既不是全 0 也不像私钥") {
		t.Fatalf("平凡数据被误判：\n%s", out)
	}
	if strings.Contains(out, "另有像私钥") {
		t.Fatalf("平凡数据不该报出额外候选：\n%s", out)
	}
}

// TestJudgeNeighborhoodSlotDumpNotJudged 钉死「指针槽位不套用公钥判读」。
func TestJudgeNeighborhoodSlotDumpNotJudged(t *testing.T) {
	blk := make([]byte, 64)
	out := judgeNeighborhood(pubHit{Dump: blk, DumpAt: 0, Judge: false})
	if out != "" {
		t.Fatalf("Judge=false 时应返回空，实际：%q", out)
	}
}

// TestLooksLikePriv 钉死阈值边界。
func TestLooksLikePriv(t *testing.T) {
	zeros := make([]byte, 32)
	if looksLikePriv(zeros) {
		t.Fatal("全 0 不该被判成私钥")
	}
	if looksLikePriv(make([]byte, 31)) {
		t.Fatal("长度不足 32 不该被判成私钥")
	}
	good := make([]byte, 32)
	for i := range good {
		good[i] = byte(i * 8)
	}
	if !looksLikePriv(good) {
		t.Fatal("32 个不同值应该被判成私钥")
	}
}

// ── 第十五轮（20:18 现场）：静默窗口必须压到毫秒级 ──

// TestKeyBatchQuietGapIsTiny 钉死「等候选的时间不能超过 2 ms」。
//
// 20:18 现场把这条线量到底了：「握手→搜索」= 19 ms，其中 12 ms 就是
// 这个静默窗口，剩下 ~7 ms 是 FreezeFast。而同一份报告里 2 处命中点是
// `pub[32] + 32 字节全 0` —— 那是**冻结那一刻**的状态（locatePub 和
// takeSnap 都在 NtSuspendProcess 之后跑，进程已停住，读到的不可能是
// 后来才擦掉的）。结论：客户端在公钥上网后 19 ms 内就清零了私钥。
//
// 所以这个值不是"调优"，是"能不能抢到"的分母。1 ms 对微秒级的投递
// 间隔仍有 3 个数量级余量，再多等就是白送。
func TestKeyBatchQuietGapIsTiny(t *testing.T) {
	if keyBatchQuietGap > 2*time.Millisecond {
		t.Fatalf("keyBatchQuietGap = %s，超过 2 ms —— 这段是 freeze 之前的死等，"+
			"每多 1 ms 就少 1 ms 竞速余量（20:18 现场 19 ms 时私钥已全 0）",
			keyBatchQuietGap)
	}
	if keyBatchQuietGap <= 0 {
		t.Fatalf("keyBatchQuietGap = %s，不能为 0（会被当成未设置而回落到默认值）",
			keyBatchQuietGap)
	}
}

// TestCollectBatchRealGapIsFast 用**真实的**常量跑一遍，确认端到端不会白等。
func TestCollectBatchRealGapIsFast(t *testing.T) {
	ch := make(chan []byte, 16)
	stop := make(chan struct{})
	ch <- []byte("only-one")

	t0 := time.Now()
	got := collectBatch(ch, stop, keyBatchQuietGap)
	el := time.Since(t0)

	if len(got) != 1 {
		t.Fatalf("收到 %d 个候选，期望 1", len(got))
	}
	// 上限 50 ms：1 ms 的 timer 在负载高的机器上会被拖到十几毫秒，
	// 但绝不该接近旧的 12 ms 设计值加上调度抖动。
	if el > 50*time.Millisecond {
		t.Fatalf("单候选花了 %s（keyBatchQuietGap=%s），说明静默窗口没生效",
			el, keyBatchQuietGap)
	}
	t.Logf("单候选 %s 返回（keyBatchQuietGap=%s）", el.Round(100*time.Microsecond), keyBatchQuietGap)
}

// TestFreezeOutcomeReportsCost 钉死「挂进程自身的开销要单独可读」。
//
// 没有这一项就分不清「等候选慢」和「NtSuspendProcess 慢」——
// 20:18 的 19 ms 里两段都在没保护的状态里，但优化手段完全不同：
// 前者改常量，后者要换挂进程方式。
func TestFreezeOutcomeReportsCost(t *testing.T) {
	fz := &fakeFreezer{}
	out := freezeRun(fz, time.Second, func() {
		time.Sleep(2 * time.Millisecond)
	})
	if !out.Froze {
		t.Fatal("应该冻上了")
	}
	if out.FreezeAt.IsZero() {
		t.Fatal("FreezeAt 没被记录 —— 「握手→冻结」就算不出来")
	}
	if out.FreezeCost < 0 {
		t.Fatalf("FreezeCost = %s，不能为负（计时区间算反了）", out.FreezeCost)
	}
	if out.FreezeCost > out.Hold {
		t.Fatalf("FreezeCost %s 大于 Hold %s，计时区间算错了", out.FreezeCost, out.Hold)
	}
	t.Logf("挂进程耗时 %s，持有 %s", out.FreezeCost, out.Hold.Round(time.Millisecond))
}

// ── 第十五轮：槽位 dump 必须优先读冻结副本 ──

// TestSnapRead 钉死「只完整覆盖才返回」。
//
// 半截数据比没有更危险：副本是分段抓的，一段一个 chunk，
// 跨 chunk 边界的读必须返回 nil 让调用方退回活内存。
func TestSnapRead(t *testing.T) {
	const base = uintptr(0x10000000)
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i + 1)
	}
	snap := &memSnapshot{chunks: []snapChunk{{addr: base, data: data}}}

	// 完整覆盖
	got := snapRead(snap, base+8, 8)
	if len(got) != 8 || got[0] != 9 {
		t.Fatalf("完整覆盖应返回 data[8:16]，实得 %v", got)
	}
	// 刚好到边界
	if got := snapRead(snap, base+56, 8); len(got) != 8 {
		t.Fatalf("正好到末尾应该能读，实得 %d 字节", len(got))
	}
	// 越界一格
	if got := snapRead(snap, base+57, 8); got != nil {
		t.Fatalf("跨出 chunk 末尾必须返回 nil，实得 %d 字节", len(got))
	}
	// 在 chunk 之前
	if got := snapRead(snap, base-1, 1); got != nil {
		t.Fatal("chunk 之前必须返回 nil")
	}
	// nil 副本
	if got := snapRead(nil, base, 8); got != nil {
		t.Fatal("nil 副本必须返回 nil")
	}
}

// TestFormatSlotDumpPrefersSnapshot 钉死「有副本时从副本读，并标注来源」。
//
// 20:18 现场的假 bug：槽位是在冻结副本里反查出来的，dump 却读解冻后
// 一分钟的活内存，于是"值等于公钥地址的槽位"显示成 0x0，
// 看起来像反查算法坏了。这个测试保证以后不会再出现这种误判。
func TestFormatSlotDumpPrefersSnapshot(t *testing.T) {
	const (
		addr   = uintptr(0x20000000)
		target = uintptr(0x20001000) // 槽位指向的"公钥地址"
	)
	// 造一段副本：addr 处放 target 这个指针。
	// 长度必须是 span(64) + 槽位后 want(64+32) = 160，少一个字节
	// formatSlotDump 就会判"读不到上下文"——这本身也是契约的一部分。
	data := make([]byte, 160)
	for i := 0; i < 8; i++ {
		data[64+i] = byte(uint64(target) >> (8 * i))
	}
	snap := &memSnapshot{chunks: []snapChunk{{addr: addr - 64, data: data}}}

	// proc 传 nil：只要读了活内存就会失败，逼出"必须用副本"这个契约。
	out := formatSlotDump(nil, snap, addr, 64, nil)

	if !strings.Contains(out, "冻结副本") {
		t.Fatalf("没有标注数据来源是冻结副本：\n%s", out)
	}
	want := fmt.Sprintf("槽位值 = %#x", target)
	if !strings.Contains(out, want) {
		t.Fatalf("槽位值不是从副本解出来的（期望含 %q）：\n%s", want, out)
	}
	if strings.Contains(out, "槽位值 = 0x0") {
		t.Fatalf("读到了 0，说明没用副本：\n%s", out)
	}
}

// TestFormatSlotDumpNoSnapStillWorks 副本没覆盖时退回活内存（读自身进程）。
func TestFormatSlotDumpNoSnapStillWorks(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程: %v", err)
	}
	defer proc.Close()

	const fakeTarget = uintptr(0x77770000)
	slotProbe[1] = fakeTarget
	addr := uintptr(unsafe.Pointer(&slotProbe[1]))

	// 空副本 → 必须退回活内存，不能因此报"读不到"
	out := formatSlotDump(proc, &memSnapshot{}, addr, 64, nil)
	if !strings.Contains(out, "活内存") {
		t.Fatalf("副本为空时应标注取自活内存：\n%s", out)
	}
	if want := fmt.Sprintf("槽位值 = %#x", fakeTarget); !strings.Contains(out, want) {
		t.Fatalf("没解出槽位值（期望含 %q）：\n%s", want, out)
	}
}

// ── 第十六轮（21:01 现场 + 封号事故）：两处判读/默认值纠错 ──

// TestJudgeNeighborhoodWireNotPriv 钉死「报文副本不许报『疑似私钥』」。
//
// 21:01 现场的假阳性：第 1 处命中 `0xb8e97ee23c` 前面是
// `3a 75 0a 31 08 01 12 20`（protobuf 字段头），后面 32 字节被判成
// 「高熵 → 疑似私钥」。其实那是**握手包在内存里的副本**，
// 公钥后面当然是整段密文载荷，熵必然高。报成"疑似私钥"会把人引向错误偏移。
func TestJudgeNeighborhoodWireNotPriv(t *testing.T) {
	// 造一份 dump：公钥前面是 `08 01 12 20`，后面是 32 字节高熵
	const klen = 32
	buf := make([]byte, 128)
	buf[4], buf[5], buf[6], buf[7] = 0x08, 0x01, 0x12, 0x20
	pos := 8
	for i := 0; i < klen; i++ {
		buf[pos+i] = byte(i + 1) // 公钥（内容无所谓）
	}
	// +32 处放一段"像私钥"的高熵
	for i := 0; i < klen; i++ {
		buf[pos+klen+i] = byte(i*8 + 3)
	}

	h := pubHit{
		Addr:   0x1000,
		Dump:   buf,
		DumpAt: pos,
		Judge:  true,
		Wire:   wireLike(buf, pos),
	}
	if !h.Wire {
		t.Fatal("wireLike 应该认出 08 01 12 20 这个前缀")
	}
	out := judgeNeighborhood(h)
	if !strings.Contains(out, "报文") {
		t.Fatalf("报文副本必须被点明是报文副本：\n%s", out)
	}
	if strings.Contains(out, "疑似私钥") {
		t.Fatalf("报文副本不能报「疑似私钥」—— 那是密文载荷：\n%s", out)
	}

	// 反证：同样的字节，但**不是**报文副本（前面没有 protobuf 头），
	// 就应该照常判成高熵。
	buf2 := append([]byte(nil), buf...)
	buf2[4], buf2[5], buf2[6], buf2[7] = 0xde, 0xad, 0xbe, 0xef
	h2 := pubHit{Addr: 0x2000, Dump: buf2, DumpAt: pos, Judge: true, Wire: wireLike(buf2, pos)}
	if h2.Wire {
		t.Fatal("wireLike 不该在随机前缀上返回 true")
	}
	if out2 := judgeNeighborhood(h2); !strings.Contains(out2, "高熵") {
		t.Fatalf("非报文副本的高熵块应该照常报高熵：\n%s", out2)
	}
}

// TestDefaultFreezeIsShortAndACGuarded 钉死「默认可拿密钥、且反作弊闸门在位」。
//
// 归因演进（这条测试的断言跟着结论一起改，保护的东西没变）：
//
//	2026-10-17 21:01 封号，当时默认 `-freeze full` = 冻结 1.979 秒
//	2026-10-18 确认原版也用 `NtSuspendProcess` → 冻结动作本身不是主因
//	2026-10-19 14:55 现场「上次读取完账号被封禁了」→ 改成默认 off
//	2026-10-19 15:20 现场 → **默认 off 等于自废武功**：日志里
//	                   `[key] 快照耗时…**未冻结**` + `还没有客户端私钥（需要 -freeze short）`，
//	                   一局跑完 0 密钥、0 目标。用户原话：「之前冻结不是已经可以
//	                   拿到密钥了么？怎么现在又在做重复的事情获取不到密钥」
//
// 🔴 结论修正：**安全网应该是 acguard 闸门，不是「默认不冻」。**
// 闸门检测到完美/5E/Faceit/EAC/BattlEye 就拒绝碰进程，这才是真正的防线；
// 在没有反作弊的纯社区服上，冻结本来就该正常工作 —— 用默认 off 去"兜底安全"，
// 等于把功能关掉换心理安慰，而用户要的是能出目标。
//
// 因此这里断言四件事：
//  1. 默认必须是会冻结的档位（short/full），不能退回 off；
//  2. `-allow-ac` 必须存在且默认 false —— 反作弊场次的唯一逃生口；
//  3. `freezeHoldLimit` 必须 ≤ 700 ms —— 就算冻结，也不能超过原版上限；
//  4. 帮助文本必须点明「封号」和「时长」，把风险写在用户看得见的地方。
func TestDefaultFreezeIsShortAndACGuarded(t *testing.T) {
	f := flag.Lookup("freeze")
	if f == nil {
		t.Fatal("找不到 -freeze 这个 flag")
	}
	switch got := strings.ToLower(f.DefValue); got {
	case "short", "full":
		// 好：会冻结，能拿私钥
	case "off":
		t.Fatalf("-freeze 默认是 off —— 不冻结拿不到会话私钥，"+
			"整局 0 密钥 0 目标（2026-10-19 15:20 现场已复现）。"+
			"安全应该由 acguard 闸门负责，不是靠默认关掉功能")
	default:
		t.Fatalf("-freeze 默认值是 %q，应为 short/full", got)
	}

	ac := flag.Lookup("allow-ac")
	if ac == nil {
		t.Fatal("找不到 -allow-ac 这个 flag —— 反作弊闸门被删了？")
	}
	if ac.DefValue != "false" {
		t.Fatalf("-allow-ac 默认值应为 false（默认禁止碰反作弊场次里的进程），现在是 %q", ac.DefValue)
	}

	// 硬安全边界：单次冻结不得超过原版上限。
	const origHold = 700 * time.Millisecond
	if freezeHoldLimit > origHold {
		t.Fatalf("单次冻结上限 %s 超过原版上限 %s —— 21:01 那次就是 1979ms 出的事",
			freezeHoldLimit, origHold)
	}

	if !strings.Contains(f.Usage, "封") {
		t.Fatalf("-freeze 的帮助文本必须点明封号事实，现在是：%q", f.Usage)
	}
	if !strings.Contains(f.Usage, "时长") {
		t.Fatalf("-freeze 的帮助文本必须点明冻结时长这个风险点，现在是：%q", f.Usage)
	}
}

// TestHintsFlagExists 钉死 hint 快路径的开关存在且默认自动启用。
//
// 这条 flag 是「原版不被检测、我们被检测」这个差距的直接对策：
// 有 hint 时只读 32 字节×条数，不冻结、不扫描。
// 如果哪天它被删掉，collector 就会退回"每次全量扫描 7.5 GB"，必须拦住。
func TestHintsFlagExists(t *testing.T) {
	f := flag.Lookup("hints")
	if f == nil {
		t.Fatal("找不到 -hints 这个 flag —— hint 快路径被删了？")
	}
	if f.DefValue != "" {
		t.Fatalf("-hints 默认值应为空（= exe 同目录 hints.json），现在是 %q", f.DefValue)
	}
	if !strings.Contains(f.Usage, "32") {
		t.Fatalf("-hints 的帮助文本应说明快路径只读 32 字节，现在是：%q", f.Usage)
	}
}

// TestHintPathResolves 验证 -hints 的三态：空=默认路径 / off=禁用 / 其它=原样。
func TestHintPathResolves(t *testing.T) {
	old := *flagHints
	defer func() { *flagHints = old }()

	for _, v := range []string{"off", "OFF", "none", "0", "false"} {
		*flagHints = v
		if got := hintPath(); got != "" {
			t.Fatalf("-hints=%q 应禁用，实际返回 %q", v, got)
		}
	}

	*flagHints = ""
	got := hintPath()
	if !strings.HasSuffix(got, "hints.json") {
		t.Fatalf("-hints 为空时应退到 exe 同目录 hints.json，实际 %q", got)
	}

	*flagHints = `D:\tmp\custom-hints.json`
	if hintPath() != `D:\tmp\custom-hints.json` {
		t.Fatalf("自定义路径未被原样采用：%q", hintPath())
	}
}

// TestHintPathStaysInExeDir 是一条**回归护栏**（硬规则 271）。
//
// 用户 2026-10-20 08:58 明确要求：生成的文件只能留在原始位置，
// 不经允许不得在其它位置新建存储。曾经把 hints.json 再写一份到
// `%LOCALAPPDATA%\cs2radar\`，已被要求撤掉。这条测试就是为了防止有人
// 再"顺手"加一个别处的落点。
func TestHintPathStaysInExeDir(t *testing.T) {
	old := *flagHints
	defer func() { *flagHints = old }()
	*flagHints = ""

	got := hintPath()
	want := filepath.Join(exeDir(), "hints.json")
	if !strings.EqualFold(got, want) {
		t.Fatalf("hint 落点必须只在 exe 同目录，期望 %q，实际 %q", want, got)
	}
	// 真正的不变量：落点所在目录必须**就是** exe 目录。
	// （不要按 "appdata" 之类的子串判断 —— 测试二进制本身就跑在 Temp 下。）
	if !strings.EqualFold(filepath.Dir(got), exeDir()) {
		t.Fatalf("hint 目录必须是 exe 目录 %q，实际 %q", exeDir(), filepath.Dir(got))
	}
}
