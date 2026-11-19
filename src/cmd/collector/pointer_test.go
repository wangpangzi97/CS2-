package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
)

// ── 第十一轮：指针反查（原版 chase，tag="pointer"）──
//
// 为什么需要这一级：Go 的 crypto/ecdh 里公钥和私钥是**两个独立的堆分配**
//
//	type PrivateKey struct {
//	    curve      Curve   // 0x00, 16 字节（itab + data）
//	    publicKey  []byte  // 0x10 ptr / 0x18 len / 0x20 cap
//	    privateKey []byte  // 0x28 ptr / 0x30 len / 0x38 cap
//	}
//
// 我们在内存里扫到的公钥 32 字节，是 publicKey 那个 slice 的底层数组；
// 私钥那 32 字节在另一块堆上，两者地址毫无关系。所以「贴着公钥扫 ±8 MB」
// 在原理上就可能永远找不到 —— 第八轮、第九轮两次实测确实都是 0 命中。
// 正确做法是反查「谁指向公钥字节」，再从那个槽位的相邻 qword 取指针去校验。

// fakeEcdhPriv 复刻 crypto/ecdh.PrivateKey 的字段布局（只保留关键三段）。
// 布局必须和真的一致，否则反查出来的偏移对不上 —— 下面的测试会显式断言。
type fakeEcdhPriv struct {
	curve      [2]uintptr // 0x00..0x10：interface 的 itab + data
	publicKey  []byte     // 0x10
	privateKey []byte     // 0x28
}

// chunkOf 把一段真实内存做成快照分片（addr 用真实地址，这样里面的指针值能对上）。
func chunkOf(p unsafe.Pointer, n int) snapChunk {
	src := unsafe.Slice((*byte)(p), n)
	data := make([]byte, n)
	copy(data, src)
	return snapChunk{addr: uintptr(p), data: data}
}

// TestFakeEcdhLayout 先把"布局假设"钉死。这条失败说明标准库改了布局，
// 那么 ptrChaseFwd/ptrChaseBack 的取值也要跟着改。
func TestFakeEcdhLayout(t *testing.T) {
	var fk fakeEcdhPriv
	if off := unsafe.Offsetof(fk.publicKey); off != 0x10 {
		t.Fatalf("publicKey 偏移 %#x，期望 0x10", off)
	}
	if off := unsafe.Offsetof(fk.privateKey); off != 0x28 {
		t.Fatalf("privateKey 偏移 %#x，期望 0x28（publicKey.ptr 到 privateKey.ptr 差 0x18）", off)
	}
}

// TestFindPointersTo 钉死"只认 8 字节对齐、且只认完全相等"。
func TestFindPointersTo(t *testing.T) {
	buf := make([]byte, 4096)
	base := uintptr(unsafe.Pointer(&buf[0]))

	// 从 base 起第一个 8 字节对齐的偏移
	start := 0
	if r := base & 7; r != 0 {
		start = int(8 - r)
	}
	put := func(off int, v uintptr) {
		*(*uintptr)(unsafe.Pointer(&buf[off])) = v
	}
	const target = 0xdeadbeef00
	put(start+8, target)    // 对齐，应命中
	put(start+32, target)   // 对齐，应命中
	put(start+17, target)   // 非对齐，不该命中
	put(start+64, target+1) // 值不等，不该命中

	got := findPointersTo(buf, base, target)
	if len(got) != 2 {
		t.Fatalf("命中 %d 处，期望 2：%x", len(got), got)
	}
	if got[0] != base+uintptr(start+8) || got[1] != base+uintptr(start+32) {
		t.Fatalf("命中地址不对：%x，期望 [%x %x]",
			got, base+uintptr(start+8), base+uintptr(start+32))
	}
	// 边界
	if findPointersTo(buf[:7], base, target) != nil {
		t.Fatalf("不足 8 字节不该命中")
	}
	if findPointersTo(buf, base, 0) != nil {
		t.Fatalf("target=0 不该命中（0 到处都是）")
	}
}

// TestFindPointersToAny 钉死多目标版：一次遍历要同时命中"指向任一目标"的槽位，
// 且结果和逐个目标扫一遍完全一致（这是替换单目标版的前提）。
func TestFindPointersToAny(t *testing.T) {
	buf := make([]byte, 4096)
	base := uintptr(unsafe.Pointer(&buf[0]))
	start := 0
	if r := base & 7; r != 0 {
		start = int(8 - r)
	}
	put := func(off int, v uintptr) {
		*(*uintptr)(unsafe.Pointer(&buf[off])) = v
	}
	const t1, t2, t3 = 0x11110000, 0x22220000, 0x33330000
	put(start+64, t1)  // 命中
	put(start+128, t3) // 不在集合里
	put(start+192, t2) // 命中
	put(start+256, t1) // 命中（重复值，仍算一个槽位）
	// 非对齐写：必须落在**不覆盖**上面任何对齐 qword 的位置。
	// （踩过的坑：这里原本写 start+25，8 字节写穿到 25..32，
	//   把 start+24 那个 qword 的低 7 字节覆盖掉了，断言直接错乱。）
	put(start+320+3, t2)

	want := map[uintptr]struct{}{t1: {}, t2: {}}
	got := findPointersToAny(buf, base, want)
	if len(got) != 3 {
		t.Fatalf("命中 %d 处，期望 3（%#x/%#x/%#x）：%x", len(got),
			base+uintptr(start+64), base+uintptr(start+192), base+uintptr(start+256), got)
	}
	for _, q := range got {
		if q%8 != 0 {
			t.Fatalf("返回了非 8 字节对齐的槽位 %#x", q)
		}
		if q == base+uintptr(start+320+3) {
			t.Fatalf("返回了非对齐写入的位置 %#x", q)
		}
	}
	// 和逐个目标扫一遍的结果做交叉验证
	single := append(findPointersTo(buf, base, t1), findPointersTo(buf, base, t2)...)
	if len(single) != len(got) {
		t.Fatalf("多目标 %d 处，单目标合计 %d 处，不一致", len(got), len(single))
	}
	// 空集合 / 太短
	if findPointersToAny(buf, base, nil) != nil {
		t.Fatalf("空集合不该命中")
	}
	if findPointersToAny(buf[:7], base, want) != nil {
		t.Fatalf("不足 8 字节不该命中")
	}
}

// TestScanPointersToLiveFindsPriv 是活内存版的反查测试。
//
// 和合成地址那版不同，这里走的是**真实 ReadProcessMemory**：
// 结构体、公钥、私钥都真实分配，只把「扫描区域」限定成结构体所在那一小段。
// 这样同时验证了三件事：区域过滤、跨块读取、槽位跟踪。
func TestScanPointersToLiveFindsPriv(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	pub := k.PublicKey().Bytes()

	pubBuf := make([]byte, 32)
	copy(pubBuf, pub)
	privBuf := make([]byte, 32)
	copy(privBuf, priv)
	structBuf := make([]byte, 0x40)
	*(*uintptr)(unsafe.Pointer(&structBuf[0x10])) = uintptr(unsafe.Pointer(&pubBuf[0]))
	*(*uintptr)(unsafe.Pointer(&structBuf[0x28])) = uintptr(unsafe.Pointer(&privBuf[0]))
	// 防止 GC 把这三块回收掉（扫描是异步的，虽然这里已 Wait）
	defer runtime.KeepAlive(structBuf)
	defer runtime.KeepAlive(pubBuf)
	defer runtime.KeepAlive(privBuf)

	structAddr := uintptr(unsafe.Pointer(&structBuf[0]))
	privAddr := uintptr(unsafe.Pointer(&privBuf[0]))
	regions := []memscan.Region{{
		Base:    structAddr,
		Size:    uintptr(len(structBuf)),
		Protect: 0x04, // PAGE_READWRITE
	}}

	kf := keyfind.New(proc, pub, time.Now().Add(30*time.Second))
	var foundAt uintptr
	var foundTag string
	kf.OnFound = func(_ []byte, tag string, a uintptr) {
		foundAt = a
		foundTag = tag
	}

	st := new(scanStat)
	slots, chases := scanPointersToLive(kf, proc, regions,
		[]pubHit{{Addr: uintptr(unsafe.Pointer(&pubBuf[0]))}},
		time.Now().Add(20*time.Second), st)

	if slots != 1 {
		t.Fatalf("活内存里指向公钥的槽位 %d 个，期望 1 个（读到 %d 字节/区域 %d 个/短读 %d）",
			slots, st.bytes.Load(), st.regions.Load(), st.shortRd.Load())
	}
	if !kf.Found() {
		t.Fatalf("活内存反查没找到私钥（槽位 %d，跟踪 %d，短读 %d）",
			slots, chases, st.shortRd.Load())
	}
	if foundAt != privAddr {
		t.Fatalf("命中地址 %#x，期望 %#x", foundAt, privAddr)
	}
	if foundTag != "pointer" {
		t.Fatalf("命中标签 %q，期望 pointer", foundTag)
	}
}

// TestScanPointersToLiveSkipsReadOnly 确认只读区域被跳过（指针槽只可能在可写内存里）。
func TestScanPointersToLiveSkipsReadOnly(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程: %v", err)
	}
	defer proc.Close()

	priv := make([]byte, 32)
	rand.Read(priv)
	k, _ := ecdh.X25519().NewPrivateKey(priv)
	pub := k.PublicKey().Bytes()
	pubBuf := make([]byte, 32)
	copy(pubBuf, pub)
	structBuf := make([]byte, 0x40)
	*(*uintptr)(unsafe.Pointer(&structBuf[0x10])) = uintptr(unsafe.Pointer(&pubBuf[0]))
	defer runtime.KeepAlive(structBuf)
	defer runtime.KeepAlive(pubBuf)

	// PAGE_READONLY = 0x02
	regions := []memscan.Region{{
		Base:    uintptr(unsafe.Pointer(&structBuf[0])),
		Size:    uintptr(len(structBuf)),
		Protect: 0x02,
	}}
	kf := keyfind.New(proc, pub, time.Now().Add(10*time.Second))
	slots, _ := scanPointersToLive(kf, proc, regions,
		[]pubHit{{Addr: uintptr(unsafe.Pointer(&pubBuf[0]))}},
		time.Now().Add(5*time.Second), new(scanStat))
	if slots != 0 {
		t.Fatalf("只读区域不该被扫，却找到 %d 个槽位", slots)
	}
}

// absDiff 返回两个地址之差的绝对值。
func absDiff(a, b uintptr) uintptr {
	if a > b {
		return a - b
	}
	return b - a
}

// TestScanPointersToFindsPrivBehindPointer 是这一级的核心证明：
// 公钥和私钥相距几百 MB、彼此毫无关系，只有「谁指向公钥」这条线索能连起来。
//
// 刻意用**合成地址**而不是真实分配，原因有两条：
//   - 真实分配下 Go 会把两个 32 字节对象放进同一个 span 的相邻位置（实测相距 0x20），
//     那样"命中"就无法排除"其实是靠 ±32 字节的邻居碰到的"；
//   - 在两个 32 字节对象之间插 1 MB padding 也无效 —— 32 字节走小对象 size class，
//     1 MB 走大对象 span，两者根本不在同一片。
//
// 合成地址还顺带钉死了一件事：反查**不受邻域窗口（现在 8 MB）限制**。
func TestScanPointersToFindsPrivBehindPointer(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	pub := k.PublicKey().Bytes()

	// 三块合成内存：公钥字节 / PrivateKey 结构体 / 私钥字节。
	const (
		pubAt    = uintptr(0x10000000)
		structAt = uintptr(0x20000000)
		privAt   = uintptr(0x40000000)
	)
	const farApart = 64 << 20
	if absDiff(privAt, pubAt) < farApart {
		t.Fatalf("测试前提：私钥 %#x 和公钥 %#x 相距不足 %d 字节", privAt, pubAt, farApart)
	}

	// 结构体：+0x10 放 publicKey.ptr，+0x28 放 privateKey.ptr（与真实布局一致）。
	structBuf := make([]byte, 0x40)
	*(*uintptr)(unsafe.Pointer(&structBuf[0x10])) = pubAt
	*(*uintptr)(unsafe.Pointer(&structBuf[0x28])) = privAt

	pubBuf := make([]byte, 32)
	copy(pubBuf, pub)
	privBuf := make([]byte, 32)
	copy(privBuf, priv)

	snap := &memSnapshot{
		chunks: []snapChunk{
			{addr: structAt, data: structBuf},
			{addr: pubAt, data: pubBuf},
			{addr: privAt, data: privBuf},
		},
	}
	snap.primary = len(snap.chunks)
	for _, c := range snap.chunks {
		snap.bytes += uint64(len(c.data))
	}

	// proc 传 nil：本次所有读取都落在副本里，不该退回读进程。
	kf := keyfind.New(nil, pub, time.Now().Add(30*time.Second))
	var found []byte
	var foundAt uintptr
	kf.OnFound = func(p []byte, tag string, a uintptr) {
		found = append([]byte(nil), p...)
		foundAt = a
		if tag != "pointer" {
			t.Errorf("命中标签是 %q，期望 pointer（原版 chase 用这个标签）", tag)
		}
	}

	st := new(scanStat)
	slots, chases := scanPointersTo(kf, nil, snap, []pubHit{{Addr: pubAt}},
		time.Now().Add(20*time.Second), st)

	if slots != 1 {
		t.Fatalf("指向公钥的槽位 %d 个，期望 1 个（%#x 处的 publicKey.ptr）", slots, structAt+0x10)
	}
	if !kf.Found() {
		t.Fatalf("指针反查没找到私钥（槽位 %d 个，跟踪 %d 次，短读 %d）",
			slots, chases, st.shortRd.Load())
	}
	if string(found) != string(priv) {
		t.Fatalf("找到的私钥不对: %x", found)
	}
	if foundAt != privAt {
		t.Fatalf("命中地址 %#x，期望私钥所在地址 %#x", foundAt, privAt)
	}
	t.Logf("槽位 %d 个、跟踪 %d 次，从 %#x 跳到 %#x（相距 %.0f MB）",
		slots, chases, pubAt, privAt, float64(absDiff(privAt, pubAt))/(1<<20))
}

// TestScanPointersToNoPointer 是反面：没有任何指针指向公钥时，不该瞎报命中。
//
// ⚠ 这里刻意用**随机 32 字节**当公钥，而不是真 X25519 密钥对。
//
// 2026-10-19 踩到的坑：用真密钥对时，`crypto/ecdh` 会在进程里留下它自己那份
// （clamp 过的）私钥副本，而 X25519 的 clamp 让 `priv` 和 `clamp(priv)` 等价。
// 于是 chaseAt 的 ±256 字节窗口只要扫到指向那份副本的指针，就会**真的命中** ——
// 那是正确的命中，却会让这个"反面用例"随 Go 堆布局时好时坏：
// 同一份代码、同一台机器，只加了一行 t.Logf（改动了堆布局）就从 FAIL 变 PASS。
//
// 随机 32 字节不存在可用私钥（求 X25519 原像 = 解离散对数），
// 所以这里"命中"只可能来自逻辑错误 —— 这正是本用例要守的东西。
func TestScanPointersToNoPointer(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	pub := make([]byte, 32)
	rand.Read(pub)

	pubBuf := make([]byte, 32)
	copy(pubBuf, pub)
	// 故意不放任何指向 pubBuf 的指针，只放一块无关数据。
	noise := make([]byte, 512)
	for i := range noise {
		noise[i] = byte(i * 7)
	}

	snap := &memSnapshot{
		chunks: []snapChunk{
			chunkOf(unsafe.Pointer(&noise[0]), len(noise)),
			chunkOf(unsafe.Pointer(&pubBuf[0]), len(pubBuf)),
		},
	}
	snap.primary = len(snap.chunks)

	kf := keyfind.New(proc, pub, time.Now().Add(10*time.Second))
	st := new(scanStat)
	slots, chases := scanPointersTo(kf, proc, snap,
		[]pubHit{{Addr: uintptr(unsafe.Pointer(&pubBuf[0]))}},
		time.Now().Add(5*time.Second), st)
	if slots != 0 {
		t.Fatalf("不该找到指向公钥的槽位，实际 %d 个", slots)
	}
	if kf.Found() {
		t.Fatalf("没有指针线索却报命中（跟踪 %d 次）—— 说明校验逻辑有问题", chases)
	}
}

// TestScanPointersToNilSafe 传 nil 不该 panic（不冻结时 snap 就是 nil）。
func TestScanPointersToNilSafe(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()
	priv := make([]byte, 32)
	rand.Read(priv)
	k, _ := ecdh.X25519().NewPrivateKey(priv)
	kf := keyfind.New(proc, k.PublicKey().Bytes(), time.Now().Add(5*time.Second))

	if slots, chases := scanPointersTo(kf, proc, nil, []pubHit{{Addr: 0x1000}},
		time.Now().Add(time.Second), new(scanStat)); slots != 0 || chases != 0 {
		t.Fatalf("nil 快照应直接返回 0,0")
	}
	if slots, chases := scanPointersTo(nil, proc, &memSnapshot{}, nil,
		time.Now().Add(time.Second), new(scanStat)); slots != 0 || chases != 0 {
		t.Fatalf("nil 参数应直接返回 0,0")
	}
}

// ── 第十三轮：追两层（ptrChase2Depth = 2）──
//
// 19:10 现场：活内存里找到 1 个槽位指向公钥，±4 个 qword 里 2 个合法指针，
// 全都没命中。两个可能的原因：
//
//  1. 窗口太窄 —— ±4 的依据是 Go 的 crypto/ecdh 布局，而 cs2.exe 是 C++，
//     字段偏移完全未知（命中点 dump 显示 -32/-24/-16、+64/+80 都是指针）；
//  2. 只追一层 —— 真实形态很可能是「槽位 → 结构体 → 私钥指针 → 私钥字节」，
//     槽位直接指向的往往不是私钥本身。
//
// 这个测试钉死第 2 点：私钥离基准地址隔了**两次跳转**，
// 只追一层必然 0 命中，追两层才找得到。

// putU64 往合成内存里写一个 8 字节值（buf 是本地切片，不涉及真实进程）。
func putU64(buf []byte, off int, v uintptr) {
	for i := 0; i < 8; i++ {
		buf[off+i] = byte(v >> (8 * i))
	}
}

// TestChaseAtTwoHops 两层追击能跨过中间结构体找到私钥。
//
// 地址全部是**合成的**（0x10000000 起，落在 ptrMinUser..ptrMaxUser 之内），
// 不依赖本进程的堆分配位置 —— Go 在 Windows 上把堆放在 0xc000000000，
// 已经超出原版 chase 的用户态上限 0x7ffffffeffff，用真实地址这个测试
// 会因为"看着不像用户指针"而假失败。
func TestChaseAtTwoHops(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	priv := k.Bytes()
	pub := k.PublicKey().Bytes()

	const (
		base       = uintptr(0x10000000)
		size       = 64 << 10
		privOff    = 0x1000 // 私钥字节
		structOff  = 0x2000 // 中间结构体
		privPtrOff = 0x2040 // 结构体里指向私钥的字段
		slotOff    = 0x3000 // 指向结构体的槽位
	)
	buf := make([]byte, size)
	copy(buf[privOff:], priv)
	putU64(buf, privPtrOff, base+privOff) // 结构体 → 私钥
	putU64(buf, slotOff, base+structOff)  // 槽位   → 结构体

	snap := &memSnapshot{
		chunks:  []snapChunk{{addr: base, data: buf}},
		bytes:   size,
		primary: 1,
	}
	var gotAddr uintptr
	var gotTag string
	kf := keyfind.New(nil, pub, time.Now().Add(10*time.Second))
	kf.OnFound = func(_ []byte, tag string, addr uintptr) {
		gotTag, gotAddr = tag, addr
	}
	st := new(scanStat)
	r := ptrReader{snap: snap}

	// 先确认「只追一层」确实找不到 —— 否则这个测试证明不了什么。
	if n := chaseAt(kf, r, base+slotOff, 1, st); kf.Found() {
		t.Fatalf("只追一层竟然命中了（校验 %d 次），测试布局没体现两层结构", n)
	}
	if n := chaseAt(kf, r, base+slotOff, ptrChase2Depth, st); !kf.Found() {
		t.Fatalf("追两层没找到私钥（校验 %d 次，短读 %d）", n, st.shortRd.Load())
	}
	if gotAddr != base+privOff {
		t.Fatalf("命中地址 %#x，期望 %#x", gotAddr, base+privOff)
	}
	if gotTag != "pointer" {
		t.Fatalf("命中 tag = %q，期望 pointer", gotTag)
	}
}

// TestChaseAtWideWindow 钉死 ±32 个 qword 的窗口宽度。
//
// 私钥指针放在基准地址 **+0xF0（30 个 qword）** 处：旧的 ±4 窗口够不到，
// 现在的 ±32 能覆盖。这正是 19:10 那次"槽位找到了但追不到"的一个可能解释。
func TestChaseAtWideWindow(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	priv := k.Bytes()
	pub := k.PublicKey().Bytes()

	const (
		base    = uintptr(0x20000000)
		size    = 16 << 10
		privOff = 0x800
		// 30 个 qword = 240 字节 = 0xF0
		ptrOff = 0xF0
	)
	buf := make([]byte, size)
	copy(buf[privOff:], priv)
	putU64(buf, ptrOff, base+privOff)

	snap := &memSnapshot{chunks: []snapChunk{{addr: base, data: buf}}, bytes: size, primary: 1}
	kf := keyfind.New(nil, pub, time.Now().Add(10*time.Second))
	r := ptrReader{snap: snap}
	if n := chaseAt(kf, r, base, 1, new(scanStat)); !kf.Found() {
		t.Fatalf("±%d 个 qword 的窗口没能覆盖 +0xF0 处的指针（校验 %d 次）",
			ptrChaseFwd, n)
	}
	if ptrChaseFwd < 30 || ptrChaseBack < 30 {
		t.Fatalf("窗口 ±(%d,%d) 个 qword，小于本测试断言的 30", ptrChaseBack, ptrChaseFwd)
	}
}

// ── 第二十一轮：锚点内联窗口（2026-10-19，20:36 现场驱动）──

// TestProbeInlineWindowsFindsUnalignedPrivateKey 钉死"内联窗口"这一级的存在理由。
//
// 20:36 现场拿到的唯一结构化线索：
//
//	槽位 0x2a083bd2ed8  →  公钥命中 4/7 0x2a083bd30e0
//	同一块 64 KB 区域，相距 520 字节
//
// 指针追了 3006 次全空。而"私钥内联在结构体里、既不是指针目标、也不一定
// 8 字节对齐"这个形态 chaseAt 原理上碰不到 —— 它只读指针**指向的**32 字节。
//
// 所以这里刻意把布局做成 chaseAt 绝对碰不到的样子：
//   - 私钥落在**非 8 字节对齐**的偏移（0x4003）；
//   - 私钥不是任何指针的目标；
//   - 锚点（模拟"指向公钥的槽位"）与私钥相距 500 字节。
//
// 断言两件事：指针追逐 0 命中（证明缺口真实存在），内联窗口必须命中。
func TestProbeInlineWindowsFindsUnalignedPrivateKey(t *testing.T) {
	const (
		size      = 64 << 10
		privOff   = 0x4003 // 故意不对齐：chaseAt 的 8 字节格子里永远取不到它
		anchorOff = privOff - 500
	)
	buf, hits, pub := plantKeyPair(t, size, privOff, privOff+520)

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	kf := keyfind.New(proc, pub, time.Now().Add(2*time.Minute))
	var got []byte
	var gotAt uintptr
	kf.OnFound = func(p []byte, _ string, at uintptr) {
		got = append([]byte(nil), p...)
		gotAt = at
	}

	r := ptrReader{proc: proc}
	anchor := uintptr(unsafe.Pointer(&buf[anchorOff]))

	// ① 指针反查：这个布局下应当 0 命中。
	chaseAt(kf, r, anchor, ptrChase2Depth, new(scanStat))
	runtime.KeepAlive(buf)
	if kf.Found() {
		t.Fatalf("指针追逐不该命中这个布局 —— 如果命中了，说明测试构造已经不代表现场的形态")
	}

	// ② 内联窗口：必须命中，且命中的正是那块非对齐的私钥。
	st := new(scanStat)
	n := probeInlineWindows(kf, r, []uintptr{anchor, hits[0].Addr}, st)
	runtime.KeepAlive(buf)

	if !kf.Found() {
		t.Fatalf("内联窗口没找到私钥（校验 %d 次，锚点 %#x，私钥应在 %#x）",
			n, anchor, uintptr(unsafe.Pointer(&buf[privOff])))
	}
	if gotAt != uintptr(unsafe.Pointer(&buf[privOff])) {
		t.Fatalf("命中地址不对：got %#x，want %#x", gotAt, uintptr(unsafe.Pointer(&buf[privOff])))
	}
	if len(got) != 32 {
		t.Fatalf("命中长度不对：%d", len(got))
	}
	if st.cand.Load() == 0 {
		t.Fatalf("cand 计数没涨，统计没接上")
	}
}

// TestProbeInlineWindowsSkipsFarAndEmpty 钉死两件事：
//   - 私钥在 ±512 字节之外时**不该**被找到（否则半径就没意义了）；
//   - 空锚点列表 / nil kf 不 panic。
func TestProbeInlineWindowsSkipsFarAndEmpty(t *testing.T) {
	const (
		size      = 64 << 10
		privOff   = 0x4003
		anchorOff = privOff - 4000 // 超出 ±512
	)
	buf, hits, pub := plantKeyPair(t, size, privOff, privOff+520)

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	kf := keyfind.New(proc, pub, time.Now().Add(time.Minute))
	r := ptrReader{proc: proc}
	anchor := uintptr(unsafe.Pointer(&buf[anchorOff]))

	probeInlineWindows(kf, r, []uintptr{anchor}, new(scanStat))
	runtime.KeepAlive(buf)
	if kf.Found() {
		t.Fatalf("±%d 字节之外不该命中（距离 %d）", inlineProbeRadius, privOff-anchorOff)
	}

	// 空输入不 panic
	if n := probeInlineWindows(nil, r, []uintptr{anchor}, new(scanStat)); n != 0 {
		t.Fatalf("nil kf 应返回 0，得到 %d", n)
	}
	if n := probeInlineWindows(kf, r, nil, new(scanStat)); n != 0 {
		t.Fatalf("空锚点应返回 0，得到 %d", n)
	}
	_ = hits
}

// BenchmarkScanPointersTo 量"指针反查"这一步的吞吐。
//
// 为什么要有这个基准：03:43 现场（freezeE.log）这一步对 1024 MB 冻结副本
// 做串行 8 字节比较花了 742 ms（1.4 GB/s），而同一台机器上并行 memmem
// （locatePub）能到 15.7 GB/s。这一步根本不需要 X25519，本该贴着内存带宽跑，
// 差 10 倍纯粹是没用多核。并行后应有数倍提升。
//
// 用法：go test ./cmd/collector/ -run XXX -bench BenchmarkScanPointersTo -benchtime 3x
func BenchmarkScanPointersTo(b *testing.B) {
	const total = 256 << 20
	const seg = 4 << 20
	base := uintptr(0x1_0000_0000)
	snap := &memSnapshot{}
	for off := uintptr(0); off < total; off += seg {
		snap.chunks = append(snap.chunks, snapChunk{addr: base + off, data: make([]byte, seg)})
	}
	snap.primary = len(snap.chunks)

	// 目标公钥用一段随便的字节：保证一个槽位都反查不到，扫满整段。
	target := make([]byte, 32)
	for i := range target {
		target[i] = byte(0xB0 + i)
	}

	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kf := keyfind.New(nil, target, time.Now().Add(5*time.Minute))
		st := new(scanStat)
		// 命中点故意落在副本内部：part ② 会去追，但副本里全是 0，追不出东西。
		scanPointersTo(kf, nil, snap, []pubHit{{Addr: base + 8}},
			time.Now().Add(5*time.Minute), st)
		if i == 0 {
			b.Logf("扫 %d MB，耗时 %s", total>>20, st.elapsed.Truncate(time.Millisecond))
		}
	}
}
