package main

// 指针反查（原版 v2.0.5 的 `chase`，tag="pointer"）
//
// ── 为什么必须补这一级 ──────────────────────────────────────────────
//
// 第十轮把原版 `source/capture.exe` 反汇编了（3816 个符号全部恢复），
// `main.(*keySearch).chase.func1` 干的事很清楚：
//
//	readBlock(addr, 8)                       // 读 8 字节
//	next := *(*uint64)(buf)
//	if next < 0x10000 || next > 0x7ffffffeffff { return false }   // 用户态校验
//	readBlock(next, 32)                      // 在目标处读 32 字节
//	check(next, buf32, 32, tag="pointer")    // 当候选私钥校验
//
// 也就是说：**把某个槽位里的 8 字节当指针，跟着它去校验目标处的 32 字节**。
// 我们之前完全没有这个机制。
//
// 为什么它可能是关键：Go 的 `crypto/ecdh` 里，公钥和私钥是**两个独立的堆分配**：
//
//	type PrivateKey struct {
//	    curve      Curve   // 0x00, 16 字节（itab + data）
//	    publicKey  []byte  // 0x10 ptr / 0x18 len / 0x20 cap
//	    privateKey []byte  // 0x28 ptr / 0x30 len / 0x38 cap
//	}
//
// 我们在内存里扫到的公钥 32 字节，是 `publicKey` 那个 slice 的**底层数组**。
// 私钥那 32 字节在另一块堆上，两者地址毫无关系 —— 所以「贴着公钥扫 ±8 MB」
// 这个思路在原理上就可能是错的（第八轮/第九轮两次实测也确实都是 0 命中）。
//
// 正确的追法是**反查**：谁指向公钥那段字节？找到那个指针槽 q 之后，
// `privateKey.ptr` 就在 q 附近（布局里 publicKey.ptr 和 privateKey.ptr 相差 0x18）。
// 于是从 q 的相邻槽位里取指针去校验，就能跨过"地址不相关"这道墙。
//
// 成本：反查只是一次 8 字节比较，**不需要 X25519**，512 MB 副本约 0.3 秒；
// 每个命中槽位只多出十几个校验。相对于"再扫 3.3 GB"几乎免费。

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
)

const (
	// ptrMinUser / ptrMaxUser 是原版 chase 里的用户态地址范围校验
	// （反汇编里是 `cmp r12(=0x7ffffffeffff), rdx(=next-0x10000); jb fail`）。
	ptrMinUser = 0x10000
	ptrMaxUser = 0x7ffffffeffff

	// ptrChaseBack / ptrChaseFwd 决定从基准地址往前/往后各看几个 qword。
	//
	// ⚠ 这两个值原来是 4（±32 字节），依据是 Go 的 `crypto/ecdh.PrivateKey`
	// 布局（publicKey.ptr @0x10、privateKey.ptr @0x28，差 0x18 = 3 个 qword）。
	// **那个依据是错的** —— 那说的是我们自己 Go 程序的布局，而目标是 cs2.exe，
	// 一个 C++ 程序，根本不用 Go 的 crypto/ecdh。
	//
	// 19:10 现场：活内存里确实找到 1 个槽位指向公钥，但 ±4 个 qword 里只有
	// 2 个是合法指针，都没命中。而公钥命中点的 dump 显示，公钥周围本身就有
	// 一堆指针（-32/-24/-16、+64/+80）—— 说明这是 C++ 结构体，字段偏移未知。
	//
	// 所以放宽到 ±256 字节（±32 个 qword）。代价只是几十次 ReadProcessMemory
	// 和同量级 X25519 校验（每次命中点约 0.17 秒），换来"偏移猜错也不会漏"。
	ptrChaseBack = 32
	ptrChaseFwd  = 32

	// ptrChase2Depth 是"追几层"。
	//
	// 2 层覆盖的形态：`槽位 → 结构体 → 私钥指针 → 私钥字节`。
	// 只有 1 层时，如果槽位指向的是中间结构体而不是私钥本身，就永远找不到。
	// 每一层都会被 X25519 校验兜住，所以多追一层不会有假命中，只是多花时间。
	ptrChase2Depth = 2

	// inlineProbeRadius 是"锚点内联窗口"的探测半径（字节）。
	//
	// 20:36 现场给了一个非常具体的数字：槽位 0x2a083bd2ed8 与公钥命中 4/7
	// 0x2a083bd30e0 **在同一块 64 KB 区域、相距 520 字节**。
	// 也就是说引用公钥的那个结构体就在槽位附近，私钥如果内联在里面，
	// 一定落在 ±512 字节之内。取 512 正好把这个距离包住并留一倍余量。
	inlineProbeRadius = 512
)

// ptrReader 抽象"从哪读内存"：冻结副本 + 目标进程（副本没覆盖就退回活内存）。
type ptrReader struct {
	snap *memSnapshot
	proc *memscan.Process
}

func (r ptrReader) q(addr uintptr) (uintptr, bool) {
	if r.snap != nil {
		if v, ok := r.snap.readQword(addr); ok {
			return v, true
		}
	}
	if r.proc != nil {
		return readQwordLive(r.proc, addr)
	}
	return 0, false
}

func (r ptrReader) b32(addr uintptr) []byte {
	return readAt(r.snap, r.proc, addr, 32)
}

// chaseAt 从 base 前后 ptrChaseBack/ptrChaseFwd 个 qword 里取指针，
// 读目标处 32 字节当候选私钥校验；depth>1 时再往下追一层。
//
// 这就是原版 `chase` 的通用形态：不假设任何结构体布局，只假设
// "某个 8 字节格子里的值是一个指向密钥的地址"。
//
// 返回实际做了多少次校验。
func chaseAt(kf *keyfind.Search, r ptrReader, base uintptr, depth int, st *scanStat) (chases int) {
	if depth <= 0 || base < ptrMinUser {
		return 0
	}
	for k := -ptrChaseBack; k <= ptrChaseFwd; k++ {
		if kf.Found() {
			return chases
		}
		slot := uintptr(int64(base) + int64(k)*8)
		if slot < ptrMinUser {
			continue
		}
		t, ok := r.q(slot)
		if !ok || !isUserPtr(t) {
			continue
		}
		b := r.b32(t)
		if b == nil {
			st.shortRd.Add(1)
			continue
		}
		chases++
		st.cand.Add(1)
		if kf.Check(b, "pointer", t) {
			return chases
		}
		if depth > 1 {
			// 目标看起来是个结构体：在它内部再找一层指针。
			// 防止自我递归爆炸 —— depth 最多 2，所以只多一层。
			chases += chaseAt(kf, r, t, depth-1, st)
			if kf.Found() {
				return chases
			}
		}
	}
	return chases
}

// isUserPtr 判断 v 是否像一个用户态地址（原版 chase 的同一套判据）。
func isUserPtr(v uintptr) bool {
	return v >= ptrMinUser && v <= ptrMaxUser
}

// findPointersTo 在 buf（覆盖地址区间 base..base+len(buf)）里找出所有
// **8 字节对齐**、值等于 target 的位置，返回这些位置的绝对地址。
//
// 只认对齐是刻意的：Go 的 slice 底层数组至少 8 字节对齐，指向它的指针槽
// 也在结构体里按 8 字节对齐。逐字节找会把命中数放大 8 倍却几乎没有新增，
// 反而拖慢这一步。
func findPointersTo(buf []byte, base, target uintptr) []uintptr {
	if len(buf) < 8 || target == 0 {
		return nil
	}
	// 从 base 起第一个 8 字节对齐的偏移
	off := 0
	if r := base & 7; r != 0 {
		off = int(8 - r)
	}
	var out []uintptr
	for ; off+8 <= len(buf); off += 8 {
		if *(*uintptr)(unsafe.Pointer(&buf[off])) == target {
			out = append(out, base+uintptr(off))
		}
	}
	return out
}

// findPointersToAny 是 findPointersTo 的多目标版：一次遍历里把所有
// "值命中 targets 中任一元素"的 8 字节对齐槽位收集出来。
//
// 为什么要多目标版：一次运行里公钥可能有 6 处命中，单目标版要为每处各扫一遍
// 副本 —— 6 × 512 MB = 3 GB 的 qword 比较，其中 5 遍是纯重复。多目标版只扫一遍。
// （targets 里不会有 0，调用方已跳过 Addr==0 的命中，所以不必特判零值。）
func findPointersToAny(buf []byte, base uintptr, targets map[uintptr]struct{}) []uintptr {
	if len(buf) < 8 || len(targets) == 0 {
		return nil
	}
	off := 0
	if r := base & 7; r != 0 {
		off = int(8 - r)
	}
	var out []uintptr
	for ; off+8 <= len(buf); off += 8 {
		if _, ok := targets[*(*uintptr)(unsafe.Pointer(&buf[off]))]; ok {
			out = append(out, base+uintptr(off))
		}
	}
	return out
}

// readQword 从副本里读一个 8 字节；不完整则返回 (0,false)。
func (s *memSnapshot) readQword(addr uintptr) (uintptr, bool) {
	if s == nil {
		return 0, false
	}
	for _, c := range s.chunks {
		lo := c.addr
		hi := lo + uintptr(len(c.data))
		if addr >= lo && addr+8 <= hi {
			return *(*uintptr)(unsafe.Pointer(&c.data[addr-lo])), true
		}
	}
	return 0, false
}

// readBytes 从副本里读 n 字节；不完整则返回 nil（调用方再退回读进程）。
func (s *memSnapshot) readBytes(addr uintptr, n int) []byte {
	if s == nil || n <= 0 {
		return nil
	}
	for _, c := range s.chunks {
		lo := c.addr
		hi := lo + uintptr(len(c.data))
		if addr >= lo && addr+uintptr(n) <= hi {
			return c.data[addr-lo : addr-lo+uintptr(n)]
		}
	}
	return nil
}

// readAt 优先从副本读，副本没覆盖到再读目标进程。
// 返回 nil 表示读不到（地址不可读 / 跨了副本边界且进程读失败）。
func readAt(s *memSnapshot, proc *memscan.Process, addr uintptr, n int) []byte {
	if b := s.readBytes(addr, n); b != nil {
		return b
	}
	if proc == nil {
		return nil
	}
	buf := make([]byte, n)
	got, err := proc.ReadAt(addr, buf)
	if err != nil || got < n {
		return nil
	}
	return buf
}

// scanPointersToLive 在目标进程的**活内存**里反查指向公钥的槽位。
//
// ── 为什么必须有这一版（2026-10-17 18:47 现场教训）────────────────────
//
// 第十一轮的 scanPointersTo 只在**冻结副本**里找。但副本只有
// 465.8 MB / 7516.9 MB = 6.2%。如果引用公钥的那个结构体落在没抄到的那 93.8% 里，
// 反查就会得出「槽位 0 个」的假结论 —— 用户会据此以为"这 32 字节不是公钥"，
// 方向被彻底带偏。
//
// 原版 chase 直接读活内存，没有这个盲区。而且它**不需要冻结**：
// 只是 ReadProcessMemory + 8 字节比较，对游戏零影响。
//
// 成本：一次全可读区扫描和「公钥定位」同量级 —— 本机 7.5 GB / 1.69 s，
// 因为两者都只是内存比较，不需要 X25519。
func scanPointersToLive(kf *keyfind.Search, proc *memscan.Process, regions []memscan.Region,
	pubHits []pubHit, deadline time.Time, st *scanStat) (slots, chases int) {
	if kf == nil || proc == nil || len(pubHits) == 0 || st == nil {
		return 0, 0
	}
	start := time.Now()
	defer func() { st.elapsed += time.Since(start) }()

	want := make(map[uintptr]struct{}, len(pubHits))
	for _, h := range pubHits {
		if h.Addr != 0 {
			want[h.Addr] = struct{}{}
		}
	}
	if len(want) == 0 {
		return 0, 0
	}

	// 只扫「有东西可写」的区域：指针槽一定在可写内存里（堆/栈），
	// 只读的 PE 映像里不会存指向堆对象的指针。这一步能把扫描量砍掉一大截。
	ranges := make([]scanRange, 0, len(regions))
	for _, r := range regions {
		if r.Size == 0 || !regionWritable(r) {
			continue
		}
		ranges = append(ranges, scanRange{lo: r.Base, hi: r.Base + r.Size, tag: "ptr-live"})
	}
	if len(ranges) == 0 {
		return 0, 0
	}
	ranges = mergeRanges(ranges)

	var (
		mu      sync.Mutex
		found   []uintptr
		seen    = make(map[uintptr]struct{}, 64)
		stop    atomic.Bool
		workers = numWorkers()
		ch      = make(chan scanRange, 64)
		wg      sync.WaitGroup
	)
	go func() {
		defer close(ch)
		for _, r := range splitRanges(ranges) {
			if stop.Load() || kf.Found() {
				return
			}
			ch <- r
		}
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 0, scanChunk)
			for r := range ch {
				if stop.Load() || kf.Found() || time.Now().After(deadline) {
					stop.Store(true)
					continue
				}
				n := int(r.hi - r.lo)
				if cap(buf) < n {
					buf = make([]byte, n)
				}
				buf = buf[:n]
				got, err := proc.ReadAt(r.lo, buf)
				if err != nil || got <= 0 {
					st.shortRd.Add(1)
					continue
				}
				st.bytes.Add(uint64(got))
				st.regions.Add(1)
				for _, q := range findPointersToAny(buf[:got], r.lo, want) {
					mu.Lock()
					if _, dup := seen[q]; !dup {
						seen[q] = struct{}{}
						found = append(found, q)
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	slots = len(found)
	st.slotAddrs = append([]uintptr(nil), found...)

	r := ptrReader{proc: proc}

	// ① 从每个"指向公钥的槽位"追。
	for _, q := range found {
		if kf.Found() {
			return slots, chases
		}
		if time.Now().After(deadline) {
			st.deadline = true
			return slots, chases
		}
		chases += chaseAt(kf, r, q, ptrChase2Depth, st)
	}

	// ② 从每个公钥命中点本身追（公钥内联在 C++ 结构体里的情况）。
	for _, h := range pubHits {
		if kf.Found() {
			return slots, chases
		}
		if h.Addr == 0 {
			continue // 0 不是"超时"，别把 st.deadline 打上
		}
		if time.Now().After(deadline) {
			st.deadline = true
			return slots, chases
		}
		chases += chaseAt(kf, r, h.Addr, ptrChase2Depth, st)
	}
	return slots, chases
}

// probeInlineWindows 在锚点周围 ±inlineProbeRadius 字节内，按 **1 字节步长**
// 滑 32 字节窗口，逐个当私钥校验。
//
// ── 为什么 chaseAt 覆盖不了这里 ──────────────────────────────────────
//
// chaseAt 只认"某个 8 字节格子里的值是一个合法指针"，然后跟着指针去校验
// **目标处**的 32 字节。如果私钥是**内联**在结构体里的，形态是
//
//	struct { uint8_t priv[32]; ... uint8_t *pub; }
//
// 那它既不是任何指针的目标，也不一定 8 字节对齐 —— chaseAt 一个都碰不到。
// 20:36 现场正是这个形状：指针追了 3006 次全空，但槽位和公钥只隔 520 字节。
//
// ── 为什么"邻域副本已逐字节校验过"也不够 ─────────────────────────────
//
// 邻域那 40.4 MB 走的是 DefaultPrivFilter（通过率约 1.3%）+ 高熵段降级成
// 8 字节步长：现场日志「校验 566264 次」对应 4240 万个偏移，也就是说
// **98.7% 的偏移根本没被看过**。锚点周围这 1 KB 恰恰是最该"一个偏移都不放过"
// 的地方，所以这里不走预筛、不走步长、不降级。
//
// 成本：每个锚点 (2*512+32)-31 = 1025 次校验 ≈ 40 ms。锚点通常个位数。
func probeInlineWindows(kf *keyfind.Search, r ptrReader, anchors []uintptr, st *scanStat) (chases int) {
	if kf == nil || len(anchors) == 0 {
		return 0
	}
	seen := make(map[uintptr]struct{}, len(anchors)*8)
	for _, a := range anchors {
		if a < ptrMinUser || kf.Found() {
			continue
		}
		lo := a
		if a >= inlineProbeRadius {
			lo = a - inlineProbeRadius
		}
		n := int(a-lo) + inlineProbeRadius + 32

		buf := readAt(r.snap, r.proc, lo, n)
		if buf == nil {
			// 整块读不到（跨副本边界 / 区域尾部）：退回逐偏移读，
			// 慢一点但不会整段漏掉。
			for off := 0; off+32 <= n; off++ {
				addr := lo + uintptr(off)
				if _, dup := seen[addr]; dup {
					continue
				}
				b := readAt(r.snap, r.proc, addr, 32)
				if b == nil {
					st.shortRd.Add(1)
					continue
				}
				seen[addr] = struct{}{}
				chases++
				st.cand.Add(1)
				if kf.Check(b, "inline", addr) {
					return chases
				}
			}
			continue
		}
		for off := 0; off+32 <= len(buf); off++ {
			addr := lo + uintptr(off)
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			chases++
			st.cand.Add(1)
			if kf.Check(buf[off:off+32], "inline", addr) {
				return chases
			}
		}
	}
	return chases
}

// readQwordLive 从目标进程读一个 8 字节。
func readQwordLive(proc *memscan.Process, addr uintptr) (uintptr, bool) {
	if proc == nil {
		return 0, false
	}
	var b [8]byte
	if got, err := proc.ReadAt(addr, b[:]); err != nil || got < 8 {
		return 0, false
	}
	return *(*uintptr)(unsafe.Pointer(&b[0])), true
}

// regionWritable 判断一个区域是否可写（指针槽只会出现在可写内存里）。
func regionWritable(r memscan.Region) bool {
	const (
		pageReadWrite = 0x04
		pageWriteCopy = 0x08
		pageExecuteRW = 0x40
		pageExecuteWC = 0x80
	)
	if r.Protect&0xFF == 0x01 { // PAGE_NOACCESS
		return false
	}
	return r.Protect&(pageReadWrite|pageWriteCopy|pageExecuteRW|pageExecuteWC) != 0
}

// scanPointersTo 是"指针反查"这一级的本体。
//
// 对公钥的全部命中地址 {p1..pn}：
//  1. 在副本里**一次遍历**反查出所有 `*(uint64)q ∈ {p1..pn}` 的 q（谁指向公钥字节）；
//  2. 从 q 往前 ptrChaseBack、往后 ptrChaseFwd 个 qword 逐个当指针 t；
//  3. 读 t 处 32 字节，交给 kf 校验（和原版 chase 完全一致）。
//
// 全程不需要冻结：副本是冻结那一刻的字节，反查和校验都在解冻之后做。
//
// 返回值：slots = 找到多少个"指向公钥的槽位"，chases = 实际做了多少次校验。
func scanPointersTo(kf *keyfind.Search, proc *memscan.Process, snap *memSnapshot,
	pubHits []pubHit, deadline time.Time, st *scanStat) (slots, chases int) {
	if kf == nil || snap == nil || len(pubHits) == 0 || st == nil {
		return 0, 0
	}
	start := time.Now()
	defer func() { st.elapsed += time.Since(start) }()

	want := make(map[uintptr]struct{}, len(pubHits))
	for _, h := range pubHits {
		if h.Addr != 0 {
			want[h.Addr] = struct{}{}
		}
	}
	if len(want) == 0 {
		return 0, 0
	}

	// 一次遍历副本，把所有指向任一公钥命中的槽位都捞出来。
	//
	// 🔴 必须并行。这一步是纯 8 字节比较、不需要 X25519，本该贴着内存带宽跑。
	// 03:43 现场：1024 MB 副本串行比较花了 **742 ms**（1.4 GB/s），
	// 而同一台机器并行 memmem 能到 15 GB/s（locatePub 扫 1236 MB 只用 79 ms）。
	// 差 10 倍，纯粹是没用多核。
	targets := make([]uintptr, 0, 64)
	{
		var (
			mu     sync.Mutex
			seen   = make(map[uintptr]struct{}, 64)
			stop   atomic.Bool
			wg     sync.WaitGroup
			ch     = make(chan snapChunk, 64)
			worker = numWorkers()
		)
		go func() {
			defer close(ch)
			for _, c := range snap.chunks {
				if stop.Load() {
					return
				}
				ch <- c
			}
		}()
		for i := 0; i < worker; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for c := range ch {
					if stop.Load() {
						continue
					}
					if kf.Found() {
						// 命中优先于超时：别把"已命中"标成 deadline。
						stop.Store(true)
						continue
					}
					if time.Now().After(deadline) {
						mu.Lock()
						st.deadline = true
						mu.Unlock()
						stop.Store(true)
						continue
					}
					st.bytes.Add(uint64(len(c.data)))
					st.regions.Add(1)
					hits := findPointersToAny(c.data, c.addr, want)
					if len(hits) == 0 {
						continue
					}
					mu.Lock()
					for _, q := range hits {
						if _, dup := seen[q]; dup {
							continue
						}
						seen[q] = struct{}{}
						targets = append(targets, q)
					}
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		// 并行之后顺序是随机的；按地址排序让日志和后续追击顺序可复现。
		sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	}
	slots = len(targets)
	st.slotAddrs = append([]uintptr(nil), targets...)

	r := ptrReader{snap: snap, proc: proc}

	// ① 从每个"指向公钥的槽位"追。
	chases += parallelChase(kf, r, targets, ptrChase2Depth, deadline, st)

	// ② 从每个**公钥命中点本身**追。
	//
	// 19:10 现场：命中点 dump 显示公钥周围就是一堆指针
	// （-32/-24/-16、+64/+80），说明公钥是**内联在 C++ 结构体里**的，
	// 而不是被一个槽位指着。这种情况下只从"槽位"追就完全追不到 ——
	// 私钥指针可能就在公钥自己 ±256 字节内。
	anchors := make([]uintptr, 0, len(pubHits))
	for _, h := range pubHits {
		if h.Addr != 0 {
			anchors = append(anchors, h.Addr)
		}
	}
	chases += parallelChase(kf, r, anchors, ptrChase2Depth, deadline, st)
	if kf.Found() {
		return slots, chases
	}
	if time.Now().After(deadline) {
		st.deadline = true
	}
	return slots, chases
}

// parallelChase 把「从一批基址各追一次指针链」并行化。
//
// 🔴 为什么必须并行（2026-10-19 04:10 现场）：
//
//	指针反查：…｜跟踪校验 521 次｜耗时 955ms
//
// 955 ms 里几乎全是 chaseAt 里**读活内存**的 ReadProcessMemory：
// 每个基址要看 ±32 个 qword（65 个），每个格子里的指针 t 还要读 32 字节，
// depth=2 时再对 t 展开一层 —— 单个槽位就是 65×65 次读。
// 副本内的读是内存拷贝（纳秒级），但 t 一旦落在副本没覆盖的地方就退回
// 读活内存，一次 200 µs 上下。串行跑完就是将近一秒。
//
// 这一步之间各基址**互不依赖**（每个都独立地"从它出发找私钥"），
// 所以可以放心并行；kf.Check 本身是线程安全的（found 原子 + once）。
func parallelChase(kf *keyfind.Search, r ptrReader, bases []uintptr, depth int,
	deadline time.Time, st *scanStat) int {
	if len(bases) == 0 {
		return 0
	}
	if len(bases) == 1 {
		return chaseAt(kf, r, bases[0], depth, st)
	}
	workers := numWorkers()
	if workers > len(bases) {
		workers = len(bases)
	}
	if workers < 1 {
		workers = 1
	}
	var (
		wg    sync.WaitGroup
		total atomic.Int64
		stop  atomic.Bool
	)
	ch := make(chan uintptr, len(bases))
	for _, b := range bases {
		ch <- b
	}
	close(ch)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range ch {
				if kf.Found() || stop.Load() {
					continue
				}
				if !deadline.IsZero() && time.Now().After(deadline) {
					stop.Store(true)
					continue
				}
				total.Add(int64(chaseAt(kf, r, b, depth, st)))
			}
		}()
	}
	wg.Wait()
	return int(total.Load())
}
