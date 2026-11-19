package main

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
)

// ── 冻结窗口只做「读」，不做「算」（2026-10-17 第七轮）──
//
// 用户现场（16:50 那份日志）：
//
//	冻结 6s｜**超时被强制解冻**｜第 1 级：读 0.4 MB｜校验 433648 次｜耗时 4.294s｜**超时截断**
//
// 这行数字说明冻结窗口被用错了地方：**只读了 0.44 MB，却花了 4.294 秒**。
// 时间全花在 43 万次 X25519 校验上（每次约 10 µs）。而定位公钥又花了 2.225 秒。
// 也就是说 6 秒冻结预算里，真正"必须冻着做"的读取只占几十毫秒，
// 剩下 99% 都是**不需要冻结的计算**。
//
// 正确的分工：
//
//	冻结期间 → 把命中点附近的字节**读出来存到本地**（memcpy 级别，几毫秒）
//	解冻之后 → 在本地副本上慢慢跑 X25519 校验（想跑多久跑多久，游戏不受影响）
//
// 好处是两头都赚：
//   - 冻结时长从 6 秒降到 1 秒以内（用户感知明显）；
//   - 冻结期间能读的范围从 0.44 MB 扩到几十 MB（覆盖率反而高一个数量级）。
//
// 这也是对"冻结太短还是太早"这个问题的答案：时机不能晚（晚了私钥就没了），
// 时长不必长（长的部分本来就不需要冻着）。

// snapChunk 是一段被复制到本地的内存。
type snapChunk struct {
	addr uintptr
	data []byte
}

// memSnapshot 是冻结窗口内抓下来的内存副本。
//
// 只在冻结期间调用 takeSnapshot；之后的 verify 全部在解冻后进行。
type memSnapshot struct {
	chunks    []snapChunk
	primary   int    // chunks[0:primary] 是"命中点邻域"，其余是按评分补的
	bytes     uint64 // 实际复制到的字节数
	shortRead uint64 // 读失败/短读次数
	regions   int    // 覆盖的区间数
	truncated bool   // 是否因为上限被截断
}

// coveredRanges 返回副本实际覆盖到的地址区间（已合并）。
//
// 用途：把它交给后面的"全可写区兜底"当作"已扫过"，避免同一片内存被扫两遍。
// 用户现场 17:27：副本里 450 MB「其余」校验花了 2 分 38 秒，随后兜底又把
// 这几百 MB 从头扫了一遍 —— 白白多花两分半。
func (s *memSnapshot) coveredRanges() []scanRange {
	if s == nil || len(s.chunks) == 0 {
		return nil
	}
	out := make([]scanRange, 0, len(s.chunks))
	for _, c := range s.chunks {
		out = append(out, scanRange{lo: c.addr, hi: c.addr + uintptr(len(c.data)), tag: "snap"})
	}
	return mergeRanges(out)
}

// primaryBytes 返回邻域部分（最先校验、也最可能命中）的字节数。
func (s *memSnapshot) primaryBytes() uint64 {
	if s == nil {
		return 0
	}
	var n uint64
	for i := 0; i < s.primary && i < len(s.chunks); i++ {
		n += uint64(len(s.chunks[i].data))
	}
	return n
}

func (s *memSnapshot) total() uint64 {
	if s == nil {
		return 0
	}
	return s.bytes
}

// snapRead 从冻结副本里读 [addr, addr+n) 的字节。
//
// 只在**完整覆盖**时才返回（副本是分段抓的，一段一个 chunk）；
// 不完整就返回 nil，让调用方退回读活内存 —— 半截数据比没有更危险。
//
// 为什么需要它：槽位是在副本里反查出来的，而渲染 dump 时若去读活内存，
// 读到的是一分钟后的状态（对象可能已被释放/复用），于是"值等于公钥地址
// 的槽位"会显示成 0，看起来像反查算法有 bug。20:18 现场正是如此。
func snapRead(s *memSnapshot, addr uintptr, n int) []byte {
	if s == nil || n <= 0 {
		return nil
	}
	end := addr + uintptr(n)
	for _, c := range s.chunks {
		if len(c.data) == 0 {
			continue
		}
		if addr >= c.addr && end <= c.addr+uintptr(len(c.data)) {
			off := int(addr - c.addr)
			return c.data[off : off+n]
		}
	}
	return nil
}

// summary 用于日志/诊断报告。
func (s *memSnapshot) summary() string {
	if s == nil {
		return "未抓取"
	}
	tail := ""
	if s.truncated {
		tail = "｜**达到上限被截断**"
	}
	return itoa(int(s.bytes>>10)) + " KB" + tail
}

// snapshotWindow 是冻结期间每个命中点向两侧抓取的字节数。
//
// 8 MB 是原分级策略里最大的一级（±64 KB → ±1 MB → ±8 MB）。现在一次就抓完，
// 因为"抓"只要几十毫秒，而"校验"搬到解冻之后做。
// 实测用户现场：6 处命中 × 16 MB 窗口，与区域求交后约 67 MB。
const snapshotWindow = 8 << 20

// snapshotDefaultMax 是单次快照的字节上限。
//
// 256 MB 的堆分配对 64 位进程不是问题，而 67 MB（±8 MB × 6 处命中）是实测量级。
// 设上限是为了防止"命中点特别多 + 区域特别大"时把内存吃爆。
const snapshotDefaultMax = 256 << 20

// snapshotCapBytes 是冻结期间抓取的总字节上限，由 -snap-mb 覆盖。
//
// 第八轮把它从「命中点 ±8 MB 求交」（用户现场 64 MB，占可写区 0.9%）放开到
// 512 MB，理由是**读几乎免费**：实测抓 64 MB 只占掉 978 ms 冻结时长里的一小部分
// （memcpy 级别，约 2 GB/s），而可写区有 7068.9 MB。
//
// 🔴 2026-10-19 03:30 改成 1024 MB —— 因为 takeSnapshot 改成并行了。
//
// 基准（`BenchmarkTakeSnapshot`，Ryzen 7 5700X，128 MB / 128 段）：
//
//	并行后：6.69 GB/s  → 512 MB 约 77 ms，1024 MB 约 153 ms
//	改造前：约 0.95 GB/s（现场实测 512 MB 抄了 540 ms）
//
// 所以现在「1024 MB / ~150 ms」比改造前「512 MB / 540 ms」**又快又全**。
// 冻结时长才是反作弊风险的主要来源（21:01 那次 1.979 s 被封），
// 而读量只在本机内存里发生 —— 这笔交易明显划算。
//
// 上限别再往上顶：700 ms 冻结减去解冻余量后只有约 560 ms 可用，
// 4096 MB 需要约 611 ms，会撞看门狗。
//
// 注意：抓得多不等于校验得完 —— X25519 校验才是真瓶颈（见 verify 的预算参数）。
// 所以抓取上限放宽、校验按优先级 + 预算进行，两头解耦。
var snapshotCapBytes uintptr = 1024 << 20

// takeSnapshot 把 ranges 覆盖到的字节全部复制到本地。
//
// 必须在冻结窗口内调用 —— 它的唯一目的就是"趁进程不动，把字节抢下来"。
//
// ── 为什么必须并行（2026-10-19 03:05 实测）────────────────────────────
//
// 原来是单线程顺序读：512 MB 花了 **540 ms**（≈0.95 GB/s），几乎吃满
// 700 ms 冻结预算。而同一份日志里 `locatePub` 扫 993 MB 只用了 **63 ms**
// （≈15.7 GB/s）—— 两者都是 ReadProcessMemory，差 16 倍，
// **差别只在有没有并行**。
//
// 冻结时长直接等于反作弊风险（21:01 那次 1.979 s 被封号）。
// 并行之后同样的 512 MB 只要 ~100 ms，冻结时长跟着降一个数量级；
// 反过来也可以在同样 700 ms 里抄下 3~4 GB。
// 两头都赚，所以这里必须并行。
//
// primaryCount 是 ranges 里属于"命中点邻域"的前几段（其余是按区域评分补的）。
// 记下来是为了解冻后**先校验邻域**：私钥更可能在公钥旁边，先花几十秒把最可能
// 的地方排除掉，比均匀地摊到几百 MB 上更有意义。
func takeSnapshot(proc *memscan.Process, ranges []scanRange, primaryCount int,
	maxBytes uintptr, deadline time.Time) *memSnapshot {
	s := &memSnapshot{}
	if proc == nil || len(ranges) == 0 {
		return s
	}
	if maxBytes <= 0 {
		maxBytes = snapshotDefaultMax
	}
	const block = 1 << 20

	// ① 先把 ranges 展开成 1 MB 块列表，**保持优先级顺序**
	//    （takeSnapshot 的调用方按"邻域 → 小区域 → …"排好了序，
	//     这里不能重排，否则预算截断时就又抄到没用的地方去了）。
	type blockRef struct {
		addr      uintptr
		want      int
		isPrimary bool
	}
	var blocks []blockRef
	for ri, r := range ranges {
		isP := ri < primaryCount
		for a := r.lo; a < r.hi; a += block {
			want := block
			if rem := r.hi - a; rem < uintptr(block) {
				want = int(rem)
			}
			if want < 32 {
				break
			}
			blocks = append(blocks, blockRef{addr: a, want: want, isPrimary: isP})
		}
	}
	if len(blocks) == 0 {
		return s
	}

	workers := numWorkers()
	if workers > 16 {
		workers = 16 // 再多收益很小，而每个 worker 要占 1 MB 缓冲
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(blocks) {
		workers = len(blocks)
	}

	var (
		mu      sync.Mutex
		near    []snapChunk
		rest    []snapChunk
		got     uintptr
		shortRd uint64
		trunc   bool
		stop    atomic.Bool
	)
	ch := make(chan blockRef, 128)
	go func() {
		defer close(ch)
		for _, b := range blocks {
			if stop.Load() {
				return
			}
			ch <- b
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, block)
			for b := range ch {
				if stop.Load() {
					continue
				}
				if !deadline.IsZero() && time.Now().After(deadline) {
					mu.Lock()
					trunc = true
					mu.Unlock()
					stop.Store(true)
					continue
				}
				// 预算用"先占位、再读"的方式控制：占不到就直接停，
				// 保证总量不超过 maxBytes（短读造成的浪费可接受）。
				mu.Lock()
				if got >= maxBytes {
					trunc = true
					mu.Unlock()
					stop.Store(true)
					continue
				}
				want := b.want
				if rem := maxBytes - got; rem < uintptr(want) {
					want = int(rem)
				}
				got += uintptr(want)
				mu.Unlock()
				if want < 32 {
					stop.Store(true)
					continue
				}
				n, err := proc.ReadAt(b.addr, buf[:want])
				if err != nil || n < 32 {
					mu.Lock()
					shortRd++
					mu.Unlock()
					continue
				}
				// 必须拷贝：buf 下一轮就被覆盖了。
				c := snapChunk{addr: b.addr, data: append([]byte(nil), buf[:n]...)}
				mu.Lock()
				if b.isPrimary {
					near = append(near, c)
				} else {
					rest = append(rest, c)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// ② 按地址排序：并行之后顺序是随机的，而下游的 verifyNear/verifyRest
	//    以及 coveredRanges 都假定副本是**地址升序**（原来顺序读天然满足）。
	sort.Slice(near, func(i, j int) bool { return near[i].addr < near[j].addr })
	sort.Slice(rest, func(i, j int) bool { return rest[i].addr < rest[j].addr })
	s.chunks = append(near, rest...)
	s.primary = len(near)
	s.shortRead = shortRd
	s.truncated = trunc || got >= maxBytes
	s.regions = len(s.chunks)
	for _, c := range s.chunks {
		s.bytes += uint64(len(c.data))
	}
	return s
}

// primaryRanges 返回「邻域副本」实际覆盖到的地址区间（已合并）。
//
// ⚠ 千万别用 `snap.primary > 0` 当作"邻域已经校验过了"。`primary` 是在遍历到
// 第 primaryCount 段时**就**记下的下标，而段内可能发生短读（ReadAt 失败）或
// 尾部不足 32 字节 —— 这时这一段只覆盖了一部分，`primary` 仍然 > 0。
// 第九轮的 coveredNear 就是只看 > 0，一旦某个命中点窗口里有洞，前三级邻域
// 扫描会被**静默跳过**：不报错、不提示，只是永远找不到私钥。
func (s *memSnapshot) primaryRanges() []scanRange {
	if s == nil || s.primary <= 0 {
		return nil
	}
	out := make([]scanRange, 0, s.primary)
	for _, c := range s.chunks[:s.primary] {
		out = append(out, scanRange{
			lo:  c.addr,
			hi:  c.addr + uintptr(len(c.data)),
			tag: "snap-near",
		})
	}
	return mergeRanges(out)
}

// coversRange 报告 [lo,hi) 是否被 ranges（已合并、升序）完整覆盖。
//
// 空窗口（hi<=lo）算覆盖 —— 调用方用"与可读区求交"的结果，交集为空时
// 本来就没有东西要扫。
func coversRange(ranges []scanRange, lo, hi uintptr) bool {
	if hi <= lo {
		return true
	}
	cur := lo
	for _, r := range ranges {
		if r.hi <= cur {
			continue
		}
		if r.lo > cur {
			return false // 中间有洞
		}
		cur = r.hi
		if cur >= hi {
			return true
		}
	}
	return false
}

// verify 在本地副本上跑 X25519 校验（解冻之后调用）。
//
// 和 scanRangesStat 的差别只有一处：数据来源是本地内存而不是目标进程，
// 所以不需要冻结、不需要考虑短读、可以用满所有核而不用担心影响游戏。
func (s *memSnapshot) verify(kf *keyfind.Search, deadline time.Time, st *scanStat) bool {
	if s == nil {
		return false
	}
	return s.verifyRange(kf, 0, len(s.chunks), deadline, st)
}

// verifyNear 只校验"命中点邻域"那一段（chunks[0:primary]）。
//
// 单独拆出来是因为优先级不同：邻域只有几十 MB，几十秒就能跑完，
// 而全量副本可能是几百 MB。先跑完邻域，"私钥到底在不在公钥旁边"这个
// 问题在 1 分钟内就有答案；后面的大范围校验即使被关窗口打断，结论也不受影响。
func (s *memSnapshot) verifyNear(kf *keyfind.Search, deadline time.Time, st *scanStat) bool {
	if s == nil {
		return false
	}
	return s.verifyRange(kf, 0, s.primary, deadline, st)
}

// verifyRest 校验邻域之外的剩余部分。
func (s *memSnapshot) verifyRest(kf *keyfind.Search, deadline time.Time, st *scanStat) bool {
	if s == nil {
		return false
	}
	return s.verifyRange(kf, s.primary, len(s.chunks), deadline, st)
}

func (s *memSnapshot) verifyRange(kf *keyfind.Search, from, to int, deadline time.Time,
	st *scanStat) bool {
	if s == nil || kf == nil {
		return false
	}
	if from < 0 {
		from = 0
	}
	if to > len(s.chunks) {
		to = len(s.chunks)
	}
	if from >= to {
		return false
	}
	pf := privFilter{MinDistinct: 0, MaxZeros: -1}
	if s.bytes > uint64(exhaustiveLimit) && !privFilterDisabled {
		pf = DefaultPrivFilter
	}
	st.filter = pf
	st.filtered = pf.Enabled()

	begin := time.Now()
	defer func() {
		st.elapsed += time.Since(begin)
		if !deadline.IsZero() && time.Now().After(deadline) {
			st.deadline = true
		}
	}()

	workers := numWorkers()
	ch := make(chan snapChunk, 32)
	var wg sync.WaitGroup
	var stop atomic.Bool

	go func() {
		defer close(ch)
		for _, c := range s.chunks[from:to] {
			if stop.Load() {
				return
			}
			ch <- c
		}
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range ch {
				if stop.Load() || kf.Found() ||
					(!deadline.IsZero() && time.Now().After(deadline)) {
					stop.Store(true)
					continue
				}
				st.regions.Add(1)
				st.bytes.Add(uint64(len(c.data)))
				if scanBufferStatClampFirst(kf, c.data, c.addr, "snapshot", pf, st) {
					stop.Store(true)
					return
				}
			}
		}()
	}
	wg.Wait()
	return kf.Found()
}
