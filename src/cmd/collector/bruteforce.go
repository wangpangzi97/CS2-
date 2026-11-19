// 全内存暴力找会话密钥 —— 不依赖任何锚点。
//
// 为什么需要这一层
// ----------------
// 2026-10-19 08:03 实测：客户端公钥在内存里只有 2 处、指针槽位 4 处，
// 围着这 6 个锚点从 ±512B 一直试到 ±64KB，全部没中。
// 也就是说「会话密钥就在握手状态结构体旁边」这个假设是错的 ——
// 它可能在别的分配里，离公钥十万八千里。
//
// 继续找更强的锚点是在赌运气。换一个确定性的做法：
//
//	AES-GCM 的认证标签是「密钥对不对」的完美判据（错一字节必失败），
//	那就把**整个可写内存按字节遍历一遍**，每个位置取 32 字节当密钥试一帧。
//
// 代价是算得出来的：单核一次约 280 ns（实测 BenchmarkGCMOpenPerKey），
// 5 GB 可写内存按字节遍历 = 5e9 次 × 280 ns / 16 线程 ≈ 90 秒。
// 这个量级完全可接受，而且**结果是确定的** —— 命中就是命中，没命中就说明
// 参数（cipher / 密文起点 / nonce 构造 / AAD）猜错了，而不是"没找到地方"。
//
// 参数按可能性排序，逐个组合跑；每个组合跑完才换下一个，命中立刻停。
package main

import (
	"encoding/binary"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/memscan"
)

// skCombo 是一组待暴力验证的加解密参数。
type skCombo struct {
	name   string
	cipher string
	keyLen int
	offset int
	nonce  int // 0=零前缀+LE64 1=连接ID前缀+LE64 2=零前缀+LE32 3=零前缀+BE64
	aad    int // 0=无 1=帧头[:offset]
}

// 非 zero 前缀的 nonce 用 prefix4-* 方案；其余用现成的。
func (c skCombo) nonceName() string {
	switch c.nonce {
	case 1:
		return "prefix4-ctr-le-u64"
	case 2:
		return "ctr-le-u32"
	case 3:
		return "ctr-be-u64"
	case 4:
		return "seq-le64-head"
	default:
		return "ctr-le-u64"
	}
}

// skTarget 是一帧在某个组合下的「密文 / nonce / AAD」三元组。
type skTarget struct {
	ct    []byte
	nonce []byte
	aad   []byte
}

// buildTargets 把一个组合套到所有帧上，得到可直接喂给 TryOpen 的三元组。
func buildTargets(frames [][]byte, c skCombo) []skTarget {
	out := make([]skTarget, 0, len(frames))
	for i, f := range frames {
		if len(f) <= c.offset+16 { // 至少要有 16 字节 tag
			continue
		}
		// 只有当帧头确实存在（密文起点 ≥7）时才用线上序号；
		// 否则 f[5:7] 是密文，读出来的"序号"是垃圾。
		seq := uint64(i)
		if c.offset >= 7 {
			if v, ok := cs2crypto.FrameSeq(f); ok {
				seq = v
			}
		}
		nonce := make([]byte, 12)
		switch c.nonce {
		case 1:
			copy(nonce[:4], f[1:5])
			binary.LittleEndian.PutUint64(nonce[4:], seq)
		case 2:
			binary.LittleEndian.PutUint32(nonce[8:], uint32(seq))
		case 3:
			binary.BigEndian.PutUint64(nonce[4:], seq)
		case 4:
			binary.LittleEndian.PutUint64(nonce[0:], seq)
		default:
			binary.LittleEndian.PutUint64(nonce[4:], seq)
		}
		var aad []byte
		if c.aad == 1 {
			aad = f[:c.offset]
		}
		out = append(out, skTarget{ct: f[c.offset:], nonce: nonce, aad: aad})
	}
	return out
}

// 默认组合表，按可能性从高到低。
//
// 依据：帧布局是 [0x82][连接ID 4][包序号 2 小端][密文]（真实抓包 2837 帧验证过），
// 所以密文起点 7 是确定的；不确定的是 cipher / nonce 构造 / AAD。
func defaultCombos() []skCombo {
	return []skCombo{
		{"gcm256 off7 le64", "aes-256-gcm", 32, 7, 0, 0},
		{"gcm256 off7 le64 +aad7", "aes-256-gcm", 32, 7, 0, 1},
		{"gcm256 off7 connid+le64", "aes-256-gcm", 32, 7, 1, 0},
		{"gcm256 off7 seq-head", "aes-256-gcm", 32, 7, 4, 0},
		{"gcm256 off7 le32", "aes-256-gcm", 32, 7, 2, 0},
		{"gcm128 off7 le64", "aes-128-gcm", 16, 7, 0, 0},
		{"gcm256 off7 be64", "aes-256-gcm", 32, 7, 3, 0},
		{"gcm256 off0 le64", "aes-256-gcm", 32, 0, 0, 0},
	}
}

// bruteResult 是一次暴力搜索的产物。
type bruteResult struct {
	combo skCombo
	key   []byte
	addr  uintptr
}

// bruteSearch 依次用每个组合扫全内存，命中即返回。
func bruteSearch(proc *memscan.Process, frames [][]byte, combos []skCombo,
	deadline time.Time) (bruteResult, bool) {

	for _, c := range combos {
		if time.Now().After(deadline) {
			privateDiagnosticf("[sk] 暴力搜索预算用尽，未跑的组合：%d 个\n", len(combos))
			return bruteResult{}, false
		}
		tg := buildTargets(frames, c)
		if len(tg) < 3 {
			continue
		}
		// 最短的帧放最前面：内层循环每多 16 字节密文就多一次 GHASH。
		for i := 1; i < len(tg); i++ {
			for j := i; j > 0 && len(tg[j].ct) < len(tg[j-1].ct); j-- {
				tg[j], tg[j-1] = tg[j-1], tg[j]
			}
		}

		t0 := time.Now()
		privateDiagnosticf("[sk] 暴力搜索开始：%s（密钥 %d 字节，判据帧 %d 字节）\n",
			c.name, c.keyLen, len(tg[0].ct))

		key, addr, scanned, ok := scanAllMemory(proc, c.keyLen, tg, deadline, true)
		rate := float64(scanned) / time.Since(t0).Seconds() / (1 << 20)
		privateDiagnosticf("[sk]   %s 扫完 %.1f MB（%.0f MB/s，%s）→ %s\n",
			c.name, float64(scanned)/(1<<20), rate,
			time.Since(t0).Truncate(time.Millisecond), hitText(ok))

		if ok {
			return bruteResult{combo: c, key: key, addr: addr}, true
		}
	}

	// 兜底中的兜底：关掉熵预筛，把最可能的组合再扫一遍。
	//
	// 预筛理论上会误杀极少数「长得不像随机数」的密钥（比如密钥里恰好
	// 有一段零填充，或者它跟相邻字段拼在一起）。这条慢路径就是为它准备的：
	// 代价约 3 倍时间，但换「不会因为预筛而漏掉」。
	if time.Now().Before(deadline) {
		c := combos[0]
		tg := buildTargets(frames, c)
		if len(tg) >= 3 {
			t0 := time.Now()
			privateDiagnosticf("[sk] 最后一轮：%s（关闭熵预筛，慢 3 倍）\n", c.name)
			key, addr, scanned, ok := scanAllMemory(proc, c.keyLen, tg, deadline, false)
			privateDiagnosticf("[sk]   扫完 %.1f MB（%.1f MB/s，%s）→ %s\n",
				float64(scanned)/(1<<20),
				float64(scanned)/time.Since(t0).Seconds()/(1<<20),
				time.Since(t0).Truncate(time.Millisecond), hitText(ok))
			if ok {
				return bruteResult{combo: c, key: key, addr: addr}, true
			}
		}
	}
	return bruteResult{}, false
}

func hitText(ok bool) string {
	if ok {
		return "命中"
	}
	return "没中"
}

// scanAllMemory 按字节遍历所有非映像区域，逐位置试密钥。
//
// 三个细节：
//  1. 跳过 MEM_IMAGE —— PE 映像里只有代码和只读常量，密钥在堆上。
//  2. 块之间留 keyLen-1 字节重叠 —— 否则跨越 1 MB 边界的密钥永远试不到。
//  3. 第一帧认证通过后，用另外两帧复核 —— 防止（概率极低的）误报。
func scanAllMemory(proc *memscan.Process, keyLen int, tg []skTarget,
	deadline time.Time, filter bool) ([]byte, uintptr, uint64, bool) {

	regions, err := proc.RegionsParallel(time.Now().Add(10*time.Second), numWorkers())
	if err != nil && len(regions) == 0 {
		privateDiagnosticf("[sk]   区域枚举失败：%v\n", err)
		return nil, 0, 0, false
	}
	var todo []memscan.Region
	var total uint64
	for _, r := range regions {
		if r.Type == 0x1000000 || r.Size < uintptr(keyLen) { // MEM_IMAGE
			continue
		}
		todo = append(todo, r)
		total += uint64(r.Size)
	}
	privateDiagnosticf("[sk]   待扫 %d 个区域 / %.1f MB，%d 线程\n",
		len(todo), float64(total)/(1<<20), numWorkers())

	// GC 松绑：内层每命中一个"像密钥"的窗口就要分配一次 AES 轮密钥 + GCM 结构体，
	// 7 GB 扫下来是几百 GB 的短命垃圾。默认 GCPercent=100 会把大量时间花在
	// 反复回收这些垃圾上（现场表现：前 50% 有 145 MB/s，后 35% 掉到 37 MB/s）。
	oldGC := debug.SetGCPercent(800)
	defer debug.SetGCPercent(oldGC)

	var (
		scanned atomic.Uint64
		done    atomic.Bool
		mu      sync.Mutex
		hitKey  []byte
		hitAddr uintptr
	)

	// 进度：每 10 秒一行，带速率和预计剩余。
	stop := make(chan struct{})
	var wgProg sync.WaitGroup
	wgProg.Add(1)
	go func() {
		defer wgProg.Done()
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		last, lastT := uint64(0), time.Now()
		for {
			select {
			case <-stop:
				return
			case now := <-tk.C:
				cur := scanned.Load()
				dt := now.Sub(lastT).Seconds()
				rate := float64(cur-last) / dt / (1 << 20)
				last, lastT = cur, now
				pct := 0.0
				if total > 0 {
					pct = float64(cur) * 100 / float64(total)
				}
				eta := "∞"
				if rate > 1 {
					eta = fmt.Sprintf("%.0fs", (float64(total)-float64(cur))/(1<<20)/rate)
				}
				privateDiagnosticf("[sk]   进度 %.0f%%（%.0f/%.0f MB，%.0f MB/s，剩余 %s）\n",
					pct, float64(cur)/(1<<20), float64(total)/(1<<20), rate, eta)
			}
		}
	}()

	const blockSize = 1 << 20
	var wg sync.WaitGroup
	work := make(chan memscan.Region, 64)

	nw := numWorkers()
	for i := 0; i < nw; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, blockSize+keyLen-1)
			for r := range work {
				if done.Load() {
					continue
				}
				addr, end := r.Base, r.Base+r.Size
				for addr < end {
					if done.Load() || time.Now().After(deadline) {
						return
					}
					n := int(end - addr)
					if n > blockSize {
						n = blockSize
					}
					got, _ := proc.ReadAt(addr, buf[:n])
					if got <= 0 {
						addr += uintptr(n)
						continue
					}
					// 尾部重叠：保证跨块边界的密钥也能试到。
					if got+keyLen-1 <= len(buf) {
						if extra, _ := proc.ReadAt(addr+uintptr(got), buf[got:got+keyLen-1]); extra > 0 {
							got += extra
						}
					}
					win := buf[:got]
					if off := scanBufOpt(win, keyLen, tg, filter); off >= 0 {
						mu.Lock()
						if hitKey == nil {
							hitKey = append([]byte(nil), win[off:off+keyLen]...)
							hitAddr = addr + uintptr(off)
							done.Store(true)
						}
						mu.Unlock()
						return
					}
					scanned.Add(uint64(got))
					addr += uintptr(n)
				}
			}
		}()
	}

	// 先把区域喂进去（work 有缓冲，喂完再 close）。
	go func() {
		for _, r := range todo {
			if done.Load() {
				break
			}
			work <- r
		}
		close(work)
	}()

	wg.Wait()
	close(stop)
	wgProg.Wait()

	mu.Lock()
	defer mu.Unlock()
	return hitKey, hitAddr, scanned.Load(), hitKey != nil
}

// scanBuf 在一块内存里逐字节找「能解开 tg[0] 的那把密钥」。
// 找到返回它在 win 里的偏移，没找到返回 -1。
//
// 单独拆出来是为了能单测：内存读取、线程调度那些都是外壳，
// 真正决定成败的是「组合构造 + 内层判定」这一段。
func scanBuf(win []byte, keyLen int, tg []skTarget) int {
	return scanBufOpt(win, keyLen, tg, true)
}

// scanBufOpt 是 scanBuf 的可选预筛版本。
//
// filter=true 时先做一次极廉价的熵检查，只对「看起来像密钥」的窗口才跑 GCM。
// 为什么必须这么做：一次 GCM 要 280 ns 且**每次都分配内存**，5e9 个位置就是
// 数 TB 的垃圾，GC 会把多线程吞吐吃掉大半。而堆里绝大多数 32 字节窗口
// 是指针（每个带 2 个 0x00）、字符串或零填充，一筛就掉。
func scanBufOpt(win []byte, keyLen int, tg []skTarget, filter bool) int {
	for off := 0; off+keyLen <= len(win); off++ {
		k := win[off : off+keyLen]
		if filter && !looksLikeKeyN(k, keyLen) {
			continue
		}
		if !cs2crypto.TryOpen(k, tg[0].nonce, tg[0].ct, tg[0].aad) {
			continue
		}
		// 复核：另外几帧也必须解开，且解出来的像 netmessage 流。
		if !verifyHit(k, tg) {
			continue
		}
		return off
	}
	return -1
}

// looksLikeKey 是一个极廉价的熵预筛：判断这 32 字节像不像一把随机密钥。
//
// 判据刻意宽松（真实密钥 99.9% 都能通过），但足以滤掉堆里绝大多数结构化数据：
//   - 零字节 ≤4：随机 32 字节里出现 0 的期望只有 0.125 个；
//     而 x64 指针 `70 d9 fe d5 72 01 00 00` 每个带 2 个零，4 个连排就是 8 个。
//   - 不同字节值 ≥20：随机 32 字节的期望不同值约 30 个；ASCII 文本、重复填充都远低于 20。
//
// 先用 4 个 uint64 挡掉整段为零的情况（大块零填充在进程内存里占比很高），
// 这一步几乎不花钱。
func looksLikeKey(b []byte) bool {
	return looksLikeKeyN(b, 32)
}

// looksLikeKeyN 按窗口长度 n 判断（n=32 用于 AES-256，n=16 用于 AES-128）。
func looksLikeKeyN(b []byte, n int) bool {
	if len(b) < n {
		return false
	}
	b = b[:n]

	// 整段为零：进程内存里占比很高，用 uint64 比较几乎不花钱。
	var z uint64
	for i := 0; i+8 <= n; i += 8 {
		v := uint64(b[i]) | uint64(b[i+1])<<8 | uint64(b[i+2])<<16 | uint64(b[i+3])<<24 |
			uint64(b[i+4])<<32 | uint64(b[i+5])<<40 | uint64(b[i+6])<<48 | uint64(b[i+7])<<56
		z |= v
	}
	if z == 0 {
		return false
	}

	// 阈值按长度缩放，保证真实密钥（无论 16 还是 32 字节）几乎不会被误杀。
	maxZeros := n / 8
	if maxZeros < 2 {
		maxZeros = 2
	}
	minDistinct := n * 20 / 32
	if minDistinct < 10 {
		minDistinct = 10
	}

	// 高位平衡：随机字节约一半的最高位是 1（n=32 时均值 16、标准差 2.8）。
	// 而指针、ASCII、小整数的高位几乎全是 0 —— 这一条对结构化数据的杀伤力最大。
	lo, hi := n*3/16, n*13/16

	var bits [4]uint64
	zeros, distinct, highBit := 0, 0, 0
	for _, c := range b {
		if c&0x80 != 0 {
			highBit++
		}
		if c == 0 {
			zeros++
			if zeros > maxZeros {
				return false
			}
			continue
		}
		w, m := c>>6, uint64(1)<<(c&63)
		if bits[w]&m == 0 {
			bits[w] |= m
			distinct++
		}
	}
	return distinct >= minDistinct && highBit >= lo && highBit <= hi
}

// verifyHit 用另外两帧复核，并要求解出来的明文像 netmessage 流。
func verifyHit(key []byte, tg []skTarget) bool {
	for i := 1; i < len(tg) && i < 4; i++ {
		g := cs2crypto.TryDecrypt(key, tg[i].nonce, tg[i].ct, tg[i].aad)
		if g == nil {
			return false
		}
		if _, good := cs2proto.Score(g, cs2proto.MaxCmd); !good {
			return false
		}
	}
	return true
}
