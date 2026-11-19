// 直接找「会话密钥」：绕开未知的 KDF。
//
// 背景
// ----
// 链路上需要的最后一步是「共享密钥 → 会话密钥」。共享密钥那一步已经通了
// （ECDH(客户端私钥, 服务器临时公钥)，2026-10-19 修好），但**推导方式未知**：
// 报告 `20261018-差异分析与密钥可行性.md` 早就写明
// 「共享密钥 → 会话密钥的 KDF（info/salt 串）不在 v2.0.5 的两个 EXE 内」。
//
// 继续猜 info 串是没有出路的。换一个思路：
//
//	AES-GCM 的认证标签本身就是「这把密钥对不对」的**完美判据** ——
//	密钥错一个字节，Open 就必然返回错误。所以根本不需要知道 KDF，
//	只要在目标进程内存里找到那把能解开真实密文的 32 字节密钥即可。
//
// 三步
// ----
//  1. 一次遍历内存，同时搜两样东西，拿它们当「锚点」：
//     · 服务器临时公钥（客户端一定要存，重协商要用）
//     · 客户端临时公钥（同上）
//     两者都落在客户端的握手状态结构体里，而**会话密钥就在同一个结构体附近**。
//     再把命中地址当**指针值**搜一遍，谁指向它谁就持有握手状态 —— 也是锚点。
//  2. 每个锚点周围 ±512 字节逐字节枚举 32 字节窗口，按已知布局
//     （AES-256-GCM + 密文起点 7 + 线上包序号）解真实帧；认证过 3 帧即命中。
//  3. 都没中就把窗口放大到 ±8 KB，再不行就放宽布局（全部 cipher / 起点 /
//     序号口径）重来一遍。
//
// 这一步**不需要冻结、也不需要私钥**：会话密钥活整个会话（几十分钟），
// 没有竞速压力。私钥只用来多算一根「共享密钥」的针，拿不到照样能搜。
// 也不把任何密钥落盘 —— 全程在内存里，符合「hints.json 绝不存私钥」的约束。
package main

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/memscan"
)

const (
	skMaxFrames  = 32                // 留多少帧做判据（越多越不会误判）
	skNearSpan   = 512               // 第一轮：锚点上下各看 512 字节
	skMidSpan    = 8 << 10           // 第二轮：放大到 8 KB
	skFarSpan    = 64 << 10          // 第三轮：放大到 64 KB
	skScanBudget = 240 * time.Second // 锚点阶段的时间预算
	// 暴力搜索的时间预算：7 个组合 × 约 90 秒，留足余量。
	skBruteBudget = 900 * time.Second
)

// skNeedle 是一根「锚点针」：在内存里找到它，就等于找到了握手状态结构体附近。
type skNeedle struct {
	name string
	data []byte
}

// keepFrame 保存一帧真实密文（只留最早的一批）。
func (s *captureSession) keepFrame(raw []byte) {
	s.skMu.Lock()
	defer s.skMu.Unlock()
	if len(s.skFrames) >= skMaxFrames {
		return // 前 32 帧已经够了，后面的不覆盖 —— 首批帧序号最靠前，最稳
	}
	s.skFrames = append(s.skFrames, append([]byte(nil), raw...))
}

// startSessionKeySearch 启动会话密钥搜索。
//
// 换图/重连会来一次新握手，密钥全新 —— 所以不能只搜一次（skOnce 是错的）。
// 这里用「代」计数：resetSessionKeyMaterial 每遇到一次**新**握手就 +1，
// 搜索线程发现代变了就丢掉旧结果、用新料重来。
func (s *captureSession) startSessionKeySearch() {
	if !s.skRunning.CompareAndSwap(false, true) {
		return // 已经有一个在跑，它会自己发现代变了然后重来
	}
	go func() {
		defer s.skRunning.Store(false)
		for {
			gen := s.skGen.Load()
			s.sessionKeySearch(gen)
			if s.skGen.Load() == gen {
				return // 没有新握手，收工
			}
		}
	}()
}

// resetSessionKeyMaterial 遇到新握手时清空旧料（帧、服务器公钥），并推进代数。
func (s *captureSession) resetSessionKeyMaterial(clientPub []byte) {
	s.skMu.Lock()
	old := string(s.skClientPub)
	s.skClientPub = append([]byte(nil), clientPub...)
	if old != string(clientPub) {
		s.skFrames = nil
		s.skPub = nil
		s.skGen.Add(1)
	}
	s.skMu.Unlock()
}

// sessionKeySearch 等齐「服务器公钥 + 几帧真实密文」就开始搜。
//
// 🔴 2026-10-19 07:59 修正：**不再要求私钥**。
// 原来这里等 `foundKey`，结果用户没冻结的那次私钥早被擦掉（`has_key=false`），
// 整个搜索根本没启动，日志里连一行 `[sk]` 都没有。
// 其实私钥只用来算共享密钥当锚点，而**客户端公钥 / 服务器公钥本身就是更强的锚点**
// （客户端重协商一定要用它们，必然常驻内存）。去掉这条依赖之后，
// 这条路径彻底不需要冻结 —— 对完美平台那种 Hypervisor 反作弊才真正安全。
func (s *captureSession) sessionKeySearch(gen int64) {
	// 默认不做这件事：GNS 握手派生已经是确定解，见 -mem-session-key 的说明。
	if !*flagMemSessionKey {
		privateDiagnosticf(
			"[sk] 跳过内存找密钥（GNS 握手派生已接管；要排障请加 -mem-session-key）\n")
		return
	}
	deadline := time.Now().Add(skScanBudget)
	stale := func() bool { return s.skGen.Load() != gen }

	// ① 等料齐：服务器公钥 + 至少 8 帧真实密文。
	for {
		if time.Now().After(deadline) || stale() {
			privateDiagnosticf("[sk] 等料超时/已换握手，放弃（服务器公钥或密文帧没齐）\n")
			return
		}
		s.skMu.Lock()
		pub := append([]byte(nil), s.skPub...)
		frames := len(s.skFrames)
		s.skMu.Unlock()
		if len(pub) == 32 && frames >= 8 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	s.skMu.Lock()
	pub := append([]byte(nil), s.skPub...)
	cpub := append([]byte(nil), s.skClientPub...)
	frames := make([][]byte, len(s.skFrames))
	for i := range s.skFrames {
		frames[i] = append([]byte(nil), s.skFrames[i]...)
	}
	s.skMu.Unlock()

	// 私钥是「有则更好」：有就能多一根共享密钥的针，没有也照样干活。
	s.keyMu.Lock()
	priv := append([]byte(nil), s.foundKey...)
	privAddr := s.foundAddr
	s.keyMu.Unlock()

	var shared []byte
	if len(priv) == 32 && len(pub) == 32 {
		if v, err := cs2crypto.SharedSecret(priv, pub); err == nil {
			shared = v
		}
	}
	privateDiagnosticf("[sk] 开始找会话密钥：私钥=%v｜判据 %d 帧｜预算 %s\n",
		len(priv) == 32, len(frames), skScanBudget)

	pid, err := resolvePID()
	if err != nil {
		privateDiagnosticf("[sk] 找不到目标进程：%v\n", err)
		return
	}
	proc, err := memscan.OpenForRead(pid)
	if err != nil {
		privateDiagnosticf("[sk] 打开进程失败：%v\n", err)
		return
	}
	defer proc.Close()

	// ② 第一遍：搜公钥（有私钥就再搜一下共享密钥）。
	var needles []skNeedle
	if len(shared) == 32 {
		needles = append(needles, skNeedle{"共享密钥", shared})
	}
	needles = append(needles, skNeedle{"服务器公钥", pub})
	if len(cpub) == 32 {
		needles = append(needles, skNeedle{"客户端公钥", cpub})
	}
	// 连接 ID：帧头第 1~4 字节。这是一个**比公钥好得多的锚点** ——
	// 32 字节公钥在内存里只有两三份，而 4 字节的连接 ID 在整个 7 GB 里
	// 随机撞上的期望只有 1~2 次，netchan 的连接状态一定持有它，
	// 而加解密上下文就是连接状态的一部分。
	if len(frames) > 0 && len(frames[0]) >= 5 {
		connID := append([]byte(nil), frames[0][1:5]...)
		if connID[0]|connID[1]|connID[2]|connID[3] != 0 {
			needles = append(needles, skNeedle{"连接ID", connID})
		}
	}

	t0 := time.Now()
	hits, scanned := scanForNeedles(proc, needles, deadline, 64)
	var anchors []uintptr
	for _, n := range needles {
		hs := hits[n.name]
		privateDiagnosticf("[sk] 锚点·%s：%d 处\n", n.name, len(hs))
		anchors = append(anchors, hs...)
	}
	privateDiagnosticf("[sk] 第一遍内存遍历：扫 %.1f MB，锚点 %d 个（%s）\n",
		float64(scanned)/(1<<20), len(anchors), time.Since(t0).Truncate(time.Millisecond))

	if len(anchors) == 0 && privAddr == 0 {
		privateDiagnosticf("[sk] 一根针都没搜到 —— 公钥在内存里不是明文存放的，" +
			"这条路走不通，只能逆向 netchan 解密函数读 KDF 常量\n")
		return
	}

	// ③ 第二遍：把公钥命中地址当**指针值**再搜一遍。
	// 谁指向这块内存，谁就很可能持有整个握手状态（会话密钥通常就在旁边）。
	if !time.Now().After(deadline) {
		var pn []skNeedle
		for _, n := range needles {
			// 连接 ID 只有 4 字节，"谁指向它"没什么信息量，还会引入大量噪声。
			if n.name == "连接ID" {
				continue
			}
			for i, a := range hits[n.name] {
				if i >= 8 {
					break
				}
				pn = append(pn, skNeedle{"ptr:" + n.name, leU64(a)})
			}
		}
		if len(pn) > 0 {
			t1 := time.Now()
			ph, _ := scanForNeedles(proc, pn, deadline, 32)
			slots := 0
			for _, n := range pn {
				for _, a := range ph[n.name] {
					anchors = append(anchors, a)
					slots++
				}
			}
			privateDiagnosticf("[sk] 第二遍指针槽位：%d 处（%s）\n",
				slots, time.Since(t1).Truncate(time.Millisecond))
		}
	}

	// 私钥所在位置也算一个锚点 —— 会话密钥和它常常在同一个结构体里。
	if privAddr != 0 {
		anchors = append(anchors, privAddr)
	}
	anchors = dedupAnchors(anchors, 64)
	if len(anchors) > 96 {
		anchors = anchors[:96] // 防止极端情况下把预算烧在无意义的地址上
	}
	privateDiagnosticf("[sk] 去重后锚点 %d 个，开始逐窗口试密钥\n", len(anchors))

	// ④ 逐轮试，命中即停。
	type round struct {
		span  int
		wide  bool
		maxAn int
		desc  string
	}
	rounds := []round{
		{skNearSpan, false, len(anchors), "±512B/已知布局"},
		{skMidSpan, false, len(anchors), "±8KB/已知布局"},
		{skFarSpan, false, 16, "±64KB/已知布局"},
		{skNearSpan, true, 24, "±512B/放宽布局"},
		{skMidSpan, true, 8, "±8KB/放宽布局"},
	}
	for _, rd := range rounds {
		list := anchors
		if rd.maxAn < len(list) {
			list = list[:rd.maxAn]
		}
		tr := time.Now()
		for _, a := range list {
			if stale() {
				privateDiagnosticf("[sk] 换握手了，用新料重来（%s）\n", rd.desc)
				return
			}
			if time.Now().After(deadline) {
				privateDiagnosticf("[sk] 预算用尽（%s）\n", rd.desc)
				return
			}
			key, cand, at, ok := tryKeysNear(proc, a, rd.span, frames, rd.wide)
			if !ok {
				continue
			}
			_, err := cs2crypto.SchemeFromKey(key, cand)
			if err != nil {
				continue
			}
			privateDiagnosticf(
				"[sk] ✅ 找到会话密钥：%x（地址 %#x，锚点 %#x，%s/%s off=%d wire=%v｜%s）\n",
				key, at, a, cand.Cipher, cand.Nonce, cand.Offset, cand.WireSeq, rd.desc)
			s.em.emit("session_key", map[string]any{
				"addr":   fmt.Sprintf("%#x", at),
				"anchor": fmt.Sprintf("%#x", a),
				"cipher": cand.Cipher, "nonce": cand.Nonce,
				"offset": cand.Offset, "wire_seq": cand.WireSeq,
			})
			if stale() {
				continue // 找到的是上一把会话的密钥，作废
			}
			return
		}
		privateDiagnosticf("[sk] 第「%s」轮没中（%d 个锚点，%s）\n",
			rd.desc, len(list), time.Since(tr).Truncate(time.Millisecond))
	}

	privateDiagnosticf(
		"[sk] 锚点法没找到（%d 个锚点、最大 ±%d 字节）。"+
			"说明会话密钥不在握手状态附近，转入全内存暴力搜索\n",
		len(anchors), skFarSpan)

	// ⑤ 兜底：不依赖任何锚点，把整个可写内存按字节遍历一遍。
	//
	// 这一步是确定性的：命中就是命中；没命中就说明参数猜错了
	// （cipher / 密文起点 / nonce 构造 / AAD），而不是"没找到地方"。
	if stale() {
		return
	}
	if r, ok := bruteSearch(proc, frames, defaultCombos(), time.Now().Add(skBruteBudget)); ok {
		var prefix []byte
		if r.combo.nonce == 1 {
			for _, f := range frames {
				if len(f) >= 5 {
					prefix = append([]byte(nil), f[1:5]...)
					break
				}
			}
		}
		cand := cs2crypto.Candidate{
			Cipher: r.combo.cipher, Nonce: r.combo.nonceName(),
			Offset: r.combo.offset, WireSeq: true, NoncePrefix: prefix,
		}
		_, err := cs2crypto.SchemeFromKey(r.key, cand)
		if err == nil && !stale() {
			privateDiagnosticf(
				"[sk] ✅ 暴力搜索命中会话密钥：%x（地址 %#x，%s）\n",
				r.key, r.addr, r.combo.name)
			s.em.emit("session_key", map[string]any{
				"addr":   fmt.Sprintf("%#x", r.addr),
				"combo":  r.combo.name,
				"cipher": r.combo.cipher, "nonce": r.combo.nonceName(),
				"offset": r.combo.offset, "via": "brute",
			})
			return
		}
	}

	privateDiagnosticf(
		"[sk] 全内存暴力搜索也没命中 —— 说明 cipher / 密文起点 / nonce / AAD " +
			"至少有一项猜错了，下一步只能逆向 cs2.exe 的 netchan 解密函数\n")
}

// leU64 把地址编成 8 字节小端，用来搜「谁指向这块内存」。
func leU64(v uintptr) []byte {
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return b
}

// scanForNeedles 在一次内存遍历里同时搜多根针。
//
// 跳过 MEM_IMAGE（0x1000000）：那是 PE 映像，只有代码和只读常量，
// 密钥类数据都在堆（MEM_PRIVATE）里。
func scanForNeedles(proc *memscan.Process, needles []skNeedle,
	deadline time.Time, maxPer int) (map[string][]uintptr, uint64) {

	out := make(map[string][]uintptr, len(needles))
	maxLen := 0
	for _, n := range needles {
		if len(n.data) > maxLen {
			maxLen = len(n.data)
		}
	}
	if maxLen == 0 {
		return out, 0
	}

	regions, err := proc.RegionsParallel(time.Now().Add(10*time.Second), numWorkers())
	if err != nil && len(regions) == 0 {
		return out, 0
	}

	const blockSize = 1 << 20
	buf := make([]byte, blockSize+maxLen-1)
	var scanned uint64
	for _, r := range regions {
		if r.Type == 0x1000000 { // MEM_IMAGE
			continue
		}
		addr, end := r.Base, r.Base+r.Size
		for addr < end {
			if !deadline.IsZero() && time.Now().After(deadline) {
				return out, scanned
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
			// 跨块边界：尾部多读 maxLen-1 字节，避免漏掉跨 1 MB 的命中。
			extraN := n + maxLen - 1
			if extraN > len(buf) {
				extraN = len(buf)
			}
			if extraN > got {
				if extra, _ := proc.ReadAt(addr+uintptr(got), buf[got:extraN]); extra > 0 {
					got += extra
				}
			}
			scanned += uint64(got)
			win := buf[:got]
			for _, nd := range needles {
				if len(out[nd.name]) >= maxPer {
					continue
				}
				off := 0
				for {
					i := bytes.Index(win[off:], nd.data)
					if i < 0 {
						break
					}
					out[nd.name] = append(out[nd.name], addr+uintptr(off+i))
					if len(out[nd.name]) >= maxPer {
						break
					}
					off += i + 1
				}
			}
			addr += uintptr(n)
		}
	}
	return out, scanned
}

// dedupAnchors 去掉彼此距离小于 minGap 的重复锚点，并按地址排序。
func dedupAnchors(in []uintptr, minGap uintptr) []uintptr {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i] < in[j] })
	out := in[:0]
	var last uintptr
	for i, a := range in {
		if i > 0 && a-last < minGap {
			continue
		}
		out = append(out, a)
		last = a
	}
	return out
}

// tryKeysNear 读锚点周围的内存，交给 findKeyInBuf 试。
func tryKeysNear(proc *memscan.Process, anchor uintptr, span int, frames [][]byte,
	wide bool) ([]byte, cs2crypto.Candidate, uintptr, bool) {

	if span <= 0 {
		return nil, cs2crypto.Candidate{}, 0, false
	}
	// 读锚点周围 span*2 字节。
	//
	// 🔴 不能因为 err != nil 就整段丢弃：窗口跨出 region 边界时 ReadAt 会
	// 返回错误，但**已经读到的那部分仍然有效**。原来写成
	// `if err != nil || got < 32 { return }`，结果 ±64KB 那一轮在现场
	// 耗时 0s —— 不是扫得快，是每个锚点都在这里被直接丢掉，整轮空转。
	tryRead := func(base uintptr, n int) ([]byte, uintptr) {
		b := make([]byte, n)
		got, _ := proc.ReadAt(base, b)
		if got <= 0 {
			return nil, 0
		}
		return b[:got], base
	}

	var (
		win   []byte
		wbase uintptr
	)
	if uintptr(span) <= anchor {
		win, wbase = tryRead(anchor-uintptr(span), span*2)
	}
	if len(win) < 32 {
		// 锚点前面不可读（多半是 region 起点就在锚点附近），只往后读。
		win, wbase = tryRead(anchor, span*2)
	}
	if len(win) < 32 {
		return nil, cs2crypto.Candidate{}, 0, false
	}

	key, cand, off, ok := findKeyInBuf(win, frames, wide)
	if !ok {
		return nil, cs2crypto.Candidate{}, 0, false
	}
	return key, cand, wbase + uintptr(off), true
}

// findKeyInBuf 在 buf 里逐字节枚举 32 字节窗口当密钥，用真实帧验。
// 返回命中密钥、方案、以及它在 buf 里的偏移。
//
// wide=false 只试最可能的组合（AES-256-GCM + 密文起点 7 + 线上序号）；
// wide=true 放宽到全部 cipher / 全部起点 / 两种序号口径。
func findKeyInBuf(buf []byte, frames [][]byte, wide bool) (
	[]byte, cs2crypto.Candidate, int, bool) {

	if len(buf) < 32 || len(frames) == 0 {
		return nil, cs2crypto.Candidate{}, 0, false
	}
	nonces := cs2crypto.NonceSchemes()

	if !wide {
		for off := 0; off+32 <= len(buf); off++ {
			key := buf[off : off+32]
			for _, n := range nonces {
				cand := cs2crypto.Candidate{
					Cipher: "aes-256-gcm", Nonce: n.Name, Offset: 7, WireSeq: true,
				}
				sch, err := cs2crypto.SchemeFromKey(key, cand)
				if err != nil {
					continue
				}
				if countOpenable(sch, frames) >= 3 {
					return append([]byte(nil), key...), cand, off, true
				}
			}
		}
		return nil, cs2crypto.Candidate{}, 0, false
	}

	for off := 0; off+32 <= len(buf); off++ {
		key := buf[off : off+32]
		for _, cp := range cs2crypto.Ciphers() {
			if cp.KeyLen != 32 {
				continue // 窗口固定 32 字节；128 位密钥另说，先不管
			}
			for _, n := range nonces {
				for _, coff := range []int{7, 0, 5, 6, 8} {
					for _, wire := range []bool{true, false} {
						cand := cs2crypto.Candidate{
							Cipher: cp.Name, Nonce: n.Name, Offset: coff, WireSeq: wire,
						}
						sch, err := cs2crypto.SchemeFromKey(key, cand)
						if err != nil {
							continue
						}
						if countOpenable(sch, frames) >= 3 {
							return append([]byte(nil), key...), cand, off, true
						}
					}
				}
			}
		}
	}
	return nil, cs2crypto.Candidate{}, 0, false
}

// countOpenable 数一下有多少帧能解开且像 netmessage 流。
//
// 🔴 第一帧解不开就立刻返回 0：GCM 认证失败意味着「这把密钥不对」，
// 继续试剩下 31 帧纯属浪费。宽范围枚举时这一步是 32 倍的差距。
func countOpenable(sch *cs2crypto.Scheme, frames [][]byte) int {
	ok := 0
	for i, f := range frames {
		pt, err := sch.OpenFrame(i, f)
		if err != nil {
			return 0
		}
		if _, good := cs2proto.Score(pt, cs2proto.MaxCmd); !good {
			return 0
		}
		ok++
		if ok >= 3 {
			return ok // 够了，别浪费时间
		}
	}
	return ok
}
