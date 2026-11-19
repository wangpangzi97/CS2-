// 从 cs2 进程内存里直接读 GNS 的基础 IV，再用 IV 反推会话密钥。
//
// 为什么要这条路
// --------------
// KDF 的结构已经从 steamnetworkingsockets.dll 反汇编确认到字段级：
//
//	salt  = [conn+0x1890] || [conn+0x1968]        （两个 8 字节 nonce）
//	tail  = connID 8 + "Steam datagram" 14 + 四段 cert/crypt 原始字节
//	T1..T4 = HKDF-SHA256-Expand(prk, tail)        （首轮 prev 为空）
//	客户端槽位：T1=SendKey T2=RecvKey T3=SendIV T4=RecvIV
//
// 但 384 组变体 × 64 帧仍然 0 命中，说明喂进去的**字节**有问题（四段 blob 的
// 排列有 24 种、内容也可能多包/少包一层 protobuf），而这类错误无法靠枚举
// "猜"出来 —— 每加一个维度就多一轮试错，用户已经陪跑了十几轮。
//
// 换一个不依赖 KDF 的确定性做法：**IV 和密钥在整局里都常驻内存**。
//
//	[conn+0x19f0]  12 字节基础 IV（发送侧，加密路径 `add qword [rsi+0x19f0], rax`）
//	[conn+0x19fc]  12 字节基础 IV（接收侧）
//	[conn+0x19e0]  CCrypto*（发送，Init 时 flags=1）
//	[conn+0x19e8]  CCrypto*（接收）
//	[conn+0x180] / [conn+0x184]  两个 connID（u32）
//
// 连接对象用「两个 connID 拼成的 8 字节」当唯一针就能定位 —— 这个 8 字节组合
// 在一局里只属于这一条连接，误命中率可以忽略。
//
// 于是链路变成：找 conn → 读 IV → 用 IV 去内存里找能解开真实帧的 32 字节密钥。
// **不需要冻结**（密钥活整个会话，没有竞速），**不需要 hook**，也不落盘。
package main

import (
	"bytes"
	"time"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/memscan"
)

// GNS 连接对象里与解密相关的字段偏移。
//
// 全部来自 steamnetworkingsockets.dll 的反汇编（函数起点 0x9d590，
// FinishCryptoHandshake），不是猜的：
//
//	0x9d8ac  mov rax, qword ptr [rbx + 0x1890]   ; 本地 nonce
//	0x9d8b3  mov rcx, qword ptr [rbx + 0x1968]   ; 对端 nonce
//	0x9d929  mov r10d, dword ptr [rbx + 0x180]   ; connID A
//	0x9d934  mov r11d, dword ptr [rbx + 0x184]   ; connID B
//	0x9d9be  ..   [rbx+0x19f0] / [rbx+0x19fc]    ; 两把 12 字节基础 IV
//	0x9dc4c  mov rcx, qword ptr [rbx + 0x19e0]   ; 发送侧 CCrypto*
//	0x9dc69  mov rcx, qword ptr [rbx + 0x19e8]   ; 接收侧 CCrypto*
const (
	gnsOffConnIDA = 0x180
	gnsOffConnIDB = 0x184
	gnsOffCryptTx = 0x19e0
	gnsOffCryptRx = 0x19e8
	gnsOffIV1     = 0x19f0
	gnsOffIV2     = 0x19fc
	// 连接对象跨到这里就够了（IV2 结束在 0x1a08）。
	// 🔴 0x1a20 太小了：2026-10-19 10:48 实证 conn 对象 0x1700..0x1a20 这 800 字节里
	// **没有任何 32 字节高熵窗口**（去重字节数最高才 30，且那 30 是 IV 本身），
	// 说明会话密钥不在这段里。GNS 的 m_cryptoSend/m_cryptoRecv 是内联在
	// CConnection 里的，key 只可能在 0x1a20 之后。扩到 0x3000 一次看全。
	gnsConnSpan = 0x3000
	// 一个 CCrypto 对象的前若干字节里一定含 32 字节原始密钥；
	// 不确定它具体放在哪个偏移，所以逐字节开窗试。
	//
	// 🔴 09:39 现场把这个值证伪了：日志里两个 CCrypto 指针是
	//   0x22f3b2f8e20 / 0x22f3b2f8fe0，相差 0x1c0 = 448 字节。
	// 两个同类对象紧挨着分配、间距就是对象本身的大小，所以对象至少 448 字节，
	// 原来只读 256 字节 —— 密钥很可能就落在 256..448 那段没读的地方，
	// 于是每次都是「CCrypto 对象里没找到原始密钥」。
	//
	// 现在读到 4 KB：宁可多试，反正有 plausibleKey 预筛 + GCM 认证兜底，
	// 不会误判，代价只是几十万个候选里真正送去认证的没几个。
	gnsCryptSpan = 0x1000
)

// gnsConn 是从内存里还原出来的一条 GNS 连接的关键字段。
type gnsConn struct {
	Addr   uintptr // 连接对象基址
	IDA    []byte  // [Addr+0x180]
	IDB    []byte  // [Addr+0x184]
	IV1    []byte  // [Addr+0x19f0]，12 字节
	IV2    []byte  // [Addr+0x19fc]，12 字节
	CryptT uintptr // [Addr+0x19e0]
	CryptR uintptr // [Addr+0x19e8]
	// Raw 是整段连接对象原样（gnsConnSpan 字节）。
	//
	// 留着它是因为 KDF 的输入就躺在这段内存里：四个 CUtlString 槽位
	// （+0x1798 / +0x17b8 / +0x1988 / +0x19b8）和两段 8 字节 salt
	// （+0x1890 / +0x1968）。gnskdf.go 拿它和线上重建的四段做逐槽比对，
	// 用来判定「是我们的 blob 错了」还是「salt / 标签 / 展开结构错了」。
	Raw []byte
}

// gnsMemResult 是内存恢复的产物。
type gnsMemResult struct {
	Conn   gnsConn
	Key    []byte
	IV     []byte
	Dir    string // 这把密钥对应哪个方向（"c2s" 发送 / "s2c" 接收）
	KeyAt  uintptr
	Frames int // 判据里能解开的帧数
	Src    string

	// 🔴 另一个方向的密钥。GNS 两个方向用**两把不同**的密钥，
	// 只报一边会让解码端永久只能解一边（现场：只有 c2s，s2c 实体数据全丢）。
	AltKey    []byte
	AltIV     []byte
	AltDir    string
	AltKeyAt  uintptr
	AltFrames int
}

// hasDir 表示某个方向已经命中过（不必再用别的 IV 组合重试）。
func (r *gnsMemResult) hasDir(dir string) bool {
	return (r.Key != nil && r.Dir == dir) || (r.AltKey != nil && r.AltDir == dir)
}

// addDir 记录某个方向的命中；同一方向只记第一次（GCM 认证通过就是真的）。
// 返回 true 表示两个方向都齐了。
func (r *gnsMemResult) addDir(dir string, key, iv []byte, at uintptr, frames int) bool {
	if dir == r.Dir {
		return r.AltKey != nil
	}
	if r.Key == nil {
		r.Dir, r.Key, r.IV, r.KeyAt, r.Frames = dir, key, iv, at, frames
	} else if r.AltKey == nil {
		r.AltDir, r.AltKey, r.AltIV, r.AltKeyAt, r.AltFrames = dir, key, iv, at, frames
	}
	return r.Key != nil && r.AltKey != nil
}

// gnsConnNeedles 给出「两个 connID 拼成 8 字节」的两种字节序。
//
// 内存里 [0x180]/[0x184] 的先后与谁是本地无关紧要 —— 两种都当针扫，
// 命中后再用读出来的字段本身去判方向。
func gnsConnNeedles(idA, idB []byte) [][]byte {
	if len(idA) != 4 || len(idB) != 4 {
		return nil
	}
	ab := make([]byte, 0, 8)
	ab = append(ab, idA...)
	ab = append(ab, idB...)
	ba := make([]byte, 0, 8)
	ba = append(ba, idB...)
	ba = append(ba, idA...)
	return [][]byte{ab, ba}
}

// findGNSConns 在进程内存里找 GNS 连接对象。
//
// 只扫「可写且非映像」的区域：连接对象是 new 出来的，落在堆上；PE 映像里
// 只有代码和只读常量。每个命中点再往前退 0x180 就是对象基址。
func findGNSConns(proc *memscan.Process, needles [][]byte, deadline time.Time) []gnsConn {
	if len(needles) == 0 {
		return nil
	}
	regions, err := proc.RegionsParallel(time.Now().Add(10*time.Second), numWorkers())
	if err != nil && len(regions) == 0 {
		privateDiagnosticf("[gnsmem] 区域枚举失败：%v\n", err)
		return nil
	}

	// 连接对象的基址必须 ≥ 0x180，否则 needle 落在地址 0 附近不可能是它。
	const minBase = gnsOffConnIDA
	seen := map[uintptr]bool{}
	var out []gnsConn

	for _, r := range regions {
		if r.Type == 0x1000000 { // MEM_IMAGE
			continue
		}
		if r.Size < uintptr(len(needles[0])) {
			continue
		}
		const block = 1 << 20
		buf := make([]byte, block+len(needles[0])-1)
		addr, end := r.Base, r.Base+r.Size
		for addr < end {
			if time.Now().After(deadline) {
				return out
			}
			n := int(end - addr)
			if n > block {
				n = block
			}
			got, _ := proc.ReadAt(addr, buf[:n])
			if got <= 0 {
				addr += uintptr(n)
				continue
			}
			// 尾部重叠，保证跨块边界的针也能命中。
			if got+len(needles[0])-1 <= len(buf) {
				if extra, _ := proc.ReadAt(addr+uintptr(got), buf[got:got+len(needles[0])-1]); extra > 0 {
					got += extra
				}
			}
			win := buf[:got]
			for _, nd := range needles {
				from := 0
				for {
					i := bytes.Index(win[from:], nd)
					if i < 0 {
						break
					}
					hit := addr + uintptr(from+i)
					from += i + 1
					if hit < minBase {
						continue
					}
					base := hit - gnsOffConnIDA
					if seen[base] {
						continue
					}
					seen[base] = true
					if c, ok := readGNSConn(proc, base); ok {
						out = append(out, c)
					}
				}
			}
			addr += uintptr(n)
		}
	}
	return out
}

// readGNSConn 读出一个候选连接对象，并做最低限度的合理性检查。
//
// 检查项刻意选得「宽松但有效」：8 字节针在别处也会出现（比如某个 protobuf
// 缓冲里正好连着两个 connID），但那种地方 +0x19f0 不会是两把互不相同的
// 随机 12 字节，+0x19e0 也不会是两个可读的堆指针。
func readGNSConn(proc *memscan.Process, base uintptr) (gnsConn, bool) {
	// 用页对齐的宽松读：0x3000 范围里大概率夹着未提交页，
	// ReadFull 只要有一个坏字节就整段失败，conn 就直接找不到了。
	raw := gnsReadLenient(proc, base, gnsConnSpan)
	if len(raw) < gnsConnSpan {
		return gnsConn{}, false
	}
	c := gnsConn{
		Addr:   base,
		IDA:    append([]byte(nil), raw[gnsOffConnIDA:gnsOffConnIDA+4]...),
		IDB:    append([]byte(nil), raw[gnsOffConnIDB:gnsOffConnIDB+4]...),
		IV1:    append([]byte(nil), raw[gnsOffIV1:gnsOffIV1+12]...),
		IV2:    append([]byte(nil), raw[gnsOffIV2:gnsOffIV2+12]...),
		CryptT: uintptr(gnsLE64(raw[gnsOffCryptTx:])),
		CryptR: uintptr(gnsLE64(raw[gnsOffCryptRx:])),
		Raw:    raw,
	}
	// 两把 IV 至少有一把看起来像随机数（不是全 0、不是全 ff）。
	if !plausibleIV(c.IV1) && !plausibleIV(c.IV2) {
		return gnsConn{}, false
	}
	// CCrypto 指针至少有一个像堆地址。
	if !plausiblePtr(c.CryptT) && !plausiblePtr(c.CryptR) {
		return gnsConn{}, false
	}
	return c, true
}

// plausibleIV 判断 12 字节是否像一个随机 IV。
//
// 判据只有「非全 0 / 非全 ff / 至少 4 个不同字节」—— 不检查熵，
// 因为基础 IV 可能含少量结构（例如末 4 字节是计数器初值）。
func plausibleIV(iv []byte) bool {
	if len(iv) != 12 {
		return false
	}
	zeros, ffs := 0, 0
	distinct := map[byte]bool{}
	for _, b := range iv {
		distinct[b] = true
		switch b {
		case 0:
			zeros++
		case 0xff:
			ffs++
		}
	}
	if zeros == 12 || ffs == 12 {
		return false
	}
	return len(distinct) >= 4
}

// plausiblePtr 判断一个值是否像用户态堆指针。
func plausiblePtr(v uintptr) bool {
	// Windows x64 用户态上限 0x7fff_ffff_ffff；堆地址远高于 64 KB。
	return v >= 0x10000 && v < 0x7fffffffffff
}

// plausibleKey 是 32 字节候选密钥的预筛。
//
// 存在的理由：CCrypto 的读取跨度从 256 字节放到 4 KB 之后，逐个偏移都要做
// AES key schedule + GCM 认证，几万个候选乘上去就是几秒。而堆内存里绝大
// 多数窗口是零、是重复字节、是长度/标志位这类小整数 —— 真正的 AES-256 密钥
// 是 32 个近均匀的随机字节，不同字节数的期望约 28 个。
//
// 门槛取 16：随机密钥通过的概率极高（32 字节里凑不到 16 种不同值几乎不可能），
// 而零填充、ASCII、小整数数组基本全被挡掉。这一步只筛掉明显不可能的，
// 真正的判定仍然交给 128 位 GCM 认证标签，所以不存在「筛过头」的风险。
func plausibleKey(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	var seen [256]bool
	distinct := 0
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			distinct++
			if distinct >= 16 {
				return true
			}
		}
	}
	return false
}

// gnsLE64 按小端读 8 字节。
func gnsLE64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// gnsTryKey 用一把密钥 + 一把基础 IV 去解一组真实帧，返回能解开的帧数。
//
// 判据是 GCM 认证标签：错一个字节就必然失败，所以 3 帧全过就等于确认。
// gnsNonceCandidates 是「用内存 IV 解这一帧」的候选 nonce 集合。
//
// 逻辑已经搬到 internal/cs2crypto（解码端也要用同一套），这里只是别名。
// 保留这个名字是因为采集端的测试都在用它。
func gnsNonceCandidates(iv []byte, seqI, seqRef uint16) [][]byte {
	return cs2crypto.GNSNoncesForFrame(iv, seqI, seqRef)
}

// gnsTryKey 判断这把密钥 + 这个 IV 能不能解开这批帧，返回解开的帧数。
//
// seqRef 取 frames 里最后一帧的序号（缓冲按到达顺序追加，最后一条最新）。
// 失败路径只花「一帧 × 十几个 nonce」的代价：GCM 认证不过就直接换下一把
// 密钥，不会为明显错误的候选把整批帧都试一遍。
func gnsTryKey(key, iv []byte, frames [][]byte, need int) int {
	if len(key) != 32 || len(iv) != 12 || len(frames) == 0 || need < 1 {
		return 0
	}
	g, err := cs2crypto.GNSNewAEAD(key)
	if err != nil {
		return 0
	}
	seqRef, _ := cs2crypto.FrameSeq(frames[len(frames)-1])

	ok := 0
	for _, f := range frames {
		seq, hasSeq := cs2crypto.FrameSeq(f)
		if !hasSeq {
			continue
		}
		hit := false
		for _, nonce := range gnsNonceCandidates(iv, uint16(seq), uint16(seqRef)) {
			if _, err := cs2crypto.GNSOpenWithAEAD(g, nonce, f); err == nil {
				hit = true
				break
			}
		}
		if hit {
			ok++
			if ok >= need {
				return ok
			}
		}
	}
	return ok
}

// gnsRecoverFromMemory 是这条路的主入口。
//
// framesByDir 里 "c2s" 是客户端发出的帧（用发送侧 IV / 发送侧密钥），
// "s2c" 是服务端发来的帧（用接收侧）。
//
// 顺序刻意如此：先用 CCrypto 对象里的窗口试（毫秒级），不行才退到全内存扫描
// （几十秒）。绝大多数字节问题出在 KDF 上，而密钥本身就在 CCrypto 里躺着。
func gnsRecoverFromMemory(proc *memscan.Process, idA, idB []byte,
	framesByDir map[string][][]byte, deadline time.Time,
	h *cs2crypto.GNSHandshake, priv []byte,
	onConn func(gnsConn)) (gnsMemResult, bool) {

	conns := findGNSConns(proc, gnsConnNeedles(idA, idB), deadline)
	if len(conns) == 0 {
		privateDiagnosticf("[gnsmem] 内存里没找到 GNS 连接对象（针 %x/%x）\n", idA, idB)
		return gnsMemResult{}, false
	}
	privateDiagnosticf("[gnsmem] 找到 %d 个候选连接对象\n", len(conns))
	// 先上报 IV：不管密钥找不找得到，两把 IV 本身就已经是解码端最需要的
	// 判据了（IV 高 4 字节整局不变，可以和 KDF 派生结果做精确比对）。
	if onConn != nil {
		for _, c := range conns {
			onConn(c)
		}
	}

	// 先按「IV1 ↔ 发送、IV2 ↔ 接收」试，再反过来试 —— 两端的槽位是互换的，
	// 与其赌哪边是哪边，不如两边都试（认证会判胜负）。
	type ivPair struct {
		dir string
		iv  []byte
	}
	reproDone := false
	for _, c := range conns {
		privateDiagnosticf("[gnsmem] conn @%#x  connID %x/%x  IV1=%x IV2=%x  crypt %#x/%#x\n",
			c.Addr, c.IDA, c.IDB, c.IV1, c.IV2, c.CryptT, c.CryptR)

		// 顺手把 KDF 的真实输入从这段内存里取出来，和线上重建的四段比对。
		// 这一步不花额外时间（数据已经在 c.Raw 里了），但它能把
		// 「blob 错了」和「salt / 标签 / 展开错了」彻底分开。
		gnsAnalyzeKDFInputs(proc, c, h)

		// 再把「离线复现 KDF 所需的全部字节」落一份。
		//
		// 这是为了**结束一轮一轮的现场试错**：私钥 + 握手四段 + 内存四段
		// （各 4 KB 原样）+ 两把 IV + 真实帧全写下来之后，KDF 的每一种写法
		// 都能在本地离线试遍，找到唯一正确的组合再回来改常量。
		if !reproDone {
			reproDone = gnsWriteRepro(c, h, priv, proc, framesByDir) != ""
		}

		// 🔴 命中一个方向后**不能立刻返回**：GNS 两个方向用两把不同的密钥，
		// 只报一边会让解码端永久只能解一边。现场 13:24 的日志从头到尾只有
		// `方向=c2s`，s2c（服务端下发的实体数据）一条没解，雷达没有任何目标。
		// 所以这里把两个方向都扫出来再一起报。
		var hit gnsMemResult
		hit.Conn, hit.Src = c, "CCrypto 对象"

		pairs := []ivPair{
			{"c2s", c.IV1}, {"s2c", c.IV2},
			{"c2s", c.IV2}, {"s2c", c.IV1},
		}
		for _, p := range pairs {
			// 这个方向已经命中过了，换下一个 —— 省掉重复的 4 KB 逐字节开窗。
			if hit.hasDir(p.dir) {
				continue
			}
			frames := framesByDir[p.dir]
			if len(frames) < 3 {
				continue
			}
			// 只用最近 4 帧。缓冲区是环形（尾部最新），用最新的帧还有个额外
			// 好处：内存里读到的 IV 对应「读的那一刻」，和最新帧的序号差最小，
			// nonce 修正量也就最小。原来一次拿 24 帧试，等于白白多花 6 倍。
			if len(frames) > 4 {
				frames = frames[len(frames)-4:]
			}
			for _, ptr := range []uintptr{c.CryptT, c.CryptR} {
				if !plausiblePtr(ptr) {
					continue
				}
				// 🔴 必须用页对齐的宽松读：`ReadFull` 只要这 4KB 里有**一个**
				// 不可读字节就整段失败，然后整个指针被 continue 跳过 ——
				// 日志上只会看到「没打印」，完全看不出是读失败还是真的没命中。
				// 这正是 10:22 那次 `[gnsnear] 扫 0.0 KB` 的同款坑（硬规则 145）。
				obj := gnsReadLenient(proc, ptr, gnsCryptSpan)
				if len(obj) < 32 {
					continue
				}
				tried := 0
				hitHere := false
				for off := 0; off+32 <= len(obj); off++ {
					key := obj[off : off+32]
					if !plausibleKey(key) {
						continue
					}
					tried++
					if n := gnsTryKey(key, p.iv, frames, 3); n >= 3 {
						privateDiagnosticf("[gnsmem] CCrypto 里试了 %d 个候选密钥窗口（方向 %s 命中）\n", tried, p.dir)
						// 记录这个方向，然后**继续扫**另一个方向。
						// 两把密钥在同一个 CCrypto 对象里的不同偏移，一次扫完最省。
						hit.addDir(p.dir,
							append([]byte(nil), key...), append([]byte(nil), p.iv...),
							ptr+uintptr(off), n)
						hitHere = true
						break
					}
				}
				if !hitHere {
					privateDiagnosticf("[gnsmem] %#x 起 %d 字节内试了 %d 个候选窗口，都不对\n",
						ptr, gnsCryptSpan, tried)
				}
			}
		}

		// CCrypto 对象里已经命中（至少一个方向）就到此为止，不再跑下面的宽 delta /
		// 邻域扫描 —— 那些是为了「常规路全灭」准备的兜底，会额外花好几秒。
		if hit.Key != nil {
			if hit.AltKey != nil {
				privateDiagnosticf("[gnsmem] 两个方向都取到了：%s @%#x / %s @%#x\n",
					hit.Dir, hit.KeyAt, hit.AltDir, hit.AltKeyAt)
			} else {
				privateDiagnosticf(
					"[gnsmem] 只取到 %s 一个方向；另一把密钥不在这段内存里，"+
						"解码端会用握手材料自行派生\n", hit.Dir)
			}
			return hit, true
		}

		// 宽 delta 探针：常规修正表最大只到 -1024，隐含「IV 每包 +1」。
		// 如果 GCM 计数器按**加密字节数**累加，真实 delta 会跑到几千，
		// 常规路必然全灭，而且和「KDF 错了」在日志上完全无法区分。
		// 这条只在常规路全灭后才跑（约 6 秒），命中就直接出结果。
		if res, ok := gnsProbeCryptHead(proc, c, framesByDir); ok {
			res.Conn = c
			return res, true
		}

		// CCrypto 那 4 KB 里没有原始密钥 —— 但现场（10:12）已经证明
		// 握手状态集中在另一块 32 KB 区域里（私钥和四个槽位指针都在那儿）。
		// 于是改成在**锚点邻域**里定向扫：每个已知指针向两侧各扩 32 KB，
		// 合并重叠后逐字节开窗，用真实帧的 GCM 认证判胜负。
		//
		// 这条路不依赖 KDF 正确，也不需要冻结（密钥活整个会话）。
		if res, ok := gnsRecoverNearby(proc, c, framesByDir, deadline); ok {
			res.Conn = c
			return res, true
		}
	}

	// 🔴 原来的「退到全内存扫描」在这里被删掉了（2026-10-19 09:53）。
	//
	// 删的理由不是"不想要兜底"，是这条路实测**从来没有跑完过**：
	// 6775 MB / 16 线程，抓包吞吐从 316 MB/s 掉到 22 MB/s，
	// 用户跑到 70% 就关了。它和抓包抢内存带宽，等于用主链路的帧去换一个
	// 大概率也找不到的结果。
	//
	// 更关键的是：现在有了**不依赖帧**的判据 —— conn 对象里的两把 IV
	// 已经通过 SetGNSIVs 上报给解码端，而 IV 的低 8 字节随包前移、
	// 高 4 字节整局不变，所以「KDF 派生的 IV 高 4 字节 == 内存 IV 高 4 字节」
	// 能在 1152 个变体里一次定死正确的那一组。那条路比全内存扫描精确得多，
	// 也不占带宽。
	privateDiagnosticf(
		"[gnsmem] CCrypto 对象里没有原始密钥；两把 IV 已上报解码端，"+
			"KDF 变体改用「IV 高 4 字节」比对（不再跑全内存扫描）\n"+
			"[gnsmem] 判据帧 c2s=%d s2c=%d（某个方向 <3 时那两组 IV 组合会被跳过）\n",
		len(framesByDir["c2s"]), len(framesByDir["s2c"]))

	// 🔴 这条推理必须写进日志，否则下一轮会继续往「扩大扫描范围」上使劲。
	//
	// CCrypto 里装的是**派生出来的 AES 会话密钥** —— 游戏自己每一帧都要用它
	// 加密，所以它**必然在内存里**，不可能被擦掉。因此「4096 字节内 302 个
	// 候选窗口全部 GCM 验证失败」几乎只有一种解释：**nonce/IV 派生不对**，
	// 正确的密钥其实试过了，只是用错了 nonce，认证标签自然过不了。
	//
	// 07:29 那局的日志正是这个形态（两把 IV 都读到了，窗口也扫满了，
	// 仍然一条不过）。所以下一步该查 GNSIVForSeq / 帧头序号解析，
	// 而不是把 -snap-mb 调大 —— 扫描范围从来不是这里的瓶颈。
	privateDiagnosticf(
		"[gnsmem] ⚠ 注意：派生出的 AES 密钥**必然在 CCrypto 里**（游戏每帧都要用它加密），" +
			"所以上面全不过更像是 **nonce/IV 派生不对**，而不是密钥不存在。\n" +
			"[gnsmem]   下一步优先查 GNSIVForSeq 与帧头包序号解析，别急着调大 -snap-mb。\n")
	return gnsMemResult{}, false
}

// buildTargetsFixedIV 用「已知基础 IV + 帧序号」构造判据三元组。
//
// 与 buildTargets 的区别：nonce 不再由组合猜，而是直接用从内存读到的
// 基础 IV 加上帧头里的包序号 —— 这一步一旦确定，剩下的就只有密钥了。
func buildTargetsFixedIV(frames [][]byte, iv []byte) []skTarget {
	if len(iv) != 12 {
		return nil
	}
	out := make([]skTarget, 0, len(frames))
	for _, f := range frames {
		off, ok := cs2crypto.GNSChunkOffset(f)
		if !ok || len(f)-off <= 16 {
			continue
		}
		seq, ok := cs2crypto.FrameSeq(f)
		if !ok {
			continue
		}
		out = append(out, skTarget{
			ct:    f[off:],
			nonce: cs2crypto.GNSIVForSeq(iv, seq),
		})
	}
	return out
}

// sortTargetsByLen 把最短的密文排到最前：内层循环每多 16 字节就多一次 GHASH，
// 判据帧越短，全内存扫描越快。
func sortTargetsByLen(tg []skTarget) {
	for i := 1; i < len(tg); i++ {
		for j := i; j > 0 && len(tg[j].ct) < len(tg[j-1].ct); j-- {
			tg[j], tg[j-1] = tg[j-1], tg[j]
		}
	}
}

// gnsWideDeltaSpan 是「宽 delta」探针的扫描上限。
//
// 现有 GNSNonceCorrections 最大只到 -1024，隐含前提是「IV 每发一个包加 1」。
// 但 GCM 的计数器也可能是**按加密字节数**累加的（每包 46 字节 → 加 46），
// 那样 delta 会跑到几千量级，修正表根本够不着 —— 表现就是
// 「密钥就在手里、IV 也读到了，却一帧都解不开」，和 KDF 全灭长得一模一样。
// 8 K 覆盖「按字节累加」跑几千包的量级，代价约 1.6 万次 GCM（约 6 秒）。
const gnsWideDeltaSpan = 8192

// gnsWideDeltaProbe 用一个 key + 一个内存 IV，对单帧扫 delta ∈ [-span, 0]。
//
// IV 单调前移，所以帧的 nonce 一定**不大于**读到的当前 nonce，delta 取负方向。
// 命中返回真实 delta（<=0），未命中返回 -1。
func gnsWideDeltaProbe(key, iv, pkt []byte, span int) int64 {
	if len(key) != 32 || len(iv) != 12 || len(pkt) == 0 {
		return -1
	}
	g, err := cs2crypto.GNSNewAEAD(key)
	if err != nil {
		return -1
	}
	for d := int64(0); d <= int64(span); d++ {
		// uint64(-d) 在补码下等价于「减 d」，正好模拟 add qword 的负数增量。
		nonce := cs2crypto.GNSIVForSeq(iv, uint64(-d))
		if _, err := cs2crypto.GNSOpenWithAEAD(g, nonce, pkt); err == nil {
			return -d
		}
	}
	return -1
}

// gnsProbeCryptHead 是「宽 delta」这条路的主入口。
//
// 只试最可能的那个 key 窗口（CCrypto 对象头 32 字节 —— 若 [conn+0x19e0]
// 指向 CryptoKey，前 32 字节就是原始 AES-256 密钥），四个 (方向, IV) 组合里
// 只取最合逻辑的两个：c2s×IV1、s2c×IV2。
//
// 刻意放在常规扫描**之后**：常规扫描快（毫秒级），这条路慢（秒级），
// 只有常规路全灭时才值得付这个代价。
func gnsProbeCryptHead(proc *memscan.Process, c gnsConn,
	framesByDir map[string][][]byte) (gnsMemResult, bool) {

	for _, it := range []struct {
		ptr uintptr
		dir string
		iv  []byte
	}{
		{c.CryptT, "c2s", c.IV1},
		{c.CryptR, "s2c", c.IV2},
	} {
		if !plausiblePtr(it.ptr) || len(it.iv) != 12 {
			continue
		}
		frames := framesByDir[it.dir]
		if len(frames) == 0 {
			continue
		}
		obj := gnsReadLenient(proc, it.ptr, gnsCryptSpan)
		if len(obj) < 32 {
			continue
		}
		last := frames[len(frames)-1]
		for _, off := range []int{0, 32} {
			if off+32 > len(obj) {
				continue
			}
			key := obj[off : off+32]
			if !plausibleKey(key) {
				continue
			}
			if d := gnsWideDeltaProbe(key, it.iv, last, gnsWideDeltaSpan); d >= 0 {
				privateDiagnosticf(
					"[gnsmem] 宽 delta 命中：%#x+%d key=%x iv=%x delta=%d dir=%s\n",
					it.ptr, off, key, it.iv, d, it.dir)
				return gnsMemResult{
					Key:    append([]byte(nil), key...),
					IV:     append([]byte(nil), it.iv...),
					Dir:    it.dir,
					KeyAt:  it.ptr + uintptr(off),
					Frames: 1,
					Src:    "CCrypto 头部（宽 delta）",
				}, true
			}
		}
	}
	return gnsMemResult{}, false
}
