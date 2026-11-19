// GNS 握手材料的收集与上行 —— 2026-10-19 定案后的主链路。
//
// 结论：CS2 的 game 连接走的是 Valve GameNetworkingSockets 的直连 UDP 传输，
// 0x22/0x23 是它的 ConnectRequest/ConnectOK，会话密钥由
// FinishCryptoHandshake 里的 HKDF-SHA256 派生。派生需要四段**线上原始字节**
// （双方 cert.cert 与 crypt.info），所以必须把整个握手报文留下来，不能只留公钥。
//
// 本文件只做「攒料 + 推给解码端」，真正的派生在 radarsrv.tryGNS 里做 ——
// 因为私钥在解码端（uplink 的 Key 字段）才有。
package main

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/handshake"
	"local/cs2-radar/internal/memscan"
	"local/cs2-radar/internal/uplink"
)

// gnsMaxFrames 是每个方向留多少帧做判据。
//
// 不需要很多：GCM 认证错一个字节就失败，3 帧就能定胜负。留 24 帧是为了
// 容忍「前几帧序号偏大导致回绕判断失败」这类边角情况，同时让全内存扫描
// 有多个短帧可选（判据帧越短扫得越快）。
const gnsMaxFrames = 24

// gnsRecoverMinFrames 是「开跑内存恢复」前，**每个方向**至少要攒多少帧。
//
// gnsTryKey 要求 3 帧全部通过 GCM 认证。用 3 帧去验密钥，等于让
// 「其中一帧不完整」直接变成「密钥错了」—— 2026-10-19 15:08 现场就是这样：
// s2c 只有 3 帧，全灭，日志只写「都不对」，看不出是判据本身不够。
// 取 6 = 判据帧数的两倍余量，成本为零（帧本来就每包都在收）。
const gnsRecoverMinFrames = 6

// gnsRecoverMaxTries 是一次会话里最多扫几遍内存。
//
// 原来是 3，但配合旧的「一边够就开跑」闸门，这 3 次全在开局几秒内烧完
// （帧才 6 个的时候），之后帧涨到 2000 也不再试。现在配合 gnsRecoverAt
// 的「帧数涨一档才重试」，6 次能覆盖 6/12/18/24 四档，够用。
const gnsRecoverMaxTries = 6

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// noteGNSPeer 记下一个方向的握手材料；两个方向都齐了才推给解码端。
//
// 客户端材料一变（换图/重连/换服务器），服务器材料必须一起作废 ——
// 否则会拿上一次的服务器公钥配这一次的客户端私钥，派生出永远解不开的密钥，
// 而日志上看起来一切正常。
func (s *captureSession) noteGNSPeer(p *handshake.GNSPeer) {
	if p == nil || len(p.Pub) != 32 {
		return
	}
	s.gnsMu.Lock()
	switch p.Type {
	case handshake.TypeGNSConnectRequest:
		changed := string(p.ConnID) != string(s.gnsClientID)
		s.gnsClient = p
		s.gnsClientID = p.ConnID
		if changed {
			s.gnsServer = nil
			s.gnsServerID = nil
			// 换连接就得换判据帧：旧帧是用旧密钥加的，拿它验证新密钥必然失败。
			s.gnsFrameMu.Lock()
			s.gnsC2S, s.gnsS2C = nil, nil
			s.gnsFrameMu.Unlock()
			s.gnsRecover.Store(false)
			s.gnsRecoverTries.Store(0)
			s.gnsRecoverAt.Store(0)
		}
	case handshake.TypeGNSConnectOK:
		// 只有回显的客户端连接 ID 对得上的 ConnectOK 才收
		// （五元组已经在调用点卡过，这里再核一次连接 ID，防串连接）。
		if s.gnsClient == nil {
			s.gnsMu.Unlock()
			return
		}
		if len(p.EchoConnID) == 4 && len(s.gnsClient.ConnID) == 4 &&
			string(p.EchoConnID) != string(s.gnsClient.ConnID) {
			s.gnsMu.Unlock()
			return
		}
		s.gnsServer = p
		s.gnsServerID = p.ConnID
	default:
		s.gnsMu.Unlock()
		return
	}
	c, sv := s.gnsClient, s.gnsServer
	s.gnsMu.Unlock()

	if c == nil || sv == nil {
		return
	}
	m := &uplink.GNSMaterial{
		ClientConnID: b64(c.ConnID),
		ServerConnID: b64(sv.ConnID),
		ClientPub:    b64(c.Pub),
		ServerPub:    b64(sv.Pub),
		ClientNonce:  b64(c.Nonce),
		ServerNonce:  b64(sv.Nonce),
		ClientCert:   b64(c.Cert),
		ServerCert:   b64(sv.Cert),
		ClientCrypt:  b64(c.Crypt),
		ServerCrypt:  b64(sv.Crypt),
	}
	if !m.Complete() {
		privateDiagnosticf("[gns] 握手材料不齐（cert/crypt 缺失），暂不下发：client cert=%d crypt=%d / server cert=%d crypt=%d\n",
			len(c.Cert), len(c.Crypt), len(sv.Cert), len(sv.Crypt))
		return
	}
	s.sender.SetGNS(m)
	privateDiagnosticf(
		"[gns] 握手材料已下发：connID %x→%x｜客户端临时公钥 %x｜服务器临时公钥 %x\n",
		c.ConnID, sv.ConnID, c.Pub, sv.Pub)
}

// keepGNSFrame 收一帧本连接的 GNS 加密数据包。
//
// 两个条件缺一不可：
//  1. flags ∈ {0x80..0x83}（`GNSChunkOffset` 管，把 Steam 客户端那些
//     长得像的私有协议包挡在外面）；
//  2. 帧头第 1~4 字节的**收方 connID** 等于本次连接对应的一端。
//
// 09:01 那次现场就是因为缺了 ②，缓冲区里 2000 帧绝大部分是别的 UDP 流，
// 挑出来的判据帧 connID 全对不上，768 组变体自然全灭。
func (s *captureSession) keepGNSFrame(dir string, raw []byte) bool {
	if len(raw) < 24 { // 7 字节头 + 至少 1 字节密文 + 16 字节 tag
		return false
	}
	hiBit := raw[0]&0x80 != 0
	s.gnsMu.Lock()
	want := s.gnsClientID // s2c：收方是客户端
	if dir == "c2s" {
		want = s.gnsServerID // c2s：收方是服务器
	}
	idA := append([]byte(nil), s.gnsClientID...)
	idB := append([]byte(nil), s.gnsServerID...)
	s.gnsMu.Unlock()

	// connID 是这里唯一有现场证据的判据 —— store 侧就靠它从同一批包里挑出
	// 1167 帧。flags 高位没有证据：09:27 那次「flags 必须 ∈ 0x80..0x83」这条
	// 照开源源码推出来的假设把帧全拒了，采集端一帧没留、日志一个字没有。
	// 所以高位只用来排优先级，不再当闸门。
	connOK := len(want) == 4 && cs2crypto.GNSFrameForConn(raw, want)

	kept := false
	if connOK {
		s.gnsFrameMu.Lock()
		buf := &s.gnsS2C
		if dir == "c2s" {
			buf = &s.gnsC2S
		}
		if len(*buf) < gnsMaxFrames {
			*buf = append(*buf, append([]byte(nil), raw...))
		} else {
			// 🔴 满了必须丢**最旧**的、留最新的，不能停止追加。
			//
			// 内存里读到的 IV 是「读的那一刻」的当前 nonce（见硬规则 127），
			// 所以判据帧的序号越接近读内存的时刻，nonce 修正量越小。
			// 原来满了就 `kept=false` 直接跳过 —— 缓冲区里留的是一局开头那
			// 24 帧，等到真的去读内存时已经过去几千个包，nonce 无论怎么修
			// 都对不上，而现象只是「0 帧可解」。
			copy(*buf, (*buf)[1:])
			(*buf)[len(*buf)-1] = append([]byte(nil), raw...)
		}
		kept = true
		s.gnsFrameMu.Unlock()
	}

	s.gnsDiagObserve(dir, raw, idA, idB, hiBit, connOK, kept)
	return kept
}

// gnsFrameDiag 是一次性的收帧诊断。
//
// 存在的理由：09:27 那次现场 `has_gns=true`、store 里攒了 1167 帧，
// 但采集端一帧都没收进判据缓冲，于是「内存读 IV」整条链路根本没启动，
// 而日志上一个字都没有 —— 只能靠猜是哪一道闸门。
// 这里把每道闸门的通过数、flags 直方图、以及几条真实包头都打出来，
// 一次就能定位，不用再来一轮。
type gnsFrameDiag struct {
	seen   int
	hi     int
	conn   int
	kept   int
	flags  map[byte]int
	ids    map[string]int
	sample []string
	done   bool

	// idsS2C 统计**所有** s2c 包的 pkt[1:5]，不管有没有命中。
	//
	// 为什么要它：10:12 现场的 391 个命中帧收方全是 `d6fecb01`（服务器），
	// 客户端 `2fb8427a` 一个都没有 —— 而诊断报告说 51335 端口上有 2087 个
	// s2c 包。也就是说「服务端发回来的帧，收方字段根本不是客户端 connID」，
	// 或者根本不是 GNS 数据帧。这条独立于 KDF，不查清就算密钥找到了
	// 也只有 c2s 能解，雷达照样不出目标。
	idsS2C map[string]int
	s2cN   int
}

// gnsDiagObserve 记录一次判定，够量了打印一次就永久停。
func (s *captureSession) gnsDiagObserve(dir string, raw []byte, idA, idB []byte, hiBit, connOK, kept bool) {
	s.gnsDiagMu.Lock()
	defer s.gnsDiagMu.Unlock()
	d := &s.gnsDiag
	if d.flags == nil {
		d.flags = map[byte]int{}
		d.ids = map[string]int{}
		d.idsS2C = map[string]int{}
	}
	// s2c 的收方字段分布**永远统计**，不受 400 包窗口和 done 影响。
	//
	// 因为 s2c 流量往往在握手之后才开始，而 400 包窗口在握手那一刻就用完了 ——
	// 10:12 那次正是这样：主汇总里 s2c 收方是空的，但报告说有 2087 个 s2c 包。
	if dir == "s2c" && len(raw) >= 5 {
		d.idsS2C[fmt.Sprintf("%x", raw[1:5])]++
		d.s2cN++
		if d.s2cN == 200 || d.s2cN == 2000 || d.s2cN == 20000 {
			gnsPrintS2CIDs(d, idA)
		}
	}
	if d.done {
		return
	}
	d.seen++
	// 🔴 flags 直方图必须统计**全部**候选包，不能只在「高位=1」时记。
	// 09:27 那次就是不确定真实 flags 长什么样才要打这个表；如果只在
	// 高位为 1 时记，而真实 flags 恰好不带高位，打出来就是空表 ——
	// 等于花了一轮什么都没问到。
	d.flags[raw[0]]++
	if hiBit {
		d.hi++
	}
	if connOK {
		d.conn++
	}
	if kept {
		d.kept++
	}
	if connOK && len(d.sample) < 6 {
		n := len(raw)
		if n > 24 {
			n = 24
		}
		id, _ := cs2crypto.GNSFrameToConnID(raw)
		d.ids[fmt.Sprintf("%x", id)]++
		d.sample = append(d.sample, fmt.Sprintf("    %s len=%d % x", dir, len(raw), raw[:n]))
	}
	if d.seen < 400 {
		return
	}
	d.done = true

	var fl []string
	for b, n := range d.flags {
		fl = append(fl, fmt.Sprintf("%02x×%d", b, n))
	}
	sort.Strings(fl)
	var ids []string
	for k, n := range d.ids {
		ids = append(ids, fmt.Sprintf("%s×%d", k, n))
	}
	sort.Strings(ids)

	privateDiagnosticf(
		"[gnsdiag] 判定 %d 包｜高位=1 %d｜connID 命中 %d｜收下 %d\n"+
			"          期望 s2c 收方=%x / c2s 收方=%x\n"+
			"          flags 分布 %v\n"+
			"          命中帧收方 %v\n%s\n",
		d.seen, d.hi, d.conn, d.kept,
		idA, idB, fl, ids,
		strings.Join(d.sample, "\n"))
	gnsPrintS2CIDs(d, idA)
}

// gnsPrintS2CIDs 打印 s2c 收方字段的 top5（按次数降序）。
//
// 这条输出的用途很具体：如果 top 里没有客户端的 connID，
// 说明「服务端发回来的帧」的收方字段根本不是客户端 ID ——
// 要么帧头布局不是 [flags][to][seq]，要么这些包不是 GNS 数据帧。
// 无论哪种，都得先修这个再看 KDF，否则密钥找到了也只有 c2s 能解。
func gnsPrintS2CIDs(d *gnsFrameDiag, clientID []byte) {
	type idc struct {
		id string
		n  int
	}
	top := make([]idc, 0, len(d.idsS2C))
	for k, n := range d.idsS2C {
		top = append(top, idc{k, n})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].n != top[j].n {
			return top[i].n > top[j].n
		}
		return top[i].id < top[j].id
	})
	if len(top) > 5 {
		top = top[:5]
	}
	var s2cIDs []string
	hit := false
	for _, t := range top {
		s2cIDs = append(s2cIDs, fmt.Sprintf("%s×%d", t.id, t.n))
		if t.id == fmt.Sprintf("%x", clientID) {
			hit = true
		}
	}
	verdict := "top5 里**没有**客户端 connID —— s2c 帧头布局或帧类型不对"
	if hit {
		verdict = "top5 里有客户端 connID —— 收方字段正常"
	}
	privateDiagnosticf(
		"[gnsdiag] s2c 收方分布（累计 %d 包，期望 %x）%v\n          %s\n",
		d.s2cN, clientID, s2cIDs, verdict)
}

// gnsHandshakeSnapshot 把当前握手材料拍成一份 cs2crypto.GNSHandshake。
//
// 采集端内部用的是 handshake.GNSPeer（解析产物），而 KDF 输入比对要用
// cs2crypto 那套字段名。这里做一次浅拷贝 —— 两个结构里的切片都是
// 解析完就只读的，共享底层数组安全。
func (s *captureSession) gnsHandshakeSnapshot() *cs2crypto.GNSHandshake {
	s.gnsMu.Lock()
	c, sv := s.gnsClient, s.gnsServer
	s.gnsMu.Unlock()
	if c == nil || sv == nil {
		return nil
	}
	return &cs2crypto.GNSHandshake{
		ClientConnID: c.ConnID, ServerConnID: sv.ConnID,
		ClientPub: c.Pub, ServerPub: sv.Pub,
		ClientNonce: c.Nonce, ServerNonce: sv.Nonce,
		ClientCert: c.Cert, ServerCert: sv.Cert,
		ClientCrypt: c.Crypt, ServerCrypt: sv.Crypt,
	}
}

// maybeRecoverGNS 在攒够判据帧之后，启动一次「内存读 IV + 反推密钥」。
//
// 为什么要有这条旁路：KDF 的结构已经反汇编确认到字段级，但它的输入里
// 有两段无法枚举的原始字节（四段 cert/crypt 的排列与边界）。拼错的话
// 密钥和 IV 会一起错，而且没有任何可观测迹象 —— 只能靠真实帧的 GCM
// 认证去证伪，枚举再多变体也是在赌。
//
// 内存这条路是确定的：基础 IV 常驻在 [conn+0x19f0]/[conn+0x19fc]，
// 密钥常驻在 CCrypto 对象里，两者都活整个会话，不需要冻结、不需要 hook。
func (s *captureSession) maybeRecoverGNS() {
	// 🔴 密钥已经通过 GCM 认证并交给解析器之后，内存恢复就没有意义了。
	//
	// 22:35 那局的现场：`[room1] GNS 复核：16/16 帧 GCM 认证通过` 之后，
	// `[gnsmem] ... 177 个候选窗口，都不对` 又刷了 6 遍，中间还夹着一次
	// `[gnsnear] 扫 330.2 KB / 试 176132 个窗口（耗时 16.005s）`。
	// 这些都是纯浪费：每轮要遍历一遍 cs2.exe 的内存，对局中白烧 CPU 和
	// 内存带宽，而且**对结果没有任何影响** —— 密钥已经拿到了。
	if s.keyReady.Load() && !*flagMemSessionKey {
		return
	}
	// 先把「还值不值得试」判掉，再复制缓冲区。
	// 现在每收一帧都会走到这里（环形缓冲一直保持满），先判条件能省掉
	// 每包 48 次切片复制的开销。
	if s.gnsRecoverTries.Load() >= gnsRecoverMaxTries {
		return
	}
	if s.gnsRecover.Load() {
		return // 已经有一个在跑
	}

	s.gnsFrameMu.Lock()
	c2s := append([][]byte(nil), s.gnsC2S...)
	s2c := append([][]byte(nil), s.gnsS2C...)
	s.gnsFrameMu.Unlock()

	// 🔴 两个方向都必须够，不能「一边够就开跑」。
	//
	// 2026-10-19 15:08 现场：闸门原来是 `len(c2s) < 6 && len(s2c) < 6`，
	// 于是第一次恢复在 c2s=6 / s2c=3 时启动。gnsTryKey 要求 3 帧全过，
	// s2c 只有 3 帧 = 任何一帧不完整就把正确密钥判死，而且日志上
	// 看起来只是「都不对」。这种假阴性比「没跑」更难查。
	minN := len(c2s)
	if len(s2c) < minN {
		minN = len(s2c)
	}
	if minN < gnsRecoverMinFrames {
		return // 有一边帧太少，等下一批
	}
	// 上一轮试过之后帧没涨多少，就别再扫同一段内存。
	// 同样的内存扫两遍不会变出新结果，只会白烧十几秒 CPU 和内存带宽。
	if prev := int(s.gnsRecoverAt.Load()); prev > 0 && minN < prev+gnsRecoverMinFrames {
		return
	}
	// 每次尝试都要遍历一遍目标进程内存，所以限定次数：连接对象如果是
	// 稍后才分配的，前几次失败是正常的；但同样的内存多扫几遍并不会
	// 提高成功率。
	if !s.gnsRecover.CompareAndSwap(false, true) {
		return // 已经有一个在跑
	}
	s.gnsRecoverTries.Add(1)
	s.gnsRecoverAt.Store(int32(minN))
	s.gnsMu.Lock()
	idA := append([]byte(nil), s.gnsClientID...)
	idB := append([]byte(nil), s.gnsServerID...)
	s.gnsMu.Unlock()
	if len(idA) != 4 || len(idB) != 4 {
		s.gnsRecover.Store(false)
		return
	}

	go func() {
		ok := false
		defer func() {
			if !ok {
				// 失败后放开闸门：下一批帧进来会再试一次。
				// 只失败一次就永久放弃是错的 —— 连接对象可能是稍后才分配的。
				s.gnsRecover.Store(false)
			}
		}()

		pid, err := resolvePID()
		if err != nil {
			// 🔴 只打一次。反作弊在场时 resolvePID 每次都被闸门拦下，
			// 原来这里每 2 秒刷一行，07:20 那局 88 秒刷了 4 遍以上，
			// 把「为什么没目标」的说明全冲掉了。
			if s.memPIDErrOnce.CompareAndSwap(false, true) {
				privateDiagnosticf("[gnsmem] 解析目标进程失败：%v\n"+
					"         （这条只打一次；后面不再重试，直到进程状态变化）\n", err)
			}
			return
		}
		proc, err := memscan.OpenForRead(pid)
		if err != nil {
			privateDiagnosticf("[gnsmem] 打开进程失败：%v\n", err)
			return
		}
		defer proc.Close()

		frames := map[string][][]byte{"c2s": c2s, "s2c": s2c}
		deadline := time.Now().Add(10 * time.Minute)
		t0 := time.Now()
		// 定位到 conn 对象就先把两把 IV 上报 —— 这是**不依赖帧**的判据：
		// IV 低 8 字节随包前移、高 4 字节整局不变，所以解码端可以拿
		// 「KDF 派生的 IV 高 4 字节」直接和它对，一次定死 1152 个变体。
		onConn := func(c gnsConn) {
			s.sender.SetGNSIVs(&uplink.GNSIVMaterial{
				ClientConnID: fmt.Sprintf("%x", c.IDA),
				ServerConnID: fmt.Sprintf("%x", c.IDB),
				SendIV:       b64(c.IV1),
				RecvIV:       b64(c.IV2),
			})
		}
		// 私钥：KDF 离线复现包要用它。keyfind 在另一个 goroutine 里写，
		// 所以这里必须拿 keyMu 拷一份。
		s.keyMu.Lock()
		priv := append([]byte(nil), s.foundKey...)
		s.keyMu.Unlock()

		res, found := gnsRecoverFromMemory(proc, idA, idB, frames, deadline,
			s.gnsHandshakeSnapshot(), priv, onConn)
		if !found {
			privateDiagnosticf("[gnsmem] 内存恢复未命中（耗时 %s），判据帧 c2s=%d s2c=%d\n",
				time.Since(t0).Truncate(time.Millisecond), len(c2s), len(s2c))
			return
		}
		ok = true

		privateDiagnosticf(
			"[gnsmem] 会话密钥已从内存取到：方向 %s｜密钥 @%#x（%s）｜IV %x｜%d 帧可解\n",
			res.Dir, res.KeyAt, res.Src, res.IV, res.Frames)

		m := &uplink.GNSKeysMaterial{
			ClientConnID: b64(idA),
			ServerConnID: b64(idB),
			Dir:          res.Dir,
			Key:          b64(res.Key),
			IV:           b64(res.IV),
		}
		// 🔴 第二个方向必须一起报。GNS 两个方向用两把不同的密钥，只报一边
		// 解码端就只能解一边 —— 现场 13:24 全程只有 `方向=c2s`，s2c 的实体
		// 数据一条没解，雷达没有任何目标。
		if res.AltKey != nil {
			m.AltDir, m.AltKey, m.AltIV = res.AltDir, b64(res.AltKey), b64(res.AltIV)
			privateDiagnosticf("[gnsmem] 另一方向也一起上报：%s｜密钥 @%#x｜%d 帧可解\n",
				res.AltDir, res.AltKeyAt, res.AltFrames)
		}
		s.sender.SetGNSKeys(m)

		// 立刻刷一批：材料要赶在下一批数据之前到解码端，
		// 否则那批帧会被当成"解不开"白白丢掉。
		_ = s.sender.Flush(false)
	}()
}
