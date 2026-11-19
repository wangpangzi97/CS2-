// 从连接对象里把 KDF 的**真实输入**取出来，和我们从线上报文重建的那一份做比对。
//
// 为什么需要这个文件
// ----------------
// 09:53 和 10:02 两次现场，私钥都拿到了（`has_key=true`），1152 个变体
// 全灭；而「IV 高 4 字节」这个**不依赖帧**的判据也一次都没命中：
//
//	[room1] IV 高 4 字节在全部变体里都没对上 —— KDF 的输入仍然不对
//
// 这条判据把 nonce 规则彻底排除了，剩下的只可能是 KDF 的输入本身：
// 四段 cert/crypt 的**字节**、salt、connID 上下文、或者标签。
//
// 而 `FinishCryptoHandshake` 读的就是连接对象里的四个槽位
// （+0x1798 / +0x17b8 / +0x1988 / +0x19b8）和两段 8 字节 salt
// （+0x1890 / +0x1968）。这些东西**现在都能直接读到**（conn 对象已经定位到）。
//
// 所以不需要再猜：把内存里的原样取出来，和线上重建的那一份比。
//   - 四段全等 → 我们的 blob 是对的，错在 salt / 标签 / 展开结构
//   - 有不等   → 拿到正确字节，直接换掉
//
// 两种结果都直接指向下一步，不用再来一轮盲改。
package main

import (
	"fmt"
	"time"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/memscan"
)

// KDF 输入在连接对象里的偏移（全部来自 0x9d590 的反汇编）。
const (
	gnsOffSaltA = 0x1890 // 8 字节 nonce（客户端侧）
	gnsOffSaltB = 0x1968 // 8 字节 nonce（服务器侧，RecvConnectOK 写入）
	gnsOffBlob0 = 0x1798 // 内联 CUtlString
	gnsOffBlob1 = 0x17b8 // 内联 CUtlString
	gnsOffBlob2 = 0x1988 // 指针型 CUtlString
	gnsOffBlob3 = 0x19b8 // 指针型 CUtlString

	// 单个 blob 最多读多少字节。cert/crypt 都是几百字节量级，1 KB 够。
	gnsBlobRead = 1024
)

// gnsWireBlob 是线上重建的一段（名字 + 原始字节），顺序固定，便于比对。
type gnsWireBlob struct {
	Name string
	Data []byte
}

// gnsBlobSlot 描述一个槽位在内存里的原样内容，以及几种可能的解读。
//
// 为什么要这么多种解读：CUtlString / CUtlMemory 在不同 Valve 构建里布局不完全一样，
// 而反汇编只能看出「读了这个地址」，看不出类型。真正安全的做法不是赌一种，
// 而是把常见布局全解一遍，然后拿「和线上四段能不能对上」来判胜负 ——
// 字节本身会说话，不需要猜。
type gnsBlobSlot struct {
	Off    int    `json:"off"`
	RawHex string `json:"raw_hex"` // 槽位处 32 字节原样
	Ptr    string `json:"ptr,omitempty"`
	Alloc  int    `json:"alloc"` // dword @ off+8
	Len16  int    `json:"len16"` // dword @ off+16（CUtlString::m_nActualLength 常见位置）
	// 指针 + 容量长度 / 指针 + strlen / 指针 + len16
	AsPtrCap string `json:"as_ptr_cap,omitempty"`
	AsPtrStr string `json:"as_ptr_str,omitempty"`
	AsPtrLen string `json:"as_ptr_len16,omitempty"`
	// 内联 + 容量长度 / 内联 + strlen / 内联 + len16
	AsInCap string `json:"as_inline_cap,omitempty"`
	AsInStr string `json:"as_inline_str,omitempty"`
	AsInLen string `json:"as_inline_len16,omitempty"`
	// 和线上重建的四段里哪一段对上了（"ptr_cap:client_cert" 等），空=都没对上
	Matched string `json:"matched,omitempty"`
	// 指针指向的那块内存的头 64 字节 —— 现场（10:12）证明槽位里是指针+元数据，
	// 不是 blob 本体，所以必须把被指向的内容也打出来才看得出结构。
	PtrHead string `json:"ptr_head,omitempty"`
	// 顺着指针（必要时再下一层）找到的四段位置，形如 "client_cert@+0x10"
	PtrScan string `json:"ptr_scan,omitempty"`
	Note    string `json:"note,omitempty"`
}

// gnsKDFDump 是写到磁盘的完整现场，供离线复现。
type gnsKDFDump struct {
	Ts           string `json:"ts"`
	ConnAddr     string `json:"conn_addr"`
	ClientConnID string `json:"client_conn_id"`
	ServerConnID string `json:"server_conn_id"`
	SendIV       string `json:"send_iv"`
	RecvIV       string `json:"recv_iv"`

	SaltAMem        string `json:"salt_a_mem"` // [conn+0x1890] 8 字节
	SaltBMem        string `json:"salt_b_mem"` // [conn+0x1968] 8 字节
	ClientNonceWire string `json:"client_nonce_wire"`
	ServerNonceWire string `json:"server_nonce_wire"`
	SaltSame        string `json:"salt_same"` // salt 与线上 nonce 的对应关系结论
	RawScan         string `json:"raw_scan"`  // 线上四段在连接对象里的实际偏移

	Slots []gnsBlobSlot `json:"slots"`

	// 线上重建的四段（我们现在喂给 KDF 的那一份）
	WireClientCert  string `json:"wire_client_cert"`
	WireServerCert  string `json:"wire_server_cert"`
	WireClientCrypt string `json:"wire_client_crypt"`
	WireServerCrypt string `json:"wire_server_crypt"`
	WireLens        string `json:"wire_lens"`

	// 连接对象整段原样（0x1700 起，覆盖四个槽位 + 两段 salt）
	RawHex string `json:"raw_hex_1700_1a20"`
}

// gnsWireBlobs 返回线上重建的四段及其名字。
func gnsWireBlobs(h *cs2crypto.GNSHandshake) [4]gnsWireBlob {
	return [4]gnsWireBlob{
		{"client_cert", h.ClientCert},
		{"server_cert", h.ServerCert},
		{"client_crypt", h.ClientCrypt},
		{"server_crypt", h.ServerCrypt},
	}
}

// gnsAlignRead 把 [addr, addr+n) 对齐到 4 KB 页边界。
//
// 返回对齐后的起始地址、总长度、以及目标地址相对起始地址的前导字节数。
// 单独抽出来是因为「按页读」的正确性全在这三行算术上，值得单独钉住。
func gnsAlignRead(addr uintptr, n int) (start uintptr, total, lead int) {
	const page = 0x1000
	start = addr &^ (page - 1)
	lead = int(addr - start)
	return start, lead + n, lead
}

// gnsReadLenient 尽量读满 n 字节，坏页留零、不整体失败。
//
// 🔴 必须按页读（2026-10-19 10:22 现场踩到）：
// `ReadProcessMemory` 只要请求范围里有**一个**不可读字节就整段返回 0。
// 之前直接一次性读 64 KB 窗口，结果 `[gnsnear] 扫 0.0 KB / 试 0 个窗口` ——
// 扫描根本没跑，日志还看起来像「扫过了但没命中」。
//
// 按 4 KB 页对齐逐页读，坏页跳过（留零），返回长度恒为 n。
// 零字节会被 plausibleKey 直接筛掉，所以留零不会引入假候选。
func gnsReadLenient(proc *memscan.Process, addr uintptr, n int) []byte {
	if proc == nil || n <= 0 {
		return nil
	}
	const page = 0x1000
	start, total, lead := gnsAlignRead(addr, n)
	buf := make([]byte, total)
	for off := 0; off < total; off += page {
		hi := off + page
		if hi > total {
			hi = total
		}
		_, _ = proc.ReadAt(start+uintptr(off), buf[off:hi])
	}
	return buf[lead:]
}

// gnsScanRawForWire 在连接对象的原始字节里找每段线上 blob 的开头。
//
// 为什么还需要这一步：如果四个槽位的偏移本身就记错了（反汇编认错一层），
// 上面所有解读都会落空，但「字节其实就在附近」这个事实仍然值得看见 ——
// 找到的实际偏移可以直接拿来修 gnsOffBlob*，不用再猜。
// gnsFindBlob 在 buf 里找一段线上 blob，返回它在 buf 里的起始下标（找不到 -1）。
//
// 🔴 必须同时试「偏移 0」和「偏移 1」两种针（2026-10-19 15:08 现场定案）。
//
// 现场证据（gns-kdf-20261019-150841.json）：
//
//	conn+0x1798 的指针目标: 00 01 12 20 30327618...   ← server_cert
//	conn+0x17b8 的指针目标: 00 01 12 20 02fcc7da...   ← server_crypt
//	线上 server_cert      : 08 01 12 20 30327618...
//	线上 server_crypt     : 08 01 12 20 02fcc7da...
//
// 除首字节（内存 `00` / 线上 `08`）之外**逐字节相同**。原来从下标 0 取 12 字节
// 当针，于是永远找不到，日志写成「四段在 conn 对象里的实际位置 未找到」，
// 把「已经拿到」误报成「没拿到」—— 这个假信号会让人往完全错误的方向找。
//
// 偏移 1 的针命中后要回退 1 才是 blob 的真实起点（内存里那个 `00` 属于 blob）。
func gnsFindBlob(buf, data []byte, probe int) int {
	if probe <= 0 || len(data) < probe+1 {
		return -1
	}
	// 先试偏移 0（正常情况，最快）。
	for i := 0; i+probe <= len(buf); i++ {
		if equalBytes(buf[i:i+probe], data[:probe]) {
			return i
		}
	}
	// 再试偏移 1：跳过首字节（内存里 field-1 tag 被改写成 00 的情况）。
	for i := 0; i+probe <= len(buf); i++ {
		if equalBytes(buf[i:i+probe], data[1:1+probe]) {
			// 命中位置是 blob 的第 1 字节，真实起点在 i-1。
			if i > 0 {
				return i - 1
			}
			return i
		}
	}
	return -1
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func gnsScanRawForWire(raw []byte, wire [4]gnsWireBlob) string {
	const probe = 12 // 用 12 字节当针，误命中率可忽略
	out := ""
	for _, w := range wire {
		if len(w.Data) < probe+1 {
			continue
		}
		at := gnsFindBlob(raw, w.Data, probe)
		if out != "" {
			out += "｜"
		}
		if at >= 0 {
			out += fmt.Sprintf("%s@+%#x", w.Name, at)
		} else {
			out += fmt.Sprintf("%s@未找到", w.Name)
		}
	}
	return out
}

// gnsReader 是「从目标地址读 n 字节」的抽象。
//
// 单独抽出来是为了让指针型解读能进单元测试 —— 生产路径传 memscan 的读取器，
// 测试路径传一个 map 假读取器，两边跑的是同一份解读逻辑。
type gnsReader func(addr uintptr, n int) []byte

// gnsFindWireIn 在 addr 起 gnsBlobRead 字节里找四段线上 blob 的开头。
//
// 找不到就顺着这块内存开头的 8 字节指针再下一层（最多 depth 层）。
// 为什么允许下钻：10:12 现场证明 conn 对象里的槽位指向的是**中间对象**，
// blob 在对象里面而不是开头 —— 只比前缀会全部落空。
func gnsFindWireIn(read gnsReader, addr uintptr, wire [4]gnsWireBlob,
	depth int, visited map[uintptr]bool) string {

	if read == nil || depth < 0 || !plausiblePtr(addr) || visited[addr] {
		return ""
	}
	visited[addr] = true
	buf := read(addr, gnsBlobRead)
	if len(buf) < 16 {
		return ""
	}

	const probe = 12
	var hits []string
	for _, w := range wire {
		if len(w.Data) < probe+1 {
			continue
		}
		// gnsFindBlob 会同时试偏移 0 和偏移 1 —— 现场内存里 blob 的首字节
		// 是 00、线上是 08，只比偏移 0 会永远找不到（见 gnsFindBlob 注释）。
		if at := gnsFindBlob(buf, w.Data, probe); at >= 0 {
			hits = append(hits, fmt.Sprintf("%s@+%#x", w.Name, at))
		}
	}
	if len(hits) > 0 {
		return joinStr(hits, " ")
	}
	if depth == 0 {
		return ""
	}
	// 下一层：这块内存开头可能是另一个对象的指针。
	next := uintptr(gnsLE64(buf[0:8]))
	if !plausiblePtr(next) || next == addr {
		return ""
	}
	if s := gnsFindWireIn(read, next, wire, depth-1, visited); s != "" {
		return "→" + s
	}
	return ""
}

func joinStr(a []string, sep string) string {
	out := ""
	for i, s := range a {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}

// gnsReadSlot 把一个槽位的几种解读都取出来。
//
// 说明：内联解读（AsInCap / AsInLen / AsInStr）和头部字段在同一基址上是
// 互斥的 —— 真按 CUtlMemory 布局，数据在 *ptr 而不在槽位本身。留这三种
// 只是兜底假设（万一反汇编认错一层，槽位其实是裸缓冲），成本接近零。
// 真正有希望命中的是指针型那三种。
func gnsReadSlot(read gnsReader, raw []byte, off int) gnsBlobSlot {
	s := gnsBlobSlot{Off: off}
	if off+32 > len(raw) {
		// 末尾槽位（0x19b8）只剩到 0x1a20，够 32 字节；真不够就降级到 16。
		if off+16 > len(raw) {
			s.Note = "槽位超出已读范围"
			return s
		}
		s.RawHex = fmt.Sprintf("%x", raw[off:off+16])
	} else {
		s.RawHex = fmt.Sprintf("%x", raw[off:off+32])
	}
	head := raw[off : off+16]

	ptr := uintptr(gnsLE64(head[0:8]))
	s.Ptr = fmt.Sprintf("%#x", ptr)
	// CUtlMemory 的布局是 {T *m_pMemory; int m_nAllocationCount; int m_nGrowSize}
	alloc := int(gnsLE32(head[8:12]))
	s.Alloc = alloc
	// CUtlString 在 m_Memory 之后还有 m_nActualLength，位置通常是 +0x10。
	len16 := 0
	if off+20 <= len(raw) {
		len16 = int(gnsLE32(raw[off+16 : off+20]))
	}
	s.Len16 = len16

	// 指针型解读：容量长度 / strlen / len16。
	if read != nil && plausiblePtr(ptr) {
		if head := read(ptr, 64); len(head) > 0 {
			s.PtrHead = fmt.Sprintf("%x", head)
		}
		if b := read(ptr, gnsBlobRead); len(b) > 0 {
			if alloc > 0 && alloc <= len(b) {
				s.AsPtrCap = fmt.Sprintf("%x", b[:alloc])
			}
			if len16 > 0 && len16 <= len(b) {
				s.AsPtrLen = fmt.Sprintf("%x", b[:len16])
			}
			if n := nulIndex(b); n > 0 {
				s.AsPtrStr = fmt.Sprintf("%x", b[:n])
			}
		} else {
			s.Note = "指针读不出内容"
		}
	}

	// 内联解读：数据就在槽位本身。
	tail := raw[off:]
	if len(tail) > gnsBlobRead {
		tail = tail[:gnsBlobRead]
	}
	if alloc > 0 && alloc <= len(tail) {
		s.AsInCap = fmt.Sprintf("%x", tail[:alloc])
	}
	if len16 > 0 && len16 <= len(tail) {
		s.AsInLen = fmt.Sprintf("%x", tail[:len16])
	}
	if n := nulIndex(tail); n > 0 {
		s.AsInStr = fmt.Sprintf("%x", tail[:n])
	}
	return s
}

// nulIndex 返回第一个 0 字节的位置，没有则返回 -1。
func nulIndex(b []byte) int {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return -1
}

// gnsMatchSlot 把槽位的四种解读和线上四段逐一比对，命中的写进 s.Matched。
//
// 判据见 blobPrefixMatch：前缀相等且长度差不超过 2。
// 长度差 1~2 是留给「带不带结尾 0 / 带不带长度前缀」这种边角差异 ——
// 这种差异本身就是我们要找的东西，所以必须能看见。
func gnsMatchSlot(s *gnsBlobSlot, wire [4]gnsWireBlob) {
	type cand struct {
		kind string
		hex  string
	}
	var hits []string
	for _, c := range []cand{
		{"ptr_cap", s.AsPtrCap},
		{"ptr_str", s.AsPtrStr},
		{"ptr_len16", s.AsPtrLen},
		{"inline_cap", s.AsInCap},
		{"inline_str", s.AsInStr},
		{"inline_len16", s.AsInLen},
	} {
		if c.hex == "" {
			continue
		}
		for _, w := range wire {
			if len(w.Data) == 0 {
				continue
			}
			if blobPrefixMatch(c.hex, w.Data) {
				hits = append(hits, c.kind+":"+w.Name)
			}
		}
	}
	if len(hits) == 0 {
		return
	}
	s.Matched = hits[0]
	if len(hits) > 1 {
		// 同一个槽位的不同解读都命中了：说明这个槽位本身有歧义，
		// 直接把全部候选列出来，别让读者以为只有一种可能。
		s.Matched = ""
		for i, h := range hits {
			if i > 0 {
				s.Matched += " | "
			}
			s.Matched += h
		}
	}
}

// blobPrefixMatch 判断 hex 表示的数据和 want 是否是「同一段内容」。
func blobPrefixMatch(hexStr string, want []byte) bool {
	if len(hexStr)%2 != 0 {
		return false
	}
	got := make([]byte, len(hexStr)/2)
	for i := 0; i < len(got); i++ {
		hi := hexVal(hexStr[i*2])
		lo := hexVal(hexStr[i*2+1])
		if hi < 0 || lo < 0 {
			return false
		}
		got[i] = byte(hi<<4 | lo)
	}
	if len(got) < 8 || len(want) < 8 {
		return false
	}
	n := 32
	if len(got) < n {
		n = len(got)
	}
	if len(want) < n {
		n = len(want)
	}
	// 🔴 从索引 1 开始比，跳过首字节。
	//
	// 现场实证（2026-10-19）：内存里服务端两段的首字节是 `00`，而线上抓到的是 `08`
	// （protobuf field-1 varint tag），其余 96 / 48 字节**逐字节相同**。
	// 旧实现从 0 开始比，于是永远判「0/4 命中」，把「四段全拿到」误报成「四段全没拿到」——
	// 这条假信号误导了好几轮的方向判断。
	for i := 1; i < n; i++ {
		if got[i] != want[i] {
			return false
		}
	}
	// 长度差超过 2 就不算同一段（防止「前 32 字节碰巧相同」的误判）。
	d := len(got) - len(want)
	if d < 0 {
		d = -d
	}
	return d <= 2
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// gnsLE32 按小端读 4 字节。
func gnsLE32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// gnsReproBlob 是连接对象里一个槽位指向的那块内存的原样。
type gnsReproBlob struct {
	Off   int    `json:"off"`   // 槽位在 conn 里的偏移
	Ptr   string `json:"ptr"`   // 槽位里的指针
	Dword int    `json:"dword"` // 槽位 +0x18 处的 dword（现场是 111 / 63）
	Data  string `json:"data"`  // 指针处 4 KB 原样（hex）

	// 深一层：指针处那 4 KB 里若还有 plausible 指针，顺它再读 4 KB。
	//
	// 为什么必须有：2026-10-19 10:42 实证四个槽位分成两种形态 ——
	//   +0x1798 / +0x17b8（服务端两段）是**内联**型，*ptr 直接就是 blob 本体
	//                        （`00 01 12 20 …`，首字节 00 而不是线上的 08）；
	//   +0x1988 / +0x19b8（客户端两段）是**指针**型，*ptr 处是一个
	//                        `{dataPtr, ?, len, …}` 的小结构 ——
	//                        它的 +0x10 处写着 `31 00 00 00` = 49 = client_crypt 长度，
	//                        真正的字节在 **dataPtr 再指一层的地方。
	// 只存一层的话，客户端两段永远是「未找到」，KDF 的输入就永远缺一半。
	Deep []gnsReproBlob `json:"deep,omitempty"`
}

// gnsRepro 是「离线复现 KDF」所需的全部材料。
//
// 为什么要在采集端落盘：KDF 卡了十几轮，每一轮都要用户重开一局、贴日志，
// 而真正缺的只是**一次现场的全部字节**。把私钥 + 握手四段 + 内存四段 +
// 两把 IV + 真实帧一次性写下来，就能在本地把 KDF 的每一种写法都试遍，
// 找到唯一正确的组合，再回来改一行常量。
type gnsRepro struct {
	Ts           string `json:"ts"`
	ConnAddr     string `json:"conn_addr"`
	ClientConnID string `json:"client_conn_id"`
	ServerConnID string `json:"server_conn_id"`

	ClientPub   string `json:"client_pub"`
	ServerPub   string `json:"server_pub"`
	ClientNonce string `json:"client_nonce"`
	ServerNonce string `json:"server_nonce"`
	ClientPriv  string `json:"client_priv"`

	SaltMem   string `json:"salt_mem"` // [0x1890]||[0x1968]，16 字节
	MemSendIV string `json:"mem_send_iv"`
	MemRecvIV string `json:"mem_recv_iv"`

	WireClientCert  string `json:"wire_client_cert"`
	WireServerCert  string `json:"wire_server_cert"`
	WireClientCrypt string `json:"wire_client_crypt"`
	WireServerCrypt string `json:"wire_server_crypt"`

	MemBlobs []gnsReproBlob `json:"mem_blobs"`

	// 会话密钥本体 —— 2026-10-19 10:35 现场从 conn 对象 0x19e0/0x19e8 读出两个指针，
	// 相隔正好 0x20（= 32 字节，一个 CryptoKey 的大小）。之前 repro 只存了
	// 「四个握手槽位」指向的 4KB，**没有存这两个 key 指针指向的 4KB**，
	// 导致离线复现时手上根本没有会话密钥，只能盲猜 KDF。
	KeySendAt   string `json:"key_send_at"`
	KeyRecvAt   string `json:"key_recv_at"`
	KeySendData string `json:"key_send_data"` // 4KB
	KeyRecvData string `json:"key_recv_data"` // 4KB

	// 再深一层：上面那 4KB 里如果还有 plausible 指针，各读 4KB。
	// 理由：0x19e0/0x19e8 指向的可能是 AES_GCM_EncryptContext（含 key schedule
	// + IV + 计数器），而不是裸 CryptoKey —— 那样前 32 字节就不是原始密钥，
	// 必须顺着它内部的指针再走一层才能摸到 key。
	KeySendDeep []gnsReproBlob `json:"key_send_deep"`
	KeyRecvDeep []gnsReproBlob `json:"key_recv_deep"`

	// conn 对象全量原文（0..gnsConnSpan，现在 0x3000 = 12 KB）。
	// 0x1a20 之前只有 IV 和握手指针，**没有任何高熵 32 字节窗口**；
	// GNS 的 m_cryptoSend/m_cryptoRecv 内联在 CConnection 里，
	// 会话密钥只可能在 0x1a20 之后 —— 全量存下来才能离线定位。
	ConnRaw string `json:"conn_raw"`

	// IV 区原文：[0x19d0, 0x1a20) 共 0x50 字节。
	// 已实证 [0x19f0]=sendIV(12) 与 [0x19fc]=recvIV(12) 在内存里是**连续 24 字节**，
	// 存整段是为了看清 IV 前后还有没有别的 nonce 变体。
	IVArea string `json:"iv_area"`

	FramesC2S []string `json:"frames_c2s"`
	FramesS2C []string `json:"frames_s2c"`
}

// conn 对象里会话密钥指针与 IV 区的偏移（2026-10-19 10:35 现场 dump 实证）。
const (
	gnsOffKeyPtrSend = 0x19e0 // qword → 发送侧 CryptoKey
	gnsOffKeyPtrRecv = 0x19e8 // qword → 接收侧 CryptoKey
	gnsOffIVArea     = 0x19d0 // IV 区起点
	gnsIVAreaLen     = 0x50   // 0x19d0..0x1a20
	gnsKeySpan       = 4096   // 每个 key 指针读 4KB，覆盖 AES key schedule 整个结构
)

// gnsWriteRepro 落盘离线复现包，返回路径。
func gnsWriteRepro(c gnsConn, h *cs2crypto.GNSHandshake, priv []byte,
	proc *memscan.Process, framesByDir map[string][][]byte) string {

	if h == nil || len(priv) != 32 {
		return ""
	}
	d := gnsRepro{
		Ts:              time.Now().Format("2006-01-02 15:04:05"),
		ConnAddr:        fmt.Sprintf("%#x", c.Addr),
		ClientConnID:    fmt.Sprintf("%x", c.IDA),
		ServerConnID:    fmt.Sprintf("%x", c.IDB),
		ClientPub:       fmt.Sprintf("%x", h.ClientPub),
		ServerPub:       fmt.Sprintf("%x", h.ServerPub),
		ClientNonce:     fmt.Sprintf("%x", h.ClientNonce),
		ServerNonce:     fmt.Sprintf("%x", h.ServerNonce),
		ClientPriv:      fmt.Sprintf("%x", priv),
		MemSendIV:       fmt.Sprintf("%x", c.IV1),
		MemRecvIV:       fmt.Sprintf("%x", c.IV2),
		WireClientCert:  fmt.Sprintf("%x", h.ClientCert),
		WireServerCert:  fmt.Sprintf("%x", h.ServerCert),
		WireClientCrypt: fmt.Sprintf("%x", h.ClientCrypt),
		WireServerCrypt: fmt.Sprintf("%x", h.ServerCrypt),
	}
	if len(c.Raw) >= gnsOffSaltB+8 {
		d.SaltMem = fmt.Sprintf("%x", c.Raw[gnsOffSaltA:gnsOffSaltA+8]) +
			fmt.Sprintf("%x", c.Raw[gnsOffSaltB:gnsOffSaltB+8])
	}
	for _, off := range []int{gnsOffBlob0, gnsOffBlob1, gnsOffBlob2, gnsOffBlob3} {
		if off+32 > len(c.Raw) {
			continue
		}
		p := uintptr(gnsLE64(c.Raw[off:]))
		b := gnsReproBlob{
			Off:   off,
			Ptr:   fmt.Sprintf("%#x", p),
			Dword: int(gnsLE32(c.Raw[off+24 : off+28])),
		}
		if plausiblePtr(p) {
			if data := gnsReadLenient(proc, p, 4096); len(data) > 0 {
				b.Data = fmt.Sprintf("%x", data)
				// 深一层：客户端两段（+0x1988/+0x19b8）是指针型，
				// 真正的字节在 *(*ptr + 8·k) 那一层，只存一层永远缺 client_cert/client_crypt。
				for doff := 0; doff+8 <= len(data) && len(b.Deep) < 2; doff += 8 {
					q := uintptr(gnsLE64(data[doff:]))
					if !plausiblePtr(q) || q == p {
						continue
					}
					sub := gnsReadLenient(proc, q, 4096)
					if len(sub) == 0 {
						continue
					}
					b.Deep = append(b.Deep, gnsReproBlob{
						Off:  doff,
						Ptr:  fmt.Sprintf("%#x", q),
						Data: fmt.Sprintf("%x", sub),
					})
				}
			}
		}
		d.MemBlobs = append(d.MemBlobs, b)
	}

	// 会话密钥本体：顺 [conn+0x19e0]/[conn+0x19e8] 两个指针各读 4KB。
	// 这是「不依赖 KDF」那条路唯一的输入，缺了它离线复现就只能猜。
	for _, it := range []struct {
		off  int
		at   *string
		data *string
		deep *[]gnsReproBlob
	}{
		{gnsOffKeyPtrSend, &d.KeySendAt, &d.KeySendData, &d.KeySendDeep},
		{gnsOffKeyPtrRecv, &d.KeyRecvAt, &d.KeyRecvData, &d.KeyRecvDeep},
	} {
		if it.off+8 > len(c.Raw) {
			continue
		}
		p := uintptr(gnsLE64(c.Raw[it.off:]))
		*it.at = fmt.Sprintf("%#x", p)
		if !plausiblePtr(p) {
			continue
		}
		block := gnsReadLenient(proc, p, gnsKeySpan)
		if len(block) == 0 {
			continue
		}
		*it.data = fmt.Sprintf("%x", block)
		// 深一层：8 字节对齐扫 plausible 指针，最多取 4 个，各读 4KB。
		for off := 0; off+8 <= len(block) && len(*it.deep) < 4; off += 8 {
			q := uintptr(gnsLE64(block[off:]))
			if !plausiblePtr(q) || q == p {
				continue
			}
			sub := gnsReadLenient(proc, q, gnsKeySpan)
			if len(sub) == 0 {
				continue
			}
			*it.deep = append(*it.deep, gnsReproBlob{
				Off:  off,
				Ptr:  fmt.Sprintf("%#x", q),
				Data: fmt.Sprintf("%x", sub),
			})
		}
	}

	// IV 区整段（0x19d0..0x1a20）：两把 IV 是连续 24 字节，前后还有别的字段。
	if gnsOffIVArea+gnsIVAreaLen <= len(c.Raw) {
		d.IVArea = fmt.Sprintf("%x", c.Raw[gnsOffIVArea:gnsOffIVArea+gnsIVAreaLen])
	}
	if len(c.Raw) > 0 {
		d.ConnRaw = fmt.Sprintf("%x", c.Raw)
	}
	take := func(frames [][]byte) []string {
		n := len(frames)
		if n > 8 {
			n = 8
		}
		out := make([]string, 0, n)
		for _, f := range frames[len(frames)-n:] {
			out = append(out, fmt.Sprintf("%x", f))
		}
		return out
	}
	d.FramesC2S = take(framesByDir["c2s"])
	d.FramesS2C = take(framesByDir["s2c"])

	if p := writeJSONFile("gns-repro", &d); p != "" {
		privateDiagnosticf(
			"[gnsrepro] 离线复现包已落盘：%s（私钥+握手四段+内存四段 4KB+IV+会话密钥 2×4KB(含深一层)+%d/%d 帧）\n",
			p, len(d.FramesC2S), len(d.FramesS2C))
		return p
	}
	privateDiagnosticf("[gnsrepro] 落盘失败（cwd 不可写？）\n")
	return ""
}

// gnsAnalyzeKDFInputs 读四个槽位、和线上四段比对、把现场落盘。
//
// 返回 true 表示四个槽位都和线上四段一一对上（映射无歧义）。
// 全对上说明我们喂给 KDF 的字节本来就是对的，问题在 salt / 标签 / 展开结构；
// 有对不上说明字节本身错了，dump 里就有正确的那份。
func gnsAnalyzeKDFInputs(proc *memscan.Process, c gnsConn, h *cs2crypto.GNSHandshake) bool {
	if h == nil || len(c.Raw) < gnsOffBlob3+16 {
		return false
	}
	wire := gnsWireBlobs(h)
	offs := []int{gnsOffBlob0, gnsOffBlob1, gnsOffBlob2, gnsOffBlob3}
	read := func(addr uintptr, n int) []byte { return gnsReadLenient(proc, addr, n) }

	slots := make([]gnsBlobSlot, 0, 4)
	matchedCount := 0
	seen := map[string]bool{}
	visited := map[uintptr]bool{}
	for _, off := range offs {
		s := gnsReadSlot(read, c.Raw, off)
		gnsMatchSlot(&s, wire)
		// 槽位里是「指针 + 元数据」时，顺着指针往下找 blob 的真实位置。
		if off+8 <= len(c.Raw) {
			if p := uintptr(gnsLE64(c.Raw[off:])); plausiblePtr(p) {
				s.PtrScan = gnsFindWireIn(read, p, wire, 2, visited)
			}
		}
		if s.Matched != "" {
			// 只认「单一解读单一名字」的干净命中，有歧义的不计入。
			name := s.Matched
			if i := indexByteStr(name, ':'); i >= 0 {
				name = name[i+1:]
			}
			if indexByteStr(name, '|') >= 0 {
				s.Note = "同一槽位多个解读都命中，映射有歧义"
			} else if seen[name] {
				s.Note = "同一段被两个槽位命中，映射有歧义"
			} else {
				seen[name] = true
				matchedCount++
			}
		}
		// 🔴 指针型槽位的命中在 PtrScan 里，不在 Matched 里 —— 必须一起计入。
		//
		// 2026-10-19 15:08 现场：四个槽位全是「指针 + 元数据」布局，
		// gnsMatchSlot 拿槽位自身那 16 字节去比 97 字节的 cert，永远不可能命中；
		// 真正的内容在指针目标处，由 gnsFindWireIn 找到。
		// 原来只数 Matched，于是日志写「0/4」，而实际上 server_cert 和
		// server_crypt 两段都在 —— 假信号把人往「blob 全错」的方向带。
		for _, nm := range []string{"client_cert", "server_cert", "client_crypt", "server_crypt"} {
			if containsStr(s.PtrScan, nm) && !seen[nm] {
				seen[nm] = true
				matchedCount++
			}
		}
		slots = append(slots, s)
	}

	// salt 两段：直接和线上 nonce 比，一眼看出对不对。
	saltA := c.Raw[gnsOffSaltA : gnsOffSaltA+8]
	saltB := c.Raw[gnsOffSaltB : gnsOffSaltB+8]
	saltSame := gnsSaltVerdict(saltA, saltB, h)
	rawScan := gnsScanRawForWire(c.Raw, wire)

	dump := gnsKDFDump{
		Ts:              time.Now().Format("2006-01-02 15:04:05"),
		ConnAddr:        fmt.Sprintf("%#x", c.Addr),
		ClientConnID:    fmt.Sprintf("%x", c.IDA),
		ServerConnID:    fmt.Sprintf("%x", c.IDB),
		SendIV:          fmt.Sprintf("%x", c.IV1),
		RecvIV:          fmt.Sprintf("%x", c.IV2),
		SaltAMem:        fmt.Sprintf("%x", saltA),
		SaltBMem:        fmt.Sprintf("%x", saltB),
		ClientNonceWire: fmt.Sprintf("%x", h.ClientNonce),
		ServerNonceWire: fmt.Sprintf("%x", h.ServerNonce),
		SaltSame:        saltSame,
		RawScan:         rawScan,
		Slots:           slots,
		WireClientCert:  fmt.Sprintf("%x", h.ClientCert),
		WireServerCert:  fmt.Sprintf("%x", h.ServerCert),
		WireClientCrypt: fmt.Sprintf("%x", h.ClientCrypt),
		WireServerCrypt: fmt.Sprintf("%x", h.ServerCrypt),
		WireLens: fmt.Sprintf("client_cert=%d server_cert=%d client_crypt=%d server_crypt=%d",
			len(h.ClientCert), len(h.ServerCert), len(h.ClientCrypt), len(h.ServerCrypt)),
	}
	if len(c.Raw) >= gnsConnSpan {
		dump.RawHex = fmt.Sprintf("%x", c.Raw[0x1700:gnsConnSpan])
	}

	// 高熵区段：Valve 用 AES-NI，内存里只存裸 key、不存标准 key schedule，
	// 所以「扫 240 字节自洽」这条路必然 0 命中，只能靠熵定位。
	// 直接打在日志里，省掉下一轮再去 repro 里翻。
	if segs := gnsHighEntropySegments(c.Raw, c.Addr); len(segs) > 0 {
		privateDiagnosticf("[gnskdf] conn 里的高熵区段（%d 段，32 字节去重≥28）：\n", len(segs))
		for _, s := range segs {
			privateDiagnosticf("           %s\n", s)
		}
	} else {
		privateDiagnosticf(
			"[gnskdf] conn 的 0..%#x 里没有高熵区段 —— 会话密钥不在这个对象里\n", gnsConnSpan)
	}

	privateDiagnosticf(
		"[gnskdf] KDF 输入比对：四个槽位命中线上四段 %d/4｜%s\n"+
			"         salt 内存 [0x1890]=%x [0x1968]=%x\n"+
			"         线上 nonce  client=%x server=%x\n"+
			"         线上四段长度 %s\n"+
			"         四段在 conn 对象里的实际位置 %s\n",
		matchedCount, saltSame, saltA, saltB,
		h.ClientNonce, h.ServerNonce, dump.WireLens, rawScan)
	for _, s := range slots {
		privateDiagnosticf(
			"[gnskdf]   +%#04x raw=%s alloc=%d len16=%d ptr=%s → %s%s\n"+
				"           ptr@%s 起 64 字节：%s\n"+
				"           顺着指针找到：%s\n",
			s.Off, s.RawHex, s.Alloc, s.Len16, s.Ptr,
			gnsDash(s.Matched), gnsNote(s.Note),
			s.Ptr, gnsDash(s.PtrHead), gnsDash(s.PtrScan))
	}

	if p := writeJSONFile("gns-kdf", &dump); p != "" {
		privateDiagnosticf("[gnskdf] 现场已落盘：%s\n", p)
	}
	return matchedCount == 4
}

// gnsSaltVerdict 判断内存里两段 salt 和线上两个 nonce 的对应关系。
//
// 这一段能独立成立：salt 就是 nonce，只是「哪段是客户端的」可能反了。
// 如果连 salt 都对不上，说明 +0x1890 / +0x1968 这两个偏移本身读错了对象，
// 后面四个槽位的比对结果也不能信。
func gnsSaltVerdict(saltA, saltB []byte, h *cs2crypto.GNSHandshake) string {
	eq := func(a, b []byte) bool {
		if len(a) != len(b) || len(a) == 0 {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	switch {
	case eq(saltA, h.ClientNonce) && eq(saltB, h.ServerNonce):
		return "salt=client||server（与线上一致）"
	case eq(saltA, h.ServerNonce) && eq(saltB, h.ClientNonce):
		return "salt=server||client（与线上相反，需换 salt 顺序）"
	case eq(saltA, h.ClientNonce):
		return "只有 A=clientNonce 对上，B 不等于 serverNonce"
	case eq(saltA, h.ServerNonce):
		return "只有 A=serverNonce 对上，B 不等于 clientNonce"
	case eq(saltB, h.ClientNonce):
		return "只有 B=clientNonce 对上，A 不等于 serverNonce"
	case eq(saltB, h.ServerNonce):
		return "只有 B=serverNonce 对上，A 不等于 clientNonce"
	}
	return "两段都对不上（+0x1890/+0x1968 可能不是这对 nonce）"
}

func gnsDash(s string) string {
	if s == "" {
		return "（未命中）"
	}
	return s
}

func gnsNote(s string) string {
	if s == "" {
		return ""
	}
	return "  ⚠ " + s
}

func indexByteStr(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// containsStr 是 strings.Contains 的零依赖版本（这个包刻意不引 strings，
// 早期为了二进制体积和可审计性做了这个取舍）。
func containsStr(s, sub string) bool {
	if sub == "" {
		return true
	}
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// writeJSONFile 把 dump 写到 exe 同目录，返回路径。
func writeJSONFile(prefix string, v any) string {
	// Retired in all builds: no key/memory reproduction files.
	return ""
}

// gnsHighEntropySegments 在 conn 对象里找「看起来像 AES 密钥」的高熵区段。
//
// 为什么要这么找：2026-10-19 10:48 现场实证 ——
//
//	· 把 `key_send_data`/`key_recv_data` 那 4 KB 以及它们的 deep 层
//	  全部按 FIPS-197 扫 240 字节自洽，**0 命中**；
//	· `+0x19e0`/`+0x19e8` 指向的对象里出现 `12` / `16` 常量，以及
//	  **"Invalid AES-GCM key size"** 字符串和 x64 代码 —— 那是 CCrypto 的
//	  全局错误表，**根本不是密钥上下文**；
//	· conn 的 `0x1700..0x1a20` 这 800 字节里没有任何 32 字节高熵窗口。
//
// ⇒ 说明 Valve 用 AES-NI，内存里只存**裸 key**、不存 key schedule；
//
//	而 key 的位置在 `0x1a20` 之后（GNS 的 m_cryptoSend/m_cryptoRecv 内联在 CConnection 里）。
//
// 判据用「去重字节数 >= 28」而不是熵：32 字节样本的熵上限只有 5 bits/byte，
// 去重数更直观，而且 AES key 因生日悖论通常落在 29~32 之间。
func gnsHighEntropySegments(raw []byte, base uintptr) []string {
	const minDistinct = 28
	var starts []int
	for off := 0; off+32 <= len(raw); off++ {
		var seen [256]bool
		distinct := 0
		for _, b := range raw[off : off+32] {
			if !seen[b] {
				seen[b] = true
				distinct++
			}
		}
		if distinct >= minDistinct {
			starts = append(starts, off)
		}
	}
	if len(starts) == 0 {
		return nil
	}
	// 合并相邻窗口（间隔 <= 8 视为同一区段）。
	var out []string
	lo, hi := starts[0], starts[0]+32
	for _, off := range starts[1:] {
		if off <= hi+8 {
			hi = off + 32
			continue
		}
		out = append(out, gnsSegDesc(raw, base, lo, hi))
		lo, hi = off, off+32
	}
	out = append(out, gnsSegDesc(raw, base, lo, hi))
	return out
}

func gnsSegDesc(raw []byte, base uintptr, lo, hi int) string {
	if hi > len(raw) {
		hi = len(raw)
	}
	n := hi - lo
	if n > 64 {
		n = 64
	}
	return fmt.Sprintf("%#x..%#x（%d 字节）%x", base+uintptr(lo), base+uintptr(hi), hi-lo, raw[lo:lo+n])
}
