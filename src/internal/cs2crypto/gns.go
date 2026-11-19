// GNS 直连 UDP 的密钥派生与帧解密 —— 2026-10-19 逆向定案。
//
// 结论来源（不再有猜测成分）：
//
//	① 抓包首字节分布 + 报文结构 与 Valve GameNetworkingSockets 的
//	   ESteamNetworkingUDPMsgID（0x20..0x25）逐字段吻合；
//	② CS2 的 game/bin/win64/steamnetworkingsockets.dll 里有
//	   k_ESteamNetworkingSocketsCipher_AES_256_GCM / AES_GCM_EncryptContext；
//	③ 开源实现 src/steamnetworkingsockets/steamnetworkingsockets_connections.cpp
//	   的 FinishCryptoHandshake 就是完整的 KDF，DecryptDataChunk 就是帧解密。
//
// 于是「共享密钥 → 会话密钥」这一段**不需要再猜**：HKDF-SHA256，
// salt = 双方 nonce，info = 连接 ID + "Steam datagram" + 四段握手原始字节。
//
// 帧布局（UDPDataMsgHdr，逐字段核对过真实抓包）：
//
//	[0]     m_unMsgFlags   0x80=加密数据包 | 0x01=内联 stats protobuf | 0x02=time_since_prev
//	[1..4]  m_unToConnectionID（收方 ID，小端 u32）
//	[5..6]  m_unSeqNum（小端 u16）
//	[7..]   可选：varint(stats 长度) + stats + [可选 u16 time_since_prev]
//	...     AES-256-GCM 密文（末尾 16 字节是 tag），**无 AAD**
//
// IV：12 字节基础 IV（由 KDF 的第 3/4 段给出），把前 8 字节当小端 u64
// 加上「完整包序号」，后 4 字节不变。
package cs2crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
)

// gnsGCMTagLen 是 GCM 认证标签长度。
const gnsGCMTagLen = 16

// GNSHandshake 是一次 SteamNetworkingSockets 直连握手的**全部**密钥材料。
//
// 所有字段都按「线上原始字节」保存，不做字节序转换 —— GNS 自己在写入
// context 时用的是 LittleDWord/LittleQWord，在 x86 上就等于原样拷贝。
type GNSHandshake struct {
	// ClientConnID / ServerConnID 各 4 字节：
	//   客户端 ID = ConnectRequest(0x22) 的 field 1
	//   服务器 ID = ConnectOK(0x23) 的 field 5
	ClientConnID []byte
	ServerConnID []byte

	// ClientPub / ServerPub 是双方的**临时** X25519 公钥（32 字节），
	// 取自各自 crypt.info.key_data。注意不是 cert 里的静态 Ed25519 密钥。
	ClientPub []byte
	ServerPub []byte

	// ClientNonce / ServerNonce 是各自 crypt.info.nonce 的 8 字节原始值。
	ClientNonce []byte
	ServerNonce []byte

	// ClientCert / ServerCert 是 CMsgSteamDatagramCertificateSigned.cert 的
	// **原始字节**（不是重新序列化的结果 —— 签名基于这份原始序列化）。
	ClientCert []byte
	ServerCert []byte

	// ClientCrypt / ServerCrypt 是 CMsgSteamDatagramSessionCryptInfoSigned.info
	// 的原始字节。
	ClientCrypt []byte
	ServerCrypt []byte
}

// GNSKeys 是派生出来的四把材料（客户端视角）。
type GNSKeys struct {
	SendKey []byte // 32 字节，加密上行（client→server）
	RecvKey []byte // 32 字节，解密下行（server→client）
	SendIV  []byte // 12 字节
	RecvIV  []byte // 12 字节
}

// Valid 检查材料是否齐全到可以派生。
func (h *GNSHandshake) Valid() error {
	if h == nil {
		return errors.New("nil handshake")
	}
	for name, b := range map[string][]byte{
		"ClientConnID": h.ClientConnID, "ServerConnID": h.ServerConnID,
		"ClientNonce": h.ClientNonce, "ServerNonce": h.ServerNonce,
	} {
		if len(b) != 4 && len(b) != 8 {
			return fmt.Errorf("%s 长度异常: %d", name, len(b))
		}
	}
	if len(h.ClientPub) != 32 || len(h.ServerPub) != 32 {
		return errors.New("临时公钥长度不是 32")
	}
	// cert / crypt 允许为空（老版本可能没有 cert），但非空时必须能进 KDF。
	return nil
}

// GNSVariant 是一套 KDF 参数组合。
//
// 为什么需要它：`FinishCryptoHandshake` 我是照着开源实现读的，而 CS2 里的
// `steamnetworkingsockets.dll` 是 Valve 内部构建，个别细节（label 拼写、
// 四段握手字节的顺序、salt 顺序、计数器位置）可能和开源版不一致。
// 与其赌一种写法，不如把这几个维度都枚举出来 —— 一共不到 200 组，
// 每组只要 4 次 HMAC-SHA256（约 2µs），然后用真实帧的 GCM 认证去判胜负。
// 认证通过就是对的，通过不了就是错的，没有中间地带。
type GNSVariant struct {
	Name         string
	SaltSwap     bool // salt = clientNonce||serverNonce
	ConnSwap     bool // connID = server||client
	Label        string
	Blobs        int  // 四段 cert/crypt 的排列，见 gnsBlobOrder
	CounterFirst bool // 计数器字节放在 tail 之前
	SlotSwap     bool // d1..d4 的槽位映射反过来（等价于方向判断反了）
	// ServerByte0Zero 把服务端两段（cert/crypt）的首字节清零。
	// 现场证据见 gnsBlobOrder 的注释。
	ServerByte0Zero bool
}

// gnsBlobPerm 是四段握手字节的全部 24 种排列（4! = 24）。
//
// 元素编号：0=ServerCert 1=ClientCert 2=ServerCrypt 3=ClientCrypt。
//
// 为什么不再只试 4 种：反汇编确认那四段是**两个内联 CUtlString +
// 两个指针型 CUtlString**（`[conn+0x1798]`/`[conn+0x17b8]` 与
// `*[conn+0x19b8]`/`*[conn+0x1988]`），客户端的放入顺序是
// 内联、指针、内联、指针 —— 也就是说"本地/对端"是交错排的，
// 而"cert 对 cert、crypt 对 crypt"这种想当然的分组根本不成立。
// 既然无法从源码确定真实顺序，就把 24 种全枚举掉：每组只多 4 次 HMAC，
// 代价可以忽略，换来的是这个维度彻底不可能出错。
var gnsBlobPerm = [24][4]int{
	{0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1}, {0, 3, 1, 2}, {0, 3, 2, 1},
	{1, 0, 2, 3}, {1, 0, 3, 2}, {1, 2, 0, 3}, {1, 2, 3, 0}, {1, 3, 0, 2}, {1, 3, 2, 0},
	{2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3}, {2, 1, 3, 0}, {2, 3, 0, 1}, {2, 3, 1, 0},
	{3, 0, 1, 2}, {3, 0, 2, 1}, {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0},
}

// gnsBlobOrder 按排列编号给出四段 cert/crypt 的顺序。
//
// 编号 0 是「规范」写法（serverCert, clientCert, serverCrypt, clientCrypt），
// 其余 23 种是它的排列 —— 第一项永远是规范实现，它中不了才往下试。
//
// zeroServerByte0 是 2026-10-19 10:22 现场实证出来的一个维度：
// 客户端内存里存的**自己**那两段与线上字节完全一致（`08 01 12 20 …`），
// 而**服务端**那两段的首字节是 `00` 而不是 `08`（其余 96 / 48 字节逐字节相同）。
// 说明服务端材料在客户端是「重新写过一遍」的，而 KDF 吃的是内存里那一份。
// 所以这里给一个「把服务端两段首字节清零」的开关，让认证去判哪份是真的。
func gnsBlobOrder(idx int, h *GNSHandshake, zeroServerByte0 bool) [4][]byte {
	src := [4][]byte{h.ServerCert, h.ClientCert, h.ServerCrypt, h.ClientCrypt}
	if zeroServerByte0 {
		// 必须复制：改的是派生用的临时副本，不能污染握手材料本身。
		src[0] = zeroFirstByte(h.ServerCert)
		src[2] = zeroFirstByte(h.ServerCrypt)
	}
	if idx < 0 || idx >= len(gnsBlobPerm) {
		idx = 0
	}
	p := gnsBlobPerm[idx]
	return [4][]byte{src[p[0]], src[p[1]], src[p[2]], src[p[3]]}
}

// zeroFirstByte 返回 b 的副本，首字节置 0。
func zeroFirstByte(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	out := append([]byte(nil), b...)
	out[0] = 0
	return out
}

// GNSVariants 返回候选变体，**第一项一定是规范实现**（开源源码逐行对照的写法）。
func GNSVariants() []GNSVariant {
	labels := []string{"Steam datagram", "SteamDatagram", ""}
	var out []GNSVariant
	for _, label := range labels {
		for blobs := 0; blobs < len(gnsBlobPerm); blobs++ {
			for _, saltSwap := range []bool{false, true} {
				for _, connSwap := range []bool{false, true} {
					for _, ctrFirst := range []bool{false, true} {
						for _, sbz := range []bool{false, true} {
							name := "规范"
							if label != "Steam datagram" || blobs != 0 || saltSwap || connSwap || ctrFirst || sbz {
								name = "label=" + quoteLabel(label) +
									"/blobs=" + strconv.Itoa(blobs) +
									"/salt=" + boolTag(saltSwap, "CS", "SC") +
									"/conn=" + boolTag(connSwap, "CS", "SC") +
									"/ctr=" + boolTag(ctrFirst, "tail+ctr", "ctr+tail")
								if sbz {
									name += "/srv0=0"
								}
							}
							out = append(out, GNSVariant{
								Name: name, SaltSwap: saltSwap, ConnSwap: connSwap,
								Label: label, Blobs: blobs, CounterFirst: ctrFirst,
								ServerByte0Zero: sbz,
							})
						}
					}
				}
			}
		}
	}
	// 槽位映射反过来的版本追加在后面（只有方向判断反了才需要）。
	n := len(out)
	for i := 0; i < n; i++ {
		v := out[i]
		v.SlotSwap = true
		v.Name = "swap-slots/" + v.Name
		out = append(out, v)
	}
	return out
}

func quoteLabel(s string) string {
	if s == "" {
		return "空"
	}
	return s
}

func boolTag(v bool, t, f string) string {
	if v {
		return t
	}
	return f
}

// GNSDeriveClientKeys 按 GNS 的 FinishCryptoHandshake 派生客户端视角的四把材料。
//
// 算法（源码逐行对照）：
//
//	premaster = SHA256(X25519(clientPriv, serverPub))   // 注意那层 SHA256
//	salt      = LE64(serverNonce) || LE64(clientNonce)
//	prk       = HMAC-SHA256(key=premaster, msg=salt)   // 🔴 与 RFC5869 相反，反汇编定案
//	tail      = clientConnID || serverConnID || "Steam datagram"
//	            || serverCert || clientCert || serverCrypt || clientCrypt
//	d_1 = HMAC-SHA256(key=prk, msg=tail || 0x01)              // prev 为空！
//	d_i = HMAC-SHA256(key=prk, msg=d_{i-1} || tail || byte(i)) // i=2..4
//	客户端: d1=SendKey d2=RecvKey d3=SendIV d4=RecvIV
//	服务端: d1=RecvKey d2=SendKey d3=RecvIV d4=SendIV
//
// 也就是说 d1 的输入永远是「客户端 ID 在前、服务端 cert/crypt 在前」的同一段字节，
// 两端算出同一个 d1，只是装进不同的槽位 —— 这正是协议能对上的原因。
func GNSDeriveClientKeys(clientPriv []byte, h *GNSHandshake) (*GNSKeys, error) {
	return GNSDeriveClientKeysV(clientPriv, h, GNSVariant{Label: "Steam datagram"})
}

// GNSPremaster 算出 GNS 的预主密钥：**SHA256(裸 X25519 结果)**。
// 🔴 不是裸 X25519 结果。`CCrypto::PerformKeyExchange` 的注释写得很直白：
//
//	// NOTE: this actually returns the SHA256 of the raw DH result.  I don't know why.
//
// 三个后端（openssl / donna / libsodium）实现里都调了 GenerateSHA256Digest，
// 所以这是协议契约，不是某个后端的怪癖。少了这一层，HKDF 的输入就整体错位。
//
// 顺带确认这把私钥属于哪一侧：抓到的私钥可能是客户端也可能是服务端的，
// 拿它算出的公钥和握手里的两个临时公钥比一下就知道该用谁当对端。
func GNSPremaster(priv []byte, h *GNSHandshake) ([]byte, error) {
	raw, err := GNSPremasterRaw(priv, h)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

// GNSPremasterRaw 是没做 SHA256 的裸 X25519 结果。
//
// 留这个出口只为兜底：CS2 里的 steamnetworkingsockets.dll 是 Valve 内部构建，
// 万一它的 PerformKeyExchange 没做那层 SHA256，派生就整体差一步。
// 两种预主密钥都试，GCM 认证会告诉我们哪个对 —— 猜错没有成本，
// 猜错还不知道才有成本。
func GNSPremasterRaw(priv []byte, h *GNSHandshake) ([]byte, error) {
	if err := h.Valid(); err != nil {
		return nil, err
	}
	myPub := pubFromPriv(priv)
	var peerPub []byte
	switch {
	case bytesEqual(myPub, h.ClientPub):
		peerPub = h.ServerPub
	case bytesEqual(myPub, h.ServerPub):
		peerPub = h.ClientPub
	default:
		return nil, errors.New("私钥与握手里的临时公钥不配对")
	}
	return SharedSecret(priv, peerPub)
}

// GNSPremasters 返回两种候选预主密钥（SHA256 版在前、裸版兜底）及各自的名字。
// X25519 标量乘只做一次。
func GNSPremasters(priv []byte, h *GNSHandshake) ([][]byte, []string, error) {
	raw, err := GNSPremasterRaw(priv, h)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(raw)
	return [][]byte{sum[:], raw}, []string{"sha256(dh)", "dh"}, nil
}

// GNSDeriveFromPremaster 用预主密钥 + 指定变体派生客户端槽位的四把材料。
func GNSDeriveFromPremaster(premaster []byte, h *GNSHandshake, v GNSVariant) *GNSKeys {
	d := gnsChainFromPremaster(premaster, h, v)
	if v.SlotSwap {
		return &GNSKeys{
			SendKey: d[1], RecvKey: d[0],
			SendIV: d[3][:12], RecvIV: d[2][:12],
		}
	}
	return &GNSKeys{
		SendKey: d[0], RecvKey: d[1],
		SendIV: d[2][:12], RecvIV: d[3][:12],
	}
}

// GNSDeriveClientKeysV 用指定变体派生（客户端槽位）。
func GNSDeriveClientKeysV(clientPriv []byte, h *GNSHandshake, v GNSVariant) (*GNSKeys, error) {
	pm, err := GNSPremaster(clientPriv, h)
	if err != nil {
		return nil, err
	}
	return GNSDeriveFromPremaster(pm, h, v), nil
}

// GNSDeriveServerKeys 是同一份派生链的**服务端槽位映射**。
//
// 采集端用不到它（雷达跑在客户端），但它是「客户端算出来的 SendKey 就是
// 服务端算出来的 RecvKey」这条协议对称性的可测试证据，所以留着并进了单测。
func GNSDeriveServerKeys(serverPriv []byte, h *GNSHandshake) (*GNSKeys, error) {
	pm, err := GNSPremaster(serverPriv, h)
	if err != nil {
		return nil, err
	}
	d := gnsChainFromPremaster(pm, h, GNSVariant{Label: "Steam datagram"})
	return &GNSKeys{
		SendKey: d[1], RecvKey: d[0],
		SendIV: d[3][:12], RecvIV: d[2][:12],
	}, nil
}

// gnsChainFromPremaster 返回 4 段 32 字节摘要（d1..d4）。
func gnsChainFromPremaster(premaster []byte, h *GNSHandshake, v GNSVariant) [4][]byte {
	var out [4][]byte

	salt := make([]byte, 0, 16)
	if v.SaltSwap {
		salt = append(salt, h.ClientNonce...)
		salt = append(salt, h.ServerNonce...)
	} else {
		salt = append(salt, h.ServerNonce...)
		salt = append(salt, h.ClientNonce...)
	}

	// 🔴 prk = HMAC-SHA256(key=premaster, msg=salt)
	//
	// 2026-10-19 反汇编 steamnetworkingsockets.dll 定案（FinishCryptoHandshake）：
	//   0x18009d8e3  mov edx, 0x10          ; dataLen = 16
	//   0x18009d8e8  lea rcx, [rsp+0x50]    ; pData = salt
	//   0x18009d8d7  mov r9d, r14d          ; keyLen = 32
	//   0x18009d8da  lea r8, [rbp+0x50]     ; pKey  = premaster
	//   0x18009d8ed  call GenerateHMAC256
	// 而 GenerateHMAC256 的签名是 (pubData, cubData, pubKey, cubKey, pOutDigest)，
	// 所以 key 是 premaster、msg 是 salt —— 与 RFC5869 的 HMAC(salt, IKM) 正好相反。
	//
	// 这就是之前四万多个变体全灭的根因：基式本身反了，变体维度再多也救不回来。
	mac := hmac.New(sha256.New, premaster)
	mac.Write(salt)
	prk := mac.Sum(nil)

	// tail = connID(8) + label + 四段 cert/crypt
	label := []byte(v.Label)
	blobs := gnsBlobOrder(v.Blobs, h, v.ServerByte0Zero)
	tail := make([]byte, 0, 8+len(label)+len(blobs[0])+len(blobs[1])+len(blobs[2])+len(blobs[3]))
	if v.ConnSwap {
		tail = append(tail, h.ServerConnID...)
		tail = append(tail, h.ClientConnID...)
	} else {
		tail = append(tail, h.ClientConnID...)
		tail = append(tail, h.ServerConnID...)
	}
	tail = append(tail, label...)
	for _, b := range blobs {
		tail = append(tail, b...)
	}

	// 🔴 第一轮的 prev 必须是**空**，不是 32 个 0。
	//
	// Valve 源码里那块 32 字节是 `SeekPut(SEEK_HEAD, 32)` 预留出来的，
	// 而 `pStart = PeekPut()` 正好跳过它 —— 首轮 HMAC 的输入是
	// `tail || 0x01`，预留区根本没参与。只有第二轮开始 `pStart = Base()`
	// 才把上一轮摘要接在前面。这正是 HKDF-Expand 的定义：T(0) 为空。
	//
	// 之前按「全 0 打头」实现，192 组变体全都带着这个错误，所以怎么枚举
	// 都中不了 —— 变体维度再多也救不了一个错的基式。
	var prev []byte
	msg := make([]byte, 0, sha256.Size+len(tail)+1)
	for i := 1; i <= 4; i++ {
		msg = msg[:0]
		msg = append(msg, prev...)
		if v.CounterFirst {
			msg = append(msg, byte(i))
			msg = append(msg, tail...)
		} else {
			msg = append(msg, tail...)
			msg = append(msg, byte(i))
		}
		m := hmac.New(sha256.New, prk)
		m.Write(msg)
		prev = m.Sum(nil)
		out[i-1] = append([]byte(nil), prev...)
	}
	return out
}

// pubFromPriv 由 X25519 私钥算出公钥；失败返回 nil。
func pubFromPriv(priv []byte) []byte {
	if len(priv) != 32 {
		return nil
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil
	}
	return k.PublicKey().Bytes()
}

func bytesEqual(a, b []byte) bool {
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

// GNSOffsets 返回密文在载荷里**所有可能**的起点（升序、去重）。
//
// 为什么不只给一个：`0x82 → 9`、`0x83 → 9 + stats` 这套规则是读开源源码
// 推出来的，而线上的 steamnetworkingsockets.dll 是 Valve 内部构建。
// 硬性「只认 0x80..0x83、且只按源码算偏移」一旦和线上不一致，表现就是
// **密钥明明对了却一帧都解不开**，而日志上只会看到"不是 GNS 加密数据包"，
// 完全看不出错在这个假设上。
//
// 所以判据改成：给一组候选起点，让 GCM 认证去判。认证错一个字节就失败，
// 多试几个起点的代价是每帧多几次 GCM，可以忽略。
//
// 顺序有讲究：帧标志能算出来的那个排最前（正常情况下第一发就中），
// 其余按 7..16 依次兜底。
func GNSOffsets(pkt []byte) []int {
	if len(pkt) < 17+7 { // 至少要能容纳 7 字节头 + 1 字节密文 + 16 字节 tag
		return nil
	}
	out := make([]int, 0, 12)
	seen := map[int]bool{}
	add := func(v int) {
		if v < 0 || v+17 > len(pkt) || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	// 帧标志算出来的优先。
	if off, ok := GNSChunkOffset(pkt); ok {
		add(off)
	}
	for off := 7; off <= 16; off++ {
		add(off)
	}
	return out
}

// GNSChunkOffset 返回密文在 UDP 载荷里的起点（按帧标志字节算）。
//
// 以前一律按 7 算是错的：0x82 表示带 time_since_prev（多 2 字节），
// 0x83 还多一段内联 stats protobuf。真实抓包里 0x82 占绝对多数，
// 于是"密钥对了也一帧都解不开"。
//
// 🔴 注意：这个函数现在只用来「给出首选偏移」，不再是硬闸门。
// 判据由 GNSOffsets 放宽成候选集 —— 因为 flags 的取值范围本身就是
// 从开源源码推的，线上构建未必一致（09:27 那次现场就是被这条挡住，
// 帧缓冲一帧都没收进来）。
func GNSChunkOffset(pkt []byte) (int, bool) {
	if len(pkt) < 7 {
		return 0, false
	}
	flags := pkt[0]
	if flags&0x80 == 0 || flags > 0x83 {
		return 0, false // 不是 GNS 加密数据包
	}
	i := 7
	if flags&0x01 != 0 { // 内联 stats protobuf
		n, m := uvarint(pkt[i:])
		if m <= 0 || n > 1024 { // 长度离谱说明这不是真的 stats，直接判掉
			return 0, false
		}
		i += m + int(n)
	}
	if flags&0x02 != 0 { // time_since_prev
		i += 2
	}
	if i >= len(pkt) {
		return 0, false
	}
	return i, true
}

// GNSFrameToConnID 取帧头里的**收方**连接 ID（小端 u32 的原始 4 字节）。
//
// 这是判断"这帧是不是本连接的"唯一可靠依据。CS2 进程名下同时有多条 UDP 流
// （Steam 客户端 CM 连接、语音、发现服务…），只靠 flags 高位是分不开的：
// 09:01 那次 2000 帧的缓冲里绝大部分不是游戏流量，挑出来的 64 帧
// connID 全对不上，于是 768 组变体 × 12 帧一帧都解不开。
func GNSFrameToConnID(pkt []byte) ([]byte, bool) {
	if len(pkt) < 5 {
		return nil, false
	}
	return pkt[1:5], true
}

// GNSFrameForConn 判断这一帧的收方 connID 是否等于 connID。
func GNSFrameForConn(pkt, connID []byte) bool {
	if len(connID) != 4 {
		return false
	}
	got, ok := GNSFrameToConnID(pkt)
	return ok && bytesEqual(got, connID)
}

// GNSIVForSeq 由基础 IV + 包序号算出本帧 IV。
//
// 与源码一致：把 IV 前 8 字节当小端 u64 加上包序号，后 4 字节保持。
func GNSIVForSeq(iv []byte, seq uint64) []byte {
	out := make([]byte, 12)
	copy(out, iv)
	v := uint64(0)
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(out[i])
	}
	v += seq
	for i := 0; i < 8; i++ {
		out[i] = byte(v >> (8 * uint(i)))
	}
	return out
}

// GNSOpen 用一把密钥 + 基础 IV 解一帧 GNS 数据包。
//
// 包序号有 16 位截断，跑久了会回绕；这里依次试 seq、seq+65536 …，
// 认证通过就返回（错误 IV 概率 2^-128 通过认证，所以多试几次是安全的）。
// 密文起点同样按候选集试，理由见 GNSOffsets。
func GNSOpen(key, iv []byte, pkt []byte) ([]byte, error) {
	offs := GNSOffsets(pkt)
	if len(offs) == 0 {
		return nil, errors.New("不是 GNS 加密数据包")
	}
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	seq, _ := FrameSeq(pkt)
	for _, off := range offs {
		for k := uint64(0); k < 8; k++ {
			nonce := GNSIVForSeq(iv, seq+k<<16)
			if pt, err := g.Open(nil, nonce, pkt[off:], nil); err == nil {
				return pt, nil
			}
		}
	}
	return nil, errors.New("GCM 认证失败")
}

// GNSNewAEAD 展开一把 32 字节密钥，供「一个密钥试多个 nonce」的热路径复用。
//
// 为什么要单独暴露：内存直读那条路上，一把候选密钥要配十几个 nonce、十来个
// 密文起点去试，每次试都重新做 AES key schedule 的话，几百个候选密钥乘起来
// 就是几十万次 key schedule —— 白白多花几秒。
func GNSNewAEAD(key []byte) (cipher.AEAD, error) {
	return gnsAEAD(key)
}

// GNSOpenWithAEAD 用已展开的 AEAD + 调用方给定的 nonce 解一帧。
//
// 与 GNSOpen 的分工：GNSOpen 按「IV 是握手初值」推算 nonce，适合 KDF 派生
// 出来那一路；而内存里读到的那 12 字节是**随包前移的当前 nonce**
// （FinishCryptoHandshake 里 `add qword [rsi+0x19f0], rax` 就地累加），
// 已经不能直接加帧序号，只能由调用方算好 nonce 递进来。
func GNSOpenWithAEAD(g cipher.AEAD, nonce, pkt []byte) ([]byte, error) {
	offs := GNSOffsets(pkt)
	if len(offs) == 0 {
		return nil, errors.New("不是 GNS 加密数据包")
	}
	if len(nonce) != g.NonceSize() {
		return nil, fmt.Errorf("nonce 长度 %d，应为 %d", len(nonce), g.NonceSize())
	}
	for _, off := range offs {
		if pt, err := g.Open(nil, nonce, pkt[off:], nil); err == nil {
			return pt, nil
		}
	}
	return nil, errors.New("GCM 认证失败")
}

// GNSIVTail 返回 IV 的高 4 字节（偏移 8..11）。
//
// 为什么这 4 个字节特殊：加密路径上是 `add qword [rsi+0x19f0], rax` ——
// 只对**低 8 字节**做 64 位加法，高 4 字节整局不动。
// 所以「派生 IV 的高 4 字节 == 内存里那把 IV 的高 4 字节」是一个
// 32 位精确判据：它能把「KDF 变体对不对」和「帧能不能解开」完全解耦。
func GNSIVTail(iv []byte) []byte {
	if len(iv) != 12 {
		return nil
	}
	return iv[8:12]
}

// GNSIVTailMatch 判断派生 IV 与内存 IV 的高 4 字节是否一致。
func GNSIVTailMatch(derived, memIV []byte) bool {
	a, b := GNSIVTail(derived), GNSIVTail(memIV)
	return len(a) == 4 && len(b) == 4 && a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

// GNSNonceCorrections 是「内存 IV 与判据帧之间隔了多少包」的兜底修正量。
//
// 内存里那 12 字节是**当前 nonce**（随包前移），不是握手初值，
// 所以帧 i 的 nonce 只能是 memIV + (S_i - S_ref) - 修正。
// 只取负方向：IV 随时间单调前移，读到的一定不小于帧的。
var GNSNonceCorrections = [...]int64{
	0, -1, -2, -3, -4, -8, -16, -32, -64, -128, -256, -1024,
}

// GNSNoncesForFrame 给出「用内存 IV 解这一帧」时所有值得一试的 nonce。
//
// 同时覆盖两种互相矛盾的假设，因为目前只有一条指令证据、不能确定是哪种：
//
//	A) IV 是当前 nonce → IV + (S_i - S_ref) + 修正
//	B) IV 是握手初值   → IV + S_i + k·65536（16 位序号回绕）
//
// 认证标签 128 位，试错一个字节都不会误判，所以多试几种是安全的。
func GNSNoncesForFrame(iv []byte, seqI, seqRef uint16) [][]byte {
	if len(iv) != 12 {
		return nil
	}
	out := make([][]byte, 0, len(GNSNonceCorrections)+8)
	seen := map[uint64]bool{}
	add := func(v uint64) {
		if seen[v] {
			return
		}
		seen[v] = true
		out = append(out, GNSIVForSeq(iv, v))
	}
	delta := int64(int16(seqI - seqRef))
	for _, c := range GNSNonceCorrections {
		add(uint64(delta + c))
	}
	for k := uint64(0); k < 8; k++ {
		add(uint64(seqI) + k<<16)
	}
	return out
}

// gnsAEAD 只给 Scheme 内部用，避免每帧重新展开密钥。
func gnsAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("GNS 会话密钥必须是 32 字节，得到 %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// uvarint 解析 protobuf 风格的变长整数，返回值和消耗的字节数。
func uvarint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < 0x80 {
			if i > 9 || (i == 9 && c > 1) {
				return 0, -(i + 1)
			}
			return x | uint64(c)<<s, i + 1
		}
		x |= uint64(c&0x7f) << s
		s += 7
		if s >= 64 {
			return 0, -1
		}
	}
	return 0, 0
}
