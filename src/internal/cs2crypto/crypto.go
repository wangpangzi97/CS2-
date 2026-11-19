// Package cs2crypto 负责"密钥 + 密文包 → 明文消息"这一段。
//
// 分工与确定性分级：
//
//	✅ 确定：X25519 共享密钥 = ECDH(clientPriv, serverPub)。数学上唯一，无需猜测。
//	❓ 未知：共享密钥 → 会话密钥的 KDF（info/salt 串）、AEAD 类型、nonce 构造、
//	         AAD 取值、密文在 UDP 载荷里的起始偏移。
//	         —— 这些不在 v2.0.5 的两个 EXE 内（雷达自身不解密，只把密钥与包交给下游）。
//
// 处理办法不是"猜一个然后祈祷"，而是**枚举候选 + 自动打分**：
// 每个候选组合解密后交给 `cs2proto.Score` 判断"能不能切成合法的 netmessage 流"。
// 方案选对时，绝大多数帧都能完整解析；选错时是随机字节，几乎全部失败。
// 于是"未知"变成一个可搜索的空间，等真实抓包到位即可自动定位。
package cs2crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"local/cs2-radar/internal/cs2proto"
)

// SharedSecret 计算 X25519 共享密钥。这一步没有猜测成分。
func SharedSecret(clientPriv, serverPub []byte) ([]byte, error) {
	if len(clientPriv) != 32 {
		return nil, fmt.Errorf("client private key must be 32 bytes, got %d", len(clientPriv))
	}
	if len(serverPub) != 32 {
		return nil, fmt.Errorf("server public key must be 32 bytes, got %d", len(serverPub))
	}
	priv, err := ecdh.X25519().NewPrivateKey(clientPriv)
	if err != nil {
		return nil, fmt.Errorf("NewPrivateKey: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, fmt.Errorf("NewPublicKey: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	return shared, nil
}

// ---- KDF 候选 ----

// KDF 把握手材料推导成会话密钥。
type KDF struct {
	Name string
	// UsesSalt 表示该 KDF 是否真的用到 salt。
	// raw / sha256 忽略 salt，因此对它们枚举 UseSaltPub 只会产生等价重复项。
	UsesSalt bool
	// Derive 返回至少 need 字节的密钥材料。
	Derive func(shared, salt, info []byte, need int) []byte
}

func hkdfSHA256(shared, salt, info []byte, need int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(shared)
	prk := extract.Sum(nil)

	var out, prev []byte
	for i := byte(1); len(out) < need; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:need]
}

// KDFs 返回候选 KDF 集合。
//
// 注意：salt 的取值（nil 还是服务端公钥）是 Candidate.UseSaltPub 这个**独立维度**，
// 不在这里重复表达，否则候选空间会出现等价重复项、让 Top-1 归属变得含糊。
func KDFs() []KDF {
	infoVariants := []struct {
		name string
		info string
	}{
		{"info-empty", ""},
		{"info-cs2", "CS2"},
		{"info-cs2-radar-v1", "cs2-radar-v1"},
		{"info-netkey", "netkey"},
		{"info-connection-key", "connection key"},
	}
	var out []KDF
	out = append(out, KDF{Name: "raw", UsesSalt: false, Derive: func(s, _, _ []byte, n int) []byte {
		if n > len(s) {
			return nil
		}
		return s[:n]
	}})
	out = append(out, KDF{Name: "sha256", UsesSalt: false, Derive: func(s, _, _ []byte, n int) []byte {
		h := sha256.Sum256(s)
		if n > len(h) {
			return nil
		}
		return h[:n]
	}})
	for _, v := range infoVariants {
		info := v.info
		out = append(out, KDF{Name: "hkdf-sha256/" + v.name, UsesSalt: true, Derive: func(s, salt, _ []byte, n int) []byte {
			return hkdfSHA256(s, salt, []byte(info), n)
		}})
	}
	return out
}

// ---- AEAD 候选 ----

// Cipher 负责用会话密钥解/封一帧。
type Cipher struct {
	Name   string
	KeyLen int
	// Open 解密；失败返回 error。
	Open func(key, nonce, ct []byte) ([]byte, error)
	// Seal 加密（仅用于生成合成靶标做验证；真实链路上采集器只解密不解密）。
	Seal func(key, nonce, pt []byte) ([]byte, error)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func xorStream(key, nonce, in []byte) []byte {
	out := make([]byte, len(in))
	var ctr [8]byte
	for i := 0; i < len(in); i += 32 {
		h := sha256.New()
		h.Write(key)
		h.Write(nonce)
		binary.LittleEndian.PutUint64(ctr[:], uint64(i/32))
		h.Write(ctr[:])
		ks := h.Sum(nil)
		for j := 0; j < 32 && i+j < len(in); j++ {
			out[i+j] = in[i+j] ^ ks[j]
		}
	}
	return out
}

// Ciphers 返回候选 AEAD 集合。
func Ciphers() []Cipher {
	return []Cipher{
		{Name: "aes-256-gcm", KeyLen: 32,
			Open: func(key, nonce, ct []byte) ([]byte, error) {
				g, err := newGCM(key)
				if err != nil {
					return nil, err
				}
				return g.Open(nil, nonce, ct, nil)
			},
			Seal: func(key, nonce, pt []byte) ([]byte, error) {
				g, err := newGCM(key)
				if err != nil {
					return nil, err
				}
				return g.Seal(nil, nonce, pt, nil), nil
			}},
		{Name: "aes-128-gcm", KeyLen: 16,
			Open: func(key, nonce, ct []byte) ([]byte, error) {
				g, err := newGCM(key)
				if err != nil {
					return nil, err
				}
				return g.Open(nil, nonce, ct, nil)
			},
			Seal: func(key, nonce, pt []byte) ([]byte, error) {
				g, err := newGCM(key)
				if err != nil {
					return nil, err
				}
				return g.Seal(nil, nonce, pt, nil), nil
			}},
		// 🔴 原来这里还有一个 `xor-sha256-ctr` 候选（"排除其实没上 AEAD 的情况"）。
		// 2026-10-19 现场证明它是**有害的**：它没有任何认证，`cs2proto.Score`
		// 对随机字节也会偶尔给出正分，于是 08:44 那次它以 142/200 的假成绩
		// 被选成方案，把 scheme 占住，真正正确的 GNS 派生再也没机会上。
		// 没有认证标签的候选一律不许进候选空间。
	}
}

// ---- nonce 方案 ----

// NonceScheme 由"帧序号"构造 nonce。
type NonceScheme struct {
	Name  string
	Size  int
	Build func(prefix []byte, counter uint64, size int) []byte
}

// NonceSchemes 返回候选 nonce 方案。
func NonceSchemes() []NonceScheme {
	return []NonceScheme{
		{Name: "ctr-le-u64", Size: 12, Build: func(_ []byte, c uint64, n int) []byte {
			b := make([]byte, n)
			binary.LittleEndian.PutUint64(b[n-8:], c)
			return b
		}},
		{Name: "ctr-be-u64", Size: 12, Build: func(_ []byte, c uint64, n int) []byte {
			b := make([]byte, n)
			binary.BigEndian.PutUint64(b[n-8:], c)
			return b
		}},
		{Name: "ctr-le-u32", Size: 12, Build: func(_ []byte, c uint64, n int) []byte {
			b := make([]byte, n)
			binary.LittleEndian.PutUint32(b[n-4:], uint32(c))
			return b
		}},
		{Name: "prefix4-ctr-le-u64", Size: 12, Build: func(p []byte, c uint64, n int) []byte {
			b := make([]byte, n)
			copy(b, p)
			binary.LittleEndian.PutUint64(b[n-8:], c)
			return b
		}},
	}
}

// ---- 候选组合与打分 ----

// Candidate 是一个待验证的加解密方案。
type Candidate struct {
	KDF        string
	Cipher     string
	Nonce      string
	Offset     int
	UseSaltPub bool
	// WireSeq 表示 nonce 计数器取**帧头里的线上包序号**（FrameSeq），
	// 而不是缓冲区下标。真实链路必须为 true；合成靶标（单测）为 false。
	//
	// 为什么不能靠猜：用下标当计数器时，只要漏过一帧，后面每个 nonce 都错，
	// GCM 认证一律失败 —— 这正是"密钥挖到了但一条都解不开"的第二个原因。
	WireSeq bool
	// GNSIV 非空（12 字节）时表示这是 **SteamNetworkingSockets 直连方案**：
	// nonce = GNSIV 的前 8 字节按小端加包序号；密文起点由帧标志字节决定
	// （0x82 要跳过 2 字节 time_since_prev，0x83 还要跳过内联 stats）。
	//
	// 这条路径是 2026-10-19 逆向定案的**确定解**，不再是候选之一：
	// 见 gns.go 顶部说明。KDF/Cipher/Nonce 三个字段在 GNS 模式下只是标签。
	GNSIV []byte
	// GNSOffset 强制指定密文起点；-1 表示按帧标志字节自动算（正常路径）。
	//
	// 为什么要留这个口子：自动算的规则（0x82 → 跳过 2 字节 time_since_prev）
	// 是从开源源码读来的，而 CS2 里的 DLL 是 Valve 内部构建。万一线上的
	// 帧头布局和源码不一致，整套派生就会"密钥对、却一帧都解不开"。
	// 把起点也变成可枚举维度，就能在不动密钥的前提下把这个假设证伪。
	GNSOffset int
	// NoncePrefix 是 nonce 的前 4 字节前缀（仅 prefix4-* 方案用）。
	//
	// 真实链路的 nonce 很可能是「连接 ID（4 字节）+ 包序号（8 字节）」，
	// 而不是「4 个零 + 包序号」。这条以前是死路：Build 一直传 nil 前缀，
	// 于是 prefix4-* 退化成了 ctr-le-u64，候选空间里等于没有这个变体。
	NoncePrefix []byte
}

// Result 是一次候选探测的结果。
type Result struct {
	Candidate
	Frames   int
	OKFrames int
	Messages int
	OK       bool
}

// Scheme 是一个可直接使用的已定方案。
type Scheme struct {
	Candidate
	kdf    KDF
	cipher Cipher
	nonce  NonceScheme
	key    []byte
	// gns 非空表示走 SteamNetworkingSockets 路径（见 Candidate.GNSIV）。
	gns cipher.AEAD
}

// Probe 枚举候选方案，用"解密结果能否切成合法 netmessage 流"给每个方案打分。
//
// shared 是 X25519 共享密钥；serverPub 用于 salt 变体；frames 是按时间顺序的密文帧
// （每帧一个 UDP 载荷）。maxOffset 是密文在载荷里的起始偏移搜索上界。
//
// 返回按 OKFrames 降序排列的结果。若最高分方案 OKFrames 明显高于其它，即为命中。
func Probe(shared, serverPub []byte, frames [][]byte, maxOffset int) []Result {
	return ProbeFrom(shared, serverPub, frames, 0, maxOffset)
}

// ProbeFrom 与 Probe 相同，但额外指定 frames[0] 对应的**绝对帧序号** base。
//
// 为什么需要 base：nonce 用的是发送方的包计数器，不是"缓冲区下标"。
// 服务端只保留最近 max-frames 帧，头部会被丢弃；丢弃之后缓冲区下标 0 对应的
// 计数器已经不是 0 了。调用方必须把"已丢弃的帧数"作为 base 传进来，
// 否则所有候选都会因为 nonce 错位而解不开。
// 探测分两阶段：先用少量帧筛，再对活下来的放开验。
//
// 候选空间是 KDF(7) × salt(2) × cipher(3) × nonce(4) × offset(9) × wireSeq(2)
// ≈ 3000 个；每个都拿 2000 帧全验就是 600 万次 GCM，会把投递线程卡死好几秒。
const (
	screenFrames = 12
	verifyFrames = 200
)

// ProbeFrom 在给定共享密钥下搜索「KDF + 密码算法 + nonce 方案 + 密文起点」。
func ProbeFrom(shared, serverPub []byte, frames [][]byte, base, maxOffset int) []Result {
	if maxOffset < 0 {
		maxOffset = 0
	}
	if base < 0 {
		base = 0
	}
	var results []Result
	for _, kdf := range KDFs() {
		saltVariants := []struct {
			use  bool
			salt []byte
		}{{false, nil}}
		if kdf.UsesSalt {
			saltVariants = append(saltVariants, struct {
				use  bool
				salt []byte
			}{true, serverPub})
		}
		for _, sv := range saltVariants {
			for _, cp := range Ciphers() {
				key := kdf.Derive(shared, sv.salt, nil, cp.KeyLen)
				if len(key) < cp.KeyLen {
					continue
				}
				for _, ns := range NonceSchemes() {
					open := func(frame []byte, idx int, cand Candidate) (int, bool) {
						if cand.Offset >= len(frame) {
							return 0, false
						}
						ct := frame[cand.Offset:]
						if len(ct) <= 16 {
							return 0, false
						}
						nonce := ns.Build(shared, cand.frameSeq(frame, idx), ns.Size)
						pt, err := cp.Open(key[:cp.KeyLen], nonce, ct)
						if err != nil {
							return 0, false
						}
						return cs2proto.Score(pt, cs2proto.MaxCmd)
					}
					for off := 0; off <= maxOffset; off++ {
						// WireSeq 两种都试：真实链路取线上序号，合成靶标取下标。
						for _, wire := range []bool{true, false} {
							cand := Candidate{KDF: kdf.Name, Cipher: cp.Name, Nonce: ns.Name,
								Offset: off, UseSaltPub: sv.use, WireSeq: wire}

							// ① 筛选：只看前 screenFrames 帧。
							// 候选空间约 3000 个，逐帧全验要跑几百万次 GCM，
							// 会把投递线程卡住好几秒。先用十来帧筛，
							// 命中数为 0 的直接出局。
							lim := len(frames)
							if lim > screenFrames {
								lim = screenFrames
							}
							ok := 0
							for i := 0; i < lim; i++ {
								if _, good := open(frames[i], base+i, cand); good {
									ok++
								}
							}
							if ok < 3 {
								results = append(results, Result{
									Candidate: cand, Frames: len(frames), OKFrames: ok})
								continue
							}

							// ② 确认：活下来的放开验。
							m := len(frames)
							if m > verifyFrames {
								m = verifyFrames
							}
							ok2, msgs := 0, 0
							for i := 0; i < m; i++ {
								if n, good := open(frames[i], base+i, cand); good {
									ok2++
									msgs += n
								}
							}
							results = append(results, Result{
								Candidate: cand,
								Frames:    m,
								OKFrames:  ok2,
								Messages:  msgs,
								// 成立判据：至少 3 帧、且过半帧可解。
								// 单帧偶然解出（无 AEAD 的流式候选有极低概率命中）不算成立。
								OK: ok2 >= 3 && ok2*2 >= m,
							})
						}
					}
				}
			}
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].OKFrames != results[j].OKFrames {
			return results[i].OKFrames > results[j].OKFrames
		}
		return results[i].Messages > results[j].Messages
	})
	return results
}

// BuildScheme 用 Probe 的最优结果构造一个可直接使用的 Scheme。
func BuildScheme(shared, serverPub []byte, best Candidate) (*Scheme, error) {
	for _, k := range KDFs() {
		if k.Name != best.KDF {
			continue
		}
		for _, c := range Ciphers() {
			if c.Name != best.Cipher {
				continue
			}
			for _, n := range NonceSchemes() {
				if n.Name != best.Nonce {
					continue
				}
				salt := []byte(nil)
				if best.UseSaltPub {
					salt = serverPub
				}
				key := k.Derive(shared, salt, nil, c.KeyLen)
				if len(key) < c.KeyLen {
					return nil, errors.New("derived key too short")
				}
				return &Scheme{Candidate: best, kdf: k, cipher: c, nonce: n, key: key[:c.KeyLen]}, nil
			}
		}
	}
	return nil, fmt.Errorf("unknown candidate %+v", best)
}

// Name 返回方案名。
func (s *Scheme) Name() string {
	if s.gns != nil {
		return "gns-hkdf-sha256|aes-256-gcm|iv+seq"
	}
	return fmt.Sprintf("%s|%s|%s|off=%d", s.KDF, s.Cipher, s.Nonce, s.Offset)
}

// SchemeByName 按名字构造方案（供合成靶标工具指定"真实方案"用）。
func SchemeByName(kdfName, cipherName, nonceName string, offset int, useSaltPub bool, shared, serverPub []byte) (*Scheme, error) {
	return BuildScheme(shared, serverPub, Candidate{
		KDF: kdfName, Cipher: cipherName, Nonce: nonceName, Offset: offset, UseSaltPub: useSaltPub,
	})
}

// OpenFrame 解密第 i 帧。
// FrameSeq 从 netchan 帧头里取**线上包序号**（nonce 必须用它）。
//
// 真实帧布局（2026-10-19 抓包核对，连续 11 帧序号逐包 +1）：
//
//	[0]      类型/标志   0x82 = 加密载荷（0x80 是另一类控制包）
//	[1..4]   连接 ID
//	[5..6]   包序号，小端 uint16
//	[7..]    密文（AES-GCM，末尾 16 字节是 tag）
//
// 🔴 为什么不能用「缓冲区下标」当计数器：只要中间漏过一帧
// （端口过滤、丢包、或者握手前就已经在抓了），后面每个 nonce 都是错的，
// GCM 认证会全部失败 —— 现象就是"密钥挖到了、包也在流，但一条都解不开"，
// 而且日志上完全看不出异常。
func FrameSeq(frame []byte) (uint64, bool) {
	if len(frame) < 7 {
		return 0, false
	}
	return uint64(binary.LittleEndian.Uint16(frame[5:7])), true
}

// frameSeq 按候选的 WireSeq 取计数器。
func (c Candidate) frameSeq(frame []byte, idx int) uint64 {
	if c.WireSeq {
		if v, ok := FrameSeq(frame); ok {
			return v
		}
	}
	return uint64(idx)
}

func (s *Scheme) OpenFrame(i int, frame []byte) ([]byte, error) {
	// GNS 路径：密文起点按帧标志字节算，nonce 用「基础 IV + 包序号」。
	if s.gns != nil {
		return s.openGNSFrame(frame)
	}
	if s.Offset >= len(frame) {
		return nil, errors.New("frame shorter than offset")
	}
	nonce := s.nonce.Build(s.Candidate.NoncePrefix, s.Candidate.frameSeq(frame, i), s.nonce.Size)
	return s.cipher.Open(s.key, nonce, frame[s.Offset:])
}

// openGNSFrame 走 SteamNetworkingSockets 的帧解密。
//
// 两个不确定量都用「候选 + 认证判定」处理，不做硬假设：
//   - 密文起点：`GNSOffsets` 给出候选集，帧标志算得出来的排最前；
//   - 完整包序号：16 位线上序号会回绕，试 8 档（约 52 万个包）。
//
// 错误 IV 通过 GCM 认证的概率是 2^-128，多试没有副作用。
// 正常情况下第一个起点、第零档回绕就命中，稳态开销与单次 GCM 相同。
func (s *Scheme) openGNSFrame(frame []byte) ([]byte, error) {
	offs := GNSOffsets(frame)
	if len(offs) == 0 {
		return nil, errors.New("不是 GNS 加密数据包")
	}
	seq, _ := FrameSeq(frame)
	for _, off := range offs {
		for k := uint64(0); k < 8; k++ {
			nonce := GNSIVForSeq(s.Candidate.GNSIV, seq+k<<16)
			if pt, err := s.gns.Open(nil, nonce, frame[off:], nil); err == nil {
				return pt, nil
			}
		}
	}
	return nil, errors.New("GCM 认证失败")
}

// SealFrame 加密第 i 帧：prefix + Seal(plaintext)。仅用于生成合成靶标验证链路。
func (s *Scheme) SealFrame(i int, prefix, plaintext []byte) ([]byte, error) {
	nonce := s.nonce.Build(nil, uint64(i), s.nonce.Size)
	ct, err := s.cipher.Seal(s.key, nonce, plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(prefix)+len(ct))
	out = append(out, prefix...)
	out = append(out, ct...)
	return out, nil
}

// Available 返回候选空间的名字清单，便于文档与排查。
func Available() (kdfs, ciphers, nonces []string) {
	for _, k := range KDFs() {
		kdfs = append(kdfs, k.Name)
	}
	for _, c := range Ciphers() {
		ciphers = append(ciphers, c.Name)
	}
	for _, n := range NonceSchemes() {
		nonces = append(nonces, n.Name)
	}
	return
}
