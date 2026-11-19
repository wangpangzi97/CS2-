package cs2crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// mkGNS 造一份形状合法的握手材料（密钥对是真随机，context 字节是随机串）。
func mkGNS(t *testing.T) (*GNSHandshake, []byte, []byte) {
	t.Helper()
	cp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rb := func(n int) []byte {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	h := &GNSHandshake{
		ClientConnID: rb(4),
		ServerConnID: rb(4),
		ClientPub:    cp.PublicKey().Bytes(),
		ServerPub:    sp.PublicKey().Bytes(),
		ClientNonce:  rb(8),
		ServerNonce:  rb(8),
		ClientCert:   rb(97),
		ServerCert:   rb(97),
		ClientCrypt:  rb(49),
		ServerCrypt:  rb(49),
	}
	return h, cp.Bytes(), sp.Bytes()
}

// mkGNSFrame 造一个真实形状的 GNS 数据包：
// [flags][connID 4][seq u16][可选 stats][可选 time_since_prev][GCM 密文+tag]
func mkGNSFrame(t *testing.T, key, iv []byte, connID []byte, seq uint16, flags byte, plaintext []byte) []byte {
	t.Helper()
	g, err := gnsAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	var head []byte
	head = append(head, flags)
	head = append(head, connID...)
	var s [2]byte
	binary.LittleEndian.PutUint16(s[:], seq)
	head = append(head, s[:]...)
	if flags&0x01 != 0 {
		stats := []byte{0x0a, 0x03, 0x08, 0x01, 0x10} // 假的内联 stats protobuf
		head = append(head, byte(len(stats)))
		head = append(head, stats...)
	}
	if flags&0x02 != 0 {
		head = append(head, 0xe1, 0x0a)
	}
	nonce := GNSIVForSeq(iv, uint64(seq))
	ct := g.Seal(nil, nonce, plaintext, nil)
	return append(head, ct...)
}

// TestGNSDeriveSymmetry 钉住协议对称性：客户端算出的 SendKey/SendIV
// 必须等于服务端算出的 RecvKey/RecvIV。这是整条链路成立的前提。
func TestGNSDeriveSymmetry(t *testing.T) {
	h, cpriv, spriv := mkGNS(t)

	ck, err := GNSDeriveClientKeys(cpriv, h)
	if err != nil {
		t.Fatalf("client derive: %v", err)
	}
	sk, err := GNSDeriveServerKeys(spriv, h)
	if err != nil {
		t.Fatalf("server derive: %v", err)
	}
	if !bytes.Equal(ck.SendKey, sk.RecvKey) {
		t.Errorf("client.SendKey != server.RecvKey\n %x\n %x", ck.SendKey, sk.RecvKey)
	}
	if !bytes.Equal(ck.SendIV, sk.RecvIV) {
		t.Errorf("client.SendIV != server.RecvIV")
	}
	if !bytes.Equal(ck.RecvKey, sk.SendKey) {
		t.Errorf("client.RecvKey != server.SendKey")
	}
	if !bytes.Equal(ck.RecvIV, sk.SendIV) {
		t.Errorf("client.RecvIV != server.SendIV")
	}
	// 两个方向必须是不同的密钥/IV，否则等于流复用。
	if bytes.Equal(ck.SendKey, ck.RecvKey) {
		t.Error("上下行密钥不应相同")
	}
	if bytes.Equal(ck.SendIV, ck.RecvIV) {
		t.Error("上下行 IV 不应相同")
	}
}

func TestGNSDeriveRejectsMismatchedKey(t *testing.T) {
	h, _, _ := mkGNS(t)
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GNSDeriveClientKeys(other.Bytes(), h); err == nil {
		t.Fatal("私钥与握手公钥不配对时应当报错")
	}
}

// TestGNSRoundTrip 端到端：客户端封包 → 服务端解包，覆盖 0x80/0x82/0x83 三种帧。
func TestGNSRoundTrip(t *testing.T) {
	h, cpriv, spriv := mkGNS(t)
	ck, err := GNSDeriveClientKeys(cpriv, h)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := GNSDeriveServerKeys(spriv, h)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("svc_PacketEntities snapshot payload")

	for _, flags := range []byte{0x80, 0x82, 0x83} {
		frame := mkGNSFrame(t, ck.SendKey, ck.SendIV, h.ServerConnID, 7, flags, pt)
		got, err := GNSOpen(sk.RecvKey, sk.RecvIV, frame)
		if err != nil {
			t.Fatalf("flags=0x%02x GNSOpen: %v", flags, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("flags=0x%02x 明文不一致: %q", flags, got)
		}
	}
}

// TestGNSOpenWrongKeyFails 错密钥必须失败（GCM 认证是唯一判据）。
func TestGNSOpenWrongKeyFails(t *testing.T) {
	h, cpriv, _ := mkGNS(t)
	ck, err := GNSDeriveClientKeys(cpriv, h)
	if err != nil {
		t.Fatal(err)
	}
	frame := mkGNSFrame(t, ck.SendKey, ck.SendIV, h.ServerConnID, 3, 0x82, []byte("hello"))

	bad := append([]byte(nil), ck.RecvKey...)
	bad[0] ^= 0xff
	if _, err := GNSOpen(bad, ck.RecvIV, frame); err == nil {
		t.Fatal("错密钥不应解开")
	}
	badIV := append([]byte(nil), ck.RecvIV...)
	badIV[11] ^= 0x01
	if _, err := GNSOpen(ck.RecvKey, badIV, frame); err == nil {
		t.Fatal("错 IV 不应解开")
	}
}

// TestGNSChunkOffset 钉住「密文起点不是固定 7」这个曾经让所有候选组合全灭的坑。
func TestGNSChunkOffset(t *testing.T) {
	base := []byte{0x80, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0}
	if off, ok := GNSChunkOffset(base); !ok || off != 7 {
		t.Errorf("0x80: off=%d ok=%v, want 7", off, ok)
	}
	withTime := []byte{0x82, 1, 2, 3, 4, 5, 6, 0xe1, 0x0a, 0, 0, 0}
	if off, ok := GNSChunkOffset(withTime); !ok || off != 9 {
		t.Errorf("0x82: off=%d ok=%v, want 9", off, ok)
	}
	// 0x83 = 内联 stats（varint 长度 + 内容）+ time_since_prev
	withBoth := []byte{0x83, 1, 2, 3, 4, 5, 6, 0x05, 9, 9, 9, 9, 9, 0xe1, 0x0a, 0, 0}
	if off, ok := GNSChunkOffset(withBoth); !ok || off != 15 {
		t.Errorf("0x83: off=%d ok=%v, want 15", off, ok)
	}
	if _, ok := GNSChunkOffset([]byte{0x22, 1, 2, 3, 4, 5, 6, 0}); ok {
		t.Error("0x22 不是加密数据包")
	}
	if _, ok := GNSChunkOffset([]byte{0x82, 1, 2}); ok {
		t.Error("过短应失败")
	}
}

// TestGNSIVForSeq 钉住「前 8 字节当小端 u64 加包序号，后 4 字节不变」。
func TestGNSIVForSeq(t *testing.T) {
	iv := []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd}
	got := GNSIVForSeq(iv, 1)
	if !bytes.Equal(got, []byte{0x02, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Errorf("got %x", got)
	}
	// 进位必须跨字节传播。
	carry := []byte{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44}
	got = GNSIVForSeq(carry, 1)
	if !bytes.Equal(got, []byte{0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44}) {
		t.Errorf("carry got %x", got)
	}
	// 原 IV 不能被改写。
	if !bytes.Equal(carry, []byte{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44}) {
		t.Error("GNSIVForSeq 不应修改入参")
	}
}

// TestSchemeFromGNS 覆盖 Scheme 的 GNS 分支（decode() 走的就是它）。
func TestSchemeFromGNS(t *testing.T) {
	h, cpriv, spriv := mkGNS(t)
	ck, err := GNSDeriveClientKeys(cpriv, h)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := GNSDeriveServerKeys(spriv, h)
	if err != nil {
		t.Fatal(err)
	}
	sch, err := SchemeFromGNS(sk.RecvKey, sk.RecvIV)
	if err != nil {
		t.Fatal(err)
	}
	if sch.Name() != "gns-hkdf-sha256|aes-256-gcm|iv+seq" {
		t.Errorf("Name = %q", sch.Name())
	}
	pt := []byte("net_SvcMessages")
	frame := mkGNSFrame(t, ck.SendKey, ck.SendIV, h.ServerConnID, 42, 0x82, pt)
	got, err := sch.OpenFrame(0, frame)
	if err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("明文不一致: %q", got)
	}
	// 非加密帧必须报错，不能 panic 或返回垃圾。
	if _, err := sch.OpenFrame(0, []byte{0x22, 1, 2, 3, 4, 5, 6, 7, 8, 9}); err == nil {
		t.Error("非加密帧应当报错")
	}
	if _, err := sch.OpenFrame(0, nil); err == nil {
		t.Error("空帧应当报错")
	}
}

// TestGNSSeqWrap 覆盖 16 位包序号回绕：seq 从 65535 回到 0 时，
// 完整包序号应该是 65536 而不是 0。
func TestGNSSeqWrap(t *testing.T) {
	h, cpriv, spriv := mkGNS(t)
	ck, _ := GNSDeriveClientKeys(cpriv, h)
	sk, _ := GNSDeriveServerKeys(spriv, h)

	// 手工造一帧：wire seq = 0，但完整包序号 = 65536。
	g, err := gnsAEAD(ck.SendKey)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("wrapped")
	nonce := GNSIVForSeq(ck.SendIV, 65536)
	ct := g.Seal(nil, nonce, pt, nil)
	frame := []byte{0x80}
	frame = append(frame, h.ServerConnID...)
	frame = append(frame, 0, 0) // seq = 0
	frame = append(frame, ct...)

	got, err := GNSOpen(sk.RecvKey, sk.RecvIV, frame)
	if err != nil {
		t.Fatalf("回绕后应当能解: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("明文不一致: %q", got)
	}
}

// TestGNSExpandHasNoZeroPrefix 钉住 HKDF-Expand 的形状：
// 首轮 HMAC 的输入是 `tail || 0x01`，**不带** 32 个零字节。
//
// 依据 Valve 源码 steamnetworkingsockets_connections.cpp:1720-1749：
// `SeekPut(SEEK_HEAD, 32)` 只是预留位置，紧跟着的 `pStart = PeekPut()`
// 直接跳过这 32 字节，所以首轮消息里根本没有它们。第二轮开始
// `pStart = Base()` 才把上一轮摘要接在前面。
//
// 这条用例存在的意义：曾经按「全 0 打头」实现，192 组变体全都带着
// 这个错误基式，枚举再多维度也不可能中。没有这条钉子，同样的错很容易
// 被再次引入。
func TestGNSExpandHasNoZeroPrefix(t *testing.T) {
	h, cp, _ := mkGNS(t)
	pm, err := GNSPremaster(cp, h)
	if err != nil {
		t.Fatal(err)
	}
	got := gnsChainFromPremaster(pm, h, GNSVariant{Label: "Steam datagram"})

	// 按源码手算 prk 与 tail。
	// 🔴 prk = HMAC(key=premaster, msg=salt)，与 RFC5869 相反（反汇编定案）。
	salt := append(append([]byte(nil), h.ServerNonce...), h.ClientNonce...)
	mac := hmac.New(sha256.New, pm)
	mac.Write(salt)
	prk := mac.Sum(nil)

	blobs := gnsBlobOrder(0, h, false)
	var tail []byte
	tail = append(tail, h.ClientConnID...)
	tail = append(tail, h.ServerConnID...)
	tail = append(tail, []byte("Steam datagram")...)
	for _, b := range blobs {
		tail = append(tail, b...)
	}

	round := func(prev []byte, n byte) []byte {
		msg := append(append([]byte(nil), prev...), tail...)
		msg = append(msg, n)
		m := hmac.New(sha256.New, prk)
		m.Write(msg)
		return m.Sum(nil)
	}

	d1 := round(nil, 1)
	if !bytes.Equal(got[0], d1) {
		t.Fatalf("d1 与「prev 为空」的写法不符")
	}
	// 反证：带 32 个零的写法必须不等，否则这条用例形同虚设。
	if bytes.Equal(got[0], round(make([]byte, 32), 1)) {
		t.Fatalf("d1 竟然等于「prev=32 个零」的写法，测试没有区分力")
	}
	if d2 := round(d1, 2); !bytes.Equal(got[1], d2) {
		t.Fatalf("d2 不符")
	}
	if d3 := round(got[1], 3); !bytes.Equal(got[2], d3) {
		t.Fatalf("d3 不符")
	}
	if d4 := round(got[2], 4); !bytes.Equal(got[3], d4) {
		t.Fatalf("d4 不符")
	}
}

// TestGNSPremasterIsHashed 钉住「预主密钥 = SHA256(裸 X25519 结果)」这一层。
//
// 依据 src/common/crypto_25519.h:163 的注释：
//   // NOTE: this actually returns the SHA256 of the raw DH result.
// 以及三个后端（openssl / donna / libsodium）实现里都调了 GenerateSHA256Digest。
//
// 这一层很容易被"理所当然"地省掉 —— 大多数 ECDH 直接拿裸共享秘密进 KDF。
// 省掉之后所有派生材料整体错位，而且没有任何报错，只有 GCM 认证会失败。
func TestGNSPremasterIsHashed(t *testing.T) {
	h, cp, _ := mkGNS(t)
	raw, err := GNSPremasterRaw(cp, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("裸 DH 结果应为 32 字节，实为 %d", len(raw))
	}
	got, err := GNSPremaster(cp, h)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(raw)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("预主密钥不等于 SHA256(裸 DH)")
	}
	if bytes.Equal(got, raw) {
		t.Fatalf("预主密钥等于裸 DH —— 那层 SHA256 丢了")
	}
}

// TestGNSFrameForConn 钉住「收方 connID」这个判据。
//
// 帧头第 1~4 字节是 `m_unToConnectionID`（收方那一段），
// s2c 帧等于客户端 connID，c2s 帧等于服务器 connID。
// 这是把本连接的帧和同进程其它 UDP 流分开的唯一可靠依据。
func TestGNSFrameForConn(t *testing.T) {
	conn := []byte{0xe3, 0x54, 0x25, 0xba}
	good := []byte{0x82, 0xe3, 0x54, 0x25, 0xba, 0x01, 0x00, 0xe1, 0x0a, 0xaa}
	if !GNSFrameForConn(good, conn) {
		t.Fatal("收方 connID 对得上却判为不匹配")
	}
	// 09:01 现场里真实出现过的那种包
	for _, to := range [][]byte{{0xcc, 0x00, 0x04, 0x00}, {0xc9, 0x00, 0x07, 0x00}} {
		f := append([]byte{0x82}, to...)
		f = append(f, 0x00, 0x00, 0xe1, 0x0a, 0xaa)
		if GNSFrameForConn(f, conn) {
			t.Fatalf("收方 %x 不是本连接，却判为匹配", to)
		}
	}
	if GNSFrameForConn(good, nil) {
		t.Fatal("connID 为空时不该判为匹配")
	}
	if _, ok := GNSFrameToConnID([]byte{0x82, 0x01}); ok {
		t.Fatal("太短的帧不该取出 connID")
	}
}

// TestGNSBlobOrderServerByte0Zero 钉住「服务端两段首字节清零」这个维度。
//
// 现场依据（2026-10-19 10:22）：客户端内存里自己那两段与线上字节完全一致
// （`08 01 12 20 …`），服务端那两段首字节是 `00` 而其余字节逐字节相同。
func TestGNSBlobOrderServerByte0Zero(t *testing.T) {
	h := &GNSHandshake{
		ServerCert:  []byte{0x08, 0x01, 0xaa},
		ClientCert:  []byte{0x08, 0x01, 0xbb},
		ServerCrypt: []byte{0x08, 0x01, 0xcc},
		ClientCrypt: []byte{0x08, 0x01, 0xdd},
	}
	plain := gnsBlobOrder(0, h, false)
	if plain[0][0] != 0x08 || plain[2][0] != 0x08 {
		t.Fatalf("不开开关时服务端两段不该被改：%x %x", plain[0], plain[2])
	}
	zeroed := gnsBlobOrder(0, h, true)
	if zeroed[0][0] != 0x00 || zeroed[2][0] != 0x00 {
		t.Fatalf("开了开关服务端两段首字节应为 0：%x %x", zeroed[0], zeroed[2])
	}
	if zeroed[1][0] != 0x08 || zeroed[3][0] != 0x08 {
		t.Fatalf("客户端两段不该被改：%x %x", zeroed[1], zeroed[3])
	}
	// 只改首字节，其余必须原样。
	if zeroed[0][1] != 0x01 || zeroed[0][2] != 0xaa {
		t.Fatalf("除首字节外被改动了：%x", zeroed[0])
	}
	// 不能污染握手材料本身。
	if h.ServerCert[0] != 0x08 || h.ServerCrypt[0] != 0x08 {
		t.Fatalf("握手材料被就地修改：%x %x", h.ServerCert, h.ServerCrypt)
	}
}

// TestGNSVariantsCountAndCoverage 钉住变体总数与维度覆盖。
func TestGNSVariantsCountAndCoverage(t *testing.T) {
	vs := GNSVariants()
	// 3 label × 24 排列 × 2 salt × 2 conn × 2 ctr × 2 srv0 = 1152，再乘 swap-slots 2。
	const want = 2304
	if len(vs) != want {
		t.Fatalf("变体 %d 个，期望 %d", len(vs), want)
	}
	if vs[0].Name != "规范" {
		t.Fatalf("第一项必须是规范实现，实际 %q", vs[0].Name)
	}
	var sbz int
	for _, v := range vs {
		if v.ServerByte0Zero {
			sbz++
		}
	}
	if sbz != want/2 {
		t.Fatalf("ServerByte0Zero 变体 %d 个，期望 %d", sbz, want/2)
	}
}
