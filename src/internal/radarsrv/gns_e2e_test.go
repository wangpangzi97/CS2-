package radarsrv

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/uplink"
)

func randN(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// gnsFixture 造一份「客户端 + 服务端」握手材料，并按服务端方向封 10 帧。
func gnsFixture(t *testing.T) (mat *uplink.GNSMaterial, clientPriv []byte, frames [][]byte, plaintexts [][]byte) {
	t.Helper()
	cp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &cs2crypto.GNSHandshake{
		ClientConnID: randN(t, 4),
		ServerConnID: randN(t, 4),
		ClientPub:    cp.PublicKey().Bytes(),
		ServerPub:    sp.PublicKey().Bytes(),
		ClientNonce:  randN(t, 8),
		ServerNonce:  randN(t, 8),
		ClientCert:   randN(t, 97),
		ServerCert:   randN(t, 97),
		ClientCrypt:  randN(t, 49),
		ServerCrypt:  randN(t, 49),
	}
	enc := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	mat = &uplink.GNSMaterial{
		ClientConnID: enc(h.ClientConnID),
		ServerConnID: enc(h.ServerConnID),
		ClientPub:    enc(h.ClientPub),
		ServerPub:    enc(h.ServerPub),
		ClientNonce:  enc(h.ClientNonce),
		ServerNonce:  enc(h.ServerNonce),
		ClientCert:   enc(h.ClientCert),
		ServerCert:   enc(h.ServerCert),
		ClientCrypt:  enc(h.ClientCrypt),
		ServerCrypt:  enc(h.ServerCrypt),
	}

	sk, err := cs2crypto.GNSDeriveServerKeys(sp.Bytes(), h)
	if err != nil {
		t.Fatal(err)
	}
	// 服务端 → 客户端方向：用服务端 SendKey/SendIV 封，客户端用 RecvKey/RecvIV 解。
	for i := 0; i < 10; i++ {
		pt := make([]byte, 60)
		copy(pt, "svc_PacketEntities\x00\x01\x02\x03")
		pt[24] = byte(i)
		seq := uint16(i + 1)
		nonce := cs2crypto.GNSIVForSeq(sk.SendIV, uint64(seq))
		ct := cs2crypto.SealWith(sk.SendKey, nonce, pt, nil)
		frame := []byte{0x82} // 带 time_since_prev
		frame = append(frame, h.ClientConnID...) // 收方是客户端
		var s [2]byte
		binary.LittleEndian.PutUint16(s[:], seq)
		frame = append(frame, s[:]...)
		frame = append(frame, 0xe1, 0x0a)
		frame = append(frame, ct...)
		frames = append(frames, frame)
		plaintexts = append(plaintexts, pt)
	}
	return mat, cp.Bytes(), frames, plaintexts
}

// TestGNSProcessDerivesScheme 是主链路的端到端回归：
// 上行材料齐全 → Process → 方案自动定下来 → 帧能解出原明文。
func TestGNSProcessDerivesScheme(t *testing.T) {
	mat, clientPriv, frames, plains := gnsFixture(t)
	st := NewStore(DefaultConfig())
	b := &uplink.Batch{
		Session: "s1",
		Key:     base64.StdEncoding.EncodeToString(clientPriv),
		GNS:     mat,
	}
	for _, f := range frames {
		b.Packets = append(b.Packets, uplink.Packet{
			Dir:  "s2c",
			Data: base64.StdEncoding.EncodeToString(f),
		})
	}
	if _, err := st.Ingest(b); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	st.Process("s1")

	sess := st.Get("s1")
	sess.mu.Lock()
	sch, dir := sess.primaryScheme()
	sess.mu.Unlock()

	if sch == nil {
		t.Fatal("GNS 材料齐全却没有定出方案")
	}
	if dir != "s2c" {
		t.Errorf("probeDir = %q, want s2c", dir)
	}
	if sch.Name() != "gns-hkdf-sha256|aes-256-gcm|iv+seq" {
		t.Errorf("方案名 = %q", sch.Name())
	}
	for i, f := range frames {
		got, err := sch.OpenFrame(i, f)
		if err != nil {
			t.Fatalf("第 %d 帧解不开: %v", i, err)
		}
		if !bytes.Equal(got, plains[i]) {
			t.Fatalf("第 %d 帧明文不一致", i)
		}
	}
}

// TestGNSWrongKeyLeavesNoScheme 错私钥必须什么都定不下来，
// 而且要静默回落到候选搜索（不能把垃圾密钥当成功）。
func TestGNSWrongKeyLeavesNoScheme(t *testing.T) {
	mat, _, frames, _ := gnsFixture(t)
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st := NewStore(DefaultConfig())
	b := &uplink.Batch{
		Session: "s2",
		Key:     base64.StdEncoding.EncodeToString(other.Bytes()),
		GNS:     mat,
	}
	for _, f := range frames {
		b.Packets = append(b.Packets, uplink.Packet{
			Dir:  "s2c",
			Data: base64.StdEncoding.EncodeToString(f),
		})
	}
	if _, err := st.Ingest(b); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	st.Process("s2")
	sess := st.Get("s2")
	sess.mu.Lock()
	sch, _ := sess.primaryScheme()
	sess.mu.Unlock()
	if sch != nil {
		t.Fatalf("错私钥不应定出方案，却得到 %q", sch.Name())
	}
}

// TestGNSMissingMaterialNoScheme 材料不齐（缺 cert）时不应设置 gns，也不应崩。
func TestGNSMissingMaterialNoScheme(t *testing.T) {
	mat, clientPriv, frames, _ := gnsFixture(t)
	mat.ServerCert = "" // 故意打缺
	if mat.Complete() {
		t.Fatal("Complete() 应当为 false")
	}
	st := NewStore(DefaultConfig())
	b := &uplink.Batch{
		Session: "s3",
		Key:     base64.StdEncoding.EncodeToString(clientPriv),
		GNS:     mat,
	}
	for _, f := range frames {
		b.Packets = append(b.Packets, uplink.Packet{
			Dir:  "s2c",
			Data: base64.StdEncoding.EncodeToString(f),
		})
	}
	if _, err := st.Ingest(b); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	st.Process("s3")
	sess := st.Get("s3")
	sess.mu.Lock()
	hasGNS, sch := sess.gns != nil, sess.anyScheme()
	sess.mu.Unlock()
	if hasGNS {
		t.Error("材料不齐不应保存 gns")
	}
	if sch != nil {
		t.Errorf("材料不齐不应定出方案，却得到 %q", sch.Name())
	}
}

// TestGNSVariantAutoDetect 验证「变体自动纠错」：
// 用一组**非规范**的 KDF 参数封帧，tryGNS 必须自己找出来。
//
// 这条测试对应真实风险：CS2 里的 steamnetworkingsockets.dll 是 Valve 内部构建，
// 个别细节（label 拼写、四段握手字节顺序、salt 顺序）可能和开源版不一致。
// 与其赌一种写法，不如让程序枚举 + 用 GCM 认证判胜负。
func TestGNSVariantAutoDetect(t *testing.T) {
	cp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &cs2crypto.GNSHandshake{
		ClientConnID: randN(t, 4),
		ServerConnID: randN(t, 4),
		ClientPub:    cp.PublicKey().Bytes(),
		ServerPub:    sp.PublicKey().Bytes(),
		ClientNonce:  randN(t, 8),
		ServerNonce:  randN(t, 8),
		ClientCert:   randN(t, 97),
		ServerCert:   randN(t, 97),
		ClientCrypt:  randN(t, 49),
		ServerCrypt:  randN(t, 49),
	}

	// 挑一个非规范变体：salt 顺序反过来 + 四段字节换序。
	var variant cs2crypto.GNSVariant
	found := false
	for _, v := range cs2crypto.GNSVariants() {
		if v.SaltSwap && v.Blobs == 1 && v.Label == "Steam datagram" && !v.SlotSwap && !v.CounterFirst && !v.ConnSwap {
			variant, found = v, true
			break
		}
	}
	if !found {
		t.Fatal("没找到预期的非规范变体")
	}

	keys, err := cs2crypto.GNSDeriveClientKeysV(cp.Bytes(), h, variant)
	if err != nil {
		t.Fatal(err)
	}
	// 用派生出来的 RecvKey/RecvIV 封 s2c 帧（对称性保证服务端那把等价）。
	var frames [][]byte
	var plains [][]byte
	for i := 0; i < 10; i++ {
		pt := make([]byte, 60)
		copy(pt, "svc_PacketEntities\x00\x01\x02\x03")
		pt[24] = byte(i)
		seq := uint16(i + 1)
		nonce := cs2crypto.GNSIVForSeq(keys.RecvIV, uint64(seq))
		ct := cs2crypto.SealWith(keys.RecvKey, nonce, pt, nil)
		frame := []byte{0x82}
		frame = append(frame, h.ClientConnID...)
		var s [2]byte
		binary.LittleEndian.PutUint16(s[:], seq)
		frame = append(frame, s[:]...)
		frame = append(frame, 0xe1, 0x0a)
		frame = append(frame, ct...)
		frames = append(frames, frame)
		plains = append(plains, pt)
	}

	enc := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	mat := &uplink.GNSMaterial{
		ClientConnID: enc(h.ClientConnID), ServerConnID: enc(h.ServerConnID),
		ClientPub: enc(h.ClientPub), ServerPub: enc(h.ServerPub),
		ClientNonce: enc(h.ClientNonce), ServerNonce: enc(h.ServerNonce),
		ClientCert: enc(h.ClientCert), ServerCert: enc(h.ServerCert),
		ClientCrypt: enc(h.ClientCrypt), ServerCrypt: enc(h.ServerCrypt),
	}

	st := NewStore(DefaultConfig())
	b := &uplink.Batch{Session: "v1", Key: base64.StdEncoding.EncodeToString(cp.Bytes()), GNS: mat}
	for _, f := range frames {
		b.Packets = append(b.Packets, uplink.Packet{Dir: "s2c", Data: base64.StdEncoding.EncodeToString(f)})
	}
	if _, err := st.Ingest(b); err != nil {
		t.Fatal(err)
	}
	st.Process("v1")

	sess := st.Get("v1")
	sess.mu.Lock()
	sch, _ := sess.primaryScheme()
	sess.mu.Unlock()
	if sch == nil {
		t.Fatal("非规范变体没有被自动识别出来")
	}
	for i, f := range frames {
		got, err := sch.OpenFrame(i, f)
		if err != nil {
			t.Fatalf("第 %d 帧解不开: %v", i, err)
		}
		if !bytes.Equal(got, plains[i]) {
			t.Fatalf("第 %d 帧明文不一致", i)
		}
	}
}

// TestGNSIgnoresForeignFlows 钉住「只认本连接的帧」这条规则。
//
// 09:01 那次现场：CS2 进程名下同时有 Steam 客户端的好几条 UDP 流
// （光一个端口就 3 万多个包），而游戏服只有 3300 个。旧代码只判
// `flags & 0x80`，于是把最老的 64 个无关包当成判据帧，
// connID 全是 000400cc / 000700c9，和本次的 ba2554e3/ba10bf93 毫无关系 ——
// 768 组变体 × 12 帧，一帧都解不开。
//
// 这条用例往缓冲里先灌 200 个"长得像但不是本连接"的包，再灌 10 个真帧。
// 旧代码会挑到假包（因为从头部取），新代码必须无视它们直接命中。
func TestGNSIgnoresForeignFlows(t *testing.T) {
	mat, clientPriv, frames, plains := gnsFixture(t)
	st := NewStore(DefaultConfig())

	// 假包：flags 合法、长度也像样，但收方 connID 是别人的。
	junk := func(i int) []byte {
		f := []byte{0x82}
		f = append(f, 0xcc, 0x00, 0x04, 0x00) // to = 000400cc
		f = append(f, byte(i), 0x00)          // seq
		f = append(f, 0xe1, 0x0a)             // time_since_prev
		f = append(f, bytes.Repeat([]byte{byte(i)}, 24)...)
		return f
	}
	var b0 []uplink.Batch
	{
		b := &uplink.Batch{Session: "s1"}
		for i := 0; i < 200; i++ {
			b.Packets = append(b.Packets, uplink.Packet{
				Dir: "s2c", Data: base64.StdEncoding.EncodeToString(junk(i)),
			})
		}
		b0 = append(b0, *b)
	}
	// 先灌垃圾（此时还没有 GNS 材料，不会被过滤）
	for i := range b0 {
		if _, err := st.Ingest(&b0[i]); err != nil {
			t.Fatal(err)
		}
	}

	b := &uplink.Batch{
		Session: "s1",
		Key:     base64.StdEncoding.EncodeToString(clientPriv),
		GNS:     mat,
	}
	for _, f := range frames {
		b.Packets = append(b.Packets, uplink.Packet{
			Dir: "s2c", Data: base64.StdEncoding.EncodeToString(f),
		})
	}
	if _, err := st.Ingest(b); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	sess := st.Get("s1")
	sess.mu.Lock()
	left := len(sess.s2c)
	sess.mu.Unlock()
	if left != len(frames) {
		t.Fatalf("拿到材料后应当只留 %d 个本连接帧，实际留下 %d 个（垃圾没清掉）",
			len(frames), left)
	}

	st.Process("s1")
	sess.mu.Lock()
	sch, _ := sess.primaryScheme()
	sess.mu.Unlock()
	if sch == nil {
		t.Fatal("有 200 个无关包混在缓冲里就定不出方案了")
	}
	for i, f := range frames {
		got, err := sch.OpenFrame(i, f)
		if err != nil {
			t.Fatalf("第 %d 帧解不开: %v", i, err)
		}
		if !bytes.Equal(got, plains[i]) {
			t.Fatalf("第 %d 帧明文不一致", i)
		}
	}
}

// TestGNSRejectsReservedFlags 保留位不是数据包。
// 源码只定义了 kFlag_ProtobufBlob=0x01 / kFlag_TimeSincePrev=0x02，
// 高位除 0x80 之外全保留；放宽会把别的私有协议一起收进来。
func TestGNSRejectsReservedFlags(t *testing.T) {
	body := bytes.Repeat([]byte{0xaa}, 32)
	for _, fl := range []byte{0x84, 0x88, 0x90, 0xa0, 0xc0, 0xff} {
		f := append([]byte{fl, 1, 2, 3, 4, 0, 0}, body...)
		if _, ok := cs2crypto.GNSChunkOffset(f); ok {
			t.Fatalf("flags=0x%02x 不该被当成 GNS 数据包", fl)
		}
	}
	// 0x80 / 0x82 必须仍然通过（真实抓包里 0x82 占多数）
	for _, fl := range []byte{0x80, 0x82} {
		f := append([]byte{fl, 1, 2, 3, 4, 0, 0}, body...)
		if _, ok := cs2crypto.GNSChunkOffset(f); !ok {
			t.Fatalf("flags=0x%02x 应当通过", fl)
		}
	}
}
