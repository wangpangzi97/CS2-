package radarsrv

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/uplink"
)

// TestGNSKeysMaterialInstallsScheme 钉住「内存直读密钥」这条旁路。
//
// 背景：KDF 的结构已经反汇编确认到字段级，但输入里有两段无法枚举的原始
// 字节（四段 cert/crypt 的排列与边界），拼错时密钥和 IV 会一起错，而且
// 没有任何可观测迹象。所以采集端会改从目标进程内存里直接读基础 IV 与密钥，
// 用真实帧的 GCM 认证确认之后上行。这条测试保证解码端拿到它就能直接用。
func TestGNSKeysMaterialInstallsScheme(t *testing.T) {
	mat, _, frames, _ := gnsFixture(t)
	h := gnsFromMaterial(mat)
	if h == nil {
		t.Fatal("材料还原失败")
	}

	// 服务端视角的 SendKey/SendIV 就是客户端视角的 RecvKey/RecvIV。
	// 这里绕过 KDF 直接把它当成「从内存读到的东西」喂进去 —— 这正是
	// 旁路成立的前提：密钥对不对不靠推导，靠 GCM 认证。
	key := make([]byte, 32)
	iv := make([]byte, 12)
	for i := range key {
		key[i] = byte(0x40 + i)
	}
	for i := range iv {
		iv[i] = byte(0xa0 + i)
	}

	// 用这把密钥/IV 重新封一批帧（收方是客户端，走 s2c）。
	frames = frames[:0]
	for i := 0; i < 6; i++ {
		pt := make([]byte, 48)
		copy(pt, "svc_PacketEntities\x00\x01\x02\x03")
		seq := uint16(i + 1)
		nonce := cs2crypto.GNSIVForSeq(iv, uint64(seq))
		ct := cs2crypto.SealWith(key, nonce, pt, nil)
		frame := []byte{0x80}
		frame = append(frame, h.ClientConnID...)
		var s [2]byte
		binary.LittleEndian.PutUint16(s[:], seq)
		frame = append(frame, s[:]...)
		frame = append(frame, ct...)
		frames = append(frames, frame)
	}

	st := NewStore(DefaultConfig())
	b := &uplink.Batch{
		Session: "room1",
		GNSKeys: &uplink.GNSKeysMaterial{
			ClientConnID: mat.ClientConnID,
			ServerConnID: mat.ServerConnID,
			Dir:          "s2c",
			Key:          base64.StdEncoding.EncodeToString(key),
			IV:           base64.StdEncoding.EncodeToString(iv),
		},
	}
	for _, f := range frames {
		b.Packets = append(b.Packets, uplink.Packet{
			Dir: "s2c", Data: base64.StdEncoding.EncodeToString(f),
		})
	}
	if _, err := st.Ingest(b); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	sess := st.Get("room1")
	sess.mu.Lock()
	sch, dir := sess.primaryScheme()
	sess.mu.Unlock()

	if sch == nil {
		t.Fatal("GNSKeys 没有装上方案")
	}
	if dir != "s2c" {
		t.Fatalf("方向 = %q，期望 s2c", dir)
	}
	if len(sch.Candidate.GNSIV) != 12 {
		t.Fatalf("方案没带上 GNSIV：%x", sch.Candidate.GNSIV)
	}
	// 装上之后 Process 必须直接短路成功，不能再去跑候选枚举。
	if !sess.tryGNS() {
		t.Fatal("tryGNS 没有识别出已装好的方案")
	}
	// 逐帧确认真的解得开（不是只把字段填上了）。
	for i, f := range frames {
		if _, err := sch.OpenFrame(i, f); err != nil {
			t.Fatalf("第 %d 帧解不开：%v", i, err)
		}
	}
}

// TestGNSKeysMaterialInstallsBothDirections 钉住「两个方向各一把密钥」。
//
// GNS 的 SendKey（c2s）与 RecvKey（s2c）是**两把不同的密钥**。早期材料结构
// 只带一个方向，解码端就只能解一边 —— 现场 13:24 全程只有 `方向=c2s`，
// 服务端下发的实体数据（s2c）一条没解，雷达没有任何目标。
func TestGNSKeysMaterialInstallsBothDirections(t *testing.T) {
	mat, _, _, _ := gnsFixture(t)
	h := gnsFromMaterial(mat)
	if h == nil {
		t.Fatal("材料还原失败")
	}

	// 两个方向用不同的密钥与 IV，模拟真实链路的 SendKey / RecvKey。
	keyS2C, ivS2C := make([]byte, 32), make([]byte, 12)
	keyC2S, ivC2S := make([]byte, 32), make([]byte, 12)
	for i := range keyS2C {
		keyS2C[i] = byte(0x40 + i)
		keyC2S[i] = byte(0x80 + i)
	}
	for i := range ivS2C {
		ivS2C[i] = byte(0xa0 + i)
		ivC2S[i] = byte(0xb0 + i)
	}

	mkFrames := func(key, iv []byte, marker string) [][]byte {
		out := make([][]byte, 0, 6)
		for i := 0; i < 6; i++ {
			pt := make([]byte, 48)
			copy(pt, marker)
			seq := uint16(i + 1)
			nonce := cs2crypto.GNSIVForSeq(iv, uint64(seq))
			ct := cs2crypto.SealWith(key, nonce, pt, nil)
			frame := []byte{0x80}
			frame = append(frame, h.ClientConnID...)
			var s [2]byte
			binary.LittleEndian.PutUint16(s[:], seq)
			frame = append(frame, s[:]...)
			out = append(out, append(frame, ct...))
		}
		return out
	}
	framesS2C := mkFrames(keyS2C, ivS2C, "svc_PacketEntities\x00\x01\x02\x03")
	framesC2S := mkFrames(keyC2S, ivC2S, "svc_Move\x00\x01\x02\x03")

	st := NewStore(DefaultConfig())
	b := &uplink.Batch{
		Session: "room2",
		GNSKeys: &uplink.GNSKeysMaterial{
			ClientConnID: mat.ClientConnID,
			ServerConnID: mat.ServerConnID,
			Dir:          "s2c",
			Key:          base64.StdEncoding.EncodeToString(keyS2C),
			IV:           base64.StdEncoding.EncodeToString(ivS2C),
			AltDir:       "c2s",
			AltKey:       base64.StdEncoding.EncodeToString(keyC2S),
			AltIV:        base64.StdEncoding.EncodeToString(ivC2S),
		},
	}
	for _, f := range framesS2C {
		b.Packets = append(b.Packets, uplink.Packet{Dir: "s2c", Data: base64.StdEncoding.EncodeToString(f)})
	}
	for _, f := range framesC2S {
		b.Packets = append(b.Packets, uplink.Packet{Dir: "c2s", Data: base64.StdEncoding.EncodeToString(f)})
	}
	if _, err := st.Ingest(b); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	sess := st.Get("room2")
	sess.mu.Lock()
	schS2C, schC2S := sess.schemeS2C, sess.schemeC2S
	sess.mu.Unlock()

	if schS2C == nil {
		t.Fatal("s2c 方向没有装上方案")
	}
	if schC2S == nil {
		t.Fatal("c2s 方向没有装上方案 —— 第二个方向被丢了")
	}
	for i, f := range framesS2C {
		if _, err := schS2C.OpenFrame(i, f); err != nil {
			t.Fatalf("s2c 第 %d 帧解不开：%v", i, err)
		}
	}
	for i, f := range framesC2S {
		if _, err := schC2S.OpenFrame(i, f); err != nil {
			t.Fatalf("c2s 第 %d 帧解不开：%v", i, err)
		}
	}
	// 两把密钥不能混用：用 s2c 的方案去解 c2s 的帧必须失败。
	if _, err := schS2C.OpenFrame(0, framesC2S[0]); err == nil {
		t.Fatal("s2c 方案解开了 c2s 的帧 —— 两个方向装成了同一把密钥")
	}
	// 两个方向都齐了，tryGNS 应直接短路。
	if !sess.tryGNS() {
		t.Fatal("tryGNS 没有识别出两个方向都已装好")
	}
}

// TestGNSKeysMaterialRejectsIncomplete 确认残缺材料不会被当成有效材料。
func TestGNSKeysMaterialRejectsIncomplete(t *testing.T) {
	// 32 字节密钥的 base64 是 44 字符，12 字节 IV 是 16 字符。
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	iv := base64.StdEncoding.EncodeToString(make([]byte, 12))
	if len(key) != 44 || len(iv) != 16 {
		t.Fatalf("测试基线长度不对：key=%d iv=%d", len(key), len(iv))
	}

	cases := []*uplink.GNSKeysMaterial{
		nil,
		{Key: "AAAA", IV: "AAAA", Dir: "s2c"},                 // 长度不足
		{Key: "", IV: iv, Dir: "s2c"},                         // 缺密钥
		{Key: key, IV: "", Dir: "s2c"},                        // 缺 IV
		{Key: key, IV: iv, Dir: "sideways"},                   // 方向非法
		{Key: key, IV: iv, Dir: ""},                           // 缺方向
		{Key: key[:40], IV: iv, Dir: "s2c"},                   // 密钥被截断
	}
	for i, m := range cases {
		if m.Complete() {
			t.Fatalf("第 %d 个残缺材料被判成完整", i)
		}
	}
	for _, dir := range []string{"c2s", "s2c"} {
		ok := &uplink.GNSKeysMaterial{Key: key, IV: iv, Dir: dir}
		if !ok.Complete() {
			t.Fatalf("完整材料（%s）被判成残缺", dir)
		}
		// 没填 Alt 时 HasAlt 必须为假，不能把空字段当成第二方向。
		if ok.HasAlt() {
			t.Fatalf("没填 Alt 的材料（%s）被判成带第二方向", dir)
		}
	}

	// Alt 的校验与主字段同一套标准。
	altOK := &uplink.GNSKeysMaterial{
		Key: key, IV: iv, Dir: "s2c",
		AltDir: "c2s", AltKey: key, AltIV: iv,
	}
	if !altOK.HasAlt() {
		t.Fatal("完整的 Alt 材料被判成无效")
	}
	for i, m := range []*uplink.GNSKeysMaterial{
		{Key: key, IV: iv, Dir: "s2c", AltDir: "c2s", AltKey: key[:40], AltIV: iv},
		{Key: key, IV: iv, Dir: "s2c", AltDir: "c2s", AltKey: key, AltIV: iv[:8]},
		{Key: key, IV: iv, Dir: "s2c", AltDir: "sideways", AltKey: key, AltIV: iv},
		{Key: key, IV: iv, Dir: "s2c", AltKey: key, AltIV: iv},
	} {
		if m.HasAlt() {
			t.Fatalf("第 %d 个残缺 Alt 被判成有效", i)
		}
	}
}

// TestFrameConnIDHist 钉住「材料到达那一刻缓冲区里是谁的流量」的统计。
//
// 09:07 那次现场 frames=1419 但只有 1 帧对得上，而 dump 出来的是清空后的
// 结果 —— 唯一的证据被销毁了，只能靠猜。这条统计在清空**之前**抓，保真。
func TestFrameConnIDHist(t *testing.T) {
	own := []byte{0xe8, 0x10, 0x4c, 0xbc}
	other := []byte{0xcc, 0x00, 0x04, 0x00}

	mk := func(connID []byte) []byte {
		f := []byte{0x80}
		f = append(f, connID...)
		f = append(f, 0x01, 0x00)
		return append(f, make([]byte, 40)...)
	}
	c2s := [][]byte{mk(own), mk(own), mk(other)}
	s2c := [][]byte{mk(other), mk(other), mk(other), []byte{0x01, 0x02, 0x03}}

	hist := frameConnIDHist(c2s, s2c)
	if hist["e8104cbc"] != 2 {
		t.Fatalf("本连接计数 = %d，期望 2", hist["e8104cbc"])
	}
	if hist["cc000400"] != 4 {
		t.Fatalf("外来流计数 = %d，期望 4", hist["cc000400"])
	}
	if hist["other"] != 1 {
		t.Fatalf("非 GNS 包计数 = %d，期望 1", hist["other"])
	}

	// 渲染出来必须是可读的、按次数降序。
	txt := histText(hist)
	if txt == "" {
		t.Fatal("histText 返回空串")
	}
	if got := histText(nil); got != "" {
		t.Fatalf("空直方图应渲染成空串，得到 %q", got)
	}
}
