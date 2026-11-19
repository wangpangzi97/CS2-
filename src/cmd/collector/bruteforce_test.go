package main

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
)

// mkSealedFrames 按给定组合造一批**真实布局**的帧：
// [0x82][连接ID 4][包序号 2 小端][密文+tag]。
func mkSealedFrames(t *testing.T, key []byte, c skCombo, n int) [][]byte {
	t.Helper()
	connID := []byte{0xA9, 0xD2, 0x9F, 0xCC}
	frames := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		seq := uint64(300 + i) // 故意不从 0 起：证明用的是线上序号
		hdr := []byte{0x82, connID[0], connID[1], connID[2], connID[3],
			byte(seq), byte(seq >> 8)}
		if c.offset == 0 {
			// 「密文从 0 开始」的组合没有帧头，序号只能用下标。
			hdr = nil
			seq = uint64(i)
		}

		nonce := make([]byte, 12)
		switch c.nonce {
		case 1:
			copy(nonce[:4], connID)
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
			aad = hdr
		}
		ct := cs2crypto.SealWith(key, nonce, mkNetStream(i), aad)
		if ct == nil {
			t.Fatalf("SealWith 失败")
		}
		frames = append(frames, append(append([]byte(nil), hdr...), ct...))
	}
	return frames
}

// TestBuildTargetsNonceVariants 四种 nonce 构造都要能自洽地加解密。
func TestBuildTargetsNonceVariants(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	for _, c := range defaultCombos() {
		if c.keyLen != 32 {
			continue // 128 位密钥另测
		}
		frames := mkSealedFrames(t, key, c, 6)
		tg := buildTargets(frames, c)
		if len(tg) != len(frames) {
			t.Fatalf("%s：targets %d != frames %d", c.name, len(tg), len(frames))
		}
		if !cs2crypto.TryOpen(key, tg[0].nonce, tg[0].ct, tg[0].aad) {
			t.Fatalf("%s：正确密钥解不开第一帧（nonce/AAD 构造与加密端不一致）", c.name)
		}
		// 错一个字节必须解不开。
		bad := append([]byte(nil), key...)
		bad[5] ^= 0x01
		if cs2crypto.TryOpen(bad, tg[0].nonce, tg[0].ct, tg[0].aad) {
			t.Fatalf("%s：错密钥竟然解开了", c.name)
		}
	}
}

// TestScanBufFindsKey 密钥埋在缓冲区里，scanBuf 必须精确指出偏移。
func TestScanBufFindsKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	for _, c := range defaultCombos() {
		if c.keyLen != 32 {
			continue
		}
		frames := mkSealedFrames(t, key, c, 8)
		tg := buildTargets(frames, c)

		const wantOff = 3333
		buf := make([]byte, 8192)
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		copy(buf[wantOff:], key)

		got := scanBuf(buf, 32, tg)
		if got != wantOff {
			t.Fatalf("%s：偏移应为 %d，实际 %d", c.name, wantOff, got)
		}
	}
}

// TestScanBufRejectsNoise 缓冲区里没有密钥时必须返回 -1，不能误报。
func TestScanBufRejectsNoise(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c := defaultCombos()[0]
	frames := mkSealedFrames(t, key, c, 8)
	tg := buildTargets(frames, c)

	buf := make([]byte, 4096)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	if got := scanBuf(buf, 32, tg); got != -1 {
		t.Fatalf("不该命中，实际偏移 %d", got)
	}
}

// TestScanBufAADMismatch 用错 AAD 必须解不开 —— 这条是「AAD 猜错」的守门测试。
func TestScanBufAADMismatch(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealed := defaultCombos()[1] // off7 + aad=帧头
	frames := mkSealedFrames(t, key, sealed, 8)

	// 用「无 AAD」的组合去解「带 AAD」的帧：必须找不到。
	wrong := defaultCombos()[0]
	tg := buildTargets(frames, wrong)

	buf := make([]byte, 2048)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	copy(buf[512:], key)
	if got := scanBuf(buf, 32, tg); got != -1 {
		t.Fatalf("AAD 不匹配时不该命中，实际偏移 %d", got)
	}
}

// TestScanBufAES128 16 字节密钥也要能命中。
func TestScanBufAES128(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c := skCombo{"gcm128 off7 le64", "aes-128-gcm", 16, 7, 0, 0}
	frames := mkSealedFrames(t, key, c, 8)
	tg := buildTargets(frames, c)

	const wantOff = 777
	buf := make([]byte, 2048)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	copy(buf[wantOff:], key)
	if got := scanBuf(buf, 16, tg); got != wantOff {
		t.Fatalf("偏移应为 %d，实际 %d", wantOff, got)
	}
}

// TestLooksLikeKeyAcceptsRealKeys 真实随机密钥必须几乎全部通过预筛。
func TestLooksLikeKeyAcceptsRealKeys(t *testing.T) {
	const n = 20000
	pass := 0
	for i := 0; i < n; i++ {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			t.Fatal(err)
		}
		if looksLikeKey(k) {
			pass++
		}
	}
	// 理论漏筛率：零字节 >4 约 0.003%，不同值 <20 约 0.01% —— 合起来远小于 0.5%。
	if pass < n*995/1000 {
		t.Fatalf("预筛误杀太多：%d/%d 通过（应 ≥99.5%%）", pass, n)
	}
	t.Logf("真实密钥通过率 %d/%d = %.2f%%", pass, n, float64(pass)*100/n)
}

// TestLooksLikeKeyRejectsStructured 堆里常见的结构化数据必须被滤掉。
func TestLooksLikeKeyRejectsStructured(t *testing.T) {
	cases := map[string][]byte{
		"全零":     make([]byte, 32),
		"指针数组":   {0x70, 0xd9, 0xfe, 0xd5, 0x72, 0x01, 0, 0, 0x00, 0xc6, 0x6d, 0xb1, 0x72, 0x01, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x2f, 0, 0, 0, 0, 0, 0, 0},
		"ASCII":  []byte("hello world this is a plain text string"),
		"重复填充":  []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		"小整数序列": {1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0},
	}
	for name, b := range cases {
		if looksLikeKey(b) {
			t.Fatalf("%s 不该通过预筛", name)
		}
	}
}

// TestScanBufFilterDoesNotMiss 预筛开着时，密钥在缓冲区里仍然要能命中。
func TestScanBufFilterDoesNotMiss(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c := defaultCombos()[0]
	frames := mkSealedFrames(t, key, c, 8)
	tg := buildTargets(frames, c)

	const wantOff = 1021
	buf := make([]byte, 4096)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	copy(buf[wantOff:], key)

	if got := scanBufOpt(buf, 32, tg, true); got != wantOff {
		t.Fatalf("开预筛后偏移应为 %d，实际 %d", wantOff, got)
	}
	if got := scanBufOpt(buf, 32, tg, false); got != wantOff {
		t.Fatalf("关预筛后偏移应为 %d，实际 %d", wantOff, got)
	}
}

// heapLike 造一段「像真实堆」的数据：指针数组 + ASCII + 零填充 + 少量随机块。
func heapLike(n int) []byte {
	b := make([]byte, n)
	for i := 0; i+8 <= n; i += 8 {
		switch (i / 8) % 8 {
		case 0, 1, 2: // 指针
			b[i] = byte(randByte())
			b[i+1] = byte(randByte())
			b[i+2] = byte(randByte())
			b[i+3] = byte(randByte())
			b[i+4] = 0x72
			b[i+5] = 0x01
		case 3, 4: // 零
		default: // ASCII
			for j := 0; j < 8 && i+j < n; j++ {
				b[i+j] = 'a' + byte(j)
			}
		}
	}
	return b
}

var randPool [4096]byte
var randPos = len(randPool)

func randByte() byte {
	if randPos >= len(randPool) {
		if _, err := rand.Read(randPool[:]); err != nil {
			panic(err)
		}
		randPos = 0
	}
	c := randPool[randPos]
	randPos++
	return c
}

// mkSealedFramesB 是 mkSealedFrames 的 benchmark 版（不能用 *testing.T）。
func mkSealedFramesB(b *testing.B, key []byte, c skCombo, n int) [][]byte {
	b.Helper()
	connID := []byte{0xA9, 0xD2, 0x9F, 0xCC}
	frames := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		seq := uint64(300 + i)
		hdr := []byte{0x82, connID[0], connID[1], connID[2], connID[3],
			byte(seq), byte(seq >> 8)}
		if c.offset == 0 {
			hdr = nil
			seq = uint64(i)
		}
		nonce := make([]byte, 12)
		switch c.nonce {
		case 1:
			copy(nonce[:4], connID)
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
			aad = hdr
		}
		ct := cs2crypto.SealWith(key, nonce, mkNetStream(i), aad)
		frames = append(frames, append(append([]byte(nil), hdr...), ct...))
	}
	return frames
}

// BenchmarkScanBufFiltered 用「像真实堆」的数据测预筛版吞吐。
func BenchmarkScanBufFiltered(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	c := defaultCombos()[0]
	frames := mkSealedFramesB(b, key, c, 8)
	tg := buildTargets(frames, c)
	buf := heapLike(1 << 20)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanBufOpt(buf, 32, tg, true)
	}
}

// BenchmarkScanBufUnfiltered 同样数据但不预筛，用来量化预筛的收益。
func BenchmarkScanBufUnfiltered(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	c := defaultCombos()[0]
	frames := mkSealedFramesB(b, key, c, 8)
	tg := buildTargets(frames, c)
	buf := heapLike(1 << 20)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanBufOpt(buf, 32, tg, false)
	}
}

// TestFilterPassRate 量一下预筛的选择性：结构化数据要掉得够狠，
// 真实密钥要几乎全过。选择性直接决定暴力搜索要跑多久。
func TestFilterPassRate(t *testing.T) {
	// ① 像真实堆的数据
	buf := heapLike(1 << 20)
	pass := 0
	for i := 0; i+32 <= len(buf); i++ {
		if looksLikeKeyN(buf[i:], 32) {
			pass++
		}
	}
	rate := float64(pass) * 100 / float64(len(buf)-31)
	t.Logf("堆数据通过率：%d/%d = %.3f%%", pass, len(buf)-31, rate)
	// 3~5% 是可接受区间：再高就是白烧 CPU，再低就有误杀真实密钥的风险。
	if rate > 6 {
		t.Fatalf("预筛太弱：堆数据通过率 %.3f%%（应 ≤6%%）", rate)
	}

	// ② 真实随机密钥
	const n = 20000
	ok := 0
	for i := 0; i < n; i++ {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			t.Fatal(err)
		}
		if looksLikeKeyN(k, 32) {
			ok++
		}
	}
	t.Logf("真实密钥通过率：%d/%d = %.2f%%", ok, n, float64(ok)*100/n)
	if ok < n*995/1000 {
		t.Fatalf("预筛误杀太多：%.2f%%", float64(ok)*100/n)
	}
}
