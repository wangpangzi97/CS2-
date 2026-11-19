package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
)

// sealGNSFrame 造一帧合法的 GNS 加密数据包（flags=0x80，无 stats、无 time_since_prev）。
//
// 造靶标而不是等真实抓包：判据逻辑（IV + 序号 → nonce、密文起点、GCM 认证）
// 必须能在离线被钉住，否则现场只会得到一句"0 帧可解"，看不出错在哪一层。
func sealGNSFrame(t *testing.T, key, iv, connID []byte, seq uint16, pt []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	nonce := cs2crypto.GNSIVForSeq(iv, uint64(seq))
	ct := g.Seal(nil, nonce, pt, nil)

	out := make([]byte, 0, 7+len(ct))
	out = append(out, 0x80)
	out = append(out, connID...)
	var s [2]byte
	binary.LittleEndian.PutUint16(s[:], seq)
	out = append(out, s[:]...)
	out = append(out, ct...)
	return out
}

// TestBuildTargetsFixedIVMatchesSealedFrames 确认「用内存里读到的基础 IV
// + 帧头序号」构造出的 nonce 能解开真实封装的帧。
//
// 这是整条旁路的核心：IV 一旦确定，剩下的就只有密钥了。
func TestBuildTargetsFixedIVMatchesSealedFrames(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	connID := []byte{0xe8, 0x10, 0x4c, 0xbc}

	var frames [][]byte
	for i := 0; i < 5; i++ {
		frames = append(frames, sealGNSFrame(t, key, iv, connID, uint16(94+i),
			[]byte("player position payload")))
	}

	tg := buildTargetsFixedIV(frames, iv)
	if len(tg) != len(frames) {
		t.Fatalf("判据数量 = %d，期望 %d", len(tg), len(frames))
	}
	if n := gnsTryKey(key, iv, frames, 3); n < 3 {
		t.Fatalf("正确密钥只解开 %d 帧", n)
	}
	// 密文起点必须是 7（flags=0x80 没有额外头部），否则 nonce 会错位。
	if len(tg[0].ct) != len(frames[0])-7 {
		t.Fatalf("密文长度 = %d，期望 %d", len(tg[0].ct), len(frames[0])-7)
	}
}

// TestGNSTryKeyRejectsWrongKeyAndIV 是上一条的反向断言。
//
// 没有反向断言的正向测试没有区分力：如果 gnsTryKey 永远返回 ≥3，
// 上一条也会通过，而现场就会一直"看起来成功"。
func TestGNSTryKeyRejectsWrongKeyAndIV(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	connID := []byte{0xe8, 0x10, 0x4c, 0xbc}

	var frames [][]byte
	for i := 0; i < 5; i++ {
		frames = append(frames, sealGNSFrame(t, key, iv, connID, uint16(i), []byte("hello")))
	}

	badKey := bytes.Repeat([]byte{0x11}, 32)
	badKey[31] ^= 0x01 // 只错一个比特
	if n := gnsTryKey(badKey, iv, frames, 3); n != 0 {
		t.Fatalf("错一个比特的密钥解开了 %d 帧", n)
	}

	badIV := append([]byte(nil), iv...)
	badIV[0] ^= 0x01
	if n := gnsTryKey(key, badIV, frames, 3); n != 0 {
		t.Fatalf("错的 IV 解开了 %d 帧", n)
	}

	// 长度不对必须直接判 0，不能 panic。
	if n := gnsTryKey(key[:31], iv, frames, 3); n != 0 {
		t.Fatalf("短密钥解开了 %d 帧", n)
	}
	if n := gnsTryKey(key, iv[:11], frames, 3); n != 0 {
		t.Fatalf("短 IV 解开了 %d 帧", n)
	}
}

// TestGNSConnNeedlesBothOrders 确认两种字节序都给了针。
//
// 内存里 [conn+0x180]/[conn+0x184] 谁是本地无法从源码断定，
// 只给一种顺序就可能永远扫不到。
func TestGNSConnNeedlesBothOrders(t *testing.T) {
	a := []byte{0xf0, 0xac, 0x95, 0x8d}
	b := []byte{0xbc, 0x4c, 0x10, 0xe8}
	ns := gnsConnNeedles(a, b)
	if len(ns) != 2 {
		t.Fatalf("针数量 = %d，期望 2", len(ns))
	}
	if !bytes.Equal(ns[0], append(append([]byte(nil), a...), b...)) {
		t.Fatalf("第一根针 = %x", ns[0])
	}
	if !bytes.Equal(ns[1], append(append([]byte(nil), b...), a...)) {
		t.Fatalf("第二根针 = %x", ns[1])
	}
	// 长度不对时不能造出半根针（否则会命中一堆无关位置）。
	if got := gnsConnNeedles(a, b[:3]); got != nil {
		t.Fatalf("长度不对仍返回了 %d 根针", len(got))
	}
}

// TestPlausibleIV 钉住「像随机 IV」的判据。
//
// 判据太松会把 protobuf 缓冲里的零填充当成连接对象；太紧会把真实的
// 基础 IV 判掉（末 4 字节可能是计数器初值，只有 1~2 个不同值）。
func TestPlausibleIV(t *testing.T) {
	good := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00},
	}
	for _, iv := range good {
		if !plausibleIV(iv) {
			t.Fatalf("真实 IV %x 被误判", iv)
		}
	}
	bad := [][]byte{
		make([]byte, 12),                // 全 0
		bytes.Repeat([]byte{0xff}, 12),  // 全 ff
		{1, 1, 2, 2, 1, 1, 2, 2, 1, 1, 2, 2}, // 只有 2 个不同值
		{1, 2, 3},                       // 长度不对
	}
	for _, iv := range bad {
		if plausibleIV(iv) {
			t.Fatalf("%x 被误判成真实 IV", iv)
		}
	}
}

// TestPlausiblePtr 钉住堆指针判据。
func TestPlausiblePtr(t *testing.T) {
	for _, v := range []uintptr{0x10000, 0x1f3a2b40000, 0x7ffffffffffe} {
		if !plausiblePtr(v) {
			t.Fatalf("%#x 被误判成非法指针", v)
		}
	}
	for _, v := range []uintptr{0, 0x1000, 0xffff, 0x800000000000} {
		if plausiblePtr(v) {
			t.Fatalf("%#x 被误判成合法指针", v)
		}
	}
}

// TestGNSLE64 确认小端读取。
func TestGNSLE64(t *testing.T) {
	b := []byte{0xbc, 0x4c, 0x10, 0xe8, 0x00, 0x00, 0x00, 0x00}
	if got := gnsLE64(b); got != 0xe8104cbc {
		t.Fatalf("gnsLE64 = %#x，期望 0xe8104cbc", got)
	}
	if got := gnsLE64(b[:4]); got != 0 {
		t.Fatalf("不足 8 字节应返回 0，得到 %#x", got)
	}
}

// TestBuildTargetsFixedIVSkipsNonGNS 确认非 GNS 帧不会混进判据。
//
// 现场缓冲区里绝大部分不是游戏流量，如果这些包混进判据，
// 「3 帧可解」就永远达不到，而日志上只会看到「0 帧」。
func TestBuildTargetsFixedIVSkipsNonGNS(t *testing.T) {
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	frames := [][]byte{
		{0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9},              // flags 没有 0x80
		{0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9},              // 保留位
		{0x80, 1, 2, 3, 4, 5, 6},                       // 太短
	}
	if tg := buildTargetsFixedIV(frames, iv); len(tg) != 0 {
		t.Fatalf("非 GNS 帧进了判据：%d 个", len(tg))
	}
	if tg := buildTargetsFixedIV(frames, iv[:11]); tg != nil {
		t.Fatalf("短 IV 应返回 nil")
	}
}

// TestGNSTryKeyWithAdvancedIV 钉住「内存里的 IV 已经随包前移」这种情况。
//
// 现场依据：FinishCryptoHandshake 里是 `add qword [rsi+0x19f0], rax`，就地
// 累加 —— 读到的 12 字节是**当前 nonce**，不是握手初值。如果 gnsTryKey 只按
// 「IV + 帧序号」算 nonce，那么密钥明明取对了也会全部认证失败，而日志上
// 只会写一句「0 帧可解」，完全看不出错在 nonce 上。
//
// 这里把「读到的 IV」造成为 base+最新序号，断言仍能解出 3 帧。
func TestGNSTryKeyWithAdvancedIV(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	base := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x01, 0x02, 0x03, 0x04}
	connID := []byte{0x11, 0x22, 0x33, 0x44}

	var frames [][]byte
	for i := 0; i < 4; i++ {
		frames = append(frames, sealGNSFrame(t, key, base, connID, uint16(700+i),
			[]byte("tick payload")))
	}
	// 内存里读到的是「最后一个包用过的 nonce」，也就是 base + 703。
	advanced := cs2crypto.GNSIVForSeq(base, 703)

	if n := gnsTryKey(key, advanced, frames, 3); n < 3 {
		t.Fatalf("IV 已前移时只解开 %d 帧（应为 3）", n)
	}
	// 反向：IV 前移但密钥错，必须一帧都解不开。
	badKey := bytes.Repeat([]byte{0x5b}, 32)
	if n := gnsTryKey(badKey, advanced, frames, 3); n != 0 {
		t.Fatalf("错误密钥解开了 %d 帧", n)
	}
}

// TestGNSNonceCandidatesCoverBothHypotheses 确认 nonce 候选集同时覆盖
// 「IV 是当前值」和「IV 是初值」两种假设，且不产生重复。
func TestGNSNonceCandidatesCoverBothHypotheses(t *testing.T) {
	iv := []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0}

	got := gnsNonceCandidates(iv, 100, 103)
	if len(got) == 0 {
		t.Fatal("候选集为空")
	}
	seen := map[string]bool{}
	for _, n := range got {
		if len(n) != 12 {
			t.Fatalf("nonce 长度 %d", len(n))
		}
		if seen[string(n)] {
			t.Fatal("候选集里有重复 nonce")
		}
		seen[string(n)] = true
	}

	// 假设 A：delta = 100-103 = -3，修正 0 → IV-3。
	neg3 := int64(-3) // 走变量，避免 uint64(常量负数) 在编译期溢出
	if !seen[string(cs2crypto.GNSIVForSeq(iv, uint64(neg3)))] {
		t.Fatal("缺少「IV 是当前值」的候选（delta 修正）")
	}
	// 假设 B：IV + 帧序号。
	if !seen[string(cs2crypto.GNSIVForSeq(iv, 100))] {
		t.Fatal("缺少「IV 是初值」的候选（IV + seq）")
	}
	// 序号回绕：帧序号远小于参照序号时应走负向。
	if c := gnsNonceCandidates(iv, 1, 65530); len(c) == 0 {
		t.Fatal("回绕场景没有候选")
	}
}

// TestPlausibleKey 钉住候选密钥预筛。
//
// 预筛只在 CCrypto 里逐字节开窗时用来省时间（4 KB 跨度 = 4000 多个窗口），
// 真正判定仍然交给 128 位 GCM 标签。所以它只需要挡掉「明显不是密钥」的，
// 绝不能把真密钥挡掉 —— 这条测试两个方向都要断言。
func TestPlausibleKey(t *testing.T) {
	// 真密钥形态：32 个近均匀随机字节，必须通过。
	real := []byte{
		0x3f, 0xa1, 0x07, 0x9c, 0xe2, 0x5b, 0x14, 0x8d,
		0x6a, 0xf0, 0x23, 0xb9, 0x48, 0xce, 0x71, 0x05,
		0xd6, 0x2f, 0x84, 0x1a, 0x9b, 0x37, 0xed, 0x60,
		0x0c, 0xb5, 0x92, 0x4e, 0xf7, 0x18, 0x6d, 0xc3,
	}
	if !plausibleKey(real) {
		t.Fatal("真密钥形态被预筛挡掉了")
	}

	// 全零、全 ff、ASCII、小整数数组 —— 都该挡掉。
	if plausibleKey(make([]byte, 32)) {
		t.Fatal("全零窗口不该通过")
	}
	ff := bytes.Repeat([]byte{0xff}, 32)
	if plausibleKey(ff) {
		t.Fatal("全 ff 窗口不该通过")
	}
	if plausibleKey([]byte("this_is_not_a_key_at_all_32bytes")) {
		t.Fatal("ASCII 窗口不该通过")
	}
	small := make([]byte, 32)
	for i := range small {
		small[i] = byte(i % 4)
	}
	if plausibleKey(small) {
		t.Fatal("小整数数组不该通过")
	}
	if plausibleKey(make([]byte, 31)) {
		t.Fatal("长度不对不该通过")
	}
}
