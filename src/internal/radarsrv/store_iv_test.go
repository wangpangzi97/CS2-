package radarsrv

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
)

// sealGNSFrameForTest 造一帧合法的 GNS 加密数据包（flags=0x82，头 7 字节）。
//
// 自己造靶标而不是等真实抓包：nonce 规则必须能在离线被钉住，否则现场
// 只会得到一句「0 帧可解」，看不出错在 KDF 还是错在 nonce。
func sealGNSFrameForTest(t *testing.T, key, base []byte, seq uint16, connID, pt []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	ct := g.Seal(nil, cs2crypto.GNSIVForSeq(base, uint64(seq)), pt, nil)

	out := make([]byte, 0, 7+len(ct))
	out = append(out, 0x82)
	out = append(out, connID...)
	var s [2]byte
	binary.LittleEndian.PutUint16(s[:], seq)
	out = append(out, s[:]...)
	return append(out, ct...)
}

// TestGNSIVTailMatch 钉住「IV 高 4 字节不随包前移」这条判据的基础。
//
// `add qword [rsi+0x19f0], rax` 只对低 8 字节做 64 位加法，所以无论累加
// 多少次，高 4 字节都不变。这条性质是「KDF 变体定标」的全部依据 ——
// 如果哪天有人把 IV 的构造改成整体重算，这个测试必须炸。
func TestGNSIVTailMatch(t *testing.T) {
	base := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xaa, 0xbb, 0xcc, 0xdd}

	// 加任意多个包，高 4 字节必须不变。
	for _, n := range []uint64{0, 1, 37, 1 << 16, 1 << 20} {
		adv := cs2crypto.GNSIVForSeq(base, n)
		if !cs2crypto.GNSIVTailMatch(base, adv) {
			t.Fatalf("前进 %d 个包后高 4 字节变了：%x vs %x",
				n, cs2crypto.GNSIVTail(base), cs2crypto.GNSIVTail(adv))
		}
	}

	// 高 4 字节不同就必须判不匹配，否则这个判据没有区分力。
	other := append([]byte(nil), base...)
	other[11] ^= 0x01
	if cs2crypto.GNSIVTailMatch(base, other) {
		t.Fatal("高 4 字节不同却判成匹配")
	}
	if cs2crypto.GNSIVTailMatch(base, base[:11]) {
		t.Fatal("长度不对却判成匹配")
	}
}

// TestTrySchemeWithMemoryIV 钉住「派生密钥 + 内存 IV」这个组合。
//
// 这是本轮的核心假设：KDF 给出密钥（IV 高 4 字节对上就说明 KDF 对了），
// 内存给出 nonce（它是「读的那一刻」的当前值）。两头都取确定的来源，
// 不去猜它们之间的差值。
//
// 注意 probe 的顺序：真实调用里 pick() 从尾部取，probe[0] 是最新一帧，
// 函数用它的序号当参照。所以这里也按「新 → 旧」构造。
func TestTrySchemeWithMemoryIV(t *testing.T) {
	key := bytes.Repeat([]byte{0x7c}, 32)
	base := []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0xde, 0xad, 0xbe, 0xef,
	}
	connID := []byte{0x01, 0x02, 0x03, 0x04}

	const newest = 405
	var frames [][]byte // 新 → 旧
	for i := 0; i < 6; i++ {
		seq := uint16(newest - i)
		frames = append(frames, sealGNSFrameForTest(t, key, base, seq, connID,
			[]byte("player state payload")))
	}

	// 内存里读到的 IV 是「最新那个包用过的 nonce」，也就是 base + 405。
	mem := cs2crypto.GNSIVForSeq(base, newest)

	keys := &cs2crypto.GNSKeys{SendKey: key, RecvKey: key, SendIV: base, RecvIV: base}
	sch, n := trySchemeWithMemoryIV(keys, "c2s", mem, mem, frames)
	if sch == nil || n < 3 {
		t.Fatalf("派生密钥 + 内存 IV 应该能解开，实际 n=%d", n)
	}

	// 反向断言：密钥错就必须一帧都解不开。没有这条，上面那条没有区分力。
	badKeys := &cs2crypto.GNSKeys{
		SendKey: bytes.Repeat([]byte{0x7d}, 32),
		RecvKey: bytes.Repeat([]byte{0x7d}, 32),
		SendIV:  base, RecvIV: base,
	}
	if sch, _ := trySchemeWithMemoryIV(badKeys, "c2s", mem, mem, frames); sch != nil {
		t.Fatal("错误密钥也解开了 —— 判据没有区分力")
	}

	// 内存 IV 差太远（超过最大修正量）时应当解不开，而不是瞎猜命中。
	far := cs2crypto.GNSIVForSeq(base, newest+100000)
	if sch, _ := trySchemeWithMemoryIV(keys, "c2s", far, far, frames); sch != nil {
		t.Fatal("内存 IV 偏差过大时不该命中")
	}
}
