package cs2crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"math"
	"testing"

	"local/cs2-radar/internal/cs2proto"
)

func uv(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// mkPlain 造一条含 float32 坐标的 netmessage 流。
func mkPlain(tick int) []byte {
	payload := make([]byte, 0, 20)
	payload = append(payload, 0x0A, 12)
	var b [4]byte
	for _, v := range []float32{float32(tick) * 3.5, float32(tick) * -2.25, 128.5} {
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(v))
		payload = append(payload, b[:]...)
	}
	out := uv(5)
	out = append(out, uv(uint64(len(payload)))...)
	return append(out, payload...)
}

// TestSharedSecretSymmetry 验证 X25519 两边算出的共享密钥一致（这一步是确定的）。
func TestSharedSecretSymmetry(t *testing.T) {
	curve := ecdh.X25519()
	a, _ := curve.GenerateKey(rand.Reader)
	b, _ := curve.GenerateKey(rand.Reader)

	ab, err := SharedSecret(a.Bytes(), b.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	ba, err := SharedSecret(b.Bytes(), a.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(ab) != string(ba) {
		t.Fatalf("共享密钥不对称：%x vs %x", ab, ba)
	}
	if len(ab) != 32 {
		t.Fatalf("共享密钥应 32 字节，实际 %d", len(ab))
	}
}

func TestSharedSecretRejectsBadLength(t *testing.T) {
	if _, err := SharedSecret(make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("私钥长度不对必须报错")
	}
	if _, err := SharedSecret(make([]byte, 32), make([]byte, 33)); err == nil {
		t.Fatal("公钥长度不对必须报错")
	}
}

// newSession 造一个合成会话：返回 shared、serverPub、以及用 expect 方案加密的帧。
func newSession(t *testing.T, expect Candidate, frames int) (shared, serverPub []byte, encrypted [][]byte) {
	t.Helper()
	curve := ecdh.X25519()
	sPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPub = sPriv.PublicKey().Bytes()
	shared, err = SharedSecret(cPriv.Bytes(), serverPub)
	if err != nil {
		t.Fatal(err)
	}
	sch, err := BuildScheme(shared, serverPub, expect)
	if err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, expect.Offset)
	if _, err := rand.Read(prefix); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < frames; i++ {
		fr, err := sch.SealFrame(i, prefix, mkPlain(i))
		if err != nil {
			t.Fatal(err)
		}
		encrypted = append(encrypted, fr)
	}
	return
}

// TestProbeFindsCorrectScheme 是这套方案的核心验证：
// 在候选空间里放一个"真实方案"，Probe 必须自动把它挑出来。
func TestProbeFindsCorrectScheme(t *testing.T) {
	expect := Candidate{
		KDF: "hkdf-sha256/info-empty", Cipher: "aes-256-gcm",
		Nonce: "ctr-le-u64", Offset: 2,
	}
	shared, pub, frames := newSession(t, expect, 24)

	results := Probe(shared, pub, frames, 3)
	if len(results) == 0 {
		t.Fatal("Probe 没有返回任何结果")
	}
	top := results[0]
	t.Logf("Top-1: %+v  OKFrames=%d/%d Messages=%d", top.Candidate, top.OKFrames, top.Frames, top.Messages)
	t.Logf("Top-2: %+v  OKFrames=%d/%d", results[1].Candidate, results[1].OKFrames, results[1].Frames)

	if !top.OK {
		t.Fatalf("Top-1 未判定成立：%+v", top)
	}
	// Candidate 现在含 []byte（NoncePrefix），不能再直接比结构体。
	if top.KDF != expect.KDF || top.Cipher != expect.Cipher || top.Nonce != expect.Nonce ||
		top.Offset != expect.Offset || top.UseSaltPub != expect.UseSaltPub ||
		top.WireSeq != expect.WireSeq {
		t.Fatalf("Top-1 不是真实方案\n got  %+v\n want %+v", top.Candidate, expect)
	}
	if top.OKFrames != len(frames) {
		t.Fatalf("应全部帧可解，实际 %d/%d", top.OKFrames, len(frames))
	}
	if top.Messages < len(frames) {
		t.Fatalf("消息数应 >= 帧数，实际 %d", top.Messages)
	}
}

// 换一个 nonce 方案加密，Probe 应当挑出那个方案而不是别的。
func TestProbeDistinguishesNonceScheme(t *testing.T) {
	expect := Candidate{
		KDF: "raw", Cipher: "aes-256-gcm",
		Nonce: "ctr-be-u64", Offset: 0,
	}
	shared, pub, frames := newSession(t, expect, 16)
	results := Probe(shared, pub, frames, 1)
	if len(results) == 0 || !results[0].OK {
		t.Fatal("未找到成立方案")
	}
	if results[0].KDF != expect.KDF || results[0].Cipher != expect.Cipher ||
		results[0].Nonce != expect.Nonce || results[0].Offset != expect.Offset ||
		results[0].UseSaltPub != expect.UseSaltPub || results[0].WireSeq != expect.WireSeq {
		t.Fatalf("Top-1 应为 %+v，实际 %+v", expect, results[0].Candidate)
	}
}

// 用错误的私钥（共享密钥不对）时，不应有任何方案"成立"。
func TestProbeRejectsWrongKey(t *testing.T) {
	expect := Candidate{
		KDF: "hkdf-sha256/info-empty", Cipher: "aes-256-gcm",
		Nonce: "ctr-le-u64", Offset: 2,
	}
	shared, pub, frames := newSession(t, expect, 24)

	wrong := append([]byte(nil), shared...)
	wrong[0] ^= 0xFF

	results := Probe(wrong, pub, frames, 3)
	if len(results) == 0 {
		t.Fatal("Probe 没有返回结果")
	}
	if results[0].OK {
		t.Fatalf("密钥错误时不应有方案成立：%+v", results[0])
	}
	t.Logf("错误密钥下最高分：%+v OKFrames=%d/%d", results[0].Candidate, results[0].OKFrames, results[0].Frames)
}

// 解密后的明文必须能被 netmessage 解析器吃下去，并能扫出坐标。
func TestOpenFrameYieldsParseableAndCoords(t *testing.T) {
	expect := Candidate{
		KDF: "hkdf-sha256/info-cs2", Cipher: "aes-128-gcm",
		Nonce: "ctr-le-u32", Offset: 1,
	}
	shared, pub, frames := newSession(t, expect, 8)
	sch, err := BuildScheme(shared, pub, expect)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := sch.OpenFrame(3, frames[3])
	if err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	msgs, err := cs2proto.ParseStream(pt, cs2proto.MaxCmd)
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("应有 1 条消息，实际 %d", len(msgs))
	}
	coords := cs2proto.ScanFloat3(msgs[0].Data)
	if len(coords) == 0 {
		t.Fatal("未扫出坐标")
	}
	want := float32(3) * 3.5
	hit := false
	for _, c := range coords {
		if c.X == want {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("未扫到 x=%v，得到 %+v", want, coords)
	}
}
