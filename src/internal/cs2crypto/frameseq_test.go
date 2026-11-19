package cs2crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// 真实 netchan 帧头（2026-10-19 抓包，连续 4 帧）：
//
//	[0]      0x82 = 加密载荷
//	[1..4]   连接 ID
//	[5..6]   包序号，小端 uint16
//	[7..]    密文
//
// 序号逐包 +1 是**判据**：nonce 由它构造，用它才对得上 GCM 的 tag。
var realFrameHeads = []struct {
	hex string
	seq uint64
}{
	{"82a9d29fcc03006608f7cc3bd5e5707987484a16", 3},
	{"82a9d29fcc0400710fcb73409c056f22f1776581", 4},
	{"82a9d29fcc05006c03c40599315cdf5771b0673c", 5},
	{"82a9d29fcc0600000078c508b260cde75a1db3eb", 6},
}

// TestFrameSeqRealFrames 钉住「包序号在 [5..6]、小端」这个结论。
func TestFrameSeqRealFrames(t *testing.T) {
	prev := uint64(0)
	for i, c := range realFrameHeads {
		raw, err := hex.DecodeString(c.hex)
		if err != nil {
			t.Fatalf("hex: %v", err)
		}
		seq, ok := FrameSeq(raw)
		if !ok {
			t.Fatalf("第 %d 帧取不到序号", i)
		}
		if seq != c.seq {
			t.Fatalf("第 %d 帧序号 = %d，期望 %d（帧头 %x）", i, seq, c.seq, raw[:7])
		}
		if i > 0 && seq != prev+1 {
			t.Fatalf("第 %d 帧序号没有逐包 +1：%d → %d", i, prev, seq)
		}
		prev = seq
	}
}

// TestFrameSeqTooShort 短帧不能越界读。
func TestFrameSeqTooShort(t *testing.T) {
	for n := 0; n < 7; n++ {
		if _, ok := FrameSeq(make([]byte, n)); ok {
			t.Fatalf("%d 字节的帧不该取到序号", n)
		}
	}
}

// TestCandidateWireSeqSwitchesCounter 说明 WireSeq 开关真的改变 nonce。
//
// 这是"密钥挖到了但一条都解不开"的第二个原因：用缓冲区下标当计数器时，
// 只要漏过一帧，后面每个 nonce 都错，GCM 认证全部失败。
func TestCandidateWireSeqSwitchesCounter(t *testing.T) {
	frame, _ := hex.DecodeString(realFrameHeads[0].hex)
	on := Candidate{WireSeq: true}
	off := Candidate{WireSeq: false}

	if got := on.frameSeq(frame, 0); got != 3 {
		t.Fatalf("WireSeq=true 应取线上序号 3，实际 %d", got)
	}
	if got := off.frameSeq(frame, 0); got != 0 {
		t.Fatalf("WireSeq=false 应取下标 0，实际 %d", got)
	}
	if on.frameSeq(frame, 0) == off.frameSeq(frame, 0) {
		t.Fatal("两种模式必须给出不同的计数器，否则开关没有意义")
	}
}

// TestProbeFindsWireSeqScheme 合成一条**真实布局**的链路：
// 帧头 7 字节 + 密文，nonce 用线上序号（故意从 100 起，不从 0 起）。
// ProbeFrom 必须自己找出 WireSeq=true、Offset=7。
func TestProbeFindsWireSeqScheme(t *testing.T) {
	kdf, cipherName, nonceName := "raw", "aes-256-gcm", "ctr-le-u64"

	curve := ecdh.X25519()
	sPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPub := sPriv.PublicKey().Bytes()
	shared, err := SharedSecret(cPriv.Bytes(), serverPub)
	if err != nil {
		t.Fatal(err)
	}
	sch, err := BuildScheme(shared, serverPub, Candidate{
		KDF: kdf, Cipher: cipherName, Nonce: nonceName, Offset: 7,
	})
	if err != nil {
		t.Fatal(err)
	}

	const n = 24
	frames := make([][]byte, n)
	for i := 0; i < n; i++ {
		seq := 100 + i
		hdr := []byte{0x82, 0xAA, 0xBB, 0xCC, 0xDD, byte(seq), byte(seq >> 8)}
		nonce := sch.nonce.Build(nil, uint64(seq), sch.nonce.Size)
		ct, err := sch.cipher.Seal(sch.key, nonce, mkPlain(i))
		if err != nil {
			t.Fatal(err)
		}
		frames[i] = append(hdr, ct...)
	}

	results := ProbeFrom(shared, serverPub, frames, 0, 8)
	if len(results) == 0 || !results[0].OK {
		t.Fatalf("未找到成立方案（top=%+v）", results[0])
	}
	if !results[0].WireSeq {
		t.Fatalf("Top-1 应使用线上序号，实际 %+v", results[0].Candidate)
	}
	if results[0].Offset != 7 {
		t.Fatalf("Top-1 密文起点应为 7，实际 %d", results[0].Offset)
	}
}
