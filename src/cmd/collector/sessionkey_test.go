package main

import (
	"bytes"
	"crypto/rand"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
)

// mkNetStream 造一段「看起来像 netmessage 流」的明文：
// 若干条 varint(cmd) + varint(size) + data。
func mkNetStream(tick int) []byte {
	var out []byte
	for i := 0; i < 3; i++ {
		payload := []byte{0x0A, 0x0C, byte(tick), byte(tick >> 8), byte(i), 0x7F, 0x80, 0x01}
		out = append(out, 5)               // cmd
		out = append(out, byte(len(payload))) // size
		out = append(out, payload...)
	}
	return out
}

// mkFrames 用 key 造 n 帧真实布局的密文：
// [0]=0x82 [1..4]=连接 ID [5..6]=线上包序号（小端） [7:]=AES-GCM 密文+tag。
func mkFrames(t *testing.T, key []byte, n int) [][]byte {
	t.Helper()
	cand := cs2crypto.Candidate{
		Cipher: "aes-256-gcm", Nonce: "ctr-le-u64", Offset: 7, WireSeq: true,
	}
	sch, err := cs2crypto.SchemeFromKey(key, cand)
	if err != nil {
		t.Fatalf("SchemeFromKey: %v", err)
	}
	frames := make([][]byte, n)
	for i := 0; i < n; i++ {
		seq := 300 + i // 故意不从 0 起，证明用的是线上序号
		hdr := []byte{0x82, 0x11, 0x22, 0x33, 0x44, byte(seq), byte(seq >> 8)}
		f, err := sch.SealFrame(seq, hdr, mkNetStream(i))
		if err != nil {
			t.Fatalf("SealFrame: %v", err)
		}
		frames[i] = f
	}
	return frames
}

// TestFindKeyInBufHits 密钥埋在缓冲区里，必须精确指出它的偏移和方案。
func TestFindKeyInBufHits(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	frames := mkFrames(t, key, 8)

	const wantOff = 1234
	buf := make([]byte, 4096)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	copy(buf[wantOff:], key)

	got, cand, off, ok := findKeyInBuf(buf, frames, false)
	if !ok {
		t.Fatal("应该在缓冲区里找到会话密钥，实际没找到")
	}
	if off != wantOff {
		t.Fatalf("偏移应为 %d，实际 %d", wantOff, off)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("密钥不匹配：%x != %x", got, key)
	}
	if cand.Offset != 7 || !cand.WireSeq || cand.Cipher != "aes-256-gcm" {
		t.Fatalf("方案不对：%+v", cand)
	}
}

// TestFindKeyInBufMisses 没有密钥时必须老老实实返回 false，
// 不能因为某个随机窗口"碰巧能解开"就误报。
func TestFindKeyInBufMisses(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	frames := mkFrames(t, key, 8)

	buf := make([]byte, 2048)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := findKeyInBuf(buf, frames, false); ok {
		t.Fatal("缓冲区里没有密钥，不该命中")
	}
}

// TestFindKeyInBufWide 密钥布局与默认假设不符时，放宽模式要能救回来。
func TestFindKeyInBufWide(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	// 故意用非默认布局：密文从第 5 字节起。
	cand := cs2crypto.Candidate{
		Cipher: "aes-256-gcm", Nonce: "ctr-be-u64", Offset: 5, WireSeq: false,
	}
	sch, err := cs2crypto.SchemeFromKey(key, cand)
	if err != nil {
		t.Fatal(err)
	}
	frames := make([][]byte, 8)
	for i := 0; i < 8; i++ {
		f, err := sch.SealFrame(i, []byte{0x82, 1, 2, 3, 4}, mkNetStream(i))
		if err != nil {
			t.Fatal(err)
		}
		frames[i] = f
	}

	const wantOff = 200
	buf := make([]byte, 1024)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	copy(buf[wantOff:], key)

	if _, _, _, ok := findKeyInBuf(buf, frames, false); ok {
		t.Fatal("默认布局不该命中（密文起点是 5 不是 7）")
	}
	_, gotCand, off, ok := findKeyInBuf(buf, frames, true)
	if !ok {
		t.Fatal("放宽布局后应该命中")
	}
	if off != wantOff || gotCand.Offset != 5 || gotCand.WireSeq {
		t.Fatalf("放宽模式结果不对：off=%d cand=%+v", off, gotCand)
	}
}

// TestDedupAnchors 挨在一起的锚点要合并，避免同一片内存被反复枚举。
func TestDedupAnchors(t *testing.T) {
	in := []uintptr{0x2000, 0x1000, 0x1010, 0x1018, 0x3000, 0x1040}
	got := dedupAnchors(append([]uintptr(nil), in...), 64)
	want := []uintptr{0x1000, 0x1040, 0x2000, 0x3000}
	if len(got) != len(want) {
		t.Fatalf("数量应为 %d，实际 %d（%x）", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个应为 %#x，实际 %#x", i, want[i], got[i])
		}
	}
}
