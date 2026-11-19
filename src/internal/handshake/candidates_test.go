package handshake

import (
	"bytes"
	"testing"
)

// TestByteFieldCandidates 验证「穷举包里所有 32 字节字段」这条兜底路径。
//
// 它存在的理由：主字段路径是从 v2.0.5 逆向来的，版本一变或当初认错一层，
// 取到的就不是客户端公钥，内存里怎么搜都搜不到（用户现场正是如此）。
// 这个函数负责把包里**所有** 32 字节字段都挖出来，逐个去试。
func TestByteFieldCandidates(t *testing.T) {
	pub := bytes.Repeat([]byte{0xAB}, 32)
	other := bytes.Repeat([]byte{0x11}, 16)

	// 内层：f1(16 字节) + f2(32 字节)
	inner := []byte{0x0a, byte(len(other))}
	inner = append(inner, other...)
	inner = append(inner, 0x12, byte(len(pub)))
	inner = append(inner, pub...)

	// 两层 f4 包起来
	l2 := append([]byte{0x22, byte(len(inner))}, inner...)
	outer := append([]byte{0x22, byte(len(l2))}, l2...)

	got := ByteFieldCandidates(outer, 32)
	if len(got) != 1 {
		t.Fatalf("应只挖出 1 个 32 字节字段，实际 %d 个: %x", len(got), got)
	}
	if !bytes.Equal(got[0], pub) {
		t.Fatalf("挖出的字段不对:\n got=%x\nwant=%x", got[0], pub)
	}

	// 16 字节那层也要能挖到（说明递归确实走下去了）
	if g16 := ByteFieldCandidates(outer, 16); len(g16) != 1 || !bytes.Equal(g16[0], other) {
		t.Fatalf("16 字节字段没挖到: %x", g16)
	}

	// 不存在的长度 → 空
	if g := ByteFieldCandidates(outer, 24); len(g) != 0 {
		t.Fatalf("长度 24 不应有结果: %x", g)
	}

	// 重复字段要去重（同一个 32 字节出现两次只留一份）
	dup := append(append([]byte{}, outer...), 0x12, byte(len(pub)))
	dup = append(dup, pub...)
	if g := ByteFieldCandidates(dup, 32); len(g) != 1 {
		t.Fatalf("重复字段未去重，得到 %d 份", len(g))
	}

	// 畸形输入不能 panic
	for _, bad := range [][]byte{nil, {}, {0x22}, {0x22, 0xff}, {0xff, 0xff, 0xff}} {
		_ = ByteFieldCandidates(bad, 32)
	}
}
