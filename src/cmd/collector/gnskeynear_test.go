package main

import (
	"testing"
	"time"
)

// farDeadline 给扫描函数一个不会到期的截止时间。
func farDeadline(t *testing.T) time.Time {
	t.Helper()
	return time.Now().Add(time.Minute)
}

// TestGNSMergeWindows 确认重叠/相邻区间会被合并，避免重复扫同一段内存。
func TestGNSMergeWindows(t *testing.T) {
	got := gnsMergeWindows([][2]uintptr{
		{0x2000, 0x4000},
		{0x1000, 0x3000},
		{0x9000, 0xa000},
	})
	want := [][2]uintptr{{0x1000, 0x4000}, {0x9000, 0xa000}}
	if len(got) != len(want) {
		t.Fatalf("合并后 %d 段，期望 %d：%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 段 = %v，期望 %v", i, got[i], want[i])
		}
	}
}

// TestGNSAnchorPointers 确认锚点来自四个槽位 + CCrypto + conn 自身，
// 且重复值被去掉、非法指针被丢弃。
func TestGNSAnchorPointers(t *testing.T) {
	raw := make([]byte, gnsConnSpan)
	putQ := func(off int, v uint64) {
		for i := 0; i < 8; i++ {
			raw[off+i] = byte(v >> (8 * i))
		}
	}
	putQ(gnsOffBlob0, 0x22f3bdfeaa0)
	putQ(gnsOffBlob1, 0x22f3bdfeaa0) // 与槽位 0 重复
	putQ(gnsOffBlob2, 0x22f3bdfebe0)
	putQ(gnsOffBlob3, 0x22f3bdfe940)
	putQ(gnsOffBlob2+8, 0) // 非法（0）应被丢弃

	c := gnsConn{
		Addr:   0x22e275eb050,
		Raw:    raw,
		CryptT: 0x22f3b3f81e0,
		CryptR: 0x22f3b3f8380,
	}
	got := gnsAnchorPointers(c)
	want := map[uintptr]bool{
		0x22f3bdfeaa0: true, 0x22f3bdfebe0: true, 0x22f3bdfe940: true,
		0x22f3b3f81e0: true, 0x22f3b3f8380: true, 0x22e275eb050: true,
	}
	if len(got) != len(want) {
		t.Fatalf("锚点 %d 个，期望 %d：%v", len(got), len(want), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("多出锚点 %#x", p)
		}
	}
}

// TestGNSScanBufForKeysFindsPlantedKey 是这条路的核心断言：
// 把一个真密钥埋进缓冲的某个偏移，扫描必须**在那个偏移**上找到它。
func TestGNSScanBufForKeysFindsPlantedKey(t *testing.T) {
	// 32 个近均匀字节（plausibleKey 会放行），不能用 bytes.Repeat。
	key := gnsTestBytes(7, 32)
	iv := []byte{0x07, 0xe2, 0x2c, 0x13, 0x91, 0x36, 0x3e, 0x57, 0x34, 0xc3, 0x16, 0xf0}
	connID := []byte{0x01, 0xcb, 0xfe, 0xd6}

	var frames [][]byte
	for i := 0; i < 4; i++ {
		frames = append(frames, sealGNSFrame(t, key, iv, connID, uint16(200+i),
			[]byte("entity snapshot payload")))
	}

	// 缓冲：前面塞一些干扰，密钥放在 0x123 处。
	const at = 0x123
	buf := make([]byte, 0x400)
	for i := range buf {
		buf[i] = 0
	}
	copy(buf[at:], key)
	base := uintptr(0x22f3bdf7000)

	tried := 0
	res, ok := gnsScanBufForKeys(buf, base, frames, iv, "c2s", farDeadline(t), &tried)
	if !ok {
		t.Fatalf("埋在 +%#x 的密钥没找到（试了 %d 个窗口）", at, tried)
	}
	if res.KeyAt != base+at {
		t.Fatalf("命中地址 %#x，期望 %#x", res.KeyAt, base+at)
	}
	if res.Dir != "c2s" || res.Frames < 3 {
		t.Fatalf("结果不对：dir=%s frames=%d", res.Dir, res.Frames)
	}
}

// TestGNSScanBufForKeysNoFalsePositive 反向断言：缓冲里没有真密钥时必须返回 false。
func TestGNSScanBufForKeysNoFalsePositive(t *testing.T) {
	key := gnsTestBytes(7, 32)
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	connID := []byte{1, 2, 3, 4}

	var frames [][]byte
	for i := 0; i < 4; i++ {
		frames = append(frames, sealGNSFrame(t, key, iv, connID, uint16(10+i),
			[]byte("payload")))
	}

	// 只放别的随机数据，不放真密钥。
	buf := make([]byte, 0x400)
	for i := range buf {
		buf[i] = 0
	}
	copy(buf[0x40:], gnsTestBytes(99, 32))

	tried := 0
	if _, ok := gnsScanBufForKeys(buf, 0x1000, frames, iv, "c2s", farDeadline(t), &tried); ok {
		t.Fatalf("缓冲里没有真密钥却报告命中（试了 %d 个窗口）", tried)
	}
}
