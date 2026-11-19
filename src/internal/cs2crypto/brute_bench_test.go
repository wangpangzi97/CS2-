package cs2crypto

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// 目的：测「拿 32 字节候选当 AES-256-GCM key、试一帧能不能解开」的真实吞吐。
//
// 如果单核能到 300 万次/秒以上，那么 6 GB 内存按 8 字节对齐（7.5 亿个位置）
// 全扫一遍就是 250 秒单核 / 30 秒八核 —— 这条路才成立。
// 到不了就别浪费时间写，直接去逆向 netchan。
func BenchmarkGCMOpenPerKey(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	// 最短的真实帧：7 字节头 + 25 字节密文（其中 16 字节是 tag）
	frame := make([]byte, 32)
	if _, err := rand.Read(frame); err != nil {
		b.Fatal(err)
	}
	frame[0] = 0x82
	binary.LittleEndian.PutUint16(frame[5:7], 3)

	ct := frame[7:]
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], 3)

	buf := make([]byte, 32) // 候选密钥来源
	b.ResetTimer()
	b.SetBytes(1)
	n := 0
	for i := 0; i < b.N; i++ {
		// 模拟「每个字节位置换一把密钥」：扰动 1 个字节
		copy(buf, key)
		buf[0] = byte(i)
		g, err := newGCM(buf)
		if err != nil {
			continue
		}
		if _, err := g.Open(nil, nonce, ct, nil); err == nil {
			n++
		}
	}
	b.StopTimer()
	_ = n
}
