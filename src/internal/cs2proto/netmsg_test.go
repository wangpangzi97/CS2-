package cs2proto

import (
	"encoding/binary"
	"math"
	mrand "math/rand"
	"testing"
	"time"
)

func uv(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func mkMsg(cmd uint64, payload []byte) []byte {
	out := uv(cmd)
	out = append(out, uv(uint64(len(payload)))...)
	return append(out, payload...)
}

func TestParseStreamRoundTrip(t *testing.T) {
	var stream []byte
	stream = append(stream, mkMsg(5, []byte("aaaa"))...)
	stream = append(stream, mkMsg(23, []byte("bb"))...)
	stream = append(stream, mkMsg(7, []byte("cccccc"))...)

	msgs, err := ParseStream(stream, MaxCmd)
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("应有 3 条消息，实际 %d", len(msgs))
	}
	if msgs[0].Cmd != 5 || string(msgs[0].Data) != "aaaa" {
		t.Fatalf("第 1 条不符: %+v", msgs[0])
	}
	if msgs[1].Cmd != 23 || string(msgs[1].Data) != "bb" {
		t.Fatalf("第 2 条不符: %+v", msgs[1])
	}
	if msgs[2].Cmd != 7 || string(msgs[2].Data) != "cccccc" {
		t.Fatalf("第 3 条不符: %+v", msgs[2])
	}
}

func TestParseStreamRejectsBadCmd(t *testing.T) {
	stream := mkMsg(9999, []byte("x"))
	if _, err := ParseStream(stream, MaxCmd); err == nil {
		t.Fatal("cmd 超范围必须报错")
	}
}

func TestParseStreamRejectsTruncated(t *testing.T) {
	stream := mkMsg(5, []byte("abcdef"))
	// 砍掉尾部，让 size 与剩余长度不自洽
	if _, err := ParseStream(stream[:len(stream)-2], MaxCmd); err == nil {
		t.Fatal("截断流必须报错")
	}
}

// 随机字节几乎不可能被切成完全自洽的消息流 —— 这正是 Probe 打分的基础。
//
// ⚠ 这个测试原来是「200 个样本、okCount > 2 就 FAIL」，实测**会偶发抖动**：
// 连跑 60 次得到 0/200 ×46、1/200 ×11、2/200 ×2，单样本误判率约 0.125%
// （Poisson λ = 0.25），P(X>2) ≈ 0.2%。一次全量回归里撞上一次就红，
// 而代码根本没问题 —— 这种"红灯"比不测还糟，会训练人忽略它。
//
// 现在改成两条：
//   - **固定种子**（不读 /dev/urandom），同一份代码永远得到同一个 okCount，
//     不存在"今天过明天挂"；
//   - 样本放大到 2000、阈值 15（0.75%），是实测 0.125% 的 6 倍余量。
//     真正的回归（比如把 ParseStream 的 size 上限放得太松）会让误判率涨
//     一个数量级，稳稳越过这条线。
func TestScoreRejectsRandom(t *testing.T) {
	const (
		samples = 2000
		limit   = 15 // 0.75%，实测基线 0.125%
	)
	rng := mrand.New(mrand.NewSource(0x5EED_2026))
	okCount := 0
	for i := 0; i < samples; i++ {
		b := make([]byte, 64)
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		if _, ok := Score(b, MaxCmd); ok {
			okCount++
		}
	}
	if okCount > limit {
		t.Fatalf("随机字节被判为合法流的次数过多：%d/%d（上限 %d，基线约 0.125%%）",
			okCount, samples, limit)
	}
	t.Logf("随机字节误判率 %d/%d = %.3f%%", okCount, samples,
		float64(okCount)*100/float64(samples))
}

func TestScanFloat3(t *testing.T) {
	var b [12]byte
	binary.LittleEndian.PutUint32(b[0:], math.Float32bits(1234.5))
	binary.LittleEndian.PutUint32(b[4:], math.Float32bits(-678.25))
	binary.LittleEndian.PutUint32(b[8:], math.Float32bits(64.0))
	payload := append([]byte{0x0A, 12}, b[:]...)

	got := ScanFloat3(payload)
	if len(got) == 0 {
		t.Fatal("应扫出至少一个坐标候选")
	}
	found := false
	for _, v := range got {
		if v.X == 1234.5 && v.Y == -678.25 && v.Z == 64 {
			found = true
		}
	}
	if !found {
		t.Fatalf("未扫到预埋坐标，得到 %+v", got)
	}
}

func TestScanFloat3RejectsGarbage(t *testing.T) {
	// 全 NaN / Inf / 超大值都不该被当成坐标
	payload := make([]byte, 36)
	for i := 0; i < 3; i++ {
		binary.LittleEndian.PutUint32(payload[i*12:], 0x7FC00000)   // NaN
		binary.LittleEndian.PutUint32(payload[i*12+4:], 0x7F800000) // +Inf
		binary.LittleEndian.PutUint32(payload[i*12+8:], 0xFFFFFF00) // 巨大负数
	}
	if got := ScanFloat3(payload); len(got) != 0 {
		t.Fatalf("垃圾浮点不该被当成坐标：%+v", got)
	}
}

// 启发式解码器应当把连续位置归到同一个槽位，而不是每帧新增一个目标。
func TestHeuristicDecoderTracksMovingTarget(t *testing.T) {
	d := NewHeuristicDecoder(8)
	for i := 0; i < 30; i++ {
		payload := make([]byte, 0, 20)
		payload = append(payload, 0x0A, 12)
		var b [4]byte
		for _, v := range []float32{float32(i) * 2.5, float32(i) * 1.5, 64.5} {
			binary.LittleEndian.PutUint32(b[:], math.Float32bits(v))
			payload = append(payload, b[:]...)
		}
		m := &Msg{Cmd: 5, Data: payload}
		if err := d.Feed(m, "s2c"); err != nil {
			t.Fatal(err)
		}
	}
	snap := d.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("移动中的单个目标应占 1 个槽位，实际 %d：%+v", len(snap), snap)
	}
	if snap[0].Pos.X != 29*2.5 {
		t.Fatalf("槽位应更新到最新位置，实际 x=%v", snap[0].Pos.X)
	}
}

// 回归：Snapshot 会压缩 slots 数组，槽位存活时间必须跟着槽位本身走。
//
// 曾经的实现把"最后可见时间"存在一张以槽位下标为键的旁路表里，压缩后下标错位：
// 还活着的槽位会拿到别的槽位的旧时间戳，被误判过期而删除，下一批坐标再重新建槽，
// 结果就是同一个实体在画面上变成两个点（远端实测出现过 4 个目标而真值只有 3 个）。
func TestSnapshotKeepsSlotAliveAfterCompaction(t *testing.T) {
	d := NewHeuristicDecoderWithTTL(8, 40*time.Millisecond)

	feed := func(x, y float32) {
		payload := make([]byte, 0, 20)
		payload = append(payload, 0x0A, 12)
		var b [4]byte
		for _, v := range []float32{x, y, 64.5} {
			binary.LittleEndian.PutUint32(b[:], math.Float32bits(v))
			payload = append(payload, b[:]...)
		}
		if err := d.Feed(&Msg{Cmd: 5, Data: payload}, "s2c"); err != nil {
			t.Fatal(err)
		}
	}

	feed(100, 100)   // 槽位 0：稍后过期
	feed(5000, 5000) // 槽位 1：持续更新
	time.Sleep(80 * time.Millisecond)
	feed(5000.5, 5000.5) // 只刷新槽位 1

	first := d.Snapshot() // 压缩：槽位 0 剔除，槽位 1 落到下标 0
	if len(first) != 1 {
		t.Fatalf("第一次 Snapshot 应只剩 1 个槽位，实际 %d：%+v", len(first), first)
	}
	second := d.Snapshot() // 回归点：压缩后槽位 1 仍应存活
	if len(second) != 1 {
		t.Fatalf("压缩后槽位被误删：第二次 Snapshot 得到 %d 个槽位（应 1）", len(second))
	}
	if second[0].Pos.X != 5000.5 {
		t.Fatalf("槽位位置应保持最新，实际 x=%v", second[0].Pos.X)
	}
}

// TestChainProbeSeparatesOffsetFromFormat 锁死 ChainProbe 的判别能力。
//
// 它存在的唯一目的是把两种失败分开：起点不在消息边界（能靠"从连接起点抓"自愈）
// vs 帧格式根本不对（必须改解析器）。判错了就会往完全错误的方向排查十几轮。
func TestChainProbeSeparatesOffsetFromFormat(t *testing.T) {
	// 3 条合法消息：cmd/size 都是单字节 varint。
	good := []byte{5, 3, 1, 2, 3, 6, 2, 9, 9, 7, 1, 0}

	// 前面塞 3 个垃圾字节，模拟"可靠流起点落在某条消息中间"。
	b := append([]byte{0xAA, 0xBB, 0xCC}, good...)
	zN, _, bN, bCov := ChainProbe(b, 100)
	if zN != 0 {
		t.Fatalf("从 0 起不该切出消息，实际 %d 条", zN)
	}
	if bN != 3 {
		t.Fatalf("全偏移最佳应有 3 条，实际 %d 条", bN)
	}
	if bCov != len(good) {
		t.Fatalf("全偏移最佳应覆盖 %d 字节，实际 %d", len(good), bCov)
	}

	// 纯随机字节：全偏移也扫不出链，说明格式不对。
	junk := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	jN, _, jBest, _ := ChainProbe(junk, 100)
	if jN != 0 || jBest != 0 {
		t.Fatalf("随机字节不该切出消息，实际 从0=%d 最佳=%d", jN, jBest)
	}
}
