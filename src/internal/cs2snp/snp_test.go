package cs2snp

import (
	"bytes"
	"testing"
	"time"
)

// build 拼一个和现场字节布局完全一致的明文包。
//
// 现场依据（2026-10-19 12:19 的 gns-plain-*.json）：
//
//	帧 2  80 00 | 98 d8 00 74 00 | 57 | f5 53 00 00 00 00 | <1137B>
//	       ^stop  ^ack            ^可靠 48 位流位置 21493    ^"到包尾"
//	帧 25 80 10 | 98 da 00 9a 00 | 52 | 1c ba 00 00 00 00 | 99 | <665B>
//	                              ^可靠 48 位 47644          ^长度 512+153
//	      30 11 00 00 00 0a | <10B>   ^不可靠 32 位编号 17，长度 10
//	      41 4d | <333B>             ^可靠 相对紧跟，长度 256+77
//	      20 2d | <45B>              ^不可靠 相对 +1（编号 18），长度 45
//	      47 | <153B>                ^可靠 相对紧跟，"到包尾"
func build(parts ...any) []byte {
	var b []byte
	for _, p := range parts {
		switch v := p.(type) {
		case []byte:
			b = append(b, v...)
		case string:
			b = append(b, []byte(v)...)
		}
	}
	return b
}

func fill(n int, c byte) []byte { return bytes.Repeat([]byte{c}, n) }

func TestParseSingleReliableToEnd(t *testing.T) {
	p := NewParser()
	body := fill(1137, 0xAB)
	pkt := build(
		[]byte{0x80, 0x00},                         // stop_waiting ww=0, 偏移 0x00
		[]byte{0x98, 0xd8, 0x00, 0x74, 0x00},       // ack w=1 nnn=0, pkt=216, delay=116
		[]byte{0x57},                               // 可靠，mm=2(48位)，sss=7(到包尾)
		[]byte{0xf5, 0x53, 0x00, 0x00, 0x00, 0x00}, // 21493
		body,
	)
	segs, unrels, st := p.Parse(pkt)
	if st.Bad != 0 {
		t.Fatalf("不该有坏帧，BadType=0x%02x", st.BadType)
	}
	if st.StopWaiting != 1 || st.Acks != 1 || st.Reliable != 1 || st.Unreliable != 0 {
		t.Fatalf("计数不对: %+v", st)
	}
	if len(unrels) != 0 {
		t.Fatalf("不该有不可靠消息: %d", len(unrels))
	}
	if len(segs) != 1 {
		t.Fatalf("可靠段数 = %d", len(segs))
	}
	if segs[0].Pos != 21493 {
		t.Fatalf("流位置 = %d，应为 21493", segs[0].Pos)
	}
	if !bytes.Equal(segs[0].Data, body) {
		t.Fatalf("段数据长度 %d，应为 1137", len(segs[0].Data))
	}
}

func TestParseMixedPacketRelativeRules(t *testing.T) {
	p := NewParser()
	d665 := fill(665, 0x11)
	d333 := fill(333, 0x22)
	d10 := fill(10, 0x33)
	d45 := fill(45, 0x44)
	d153 := fill(153, 0x55)

	pkt := build(
		[]byte{0x80, 0x10},
		[]byte{0x98, 0xda, 0x00, 0x9a, 0x00},
		[]byte{0x52},
		[]byte{0x1c, 0xba, 0x00, 0x00, 0x00, 0x00}, // 47644
		[]byte{0x99},                               // 长度 512+153=665
		d665,
		[]byte{0x30, 0x11, 0x00, 0x00, 0x00, 0x0a}, // 不可靠 编号17 长度10
		d10,
		[]byte{0x41, 0x4d}, // 可靠 相对紧跟 长度 333
		d333,
		[]byte{0x20, 0x2d}, // 不可靠 相对 +1 长度 45
		d45,
		[]byte{0x47}, // 可靠 相对紧跟 到包尾
		d153,
	)
	if len(pkt) != 1232 {
		t.Fatalf("测试包长度 %d，应与现场一致 1232", len(pkt))
	}

	segs, unrels, st := p.Parse(pkt)
	if st.Bad != 0 {
		t.Fatalf("不该有坏帧，BadType=0x%02x", st.BadType)
	}
	if st.StopWaiting != 1 || st.Acks != 1 || st.Reliable != 3 || st.Unreliable != 2 {
		t.Fatalf("计数不对: %+v", st)
	}
	if len(segs) != 3 {
		t.Fatalf("可靠段数 = %d", len(segs))
	}
	want := []struct {
		pos int64
		n   int
	}{{47644, 665}, {48309, 333}, {48642, 153}}
	for i, w := range want {
		if segs[i].Pos != w.pos || len(segs[i].Data) != w.n {
			t.Fatalf("第 %d 段 = (%d,%d)，应为 (%d,%d)", i, segs[i].Pos, len(segs[i].Data), w.pos, w.n)
		}
	}
	if len(unrels) != 2 {
		t.Fatalf("不可靠消息数 = %d", len(unrels))
	}
	if unrels[0].Num != 17 || len(unrels[0].Data) != 10 || !unrels[0].Last {
		t.Fatalf("第一条不可靠消息 = %+v", unrels[0])
	}
	if unrels[1].Num != 19 || len(unrels[1].Data) != 45 {
		t.Fatalf("第二条不可靠消息编号应为 17+1（中间可靠段）+1=19，实际 %d", unrels[1].Num)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	p := NewParser()
	// 0x88 是"选通道"，紧跟的 varint 若被截断就必须报坏帧而不是硬编。
	_, _, st := p.Parse([]byte{0x8f, 0x80})
	if st.Bad == 0 {
		t.Fatal("截断的选通道帧应当报 Bad")
	}
}

func TestStreamHoldsUntilHoleFilled(t *testing.T) {
	s := NewStream()
	// 第一段定义流原点（现场第一包就是最低位置，这是成立的）。
	s.Add(80, []byte("aa"))
	if got := s.Take(); string(got) != "aa" {
		t.Fatalf("首段应直接交出，得到 %q", got)
	}
	// 82..84 是空洞，先到的 84 必须扣住，不能交出去。
	s.Add(84, []byte("cc"))
	if got := s.Take(); got != nil {
		t.Fatalf("有空洞时不该交出数据，得到 %q", got)
	}
	// 补上空洞后应当一次性吐出。
	s.Add(82, []byte("bb"))
	if got := s.Take(); string(got) != "bbcc" {
		t.Fatalf("补洞后应为 bbcc，得到 %q", got)
	}
	if s.Next() != 86 {
		t.Fatalf("next = %d，应为 86", s.Next())
	}
}

func TestStreamDropsRetransmit(t *testing.T) {
	s := NewStream()
	s.Add(10, []byte("hello"))
	s.Take()
	s.Add(10, []byte("hello")) // 重传同一段，不该重复追加
	if got := s.Take(); got != nil {
		t.Fatalf("重传段不该产生新字节，得到 %q", got)
	}
}

func TestMsgSplitAcrossFeeds(t *testing.T) {
	m := NewMsgSplit()
	// 0x6a: m=1（跟 varint 增量），ssssss=0x2a>=0x20 → 低 5 位 10，高位再跟 0x0a → size=10|(10<<5)=330
	hdr := []byte{0x6a, 0x02, 0x0a}
	body := fill(330, 0x7e)
	pkt := append(append([]byte{}, hdr...), body...)

	// 先喂一半，应当什么都出不来。
	if out := m.Feed(pkt[:100]); len(out) != 0 {
		t.Fatalf("不足一条时不该输出，得到 %d 条", len(out))
	}
	out := m.Feed(pkt[100:])
	if len(out) != 1 {
		t.Fatalf("应当凑齐 1 条，得到 %d 条", len(out))
	}
	if len(out[0]) != 330 || out[0][0] != 0x7e {
		t.Fatalf("消息体长度 %d", len(out[0]))
	}
}

func TestMsgSplitSmallInlineSize(t *testing.T) {
	m := NewMsgSplit()
	// 0x0b = m=0, ssssss=11 → 长度直接是 11
	pkt := append([]byte{0x0b}, fill(11, 0x01)...)
	out := m.Feed(pkt)
	if len(out) != 1 || len(out[0]) != 11 {
		t.Fatalf("小消息解析失败: %d 条", len(out))
	}
}

// TestAbsoluteStreamPosResetsPerPacket 锁死「首段判据按包复位」。
//
// 这是现场 64% 坏帧的根因：`SNP_WIRE_FORMAT.md` 写的是
// "First reliable segment **since start of packet** or last lane change"，
// 也就是 `mm` 的绝对/相对语义**每包重来**。当成跨包状态后，第 2 包起会把
// 48 位绝对流位置当"相对上一段结尾"累加 —— 现场表现就是流位置飞到 37 万、
// 可靠流空洞几百个、`netchan` 永远 332 字节。
func TestAbsoluteStreamPosResetsPerPacket(t *testing.T) {
	p := NewParser()
	mk := func(pos uint64, body byte) []byte {
		return build(
			[]byte{0x80, 0x00},
			[]byte{0x98, 0xd8, 0x00, 0x74, 0x00},
			[]byte{0x57}, // mm=2（48 位绝对）
			[]byte{byte(pos), byte(pos >> 8), byte(pos >> 16), byte(pos >> 24), byte(pos >> 32), byte(pos >> 40)},
			fill(64, body),
		)
	}

	s1, _, st1 := p.Parse(mk(349375, 0xAA))
	s2, _, st2 := p.Parse(mk(349710, 0xBB))
	if st1.Bad != 0 || st2.Bad != 0 {
		t.Fatalf("不该有坏帧: %+v %+v", st1, st2)
	}
	if s1[0].Pos != 349375 {
		t.Fatalf("第 1 包流位置 = %d，应为 349375", s1[0].Pos)
	}
	// 关键断言：第 2 包必须用它自己的绝对位置，而不是 349375+64+相对偏移。
	if s2[0].Pos != 349710 {
		t.Fatalf("第 2 包流位置 = %d，应为 349710（跨包状态没复位）", s2[0].Pos)
	}
}

// TestAckBlocksAreNibblePairs 锁死 ack 块的 `aaaannnn` 编码。
//
// 每块是**一个字节**：高半字节 = 连续 ack 的包数，低半字节 = 连续 nack 的包数；
// 半字节 0..7 直接是值，1xxx 表示低 3 位有效、高位再跟一个 varint。
// 旧实现按"两个游程各一字节、看 0x80 判 varint"解 —— 判据用错了位，
// 现场 13/32 个包死在这里（坏在 ack 之后紧接着的那个字节）。
func TestAckBlocksAreNibblePairs(t *testing.T) {
	// nnn=3 个块：
	//   0x12 -> ack 1, nack 2（都直接编码）
	//   0x83 -> ack 低 3 位 0，高位 varint 0x05 -> ack = 0 | (5<<3) = 40；nack 3
	//   0x0F -> ack 0, nack 低 3 位 7，高位 varint 0x02 -> nack = 7 | (2<<3) = 23
	pkt := build(
		[]byte{0x80, 0x00},
		[]byte{0x9b, 0x2a, 0x01, 0x10, 0x00}, // ack w=1 nnn=3, pkt=0x012a, delay=0x0010
		[]byte{0x12},
		[]byte{0x83, 0x05},
		[]byte{0x0F, 0x02},
		[]byte{0x57},
		[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, // 流位置 1
		fill(32, 0xCD),
	)
	p := NewParser()
	segs, _, st := p.Parse(pkt)
	if st.Bad != 0 {
		t.Fatalf("ack 块应能整段跳过，却在 0x%02x 报坏帧", st.BadType)
	}
	if st.Acks != 1 || len(segs) != 1 {
		t.Fatalf("计数不对: %+v segs=%d", st, len(segs))
	}
	if segs[0].Pos != 1 || len(segs[0].Data) != 32 {
		t.Fatalf("可靠段 = (%d,%d)，应为 (1,32)", segs[0].Pos, len(segs[0].Data))
	}
}

// TestStreamSkipStaleUnblocksDeadStream 锁死「一个包丢掉不能废掉整局」。
//
// 现场依据（2026-10-19 22:35 那局 s2c）：
//
//	流位置=149309 已出=149308   ← 从第 2 条统计起再没动过
//	最大空洞 101969 → 180394 → 260652 → 497159
//	待补段   201    → 406    → 612    → 1214
//
// 149309 那个洞永远补不上，后面所有段全堆在 pending 里，整条 s2c 流作废，
// 于是 `可靠消息=34` 之后再没有一条实体消息。
func TestStreamSkipStaleUnblocksDeadStream(t *testing.T) {
	s := NewStream()
	s.Add(1, []byte("signon"))
	if got := s.Take(); string(got) != "signon" {
		t.Fatalf("首段应直接交出，得到 %q", got)
	}
	// 7..1000 全丢，后面的段直接跳到 1000 往后。
	s.Add(1000, []byte("game"))
	s.Add(1004, []byte("data"))

	// 洞才刚开始等，不许跳。
	if n, ok := s.SkipStale(time.Now()); ok {
		t.Fatalf("刚形成的洞不该立刻跳过，跳了 %d 字节", n)
	}
	if got := s.Take(); got != nil {
		t.Fatalf("有洞时不该交出数据，得到 %q", got)
	}

	// 等够 holeMaxAge 之后必须跳，而且跳完要能继续出数据。
	n, ok := s.SkipStale(time.Now().Add(holeMaxAge + time.Second))
	if !ok {
		t.Fatal("洞等了超过 holeMaxAge 仍不跳过 —— 整条流会被永久锁死")
	}
	if n != 993 { // 1000 - 7
		t.Fatalf("跳过 %d 字节，应为 993", n)
	}
	if got := s.Take(); string(got) != "gamedata" {
		t.Fatalf("跳过后应吐出 gamedata，得到 %q", got)
	}
	if s.Next() != 1008 {
		t.Fatalf("next = %d，应为 1008", s.Next())
	}
	if s.Skipped() != 993 {
		t.Fatalf("Skipped() = %d，应为 993", s.Skipped())
	}
}

// TestStreamSkipStaleByPendingCount 锁死「pending 堆太多也算死」。
//
// 只看时间不够：一局里 s2c 每秒几十个段，512 个段堆满只要十几秒，
// 而 holeMaxAge 是 5 秒 —— 两个判据都得有，谁先到算谁。
func TestStreamSkipStaleByPendingCount(t *testing.T) {
	s := NewStream()
	s.Add(1, []byte("x"))
	s.Take()
	// 位置 2 的洞不补，往后堆超过 holeMaxPending 个段。
	for i := 0; i < holeMaxPending+8; i++ {
		s.Add(int64(1000+i*4), []byte("abcd"))
	}
	n, ok := s.SkipStale(time.Now()) // 时间还没到
	if !ok {
		t.Fatalf("pending=%d 超过上限 %d 仍不跳过", s.PendingSegs(), holeMaxPending)
	}
	// next 已经是 2（"x" 占位置 1），最小的 pending 是 1000 ⇒ 跳过 998 字节。
	if n != 998 {
		t.Fatalf("跳过 %d 字节，应为 998", n)
	}
	// 跳完应当把连续的 pending 一次性连起来交出去。
	got := s.Take()
	if len(got) != (holeMaxPending+8)*4 {
		t.Fatalf("跳过交出 %d 字节，应为 %d", len(got), (holeMaxPending+8)*4)
	}
}

// TestStreamSkipStaleNoopWhenHealthy 保证健康流永远不会被跳。
func TestStreamSkipStaleNoopWhenHealthy(t *testing.T) {
	s := NewStream()
	for i := int64(0); i < 50; i++ {
		s.Add(1+i*4, []byte("abcd"))
		s.Take()
	}
	if n, ok := s.SkipStale(time.Now().Add(time.Hour)); ok {
		t.Fatalf("没有空洞却跳了 %d 字节", n)
	}
}
