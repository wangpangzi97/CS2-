package cs2snp

import "time"

// Stream 把可靠流段按「流内绝对位置」拼成连续字节流。
//
// SNP 的可靠段可以乱序、可以重叠、可以留空洞，所以不能"来一段拼一段"：
// 必须按位置放，并且只在**位置连续**时才能交出去。否则一旦某包丢了，
// 后面所有内容都会整体错位，解出来的东西看起来"有点像"却全是垃圾。
//
// 2026-10-19 现场实测：32 个明文包拼出 [21493, 52248) 共 30755 字节，
// 空洞 0 —— 说明分帧规则与位置语义都对得上。
type Stream struct {
	started bool
	next    int64            // 下一个"还没拿到"的位置
	pending map[int64][]byte // 位置 -> 数据（乱序/超前到达的）
	out     []byte           // 已连续但还没被上层取走的字节
	emitted int64            // 累计交出的字节数（仅统计）
	maxGap  int64            // 见过的最长空洞（仅统计）

	// blockSince 是「当前位置 next 被一个空洞卡住」的起始时刻。
	//
	// 🔴 2026-10-19 22:35 现场定案：这个字段是必须的。
	// 那一局 s2c 的 `流位置=149309 已出=149308` 从第 2 条统计起就**再也没变过**，
	// 而 `最大空洞` 一路从 101969 涨到 497159、`待补段` 从 201 涨到 1214 ——
	// 说明 149309 那个洞永远补不上，后面所有段全部堆在 pending 里等，
	// 整条 s2c 流（也就是雷达唯一的实体数据源）**整局作废**。
	// 一个包丢掉就废掉一局，这个代价不能接受，所以必须有强制跳过。
	blockSince time.Time
	skipped    int64 // 累计强制跳过的字节数（仅统计）
}

const (
	// holeMaxAge 是「一个洞最多等多久」。SNP 可靠段有重传，正常 1~2 个 RTT
	// （局域网几十毫秒，公网几百毫秒）就补上；等 5 秒还没来，基本可以断定
	// 那个包我们永远抓不到（抓包漏包，不是网络丢包 —— 网络层早重传过了）。
	holeMaxAge = 5 * time.Second
	// holeMaxPending 是「pending 里堆了多少段就认为流已经死了」。
	// 正常情况下 pending 只有个位数（乱序窗口）。上百条说明洞后面已经
	// 积了一大批，再等下去只会把内存和延迟一起拖垮。
	holeMaxPending = 512
)

// NewStream 建一个流拼接器。
func NewStream() *Stream {
	return &Stream{pending: make(map[int64][]byte)}
}

// Reset 清空。
func (s *Stream) Reset() {
	s.started = false
	s.next = 0
	s.pending = make(map[int64][]byte)
	s.out = nil
	s.emitted = 0
	s.maxGap = 0
	s.blockSince = time.Time{}
	s.skipped = 0
}

// Add 放入一段可靠流数据，并把能连上的部分追加到内部缓冲。
func (s *Stream) Add(pos int64, data []byte) {
	if len(data) == 0 {
		return
	}
	if !s.started {
		s.started = true
		s.next = pos
	}
	end := pos + int64(len(data))
	if end <= s.next {
		return // 完全是旧的（重传），丢掉
	}
	if pos < s.next {
		// 部分重叠：剪掉已经交出去的前半截。
		data = data[s.next-pos:]
		pos = s.next
	}
	if pos == s.next {
		s.out = append(s.out, data...)
		s.emitted += int64(len(data))
		s.next = pos + int64(len(data))
		s.drainPending()
		return
	}
	// 有空洞：先存着，等中间那截补上再连。
	// 记下最大空洞，日志里能一眼区分「抓包丢了包」和「解析器算错位置」。
	if g := pos - s.next; g > s.maxGap {
		s.maxGap = g
	}
	if s.blockSince.IsZero() {
		s.blockSince = time.Now()
	}
	if old, ok := s.pending[pos]; !ok || len(old) < len(data) {
		s.pending[pos] = data
	}
}

// SkipStale 在「空洞等太久或堆太多」时强行跳过，返回跳过的字节数和是否跳了。
//
// 跳过之后流位置会直接落到 pending 里最小的那个位置，**中间那段字节永远缺失**。
// 这必然导致消息边界错位，所以调用方必须同时 Reset 掉 MsgSplit，
// 让它从新位置重新按消息头同步（MsgSplit.Feed 有逐字节重同步的路径）。
//
// 权衡：不跳 = 整条流永久卡死（现场实测整局作废）；跳 = 丢一小段、可能混进
// 几条乱消息。后者显然好得多 —— 而且 `feedMsg` 会按「首字节 01 + 位级精确
// 吃满」把乱消息挡掉，不会画出幽灵目标。
func (s *Stream) SkipStale(now time.Time) (int64, bool) {
	if s.blockSince.IsZero() || len(s.pending) == 0 {
		s.blockSince = time.Time{}
		return 0, false
	}
	if now.Sub(s.blockSince) < holeMaxAge && len(s.pending) < holeMaxPending {
		return 0, false
	}
	var best int64 = -1
	for p := range s.pending {
		if p > s.next && (best < 0 || p < best) {
			best = p
		}
	}
	if best < 0 {
		s.blockSince = time.Time{}
		return 0, false
	}
	skipped := best - s.next
	s.next = best
	s.skipped += skipped
	s.blockSince = time.Time{}
	s.drainPending()
	return skipped, true
}

// Skipped 返回累计强制跳过的字节数。
func (s *Stream) Skipped() int64 { return s.skipped }

func (s *Stream) drainPending() {
	for {
		var best int64
		var data []byte
		found := false
		for p, d := range s.pending {
			if p+int64(len(d)) <= s.next {
				delete(s.pending, p)
				continue
			}
			if p <= s.next && (!found || p+int64(len(d)) > best+int64(len(data))) {
				best = p
				data = d
				found = true
			}
		}
		if !found {
			break
		}
		delete(s.pending, best)
		data = data[s.next-best:]
		s.out = append(s.out, data...)
		s.emitted += int64(len(data))
		s.next += int64(len(data))
	}
	if len(s.pending) == 0 {
		s.blockSince = time.Time{}
	}
}

// Take 取走当前可用的连续字节（取走后内部缓冲清空）。
func (s *Stream) Take() []byte {
	if len(s.out) == 0 {
		return nil
	}
	b := s.out
	s.out = nil
	return b
}

// Next 返回下一个待补的位置（0 表示还没开始）。
func (s *Stream) Next() int64 { return s.next }

// PendingSegs 返回还在等空洞的段数，用来判断"流是不是卡住了"。
func (s *Stream) PendingSegs() int { return len(s.pending) }

// Emitted 返回累计交出的可靠流字节数。
func (s *Stream) Emitted() int64 { return s.emitted }

// MaxGap 返回见过的最长空洞字节数。
//
// 用途是**区分两种完全不同的故障**：
//   - 空洞小且不再增长 → 只是抓包漏了几个包，重传会补上；
//   - 空洞大到几千字节 → 位置算错了（每包首段必须带绝对位置，见 Parser.beginPacket）。
func (s *Stream) MaxGap() int64 { return s.maxGap }

// MsgSplit 从可靠流里剥出「可靠消息」的数据部分。
//
// 可靠流里的消息头是：
//
//	0mssssss [msg_num] [msg_size] data
//
// m=1 时跟一个 varint 增量；ssssss>=0x20 时低 5 位是 size 低位，高位再跟一个 varint。
// 消息可以跨多个包、多个段，所以这里必须自己缓存不足的部分。
type MsgSplit struct {
	acc []byte
}

// NewMsgSplit 建一个消息切分器。
func NewMsgSplit() *MsgSplit { return &MsgSplit{} }

// Reset 清空。
func (m *MsgSplit) Reset() { m.acc = nil }

// maxReliableMessage bounds a declared message, not an incomplete network chunk.
// Signon messages can legitimately exceed 64 KiB (recorded: 170204 bytes).
const maxReliableMessage = 16 << 20
const maxReliableHeader = 21 // flag + two uint64 varints

// Feed keeps valid incomplete messages until their declared size is available.
// Arbitrarily large caller batches are consumed in bounded pieces.
func (m *MsgSplit) Feed(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		room := maxReliableMessage + maxReliableHeader - len(m.acc)
		if room <= 0 {
			m.acc = nil
			continue
		}
		take := len(b)
		if take > room {
			take = room
		}
		m.acc = append(m.acc, b[:take]...)
		b = b[take:]
		for len(m.acc) > 0 {
			data, used, ok, needMore := splitOne(m.acc)
			if needMore {
				break
			}
			if !ok {
				m.acc = m.acc[1:]
				continue
			}
			out = append(out, data)
			m.acc = m.acc[used:]
		}
	}
	return out
}

// Header varints distinguish incomplete data from terminal overflow.
func reliableVarint(b []byte, i int) (v uint64, next int, ok, needMore bool) {
	for k := 0; k < 10; k++ {
		if i >= len(b) {
			return 0, i, false, true
		}
		c := b[i]
		i++
		if k == 9 && c > 1 {
			return 0, i, false, false
		}
		v |= uint64(c&127) << uint(7*k)
		if c < 128 {
			return v, i, true, false
		}
	}
	return 0, i, false, false
}
func splitOne(b []byte) (data []byte, used int, ok, needMore bool) {
	if len(b) == 0 {
		return nil, 0, false, true
	}
	h := b[0]
	if h&0x80 != 0 {
		return nil, 0, false, false
	}
	i := 1
	if h&0x40 != 0 {
		_, next, valid, more := reliableVarint(b, i)
		if !valid {
			return nil, 0, false, more
		}
		i = next
	}
	size := uint64(h & 0x3f)
	if size >= 0x20 {
		hi, next, valid, more := reliableVarint(b, i)
		if !valid {
			return nil, 0, false, more
		}
		i = next
		if hi > uint64(maxReliableMessage>>5) {
			return nil, 0, false, false
		}
		size = (size & 0x1f) | (hi << 5)
	}
	if size == 0 || size > maxReliableMessage {
		return nil, 0, false, false
	}
	if uint64(len(b)-i) < size {
		return nil, 0, true, true
	}
	end := i + int(size)
	return b[i:end], end, true, false
}
