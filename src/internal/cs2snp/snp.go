// Package cs2snp 解 SteamNetworkingSockets(SNP) 的线格式。
//
// # 为什么需要这一层
//
// 2026-10-19 现场定案：CS2 的 game 连接走 Valve GameNetworkingSockets 直连 UDP。
// 一个 UDP 包的布局是（`dist/gns/steamnetworkingsockets_udp.h` 的 `UDPDataMsgHdr`）：
//
//	u8  m_unMsgFlags        0x80=加密；0x01=内联 protobuf 统计块；0x02=带 2 字节 time_since_prev
//	u32 m_unToConnectionID
//	u16 m_unSeqNum
//	[flags&0x01] varint 长度 + protobuf 统计块
//	[flags&0x02] u16 time_since_prev
//	→ 之后才是 AES-256-GCM 密文，末尾 16 字节 tag
//
// 所以 GCM 解密出来的**不是 netchan 消息**，而是 SNP 的「Data frame(s)」——
// 一串按首字节分型的帧。之前把这段明文直接喂 `cs2proto.ParseStream`，等于
// 把 SNP 帧头当成 cmd/size，`[dec]` 永远为 0 是必然的。
//
// # SNP 帧（首字节高位在左）
//
//	00emosss  不可靠消息段
//	          e=1 本段是该消息最后一段；m=编码 msg_num 宽度的方式；o=是否带偏移
//	          sss=7 表示"数据延续到包尾"，0..4 表示长度 =(sss<<8)|下一个字节
//	010mmsss  可靠流段   mm: 00=24位 01=32位 10=48位（首段绝对值）
//	                     同通道后续段则是相对上一段结尾的偏移：00=紧跟 01=+u8 10=+u16 11=+u32
//	100000ww  stop_waiting  ww: 00=+1 01=+2 10=+3 11=+8
//	1001wnnn  ack           w: 0=32位 1=16位 最新包号；nnn=块数(7=跟一字节)；
//	                        再跟 u16 delay；每块是**一个字节** `aaaannnn`，
//	                        高半字节=连续 ack 数、低半字节=连续 nack 数；
//	                        半字节 0..7 直接是值，1xxx 表示低 3 位有效、高位跟一个 varint
//	10001nnn  选通道        000-110 → 通道 = nnn+1；111 → 跟 varint
//
// 🔴 可靠段/不可靠段的「首段」判据是 **since start of packet or last lane change**，
// 也就是每包都要复位 —— 见 `Parser.beginPacket`。
//
// # 可靠流里的消息头
//
//	0mssssss [msg_num] [msg_size] data
//	m=1 → 跟一个 varint 增量；ssssss>=0x20 → 低 5 位是 size 低位，高位再跟一个 varint
//
// 把每条消息的 data 按流序拼起来，才是 CS2 的 netchan 字节流。
package cs2snp

// 帧类型判定用的位掩码常量，写成常量是为了让 Parse 里的分支一眼能对上文档。
const (
	frameUnreliableMask = 0xC0 // 高两位 00 → 不可靠
	frameReliableMask   = 0xC0 // 高两位 01 → 可靠
	frameReliableValue  = 0x40

	ackMask  = 0xF0
	ackValue = 0x90

	laneMask  = 0xF8
	laneValue = 0x88

	stopWaitMask  = 0xFC
	stopWaitValue = 0x80

	// sizeToEnd 是 sss 的特殊值：数据延续到包尾。
	sizeToEnd = 7
	// sizeMaxInline 是 sss 的上界：0..4 表示长度 =(sss<<8)|下一个字节，5/6 保留。
	sizeMaxInline = 4
)

// Segment 是一条可靠流段：流内绝对位置 + 字节。
type Segment struct {
	Pos  int64
	Data []byte
}

// UnrelMsg 是一条不可靠消息（e=1 表示整条到齐）。
type UnrelMsg struct {
	Lane   int
	Offset int64
	Num    int64
	Last   bool
	Data   []byte
}

// Stats 是一次 Parse 的计数，用来在日志里一眼看出"这包到底解出了什么"。
type Stats struct {
	StopWaiting int
	Acks        int
	Reliable    int
	Unreliable  int
	Lanes       int
	// Bad 非 0 表示遇到不认识的帧类型，BadType 是那个字节。
	// 出现它说明分帧已经跑偏，后面的内容全部不可信。
	Bad     int
	BadType byte
}

// Parser 按方向持有 SNP 分帧状态（通道号、上一段结尾位置、上一不可靠编号）。
//
// 必须每方向一个实例：通道与相对偏移都是**按方向**独立的。
type Parser struct {
	unSeq    map[int]int64
	lane     int
	lastRel  map[int]int64
	lastUn   map[int]int64
	firstRel map[int]bool
	firstUn  map[int]bool
}

// NewParser 建一个分帧器。
func NewParser() *Parser {
	return &Parser{
		unSeq: make(map[int]int64), lastRel: make(map[int]int64),
		lastUn:   make(map[int]int64),
		firstRel: make(map[int]bool),
		firstUn:  make(map[int]bool),
	}
}

// Reset 清空全部状态（换方向、换会话时用）。
func (p *Parser) Reset() {
	p.unSeq = make(map[int]int64)
	p.lane = 0
	p.lastRel = make(map[int]int64)
	p.lastUn = make(map[int]int64)
	p.firstRel = make(map[int]bool)
	p.firstUn = make(map[int]bool)
}

// beginPacket 复位"本包内"的状态。
//
// 线格式规定：可靠/不可靠段的位置字段只在 "first segment since start of packet
// or last lane change" 时是绝对值，之后才是相对值；lane 也在每包开始时归 0。
// 所以这些状态的生命周期是**一个包**，不是整个会话。
//
// 用 make 而不是 clear 是为了避免 map 复用带来的隐蔽残留（每包几次分配，
// 相比解密本身可以忽略）。
func (p *Parser) beginPacket() {
	p.lane = 0
	p.lastRel = make(map[int]int64)
	p.lastUn = make(map[int]int64)
	p.firstRel = make(map[int]bool)
	p.firstUn = make(map[int]bool)
}

// readVarint 读一个 protobuf 风格 varint（每字节 7 位，高位续）。
func readVarint(b []byte, i int) (int64, int, bool) {
	var v uint64
	var s uint
	for i < len(b) {
		c := b[i]
		i++
		v |= uint64(c&0x7f) << s
		if c&0x80 == 0 {
			if v > 1<<62 {
				return 0, i, false
			}
			return int64(v), i, true
		}
		s += 7
		if s > 63 {
			return 0, i, false
		}
	}
	return 0, i, false
}

// Parse 把一包解密后的明文切成 SNP 帧。
//
// 返回可靠流段与不可靠消息；stats 里记录各类帧的条数。遇到不认识的帧类型就
// 停下并置 Bad —— 继续硬解只会产出垃圾，不如让上层看到"跑偏了"。
//
// 🔴 **每次调用都必须把"首段"状态清干净。**
// `SNP_WIRE_FORMAT.md` 写的判据是 "First reliable segment **since start of packet**
// or last lane change" —— 也就是说 `mm` 只在**本包内**的第一次可靠段才表示绝对流位置，
// 每包都从头算，lane 也回到 0。
//
// 把它当成跨包状态是致命的：现场第 2 包起 48 位绝对位置会被当"相对上一段结尾"累加，
// 流位置直接飞到 37 万、坏帧率 64%、`netchan` 永远只有 332 字节。实测修正后
// 32 个明文包坏帧 0，可靠段 349375+335=349710 一路严丝合缝，空洞 0。
func (p *Parser) Parse(b []byte) (segs []Segment, unrels []UnrelMsg, st Stats) {
	if p.unSeq == nil {
		p.unSeq = make(map[int]int64)
	}
	p.beginPacket()
	i, n := 0, len(b)
	for i < n {
		t := b[i]
		i++
		switch {
		case t&frameUnreliableMask == 0x00: // 00emosss
			last := t&0x20 != 0
			m := t&0x10 != 0
			hasOff := t&0x08 != 0
			sss := int(t & 0x07)

			var num int64
			if !p.firstUn[p.lane] {
				w := 2
				if m {
					w = 4
				}
				if i+w > n {
					st.Bad, st.BadType = 1, t
					return
				}
				num = int64(readLE(b[i : i+w]))
				if ref, ok := p.unSeq[p.lane]; ok {
					span := int64(1) << uint(w*8)
					num = (ref & ^(span - 1)) | num
					if num-ref > span/2 {
						num -= span
					} else if ref-num > span/2 {
						num += span
					}
				}
				if old, ok := p.unSeq[p.lane]; !ok || num > old {
					p.unSeq[p.lane] = num
				}
				i += w
				p.firstUn[p.lane] = true
			} else if m {
				inc, ni, ok := readVarint(b, i)
				if !ok {
					st.Bad, st.BadType = 1, t
					return
				}
				i = ni
				num = p.lastUn[p.lane] + inc
			} else {
				num = p.lastUn[p.lane] + 1
			}
			p.lastUn[p.lane] = num

			var offset int64
			if hasOff {
				v, ni, ok := readVarint(b, i)
				if !ok {
					st.Bad, st.BadType = 1, t
					return
				}
				i = ni
				offset = v
			}

			sz, ok := frameSize(b, &i, n, sss)
			if !ok {
				st.Bad, st.BadType = 1, t
				return
			}
			unrels = append(unrels, UnrelMsg{Lane: p.lane, Offset: offset, Num: num, Last: last, Data: b[i : i+sz]})
			st.Unreliable++
			i += sz

		case t&frameReliableMask == frameReliableValue: // 010mmsss
			mm := int(t>>3) & 3
			sss := int(t & 0x07)

			var pos int64
			if !p.firstRel[p.lane] {
				w := [4]int{3, 4, 6, 0}[mm]
				if w == 0 || i+w > n {
					st.Bad, st.BadType = 1, t
					return
				}
				pos = int64(readLE(b[i : i+w]))
				i += w
				p.firstRel[p.lane] = true
			} else {
				base := p.lastRel[p.lane]
				switch mm {
				case 0:
					pos = base
				case 1:
					if i+1 > n {
						st.Bad, st.BadType = 1, t
						return
					}
					pos = base + int64(b[i])
					i++
				case 2:
					if i+2 > n {
						st.Bad, st.BadType = 1, t
						return
					}
					pos = base + int64(readLE(b[i:i+2]))
					i += 2
				default:
					if i+4 > n {
						st.Bad, st.BadType = 1, t
						return
					}
					pos = base + int64(readLE(b[i:i+4]))
					i += 4
				}
			}

			sz, ok := frameSize(b, &i, n, sss)
			if !ok {
				st.Bad, st.BadType = 1, t
				return
			}
			segs = append(segs, Segment{Pos: pos, Data: b[i : i+sz]})
			p.lastRel[p.lane] = pos + int64(sz)
			if p.firstUn[p.lane] {
				p.lastUn[p.lane]++
			}
			st.Reliable++
			i += sz

		case t&ackMask == ackValue: // 1001wnnn
			w := int(t>>3) & 1
			blocks := int(t & 7)
			if w == 1 {
				i += 2
			} else {
				i += 4
			}
			i += 2 // latest_received_delay
			if blocks == 7 {
				if i+1 > n {
					st.Bad, st.BadType = 1, t
					return
				}
				blocks = int(b[i])
				i++
			}
			for k := 0; k < blocks; k++ {
				// 每个块是 `aaaannnn [num_ack] [num_nack]`：**一个字节**，
				// 高半字节 = 连续 ack 的包数，低半字节 = 连续 nack 的包数。
				// 半字节 0000-0111 直接就是数值；1xxx 表示低 3 位是低位、高位再跟一个 varint。
				//
				// 旧实现按"两个游程各一字节，高位 0x80 才算 varint"解 —— 判据用错了位，
				// 而且结构也不对，现场 13/32 个包就是死在这里。
				if i >= n {
					st.Bad, st.BadType = 1, t
					return
				}
				b0 := b[i]
				i++
				for _, nib := range [2]byte{b0 >> 4, b0 & 0x0F} {
					if nib&0x08 == 0 {
						continue
					}
					_, ni, ok := readVarint(b, i)
					if !ok {
						st.Bad, st.BadType = 1, t
						return
					}
					i = ni
				}
			}
			if i > n {
				st.Bad, st.BadType = 1, t
				return
			}
			st.Acks++

		case t&laneMask == laneValue: // 10001nnn
			v := int(t & 7)
			if v == 7 {
				x, ni, ok := readVarint(b, i)
				if !ok {
					st.Bad, st.BadType = 1, t
					return
				}
				i = ni
				p.lane = int(x)
			} else {
				p.lane = v + 1
			}
			delete(p.firstRel, p.lane)
			delete(p.firstUn, p.lane)
			st.Lanes++

		case t&stopWaitMask == stopWaitValue: // 100000ww
			ww := int(t & 3)
			i += map[int]int{0: 1, 1: 2, 2: 3, 3: 8}[ww]
			if i > n {
				st.Bad, st.BadType = 1, t
				return
			}
			st.StopWaiting++

		default:
			st.Bad, st.BadType = 1, t
			return
		}
	}
	return
}

// frameSize 按 sss 规则算出数据长度。
func frameSize(b []byte, i *int, n, sss int) (int, bool) {
	if sss == sizeToEnd {
		return n - *i, true
	}
	if sss > sizeMaxInline {
		return 0, false
	}
	if *i+1 > n {
		return 0, false
	}
	sz := (sss << 8) | int(b[*i])
	*i = *i + 1
	if *i+sz > n {
		return 0, false
	}
	return sz, true
}

func readLE(b []byte) uint64 {
	var v uint64
	for k := len(b) - 1; k >= 0; k-- {
		v = v<<8 | uint64(b[k])
	}
	return v
}
