package radarsrv

import (
	"errors"
	"sort"
)

// 本文件是 CS2 netmessage 的**位级**解析器。
//
// 🔴 2026-10-19 16:30 现场定案（硬规则 223）。
//
// 之前四轮「分帧假设全否」（硬规则 218/220）全是因为**分析对象错了**：
// 拿的是「多条可靠消息首尾相接」的流，再去找边界 —— 边界本来就有，
// 是 SNP 可靠消息自己的边界。
//
// 每条 SNP 可靠消息的载荷格式是：
//
//	[u8 0x01][varint tick][位打包的 netmessage 链]
//
// 位打包链里每条 netmessage 的头是 Source 的**位级**规则：
//
//	cmd  = ReadUBitVar()   —— 先读 6 位；若 (v&0x30)==0x10 再读 4 位拼高位，
//	                          0x20 再读 8 位，0x30 再读 28 位
//	size = ReadVarInt32()  —— 每次读 8 位，低 7 位数据、最高位续读，最多 5 组
//	body = size 个字节，**从当前位位置开始**（不字节对齐，必须逐位取）
//
// 现场验证（`gns-msgframed-20261019-163006.bin`，328 条消息）：
//   - 322/322 条（首字节 0x01）精确走完，尾部 <16 位对齐填充
//   - cmd 只出现 10 种：207×591、208×150、201×73、325×7、204×6、145×5、60×4、6×2、58×1、128×1
//   - body 抽出来当 protobuf 验，185/196 合法（含 `12 0b "cl_language"` 这类 convar）
//
// ⚠ 位序是 **LSB-first**：每个字节内从最低位开始。MSB-first 一组 0 命中。

// gnsMsgFlagReliable 是可靠消息载荷的首字节。
//
// 现场 328 条里 322 条是 0x01，其余 6 条是 0x03/0xa1/0xfc/0xb0 —— 那几条
// 是别的帧类型（不是 netmessage 链），本解析器直接跳过，不要硬解。
const gnsMsgFlagReliable = 0x01

// gnsMaxMsgsPerPayload 是单条载荷里最多解析几条 netmessage。
//
// 现场单条最多 13 条（991 字节那条）。给到 4096 是防跑飞：万一 size 读错，
// 循环会在 left() 耗尽时自然退出，这个上限只是兜底。
const gnsMaxMsgsPerPayload = 4096

// ErrGNSNotNetMsg 表示这条载荷不是 netmessage 链（首字节不是 0x01）。
var ErrGNSNotNetMsg = errors.New("gnsbitmsg: 载荷首字节不是 0x01，不是 netmessage 链")

// gnsNetMsg 是一条解出来的 netmessage。
type gnsNetMsg struct {
	// Cmd 是 ReadUBitVar 读出来的消息类型。
	Cmd uint32
	// Body 是 size 个字节，已按位抽取（可能不对齐字节边界）。
	Body []byte
	// HdrBits 是这条消息头占了多少位，排障用。
	HdrBits int
}

// gnsBitReader 是 LSB-first 位读取器。
type gnsBitReader struct {
	buf []byte
	pos int
	n   int
}

func newGNSBitReader(buf []byte, bitPos int) *gnsBitReader {
	return &gnsBitReader{buf: buf, pos: bitPos, n: len(buf) * 8}
}

func (r *gnsBitReader) left() int { return r.n - r.pos }

// read 读 k 位，返回低位在前的值。
func (r *gnsBitReader) read(k int) (uint32, bool) {
	if k == 0 {
		return 0, true
	}
	if k > 32 || r.pos+k > r.n {
		return 0, false
	}
	var v uint32
	for i := 0; i < k; i++ {
		p := r.pos + i
		bit := (r.buf[p>>3] >> uint(p&7)) & 1
		v |= uint32(bit) << uint(i)
	}
	r.pos += k
	return v, true
}

// readUBitVar 是 Source 的 ReadUBitVar。
//
// 注意它**不是**「2 位选择器」那个简化版。简化版会让 cmd 变成 1505/57580
// 这类垃圾值（硬规则 218 第 4 组就是这么失败的）。
func (r *gnsBitReader) readUBitVar() (uint32, bool) {
	v, ok := r.read(6)
	if !ok {
		return 0, false
	}
	switch v & 0x30 {
	case 0x10:
		e, ok := r.read(4)
		if !ok {
			return 0, false
		}
		return (v & 15) | (e << 4), true
	case 0x20:
		e, ok := r.read(8)
		if !ok {
			return 0, false
		}
		return (v & 15) | (e << 4), true
	case 0x30:
		e, ok := r.read(28)
		if !ok {
			return 0, false
		}
		return (v & 15) | (e << 4), true
	}
	return v, true
}

// readVarInt32 是 Source 的 ReadVarInt32：8 位一组，最高位续读。
func (r *gnsBitReader) readVarInt32() (uint32, bool) {
	var out uint32
	for cnt := 0; cnt < 5; cnt++ {
		b, ok := r.read(8)
		if !ok {
			return 0, false
		}
		out |= (b & 0x7F) << uint(7*cnt)
		if b&0x80 == 0 {
			return out, true
		}
	}
	return 0, false
}

// readBytes 按位取 n 个字节（不要求字节对齐）。
func (r *gnsBitReader) readBytes(n int) ([]byte, bool) {
	if n < 0 || r.pos+n*8 > r.n {
		return nil, false
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		v, ok := r.read(8)
		if !ok {
			return nil, false
		}
		out[i] = byte(v)
	}
	return out, true
}

// gnsParseNetMsgs 把一条 SNP 可靠消息的载荷拆成若干 netmessage。
//
// 返回值 tick 是载荷头里的那个 varint（现场 321/322 条是 0，剩下一条是 22834，
// 看起来是「带 tick 的完整快照」用一次，其余是增量）。目前只做日志，不参与解码。
func gnsParseNetMsgs(m []byte) (msgs []gnsNetMsg, tick uint32, err error) {
	data, decodedTick, e := gnsReliablePayload(m)
	tick = decodedTick
	if e != nil {
		return nil, 0, e
	}
	br := newGNSBitReader(data, 0)
	for br.left() > 8 && len(msgs) < gnsMaxMsgsPerPayload {
		start := br.pos
		cmd, ok := br.readUBitVar()
		if !ok {
			return nil, tick, errors.New("truncated reliable bit chain")
		}
		size, ok := br.readVarInt32()
		if !ok {
			return nil, tick, errors.New("truncated reliable bit chain")
		}
		hdr := br.pos - start
		if int(size) > br.left()/8 {
			// size 越界：说明这一条是错位读出来的，丢掉这一条并停。
			return nil, tick, errors.New("truncated reliable bit chain")
		}
		body, ok := br.readBytes(int(size))
		if !ok {
			return nil, tick, errors.New("truncated reliable bit chain")
		}
		msgs = append(msgs, gnsNetMsg{Cmd: cmd, Body: body, HdrBits: hdr})
	}
	if br.left() > 8 {
		return nil, tick, errors.New("reliable message count limit")
	}
	return msgs, tick, nil
}

// readGNSVarint 是字节对齐的 varint（用于载荷头的 tick）。
func readGNSVarint(b []byte) (uint32, int, bool) {
	var v uint32
	var shift uint
	for i := 0; i < len(b) && i < 5; i++ {
		c := b[i]
		if i == 4 && c > 15 {
			return 0, 0, false
		}
		v |= uint32(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

// gnsTopCmds 把 cmd 直方图按次数排序，取前 n 个，用于日志。
func gnsTopCmds(m map[uint32]int, n int) []struct {
	Cmd uint32
	N   int
} {
	out := make([]struct {
		Cmd uint32
		N   int
	}, 0, len(m))
	for k, v := range m {
		out = append(out, struct {
			Cmd uint32
			N   int
		}{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Cmd < out[j].Cmd
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// gnsTopCmdsByBytes 按「累计字节数」排序，用来找**大消息**。
//
// 🔴 为什么需要它：`gnsTopCmds` 按条数排，完美平台的 UI 消息（cmd=207）
// 条数最多，永远霸榜，而实体快照这类「条数少但每条几百到上千字节」的消息
// 会被挤到前十之外。现场 `[net] cmd 种类=19｜前10 207×141 ...` 就是这个样子，
// 于是「这局到底有没有实体消息」这个问题一直答不出来。
//
// 按字节排之后，`svc_PacketEntities` 一旦出现必然冲到第一（一条就上千字节），
// 一眼可见。日志里同时给条数和平均体长。
func gnsTopCmdsByBytes(cnt map[uint32]int, bytes map[uint32]int, n int) []struct {
	Cmd uint32
	N   int
	Avg int
} {
	out := make([]struct {
		Cmd uint32
		N   int
		Avg int
	}, 0, len(cnt))
	for k, v := range cnt {
		avg := 0
		if v > 0 {
			avg = bytes[k] / v
		}
		out = append(out, struct {
			Cmd uint32
			N   int
			Avg int
		}{k, v, avg})
	}
	sort.Slice(out, func(i, j int) bool {
		bi, bj := out[i].N*out[i].Avg, out[j].N*out[j].Avg
		if bi != bj {
			return bi > bj
		}
		return out[i].Cmd < out[j].Cmd
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
