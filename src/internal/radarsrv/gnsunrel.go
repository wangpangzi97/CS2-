package radarsrv

// 不可靠通道（0x02）载荷的解码器。
//
// 2026-10-20 10:28 那局 5300 条样本定案（硬规则 283）：
//
//	[0x02][seq varint][tick varint][若干 0 字节][位打包 netmessage 链]
//
// 位链起点实测在 11（5192/5300 = 98.0%），其余在 12~15 —— 因为 seq/tick
// 都是变长 varint，头部长度会跟着变，**不能写死 11**，要扫。
//
// 🔴 判据是「起点唯一 + cmd 收敛」，不是「吃满率高」：
// 盲扫 protobuf 时 44/48/51/53/55 六个相邻起点都能吃满 67~71%，
// 那是随机命中（protobuf 容错性太高，任何位置都能凑出一条链）；
// 而位链只有 11 一个起点能到 98%，cmd 只有 7 种且集中在 4/55。
//
// 解出来的三条消息，protobuf 语义逐字段对上：
//
//	cmd=4    CNETMsg_Tick
//	          field1=tick field4=host_computationtime field5=...std_dev
//	          field8=host_framestarttime field10=expected_long_tick
//	          field11=expected_long_tick_reason（现场值 "WarmupPeriod"）
//	          field12/13=丢帧/跳帧百分比
//	cmd=55   CSVCMsg_PacketEntities
//	          field1=max_entries field2=updated_entries field3=is_delta
//	          field6=delta_from field7=entity_data
//	          ⇒ **这是雷达一直缺的实体表，而且比 cmd=208 密两个量级**
//	cmd=452  开火事件（CMsgTEFireBullets）
//	          field1=眼睛位置 field2=角度 field13=脚底位置（z 差 58.8~64.0）
//	          🔴 硬规则 290 附带纠正：它不是「本地玩家位置」。目前只统计不绘图。

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	gnsUnrelFlag = 0x02

	// 位链起点扫描范围。下限 9 是「1+1+2+... 最短头」的保守估计，
	// 上限 20 覆盖 seq/tick 都是多字节 varint 的情况。
	gnsUnrelMinStart = 9
	gnsUnrelMaxStart = 20
	gnsUnrelMaxMsgs  = 512

	// cmd 上限。真 cmd 都是小值（现场最大 452）；
	// 起点错位时会读出 40 亿这种垃圾值，用它一刀切掉。
	gnsUnrelMaxCmd = 4096

	gnsUnrelCmdTick       = 4   // net_Tick
	gnsUnrelCmdPacketEnts = 55  // svc_PacketEntities
	gnsUnrelCmdPos        = 452 // 开火事件（原以为是本地玩家位置）
)

// gnsUnrelMsg 是位链里的一条 netmessage。
type gnsUnrelMsg struct {
	Cmd  uint32
	Body []byte
}

// gnsUnrelDecoded 是一条不可靠载荷的解码结果。
type gnsUnrelDecoded struct {
	Start    int    // 位链起点（字节偏移）
	Seq      uint32 // 头部的消息序号
	Tick     uint32 // 头部的服务器 tick
	Msgs     []gnsUnrelMsg
	LeftBits int // 解完链后剩下的位数
}

// gnsPacketEnts 是 CSVCMsg_PacketEntities 里雷达关心的字段。
type gnsPacketEnts struct {
	MaxEntries     uint32
	UpdatedEntries uint32
	IsDelta        bool
	DeltaFrom      uint32
	EntityDataLen  int
	EntityData     []byte
}

// gnsUnrelPos 是 cmd=452 里的本地玩家位置。
type gnsUnrelPos struct {
	Has     bool // 至少读到 field1
	Eye     [3]float32
	Angle   [3]float32
	Feet    [3]float32
	HasFeet bool
}

// gnsParseUnrelChain 从 startBit 开始按 `[cmd][size][body]` 走到底。
//
// 与可靠通道的 gnsParseNetMsgs 同一套位规则（ReadUBitVar + ReadVarInt32），
// 区别只是没有 0x01 标志位检查 —— 起点由调用方扫出来。
func gnsParseUnrelChain(m []byte, startBit int) (msgs []gnsUnrelMsg, leftBits int, ok bool) {
	if startBit < 0 || startBit >= len(m)*8 {
		return nil, 0, false
	}
	br := newGNSBitReader(m, startBit)
	for br.left() > 8 && len(msgs) < gnsUnrelMaxMsgs {
		cmd, okc := br.readUBitVar()
		if !okc {
			return nil, 0, false
		}
		// 垃圾 cmd 说明起点错位了，直接判负 —— 这是区分真假起点最有效的一刀。
		if cmd >= gnsUnrelMaxCmd {
			return nil, 0, false
		}
		size, oks := br.readVarInt32()
		if !oks {
			return nil, 0, false
		}
		if int(size) > br.left()/8 {
			return nil, 0, false
		}
		body, okb := br.readBytes(int(size))
		if !okb {
			return nil, 0, false
		}
		msgs = append(msgs, gnsUnrelMsg{Cmd: cmd, Body: body})
	}
	if len(msgs) == 0 {
		return nil, 0, false
	}
	return msgs, br.left(), true
}

// gnsDecodeUnrel 解一条不可靠载荷。
//
// 返回 nil 表示「不是 0x02」或「头部 varint 都读不出来」。
// 位链一个起点都试不出来时也返回 nil —— 调用方据此统计失败率。
func gnsDecodeUnrel(m []byte) *gnsUnrelDecoded {
	d, _ := gnsDecodeUnrelReason(m)
	return d

}

// Fixed diagnostic reasons. Equal scores are ambiguous only if they describe
// different messages; byte-identical chains separated by empty NOPs are one
// semantic candidate, not a reason to discard a required entity checkpoint.
func gnsDecodeUnrelReason(m []byte) (*gnsUnrelDecoded, uint8) {
	if len(m) < 12 {
		return nil, 1
	}
	if m[0] != gnsUnrelFlag && m[0] != 0x04 {
		return nil, 2
	}
	seq, n1, ok1 := readGNSVarint(m[1:])
	if !ok1 || n1 == 0 {
		return nil, 3
	}
	tick, _, ok2 := readGNSVarint(m[1+n1:])
	if !ok2 {
		return nil, 4
	}

	var best *gnsUnrelDecoded
	bestScore := -1
	ambiguous := false
	for start := gnsUnrelMinStart; start <= gnsUnrelMaxStart && start < len(m); start++ {
		data, bitStart := m, start*8
		// 0x04 is the compressed counterpart of 0x02. The preserved
		// header is followed by decoded-size varint + an LZ4 block.
		if m[0] == 0x04 {
			want, n, ok := readGNSVarint(m[start:])
			if !ok || want == 0 || want > gnsDecodedLimit {
				continue
			}
			var err error
			data, err = gnsLZ4Block(m[start+n:], int(want))
			if err != nil {
				continue
			}
			bitStart = 0
		}
		msgs, left, ok := gnsParseUnrelChain(data, bitStart)
		if !ok || left > 8 {
			continue
		}
		score, valid := gnsUnrelCandidateScore(msgs)
		if !valid {
			continue
		}
		if score > bestScore {
			bestScore = score
			ambiguous = false
			best = &gnsUnrelDecoded{Start: start, Seq: seq, Tick: tick, Msgs: msgs, LeftBits: left}
		} else if score == bestScore && (left != best.LeftBits || !gnsUnrelEquivalentMessages(best.Msgs, msgs)) {
			ambiguous = true
		}
	}
	if ambiguous {
		return nil, 6
	}
	if best == nil {
		return nil, 5
	}
	return best, 0
}

// gnsUnrelPB 走一遍 protobuf，把每个字段交给 fn。
//
// wire 0 给 v（varint 值），wire 1 给 8 字节，wire 2 给 data，wire 5 给 4 字节。
// 解析不下去就停 —— 这里只做取值，不做合法性判断。
func gnsUnrelPB(b []byte, fn func(field, wire int, v uint64, data []byte)) {
	i := 0
	for i < len(b) {
		tag, n, ok := readGNSVarint(b[i:])
		if !ok || n == 0 || tag == 0 {
			return
		}
		i += n
		field, wire := int(tag>>3), int(tag&7)
		if field == 0 {
			return
		}
		switch wire {
		case 0:
			v, n2, ok2 := readGNSVarint(b[i:])
			if !ok2 {
				return
			}
			i += n2
			fn(field, wire, uint64(v), nil)
		case 1:
			if i+8 > len(b) {
				return
			}
			fn(field, wire, 0, b[i:i+8])
			i += 8
		case 2:
			ln, n2, ok2 := readGNSVarint(b[i:])
			if !ok2 {
				return
			}
			i += n2
			if int(ln) > len(b)-i {
				return
			}
			fn(field, wire, 0, b[i:i+int(ln)])
			i += int(ln)
		case 5:
			if i+4 > len(b) {
				return
			}
			fn(field, wire, 0, b[i:i+4])
			i += 4
		default:
			return
		}
	}
}

// gnsDecodePacketEnts 解 CSVCMsg_PacketEntities 的头部字段。
//
// entity_data（field7）是**位打包 delta**，现场 159 万个字节对齐位置里
// 只有 0.04% 像坐标（随机水平），所以不是 float 数组，得单独写 delta 解码器。
// 这里只把边界和长度拿出来，供日志和下一轮用。
func gnsDecodePacketEnts(b []byte) *gnsPacketEnts {
	out := &gnsPacketEnts{}
	gnsUnrelPB(b, func(field, wire int, v uint64, data []byte) {
		switch {
		case field == 1 && wire == 0:
			out.MaxEntries = uint32(v)
		case field == 2 && wire == 0:
			out.UpdatedEntries = uint32(v)
		case field == 3 && wire == 0:
			out.IsDelta = v != 0
		case field == 6 && wire == 0:
			out.DeltaFrom = uint32(v)
		case field == 7 && wire == 2:
			out.EntityDataLen = len(data)
			out.EntityData = data
		}
	})
	return out
}

// gnsDecodeUnrelPos 解 cmd=452 的**开火事件**（眼睛/角度/脚底三元组）。
//
// 🔴 硬规则 290 附带纠正：452 不是「本地玩家位置」，公开定义是开火事件
// （CMsgTEFireBullets，含开火原点、角度、玩家 handle、实体原点）。
// 它目前只做统计、不进画面，优先级低于 208。
//
// body 形状：`field1 = CMsgVector(x,y,z)` + `field2 = CMsgQAngle(x,y,z)`
// + `field13 = CMsgVector`（脚底，比眼睛低约 64 单位）。
func gnsDecodeUnrelPos(b []byte) *gnsUnrelPos {
	out := &gnsUnrelPos{}
	gnsUnrelPB(b, func(field, wire int, v uint64, data []byte) {
		if wire != 2 || len(data) < 13 {
			return
		}
		var f [3]float32
		cnt := 0
		gnsUnrelPB(data, func(f2, w2 int, _ uint64, d2 []byte) {
			if w2 == 5 && len(d2) == 4 && f2 >= 1 && f2 <= 3 {
				f[f2-1] = math.Float32frombits(binary.LittleEndian.Uint32(d2))
				cnt++
			}
		})
		if cnt < 3 {
			return
		}
		switch field {
		case 1:
			out.Eye = f
			out.Has = true
		case 2:
			out.Angle = f
		case 13:
			out.Feet = f
			out.HasFeet = true
		}
	})
	return out
}

// gnsUnrelPosSane 判断这组坐标像不像 CS2 世界坐标。
//
// 🔴 不能用「z 在 1200~2100」这种绝对范围（硬规则 285）。
// 10:28 局 `z=1678`、10:52 局 `z=95` —— **换地图了，绝对值全变**。
// 那条硬编码的范围让 10:52 局 26 条坐标**全部**被判定不合理。
//
// 唯一跨地图稳定的是**眼睛与脚底的差**：现场 64.0 / 63.6，
// 正好是 CS2 玩家身高（约 64 单位）。这才是该用的判据。
func gnsUnrelPosSane(p *gnsUnrelPos) bool {
	if p == nil || !p.Has {
		return false
	}
	for _, v := range p.Eye {
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 20000 {
			return false
		}
	}
	if !p.HasFeet {
		// 没有 field13 就没法用差判据，退化成「三个值都是有限的小数」。
		return true
	}
	d := math.Abs(float64(p.Eye[2] - p.Feet[2]))
	return d > 40 && d < 90
}

// gnsUnrelStats 是不可靠通道的解码统计（会话级累计）。
type gnsUnrelStats struct {
	CompressedSeen    int
	CompressedDecoded int
	Seen              int // 收到的 0x02 载荷数
	Decoded           int // 位链解出来的条数
	// StartHist 是位链起点分布。现场 98% 集中在 11，剩下一百多条在 12~15。
	// 🔴 这个分布是「头部长度可变」的直接证据，不要写死 11。
	StartHist map[int]int
	CmdHist   map[uint32]int

	// PacketEntities（cmd=55）
	PE          int    // 条数
	PEDelta     int    // is_delta 为真的条数
	PEUpdated   uint64 // updated_entries 累计
	PEEntData   uint64 // entity_data 累计字节
	PEUpdMin    uint32
	PEUpdMax    uint32
	PETickMin   uint32
	PETickMax   uint32
	PEMaxEntMin uint32
	PEMaxEntMax uint32
	// PEEntDataBuf 留最后一条 entity_data，供下一轮写 delta 解码器时比对。
	PEEntDataBuf []byte

	// 开火事件（cmd=452）
	PosCount int
	PosSane  int // 通过坐标合理性检查的条数
	LastPos  *gnsUnrelPos
}

// noteGNSUnrel 解一条不可靠载荷并累计统计。**不返回错误** —— 解码失败只是计数。
func (sess *Session) noteGNSUnrel(m []byte) {
	var replayReason uint8
	if sess.replay != nil {
		defer func() { sess.observeRestrictedReplay(m, replayReason) }()
	}
	sess.pipeline.unrelSeen.Add(1)
	if len(m) < 12 || (m[0] != gnsUnrelFlag && m[0] != 0x04) {
		sess.pipeline.unrelRejected.Add(1)
		reason := uint8(1)
		if len(m) >= 12 {
			reason = 2
		}
		sess.pipeline.unrelRejectReasons[reason].Add(1)
		replayReason = reason
		sess.traceGNSOuter(m, 2|8, reason)
		return
	}
	sess.gnsUnrel.Seen++
	if sess.gnsUnrel.StartHist == nil {
		sess.gnsUnrel.StartHist = make(map[int]int, 8)
		sess.gnsUnrel.CmdHist = make(map[uint32]int, 16)
	}
	if m[0] == 4 {
		sess.gnsUnrel.CompressedSeen++
	}
	d, reason := gnsDecodeUnrelReason(m)
	if d == nil {
		sess.pipeline.unrelRejected.Add(1)
		sess.pipeline.unrelRejectReasons[reason].Add(1)
		replayReason = reason
		sess.traceGNSOuter(m, 2|8, reason)
		// Full-chain ambiguity remains rejected. Only an independently proven
		// unanimous consumed-message projection may reach the original decoder.
		if reason == 6 {
			if common := gnsDecodeUnrelEntityConsensus(m); common != nil {
				sess.traceGNSDecodedChain(common)
				sess.applyGNSUnrelMessages(common.Msgs)
			}
		}
		return
	}
	sess.traceGNSOuter(m, 2|4, 0)
	sess.traceGNSDecodedChain(d)
	sess.pipeline.unrelDecoded.Add(1)
	if m[0] == 4 {
		sess.gnsUnrel.CompressedDecoded++
	}
	sess.gnsUnrel.Decoded++
	sess.gnsUnrel.StartHist[d.Start]++
	sess.applyGNSUnrelMessages(d.Msgs)
}

// Shared dispatch keeps the original downstream entity decoder unchanged;
// authenticated ingress remains upstream and unknown commands are not projected.
func (sess *Session) applyGNSUnrelMessages(msgs []gnsUnrelMsg) {
	for _, msg := range msgs {
		sess.gnsUnrel.CmdHist[msg.Cmd]++
		switch msg.Cmd {
		case gnsUnrelCmdPacketEnts:
			sess.pipeline.unreliableEntities.Add(1)
			if sess.entityDecoder != nil {
				_ = sess.entityDecoder.PacketEntities(msg.Body, time.Now())
			}
			pe := gnsDecodePacketEnts(msg.Body)
			if pe == nil || pe.UpdatedEntries == 0 {
				continue
			}
			sess.gnsUnrel.PE++
			if pe.IsDelta {
				sess.gnsUnrel.PEDelta++
			}
			sess.gnsUnrel.PEUpdated += uint64(pe.UpdatedEntries)
			sess.gnsUnrel.PEEntData += uint64(pe.EntityDataLen)
			if sess.gnsUnrel.PEUpdMin == 0 || pe.UpdatedEntries < sess.gnsUnrel.PEUpdMin {
				sess.gnsUnrel.PEUpdMin = pe.UpdatedEntries
			}
			if pe.UpdatedEntries > sess.gnsUnrel.PEUpdMax {
				sess.gnsUnrel.PEUpdMax = pe.UpdatedEntries
			}
			if sess.gnsUnrel.PETickMin == 0 || pe.DeltaFrom < sess.gnsUnrel.PETickMin {
				sess.gnsUnrel.PETickMin = pe.DeltaFrom
			}
			if pe.DeltaFrom > sess.gnsUnrel.PETickMax {
				sess.gnsUnrel.PETickMax = pe.DeltaFrom
			}
			if pe.MaxEntries > 0 {
				if sess.gnsUnrel.PEMaxEntMin == 0 || pe.MaxEntries < sess.gnsUnrel.PEMaxEntMin {
					sess.gnsUnrel.PEMaxEntMin = pe.MaxEntries
				}
				if pe.MaxEntries > sess.gnsUnrel.PEMaxEntMax {
					sess.gnsUnrel.PEMaxEntMax = pe.MaxEntries
				}
			}
			if len(pe.EntityData) > 0 {
				sess.gnsUnrel.PEEntDataBuf = pe.EntityData
			}
		case gnsUnrelCmdPos:
			p := gnsDecodeUnrelPos(msg.Body)
			if p == nil || !p.Has {
				continue
			}
			sess.gnsUnrel.PosCount++
			if gnsUnrelPosSane(p) {
				sess.gnsUnrel.PosSane++
				sess.gnsUnrel.LastPos = p
			}
		}
	}
}

// logGNSUnrelStats 打不可靠通道的解码结果。
//
// 只打一次三行，不刷屏：
//
//	[unrel] 位链：5190/5300 吃满｜起点 11×5192 14×1｜cmd 4×5191 55×5190 ...
//	[unrel] PacketEntities：5190 条｜is_delta 5190｜updated 均值 9.8 ...
//	[unrel] 本地玩家（cmd=452）：97 条｜最近 ...
func (sess *Session) logGNSUnrelStats() {
	st := &sess.gnsUnrel
	gnsLogf("[unrel] LZ4(0x04) 成功=%d 收到=%d；失败=%d", st.CompressedDecoded, st.CompressedSeen, st.CompressedSeen-st.CompressedDecoded)
	if st.Seen == 0 {
		return
	}
	// 起点分布：按次数降序
	starts := make([]int, 0, len(st.StartHist))
	for k := range st.StartHist {
		starts = append(starts, k)
	}
	sort.Ints(starts)
	var sb strings.Builder
	for _, k := range starts {
		fmt.Fprintf(&sb, "%d×%d ", k, st.StartHist[k])
	}
	gnsLogf("[unrel] 位链解码：%d/%d 吃满（%.1f%%）｜起点 %s",
		st.Decoded, st.Seen, 100.0*float64(st.Decoded)/float64(st.Seen), sb.String())

	// cmd 分布：按次数降序，前 8
	type cv struct {
		cmd uint32
		n   int
	}
	cl := make([]cv, 0, len(st.CmdHist))
	for k, v := range st.CmdHist {
		cl = append(cl, cv{k, v})
	}
	sort.Slice(cl, func(i, j int) bool {
		if cl[i].n != cl[j].n {
			return cl[i].n > cl[j].n
		}
		return cl[i].cmd < cl[j].cmd
	})
	var cb strings.Builder
	for i, e := range cl {
		if i >= 8 {
			break
		}
		name := ""
		switch e.cmd {
		case gnsUnrelCmdTick:
			name = "=net_Tick"
		case gnsUnrelCmdPacketEnts:
			name = "=PacketEntities"
		case gnsUnrelCmdPos:
			name = "=开火事件"
		}
		fmt.Fprintf(&cb, " %d%s×%d", e.cmd, name, e.n)
	}
	gnsLogf("[unrel] cmd 分布（%d 种）：%s", len(st.CmdHist), cb.String())

	if st.PE > 0 {
		avgUpd := float64(st.PEUpdated) / float64(st.PE)
		perEnt := 0.0
		if st.PEUpdated > 0 {
			perEnt = float64(st.PEEntData) / float64(st.PEUpdated)
		}
		gnsLogf("[unrel] PacketEntities：%d 条｜is_delta %d｜updated 均值 %.1f（%d..%d）"+
			"｜entity_data %.2f MB（%.1f 字节/实体）｜delta_from %d..%d｜max_entries %d..%d",
			st.PE, st.PEDelta, avgUpd, st.PEUpdMin, st.PEUpdMax,
			float64(st.PEEntData)/(1<<20), perEnt, st.PETickMin, st.PETickMax,
			st.PEMaxEntMin, st.PEMaxEntMax)
	}
	if st.PosCount > 0 {
		if p := st.LastPos; p != nil {
			gnsLogf("[unrel] 本地玩家位置（cmd=452）：%d 条（合理 %d）｜最近眼睛 (%.1f, %.1f, %.1f)"+
				"｜角度 (%.1f, %.1f, %.1f)｜脚底 z %.1f（与眼睛差 %.1f）",
				st.PosCount, st.PosSane,
				p.Eye[0], p.Eye[1], p.Eye[2],
				p.Angle[0], p.Angle[1], p.Angle[2],
				p.Feet[2], p.Eye[2]-p.Feet[2])
		} else {
			gnsLogf("[unrel] 本地玩家位置（cmd=452）：%d 条，但**没有一条通过合理性检查**"+
				"（眼睛与脚底的 z 差应在 40~90 之间）—— 说明 field1 不是世界坐标，别照着接",
				st.PosCount)
		}
	}
}
