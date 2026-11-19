package radarsrv

import (
	"errors"
	"fmt"
	"strings"
)

// Legacy string-table pattern scanner retained only for diagnostics.
// Flag 0x03 is a compressed reliable payload; production decoding uses
// gnsReliablePayload + the same bit-chain parser as flag 0x01.
// A scanner coverage ratio is not a packet-loss measurement.
// gnsMsgFlagSignon 是 signon 段可靠消息载荷的首字节。
const gnsMsgFlagSignon = 0x03

// gnsStringTable 是从 0x03 载荷里扫出来的一张 CreateStringTable。
type gnsStringTable struct {
	Name             string // 表名（field1）
	MaxEntries       uint64 // 表容量（field2）
	DataCompressed   bool   // field9
	UncompressedSize uint64 // field8
	RawLen           int    // field7 原始字节数（压缩态）
	DecodedLen       int    // snappy 解出来的字节数；失败为 -1
	DecodeErr        string
}

var errGNSSnappyShort = errors.New("snappy: 数据被截断")

// gnsSnappyDecode 解**原始格式**（raw，非 framed）的 snappy。
//
// 为什么不是 zlib：userinfo 那张表的 field7 头两个字节是 `fe 04`，
// 按 varint 读出来正好 638 —— 与 field8 的 uncompressed_size=638 逐位相等。
// zlib/deflate 在这个位置会直接报 header 错，而 snappy 的自校验长度对得上，
// 所以压缩算法是 snappy，CS2 的字符串表就是用它。
//
//	tag = b & 3
//	  0 = literal,  len = (tag>>2)+1（tag>>2 < 60），否则 60..63 跟 1..4 字节的 len-1
//	  1 = copy1,    len = ((tag>>2)&7)+4, offset = ((tag>>5)<<8)|next
//	  2 = copy2,    len = (tag>>2)+1,     offset = 2 字节 LE
//	  3 = copy4,    len = (tag>>2)+1,     offset = 4 字节 LE
func gnsSnappyDecode(b []byte) ([]byte, error) {
	want, i, ok := readGNSVarint(b)
	if !ok {
		return nil, errors.New("snappy: 长度 varint 读不出来")
	}
	out := make([]byte, 0, int(want))
	for i < len(b) {
		tag := b[i]
		i++
		switch tag & 3 {
		case 0: // literal
			ln := int(tag >> 2)
			if ln < 60 {
				ln++
			} else {
				k := ln - 59
				if i+k > len(b) {
					return nil, errGNSSnappyShort
				}
				v := 0
				for j := 0; j < k; j++ {
					v |= int(b[i+j]) << (8 * j)
				}
				i += k
				ln = v + 1
			}
			if i+ln > len(b) {
				return nil, errGNSSnappyShort
			}
			out = append(out, b[i:i+ln]...)
			i += ln
		default:
			var ln, off int
			switch tag & 3 {
			case 1:
				ln = int((tag>>2)&7) + 4
				if i >= len(b) {
					return nil, errGNSSnappyShort
				}
				off = int(tag>>5)<<8 | int(b[i])
				i++
			case 2:
				ln = int(tag>>2) + 1
				if i+2 > len(b) {
					return nil, errGNSSnappyShort
				}
				off = int(b[i]) | int(b[i+1])<<8
				i += 2
			default:
				ln = int(tag>>2) + 1
				if i+4 > len(b) {
					return nil, errGNSSnappyShort
				}
				off = int(b[i]) | int(b[i+1])<<8 | int(b[i+2])<<16 | int(b[i+3])<<24
				i += 4
			}
			if off <= 0 || off > len(out) {
				return nil, fmt.Errorf("snappy: 回溯偏移非法 %d（已出 %d）", off, len(out))
			}
			for k := 0; k < ln; k++ {
				out = append(out, out[len(out)-off])
			}
		}
	}
	if uint64(len(out)) != uint64(want) {
		return nil, fmt.Errorf("snappy: 长度不符 期望 %d 得到 %d", want, len(out))
	}
	return out, nil
}

// gnsReadPBVarint 读 protobuf varint。
func gnsReadPBVarint(b []byte, i int) (uint64, int, bool) {
	var v uint64
	var shift uint
	for i < len(b) && shift < 64 {
		c := b[i]
		i++
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i, true
		}
		shift += 7
	}
	return 0, i, false
}

// gnsScanCreateStringTable 在一条 0x03 载荷里按模式扫描 svc_CreateStringTable。
//
// 判据（四条同时满足，宁严不松）：
//  1. b[p] == 39；
//  2. p+1 起 varint 是体长 n，8 <= n <= 1<<20；
//  3. 体首字节是 0x0a（field1 = 表名，wire type 2）；
//  4. 表名长度 2..64 且全是可打印 ASCII。
//
// 命中后按 CSVCMsg_CreateStringTable 解 field1/2/7/8/9，并对 field7 跑 snappy。
func gnsScanCreateStringTable(b []byte) []gnsStringTable {
	var out []gnsStringTable
	for p := 0; p+6 < len(b); p++ {
		if b[p] != 39 {
			continue
		}
		n, ni, ok := gnsReadPBVarint(b, p+1)
		if !ok || n < 8 || n > 1<<20 || ni+int(n) > len(b) {
			continue
		}
		body := b[ni : ni+int(n)]
		if len(body) < 3 || body[0] != 0x0a {
			continue
		}
		nameLen, qi, ok := gnsReadPBVarint(body, 1)
		if !ok || nameLen < 2 || nameLen > 64 || qi+int(nameLen) > len(body) {
			continue
		}
		name := body[qi : qi+int(nameLen)]
		printable := true
		for _, c := range name {
			if c < 32 || c >= 127 {
				printable = false
				break
			}
		}
		if !printable {
			continue
		}
		t := gnsStringTable{Name: string(name), DecodedLen: -1}

		// 遍历剩余字段
		//
		// 🔴 f7（string_data）在 f8/f9 **之前**出现，现场 userinfo 那条就是
		// `... 3a be 04 <574B> 40 fe 04 48 01`（f7 → f8=638 → f9=1）。
		// 所以不能在读到 f7 时就决定要不要解压 —— 那时 DataCompressed 还是 false，
		// 会把 574 字节压缩态当成表数据交出去。先把原始字节留住，字段走完再解。
		var rawData []byte
		var hasData bool
		i := qi + int(nameLen)
		for i < len(body) {
			key, ki, ok := gnsReadPBVarint(body, i)
			if !ok || key == 0 {
				break
			}
			f, w := key>>3, key&7
			i = ki
			switch w {
			case 0:
				v, vi, ok := gnsReadPBVarint(body, i)
				if !ok {
					i = len(body)
					break
				}
				i = vi
				switch f {
				case 2:
					t.MaxEntries = v
				case 8:
					t.UncompressedSize = v
				case 9:
					t.DataCompressed = v != 0
				}
			case 2:
				ln, li, ok := gnsReadPBVarint(body, i)
				if !ok || li+int(ln) > len(body) {
					i = len(body)
					break
				}
				if f == 7 {
					rawData = body[li : li+int(ln)]
					hasData = true
					t.RawLen = int(ln)
				}
				i = li + int(ln)
			case 5:
				i += 4
			case 1:
				i += 8
			default:
				i = len(body)
			}
		}
		if hasData {
			if t.DataCompressed {
				if dec, err := gnsSnappyDecode(rawData); err == nil {
					t.DecodedLen = len(dec)
				} else {
					t.DecodeErr = err.Error()
				}
			} else {
				t.DecodedLen = len(rawData)
			}
		}
		out = append(out, t)
	}
	return out
}

// gnsSplitReliable 按可靠消息头（0mssssss + 可选 msg_num + size）切一段字节流。
//
// 规则与 internal/cs2snp/stream.go 的 splitOne 同源。2026-10-20 08:27 那份
// 283892 字节的 signon 用它切出 **570 条、零重同步、正好走到最后 1 字节**，
// 所以这条规则本身是可信的 —— 问题从来不在这一层。
func gnsSplitReliable(b []byte) (msgs [][]byte, resync int, end int) {
	off := 0
	for off < len(b) {
		h := b[off]
		if h&0x80 != 0 {
			off++
			resync++
			continue
		}
		i := off + 1
		if h&0x40 != 0 {
			_, ni, ok := gnsReadPBVarint(b, i)
			if !ok {
				break
			}
			i = ni
		}
		s6 := uint64(h & 0x3f)
		var size uint64
		if s6 >= 0x20 {
			hi, ni, ok := gnsReadPBVarint(b, i)
			if !ok {
				break
			}
			i = ni
			if hi > 1<<26 {
				off++
				resync++
				continue
			}
			size = (s6 & 0x1f) | (hi << 5)
		} else {
			size = s6
		}
		if size == 0 || i+int(size) > len(b) {
			break
		}
		msgs = append(msgs, b[i:i+int(size)])
		off = i + int(size)
	}
	return msgs, resync, off
}

// gnsLogSignonTables 扫一段 signon 字节流，把里面的字符串表打出来。
//
// 这一行是「下一步该往哪查」的唯一依据：
//   - 出现 modelprecache / soundprecache ⇒ 模型名映射拿到了；
//   - 出现 userinfo ⇒ 玩家名单拿到了；
//   - 出现 GameEventList ⇒ 事件名拿到了（分敌我的前提）；
//   - 一条都没有 ⇒ 说明扫描模式没覆盖到，帧格式还要改。
func gnsLogSignonTables(buf []byte) {
	gnsLogf("%s", GNSSignonReport(buf))
}

// GNSSignonReport 是 gnsLogSignonTables 的可复用版本（离线工具也用它）。
//
// 导出它的原因：现场那份 gns-signon-*.bin 已经落盘了，需要能**离线重跑**
// 同一段逻辑，否则每次改扫描规则都得再打一局才知道对不对。
func GNSSignonReport(buf []byte) string {
	msgs, resync, end := gnsSplitReliable(buf)
	valid, failed, compressed, server, schemas, full := 0, 0, 0, 0, 0, 0
	var names []string
	for _, m := range msgs {
		list, _, err := gnsParseNetMsgs(m)
		if err != nil {
			failed++
			continue
		}
		valid++
		if len(m) > 0 && m[0] == 3 {
			compressed++
		}
		for _, nm := range list {
			switch nm.Cmd {
			case 40:
				server++
			case 41:
				schemas++
			case 44:
				name := ""
				if gnsWalkPB(nm.Body, func(f, w int, _ uint64, d []byte) {
					if f == 1 && w == 2 {
						name = string(d)
					}
				}) == nil && name != "" {
					names = append(names, name)
				}
			case 55:
				pe := gnsDecodePacketEnts(nm.Body)
				if pe != nil && !pe.IsDelta {
					full++
				}
			}
		}
	}
	return fmt.Sprintf("[signon] 可靠边界 %d 条｜统一位链成功 %d｜失败 %d｜LZ4载荷 %d｜重同步 %d｜边界扫描到 %d/%d 字节\n"+
		"[signon] ServerInfo=%d FlattenedSerializer=%d 完整PacketEntities=%d 字符串表=%d %s\n"+
		"[signon] 以上是消息/头部解析，不代表人物已还原；扫描范围不是丢包率，未发现schema不等于证明它落在缺口里。",
		len(msgs), valid, failed, compressed, resync, end, len(buf), server, schemas, full, len(names), strings.Join(names, ","))
}
