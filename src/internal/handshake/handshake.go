// Package handshake 还原 capture.exe 中 main.parsePB / main.parseHandshake 的行为。
//
// 对应符号（capture.exe）：
//
//	main.parsePB        @0x178e20  手写 protobuf 解析器
//	main.parseHandshake @0x179440  取 32 字节 X25519 公钥
//
// 还原结论（report §3.2）：
//   - parsePB 自行解析 varint tag，fieldNum = tag>>3，拒绝 fieldNum==0 或 >2000；
//     仅处理 wireType 0(varint) / 1(fixed64) / 2(length-delimited) / 5(fixed32)。
//   - parseHandshake 返回的 hsInfo 结构里 +0x30 就是 32 字节目标公钥；
//     取值路径 root.f4 → f4 → f2，备用路径 root.f7 → f1 → f2；
//     根消息首字节必须是 0x22（即 field 4, wireType 2）。
//   - hsInfo 另有 field1(32 位) 与 field3(64 位) 字段，语义未定（见 report §6）。
package handshake

import (
	"errors"
	"fmt"
)

// Entry 对应 parsePB 产出的 48 字节条目。
type Entry struct {
	Field  int
	Wire   int
	Varint uint64
	Bytes  []byte
	Raw    []byte
}

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5

	maxField = 2000
)

// ErrNotProto 表示字节流不像 protobuf。
var ErrNotProto = errors.New("not a protobuf message")

// ParsePB 还原手写解析器。
func ParsePB(b []byte) ([]Entry, error) {
	var out []Entry
	i := 0
	for i < len(b) {
		tag, n := uvarint(b[i:])
		if n <= 0 {
			return out, ErrNotProto
		}
		i += n
		field := int(tag >> 3)
		wire := int(tag & 7)
		if field == 0 || field > maxField {
			return out, fmt.Errorf("invalid protobuf field number %d", field)
		}
		e := Entry{Field: field, Wire: wire}
		switch wire {
		case wireVarint:
			v, m := uvarint(b[i:])
			if m <= 0 {
				return out, ErrNotProto
			}
			e.Varint = v
			e.Raw = b[i : i+m]
			i += m
		case wireFixed64:
			if i+8 > len(b) {
				return out, ErrNotProto
			}
			e.Raw = b[i : i+8]
			i += 8
		case wireBytes:
			l, m := uvarint(b[i:])
			if m <= 0 {
				return out, ErrNotProto
			}
			i += m
			if uint64(i)+l > uint64(len(b)) {
				return out, ErrNotProto
			}
			e.Bytes = b[i : i+int(l)]
			e.Raw = b[i : i+int(l)]
			i += int(l)
		case wireFixed32:
			if i+4 > len(b) {
				return out, ErrNotProto
			}
			e.Raw = b[i : i+4]
			i += 4
		default:
			return out, fmt.Errorf("unsupported wire type %d", wire)
		}
		out = append(out, e)
	}
	return out, nil
}

func uvarint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < 0x80 {
			if i > 9 || (i == 9 && c > 1) {
				return 0, -(i + 1)
			}
			return x | uint64(c)<<s, i + 1
		}
		x |= uint64(c&0x7f) << s
		s += 7
		if s >= 64 {
			return 0, -1
		}
	}
	return 0, 0
}

func field(es []Entry, num int) (Entry, bool) {
	for _, e := range es {
		if e.Field == num {
			return e, true
		}
	}
	return Entry{}, false
}

// Info 对应原程序的 hsInfo。
type Info struct {
	PublicKey []byte // +0x30
	Field1    uint32 // 语义未定
	Field3    uint64 // 语义未定
	ProtoOff  int    // protobuf 在原始 payload 中的起始偏移
}

// ParseHandshake 从 UDP payload 中解析出 32 字节 X25519 公钥。
//
// ⚠ 这是**早期逆向**的产物：首字节必须 0x22、优先 root.f4→f4→f2。
// 用真实报文核对后（2026-10-19）发现两个问题，所以解密链路改用 ParseHello：
//  1. 0x22 只是 netchan 的**消息类型字节**，ServerHello 是 0x23 —— 这里永远看不到；
//  2. 真实 ClientHello 的 f4→f4→f2 是**静态身份密钥**（跨连接不变），
//     f7→f1→f2 才是做 ECDH 的临时公钥。
//
// 这个函数保留原行为（有单测钉着它描述的旧路径），但**不要**用它算共享密钥。
func ParseHandshake(payload []byte) (*Info, error) {
	for off := 0; off < len(payload) && off < 64; off++ {
		if payload[off] != 0x22 {
			continue
		}
		root, err := ParsePB(payload[off:])
		if err != nil || len(root) == 0 {
			continue
		}
		if info, ok := extract(root); ok {
			info.ProtoOff = off
			return info, nil
		}
	}
	return nil, errors.New("handshake public key not found")
}

// ── 双向握手解析（2026-10-19 按真实报文重写） ────────────────────────────

// 握手报文的首字节是 netchan 的**消息类型**，不属于 protobuf：
//
//	0x22  ClientHello（客户端 → 服务器）
//	0x23  ServerHello（服务器 → 客户端）
//
// 早期逆向只认 0x22，于是 ServerHello 从来没被解析过 —— 服务器的临时公钥
// 一直没取出来，ECDH 只能拿客户端公钥当对端，共享密钥永远是错的
// （现象：密钥能挖到、日志有 key_ready，但雷达页一直空白）。
const (
	TypeClientHello = 0x22
	TypeServerHello = 0x23
)

// ErrNotHello 表示载荷不是握手报文。
var ErrNotHello = errors.New("not a handshake message")

// IsHelloType 判断首字节是不是握手消息类型。
func IsHelloType(b byte) bool { return b == TypeClientHello || b == TypeServerHello }

// ParseHello 解析**任意方向**的握手报文，返回 32 字节临时公钥。
//
// 字段路径固定 root.f7 → f1 → f2。真实报文核对结果：
//
//	ClientHello  f4→f4→f2 = 客户端**静态**身份密钥（跨连接完全相同，别拿它做 ECDH）
//	             f7→f1→f2 = 客户端**临时**公钥（每条连接都变）
//	ServerHello  f8→f4→f2 = 服务器静态身份密钥（内含服务器 steamid）
//	             f7→f1→f2 = 服务器**临时**公钥
//
// 所以：ClientHello 的 f7 用来在内存里找对应私钥，
//       ServerHello 的 f7 才是 ECDH 的对端公钥。
func ParseHello(payload []byte) (*Info, error) {
	if len(payload) == 0 {
		return nil, ErrNotHello
	}
	// 候选起点：有类型字节时先按"跳过 1 字节"解析（真实报文走这条），
	// 再兜底扫一遍（万一以后包前面多套了一层头）。
	offs := make([]int, 0, 8)
	if IsHelloType(payload[0]) {
		offs = append(offs, 1)
	}
	for o := 0; o < len(payload) && o < 64; o++ {
		if IsHelloType(payload[o]) && o != 1 {
			offs = append(offs, o)
		}
	}
	for _, off := range offs {
		root, err := ParsePB(payload[off:])
		if err != nil && len(root) == 0 {
			continue
		}
		if info, ok := extractEphemeral(root); ok {
			info.ProtoOff = off
			return info, nil
		}
	}
	return nil, errors.New("handshake ephemeral public key not found")
}

// extractEphemeral 走 f7 → f1 → f2 取 32 字节临时公钥。
func extractEphemeral(root []Entry) (*Info, bool) {
	e, ok := field(root, 7)
	if !ok || e.Wire != wireBytes {
		return nil, false
	}
	l1, err := ParsePB(e.Bytes)
	if err != nil && len(l1) == 0 {
		return nil, false
	}
	e2, ok := field(l1, 1)
	if !ok || e2.Wire != wireBytes {
		return nil, false
	}
	l2, err := ParsePB(e2.Bytes)
	if err != nil && len(l2) == 0 {
		return nil, false
	}
	pk, ok := field(l2, 2)
	if !ok || pk.Wire != wireBytes || len(pk.Bytes) != 32 {
		return nil, false
	}
	return &Info{PublicKey: pk.Bytes, Field1: u32(l2, 1), Field3: u64(l1, 3)}, true
}

func extract(root []Entry) (*Info, bool) {
	// 主路径 root.f4 → f4 → f2
	if e, ok := field(root, 4); ok && e.Wire == wireBytes {
		if l1, err := ParsePB(e.Bytes); err == nil {
			if e2, ok := field(l1, 4); ok && e2.Wire == wireBytes {
				if l2, err := ParsePB(e2.Bytes); err == nil {
					if pk, ok := field(l2, 2); ok && pk.Wire == wireBytes && len(pk.Bytes) == 32 {
						return &Info{PublicKey: pk.Bytes, Field1: u32(l2, 1), Field3: u64(l1, 3)}, true
					}
				}
			}
		}
	}
	// 备用路径 root.f7 → f1 → f2
	if e, ok := field(root, 7); ok && e.Wire == wireBytes {
		if l1, err := ParsePB(e.Bytes); err == nil {
			if e2, ok := field(l1, 1); ok && e2.Wire == wireBytes {
				if l2, err := ParsePB(e2.Bytes); err == nil {
					if pk, ok := field(l2, 2); ok && pk.Wire == wireBytes && len(pk.Bytes) == 32 {
						return &Info{PublicKey: pk.Bytes, Field1: u32(l2, 1), Field3: u64(l1, 3)}, true
					}
				}
			}
		}
	}
	return nil, false
}

func u32(es []Entry, num int) uint32 {
	if e, ok := field(es, num); ok {
		return uint32(e.Varint)
	}
	return 0
}

func u64(es []Entry, num int) uint64 {
	if e, ok := field(es, num); ok {
		return e.Varint
	}
	return 0
}

// ByteFieldCandidates 递归提取载荷里所有「长度恰好为 want 的字节字段」。
//
// 用途：ParseHandshake 走的是逆向得出的固定字段路径（f4→f4→f2 / f7→f1→f2）。
// 一旦协议版本变动、或者当初认错了哪一层，取到的 32 字节就不是客户端公钥，
// 之后在内存里怎么搜都搜不到。此时把包里**所有** 32 字节字段都拿去试一遍，
// 比让用户重新抓一次包快得多 —— 每个候选只要一次全内存 memmem（约 1.6 秒/7 GB）。
//
// 深度上限 6 层（真实包是 4 层），避免畸形数据把递归撑爆。
func ByteFieldCandidates(payload []byte, want int) [][]byte {
	if want <= 0 || len(payload) == 0 {
		return nil
	}
	var (
		out  [][]byte
		seen = map[string]bool{}
	)
	var walk func(b []byte, depth int)
	walk = func(b []byte, depth int) {
		if depth > 6 || len(b) == 0 {
			return
		}
		es, err := ParsePB(b)
		if err != nil && len(es) == 0 {
			return
		}
		for _, e := range es {
			if e.Wire != wireBytes {
				continue
			}
			if len(e.Bytes) == want {
				k := string(e.Bytes)
				if !seen[k] {
					seen[k] = true
					out = append(out, e.Bytes)
				}
				continue // 长度正好等于 want，不再往下钻
			}
			walk(e.Bytes, depth+1)
		}
	}
	walk(payload, 0)
	return out
}
