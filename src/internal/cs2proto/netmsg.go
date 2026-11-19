// Package cs2proto 是服务器侧的"包 → 明文消息 → 玩家坐标"解码层。
//
// 重要前提（必须先说清）：
//   - X25519 共享密钥的计算是**数学确定的**，本包直接复用 `internal/handshake` 取到的公钥
//     与 `internal/cs2crypto` 算出的共享密钥。
//   - "共享密钥 → 会话密钥 → 解密"的具体方案（KDF 的 info 串、AEAD 类型、nonce 构造）
//     **不在 v2.0.5 这两个 EXE 里**。已确证雷达自身不做 AES-CBC，它把 `密钥 + 原始包`
//     交给下游（内置 parser 或服务端）。
//   - 因此本包把"消息分帧"做成**可验证的确定结构**，把"密钥调度 / AEAD / nonce"做成
//     **可枚举的候选集**，由 `cs2crypto.Probe` 用"解密结果能否切成合法消息流"自动打分选优。
//
// Source 2 的 netmessage 分帧（与社区 demo/网络解析器一致）：
//
//	varint cmd
//	varint size
//	[size]byte protobuf payload
//
// 这个结构本身是可验证的：合法流的 cmd 落在合理区间、size 与剩余长度自洽、
// 且必须正好消费完整个缓冲区。
package cs2proto

import (
	"errors"
	"fmt"
)

// MaxCmd 是 cmd 的合理上界。Source 2 的 netmessage 命令号远小于此值；
// 用它当"看起来像合法流"的第一道筛子。
const MaxCmd = 256

// MaxMsgSize 是单条消息的合理上界（64 MB）。
const MaxMsgSize = 64 << 20

var (
	ErrTruncated = errors.New("truncated netmessage stream")
	ErrBadCmd    = errors.New("netmessage cmd out of range")
	ErrBadSize   = errors.New("netmessage size out of range")
)

// Msg 是一条 netmessage。
type Msg struct {
	Cmd  uint64
	Data []byte // protobuf payload
	Raw  []byte // cmd+size+payload 的原始字节
}

// ReadVarint 读一个 protobuf 风格 varint。
func ReadVarint(b []byte) (uint64, int, bool) {
	var x uint64
	var s uint
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < 0x80 {
			if i > 9 || (i == 9 && c > 1) {
				return 0, 0, false
			}
			return x | uint64(c)<<s, i + 1, true
		}
		x |= uint64(c&0x7f) << s
		s += 7
		if s >= 64 {
			return 0, 0, false
		}
	}
	return 0, 0, false
}

// ParseStream 把一段字节切成 netmessage 序列。
// 要求：正好消费完整个缓冲区，且每条消息的 cmd / size 都在合理范围。
func ParseStream(b []byte, maxCmd uint64) ([]Msg, error) {
	var out []Msg
	i := 0
	for i < len(b) {
		start := i
		cmd, n, ok := ReadVarint(b[i:])
		if !ok {
			return out, ErrTruncated
		}
		i += n
		if cmd > maxCmd {
			return out, fmt.Errorf("%w: cmd=%d", ErrBadCmd, cmd)
		}
		size, m, ok := ReadVarint(b[i:])
		if !ok {
			return out, ErrTruncated
		}
		i += m
		if size > MaxMsgSize || uint64(i)+size > uint64(len(b)) {
			return out, fmt.Errorf("%w: size=%d remaining=%d", ErrBadSize, size, len(b)-i)
		}
		data := b[i : i+int(size)]
		i += int(size)
		out = append(out, Msg{Cmd: cmd, Data: data, Raw: b[start:i]})
	}
	if len(out) == 0 {
		return nil, ErrTruncated
	}
	return out, nil
}

// ChainProbe 在全偏移上试切 varint cmd+size 链，返回统计。
//
// 存在的理由：只有一个「已切=0」根本分不清是哪一种失败。
//   - 流起点不是消息边界（本地复现包就是从可靠流中间开始的）→ 从 0 起为 0，
//     但全偏移能扫出很长的链。这种只要现场从连接建立时开始抓就能自愈。
//   - 帧格式根本不对 → 全偏移也扫不出像样的链，得回去改内层解析器。
//
// 两者的处置方式完全相反，所以必须能在日志里分开。
func ChainProbe(b []byte, maxCmd uint64) (atZeroN, atZeroCov, bestN, bestCov int) {
	atZeroN, atZeroCov = chainAt(b, 0, maxCmd)
	bestN, bestCov = atZeroN, atZeroCov
	limit := len(b)
	if limit > 1<<16 {
		limit = 1 << 16
	}
	for o := 1; o < limit; o++ {
		n, cov := chainAt(b, o, maxCmd)
		if cov > bestCov {
			bestN, bestCov = n, cov
		}
	}
	return
}

// chainAt 从 off 起切链，返回 (条数, 覆盖字节)。切不动就停，不报错。
func chainAt(b []byte, off int, maxCmd uint64) (int, int) {
	i, n, cnt := off, len(b), 0
	for i < n {
		cmd, k, ok := ReadVarint(b[i:])
		if !ok || cmd > maxCmd {
			break
		}
		i += k
		size, m, ok := ReadVarint(b[i:])
		if !ok || size > MaxMsgSize || uint64(i)+size > uint64(n) {
			break
		}
		i += m + int(size)
		cnt++
	}
	return cnt, i - off
}

// Score 给"一段解密结果看起来有多像合法消息流"打分。
// 返回 (消息条数, 是否完全自洽)。用于 cs2crypto.Probe 在候选方案中择优。
//
// 打分思路：必须正好消费完整段；条数越多、平均消息越大，越像真的。
func Score(b []byte, maxCmd uint64) (int, bool) {
	if len(b) < 2 {
		return 0, false
	}
	msgs, err := ParseStream(b, maxCmd)
	if err != nil {
		return 0, false
	}
	// 再来一道：所有消息必须非空，否则很像"随机字节碰巧切成小碎片"
	nonEmpty := 0
	for _, m := range msgs {
		if len(m.Data) > 0 {
			nonEmpty++
		}
	}
	if nonEmpty == 0 {
		return 0, false
	}
	return len(msgs), true
}
