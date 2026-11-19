// msgdump 把现场落下来的明文帧重新走一遍 SNP 三层，输出**带边界**的可靠消息。
//
// 为什么需要它：`netchan` 只是把消息载荷首尾相接，边界信息（SNP 消息链本来
// 就有的）被丢掉了。而内层封装的定案恰恰依赖「每条消息从哪开始、多长」——
// 在 253 KB 的拼接流里找边界只能靠猜，猜了十几轮都没结果。
//
// 输入是采集端落的 `gns-plain-*.json`（GCM 认证通过的明文帧，hex 列表，
// 按到达顺序）。输出：
//
//	msgs.bin   每条消息 `u32le 长度 + 载荷`
//	stdout     前 N 条的「序号 / 长度 / 头 16 字节」，以及长度分布
//
// 用法：
//
//	msgdump -in gns-plain-20261019-134030.json -out msgs.bin -n 40
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"local/cs2-radar/internal/cs2snp"
)

type plainFile struct {
	Direction string   `json:"direction"`
	Note      string   `json:"note"`
	Session   string   `json:"session"`
	Plain     []string `json:"plain"`
}

func main() {
	in := flag.String("in", "", "gns-plain-*.json 或已带边界的 gns-msgs-*.bin")
	out := flag.String("out", "msgs.bin", "输出：u32le 长度 + 载荷")
	n := flag.Int("n", 40, "打印前多少条")
	flag.Parse()
	if *in == "" {
		fmt.Fprintln(os.Stderr, "必须给 -in")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读文件失败：%v\n", err)
		os.Exit(1)
	}

	var msgs [][]byte
	if strings.HasSuffix(strings.ToLower(*in), ".bin") || looksFramed(raw) {
		// 已经是 `u32le 长度 + 载荷` 的带边界转储（采集端落的 gns-msgs-*.bin）。
		msgs, err = readFramed(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "解析带边界转储失败：%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("输入=带边界转储 消息=%d\n", len(msgs))
	} else {
		msgs = fromPlain(raw)
	}
	_ = out
	report(msgs, *n)
}

// looksFramed 粗判一段字节是不是 `u32le 长度 + 载荷` 的转储：
// 按长度链走前若干条，能正好走完就认为是。
func looksFramed(b []byte) bool {
	off, n := 0, 0
	for off+4 <= len(b) && n < 64 {
		l := int(binary.LittleEndian.Uint32(b[off:]))
		if l < 0 || l > 8<<20 || off+4+l > len(b) {
			return false
		}
		off += 4 + l
		n++
	}
	return n > 0 && off == len(b)
}

// readFramed 读 `u32le 长度 + 载荷` 的转储。
func readFramed(b []byte) ([][]byte, error) {
	var out [][]byte
	off := 0
	for off+4 <= len(b) {
		l := int(binary.LittleEndian.Uint32(b[off:]))
		off += 4
		if l < 0 || off+l > len(b) {
			return out, fmt.Errorf("第 %d 条长度 %d 越界（剩余 %d）", len(out), l, len(b)-off)
		}
		out = append(out, b[off:off+l])
		off += l
	}
	return out, nil
}

// fromPlain 把 gns-plain-*.json 重新走一遍 SNP 三层，拿到带边界的消息。
func fromPlain(raw []byte) [][]byte {
	var pf plainFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		fmt.Fprintf(os.Stderr, "解析 JSON 失败：%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("方向=%s 会话=%s 帧数=%d\n", pf.Direction, pf.Session, len(pf.Plain))

	parser := cs2snp.NewParser()
	stream := cs2snp.NewStream()
	split := cs2snp.NewMsgSplit()

	var msgs [][]byte
	totalSegs, totalUnrel, badPkts, okPkts := 0, 0, 0, 0
	var firstPos int64 = -1
	firstSet := false

	for i, h := range pf.Plain {
		pt, err := hex.DecodeString(h)
		if err != nil {
			continue
		}
		segs, unrels, pst := parser.Parse(pt)
		if pst.Bad != 0 {
			badPkts++
			fmt.Printf("  #%d 坏帧 type=0x%02x len=%d\n", i, pst.BadType, len(pt))
			continue
		}
		okPkts++
		totalSegs += len(segs)
		totalUnrel += len(unrels)
		for _, sg := range segs {
			if !firstSet {
				firstSet, firstPos = true, sg.Pos
			}
			stream.Add(sg.Pos, sg.Data)
		}
		if b := stream.Take(); len(b) > 0 {
			msgs = append(msgs, split.Feed(b)...)
		}
	}
	fmt.Printf("包=%d 坏包=%d 可靠段=%d 不可靠=%d 首段位置=%d 流位置=%d 已出=%d 空洞=%d\n",
		okPkts, badPkts, totalSegs, totalUnrel, firstPos,
		stream.Next(), stream.Emitted(), stream.MaxGap())
	return msgs
}

// rdvarint 读一个 varint，返回值和占用的字节数。
func rdvarint(b []byte, i int) (uint64, int, bool) {
	var v uint64
	shift := 0
	for j := i; j < len(b) && shift < 64; j++ {
		v |= uint64(b[j]&0x7f) << shift
		if b[j]&0x80 == 0 {
			return v, j - i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

// report 打前 N 条 + 长度分布 + 首字节分布 + 封装假设检验。
func report(msgs [][]byte, n int) {
	total := 0
	for _, m := range msgs {
		total += len(m)
	}
	fmt.Printf("消息=%d 总载荷=%d\n", len(msgs), total)

	fmt.Println("\n=== 前若干条 ===")
	for i, m := range msgs {
		if i >= n {
			break
		}
		h := m
		if len(h) > 24 {
			h = h[:24]
		}
		fmt.Printf("#%-4d len=%-6d head=%x\n", i, len(m), h)
	}

	type kv struct{ L, N int }
	cnt := map[int]int{}
	for _, m := range msgs {
		cnt[len(m)]++
	}
	var list []kv
	for L, N := range cnt {
		list = append(list, kv{L, N})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].N > list[j].N })
	fmt.Println("\n=== 长度分布（前 20）===")
	for i, e := range list {
		if i >= 20 {
			break
		}
		fmt.Printf("  len=%-6d ×%d\n", e.L, e.N)
	}

	first := map[byte]int{}
	for _, m := range msgs {
		if len(m) > 0 {
			first[m[0]]++
		}
	}
	var fl []kv
	for b, N := range first {
		fl = append(fl, kv{int(b), N})
	}
	sort.Slice(fl, func(i, j int) bool { return fl[i].N > fl[j].N })
	fmt.Println("\n=== 首字节分布（前 10）===")
	for i, e := range fl {
		if i >= 10 {
			break
		}
		fmt.Printf("  0x%02x ×%d\n", e.L, e.N)
	}

	// 🔴 封装假设检验：这是定内层封装的核心表。
	//
	// 对每条消息，在偏移 k（0..4）处读一个 varint，看它是否正好等于
	// 「剩余字节数」或「剩余位数」。命中率接近 100% 的那一行就是真封装。
	fmt.Println("\n=== 封装假设检验（命中率 = 满足等式的消息数 / 总数）===")
	fmt.Printf("%-4s %-6s %-10s %s\n", "k", "模式", "命中", "说明")
	for k := 0; k <= 4; k++ {
		var hitB, hitBit, tot int
		for _, m := range msgs {
			if len(m) <= k {
				continue
			}
			tot++
			v, vl, ok := rdvarint(m, k)
			if !ok {
				continue
			}
			rest := len(m) - k - vl
			if v == uint64(rest) {
				hitB++
			}
			if v == uint64(rest)*8 {
				hitBit++
			}
		}
		if tot == 0 {
			continue
		}
		fmt.Printf("%-4d %-6s %-10s %s\n", k, "字节", fmt.Sprintf("%d/%d", hitB, tot), "varint(k) == 剩余字节数")
		fmt.Printf("%-4d %-6s %-10s %s\n", k, "位", fmt.Sprintf("%d/%d", hitBit, tot), "varint(k) == 剩余位数")
	}

	// 首 2 字节组合分布：看「标志位 + 长度低字节」这类结构。
	fmt.Println("\n=== 前 2 字节组合（前 12）===")
	pair := map[uint16]int{}
	for _, m := range msgs {
		if len(m) >= 2 {
			pair[uint16(m[0])<<8|uint16(m[1])]++
		}
	}
	var pl []kv
	for p, N := range pair {
		pl = append(pl, kv{int(p), N})
	}
	sort.Slice(pl, func(i, j int) bool { return pl[i].N > pl[j].N })
	for i, e := range pl {
		if i >= 12 {
			break
		}
		fmt.Printf("  %04x ×%d\n", e.L, e.N)
	}
}
