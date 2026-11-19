// netdump 把现场落下来的明文帧重新走一遍 SNP 三层，输出**每条 netmessage**。
//
// 与 msgdump 的分工：msgdump 只到「可靠消息」这一层（带边界），
// netdump 继续往下走位级分帧，交出 (cmd, body) —— 这是分析「某个 cmd 里
// 到底装了什么」的前提。
//
// 解码器与线上同源（radarsrv.ToolParseNetMsgs），不是另写一份。
//
// 用法：
//
//	netdump -in gns-plain-20261020-075558.json -cmd 208 -n 5
//	netdump -in ... -hist           只看 cmd 直方图
//	netdump -in ... -unrel          顺便按 Num 重组不可靠消息并画像
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"local/cs2-radar/internal/cs2snp"
	"local/cs2-radar/internal/radarsrv"
)

type plainFile struct {
	Direction string   `json:"direction"`
	Plain     []string `json:"plain"`
}

type cmdStat struct {
	n    int
	byts int
}

func main() {
	in := flag.String("in", "", "gns-plain-*.json")
	dir := flag.String("dir", "s2c", "只处理这个方向")
	wantCmd := flag.Int("cmd", -1, "只 dump 这个 cmd 的 body")
	nSample := flag.Int("n", 5, "dump 多少条样本")
	hist := flag.Bool("hist", false, "只打 cmd 直方图")
	agg := flag.Bool("agg", false, "对 -cmd 指定的消息按「第一个 varint 字段」聚合（游戏事件按 eventid 分）")
	doUnrel := flag.Bool("unrel", false, "顺便重组并画像不可靠消息")
	// -out 把 -cmd 的全部 body 落成二进制（u32le 长度前缀），交给 Python 深挖。
	// 只打 5 条样本不够用：cmd=207 里 eventid=226 往往排在几十条之后。
	outPath := flag.String("out", "", "把 -cmd 的全部 body 写成 u32le 长度前缀的二进制文件")
	// -ev 只在 cmd=207（svc_GameEvent）上生效：只留这个 eventid。
	wantEv := flag.Int("ev", -1, "只留这个 eventid（仅 cmd=207 有效，-1 表示不过滤）")
	flag.Parse()

	if *in == "" {
		fmt.Fprintln(os.Stderr, "需要 -in")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读文件失败: %v\n", err)
		os.Exit(1)
	}
	// 两种输入：
	//   *.json  —— 采集端落的 gns-plain-*.json（开局那几百帧）
	//   *.bin   —— GNPB 容器：magic(4) + 版本u32 + 标志u32 + 重复[u32le 长度][帧]
	// 后者是整局的全量明文，分析必须用它，否则只能看到开局十几条消息。
	var frames [][]byte
	if len(raw) >= 12 && string(raw[:4]) == "GNPB" {
		off := 12
		for off+4 <= len(raw) {
			n := int(binary.LittleEndian.Uint32(raw[off:]))
			off += 4
			if n <= 0 || off+n > len(raw) {
				break
			}
			frames = append(frames, raw[off:off+n])
			off += n
		}
		fmt.Printf("GNPB 容器：%d 帧（版本 %d）\n", len(frames),
			binary.LittleEndian.Uint32(raw[4:]))
	} else {
		var pf plainFile
		if err := json.Unmarshal(raw, &pf); err != nil {
			fmt.Fprintf(os.Stderr, "解析 JSON 失败: %v\n", err)
			os.Exit(1)
		}
		if pf.Direction != "" && pf.Direction != *dir {
			fmt.Fprintf(os.Stderr, "文件方向是 %s，与 -dir %s 不符\n", pf.Direction, *dir)
		}
		for _, h := range pf.Plain {
			if b, e := hex.DecodeString(h); e == nil {
				frames = append(frames, b)
			}
		}
	}

	parser := cs2snp.NewParser()
	stream := cs2snp.NewStream()
	split := cs2snp.NewMsgSplit()

	stats := map[uint32]*cmdStat{}
	samples := map[uint32][][]byte{}
	allBodies := map[uint32][][]byte{}
	totalMsg := 0
	notChain := 0

	// 不可靠消息：按 Num 分组重组
	type unrelBuf struct {
		parts [][]byte
		last  bool
	}
	unrels := map[int64]*unrelBuf{}
	var unrelOrder []int64

	for _, pt := range frames {
		segs, us, pst := parser.Parse(pt)
		if pst.Bad != 0 {
			continue
		}
		for _, u := range us {
			b := unrels[u.Num]
			if b == nil {
				b = &unrelBuf{}
				unrels[u.Num] = b
				unrelOrder = append(unrelOrder, u.Num)
			}
			b.parts = append(b.parts, append([]byte(nil), u.Data...))
			if u.Last {
				b.last = true
			}
		}
		for _, sg := range segs {
			stream.Add(sg.Pos, sg.Data)
		}
		stream.SkipStale(time.Now())
		if b := stream.Take(); len(b) > 0 {
			for _, m := range split.Feed(b) {
				msgs, _, err := radarsrv.ToolParseNetMsgs(m)
				if err != nil {
					notChain++
					continue
				}
				for _, x := range msgs {
					totalMsg++
					s := stats[x.Cmd]
					if s == nil {
						s = &cmdStat{}
						stats[x.Cmd] = s
					}
					s.n++
					s.byts += len(x.Body)
					// -ev 过滤：只在游戏事件通道上按 eventid 挑，其它 cmd 原样保留。
					if *wantEv >= 0 && x.Cmd == 207 {
						if id, ok := radarsrv.ToolGameEventID(x.Body); !ok || int(id) != *wantEv {
							continue
						}
					}
					allBodies[x.Cmd] = append(allBodies[x.Cmd], x.Body)
					if len(samples[x.Cmd]) < *nSample {
						samples[x.Cmd] = append(samples[x.Cmd], append([]byte(nil), x.Body...))
					}
				}
			}
		}
	}

	type row struct {
		cmd  uint32
		n    int
		byts int
	}
	var rows []row
	for c, s := range stats {
		rows = append(rows, row{c, s.n, s.byts})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].byts > rows[j].byts })

	fmt.Printf("帧 %d｜netmessage %d 条｜不是 netmessage 链的可靠消息 %d 条\n",
		len(frames), totalMsg, notChain)
	fmt.Println("按字节量排：")
	for _, r := range rows {
		avg := 0
		if r.n > 0 {
			avg = r.byts / r.n
		}
		fmt.Printf("  cmd=%-4d 条数=%-6d 字节=%-8d 均长=%d\n", r.cmd, r.n, r.byts, avg)
	}
	if *hist {
		return
	}

	if *wantCmd >= 0 {
		bodies := samples[uint32(*wantCmd)]
		fmt.Printf("\n===== cmd=%d 样本 %d 条 =====\n", *wantCmd, len(bodies))
		for i, b := range bodies {
			fmt.Printf("--- #%d len=%d ---\n%s\n", i, len(b), hex.EncodeToString(b))
			dumpProto(b, "  ")
		}
	}
	if *agg && *wantCmd >= 0 {
		fmt.Printf("\n===== cmd=%d 按首个 varint 字段聚合 =====\n", *wantCmd)
		type grp struct{ n, byts int }
		m := map[uint64]*grp{}
		for _, b := range allBodies[uint32(*wantCmd)] {
			tag, n := readUvarint(b)
			if n <= 0 || tag&7 != 0 {
				continue
			}
			v, k := readUvarint(b[n:])
			if k <= 0 {
				continue
			}
			g := m[v]
			if g == nil {
				g = &grp{}
				m[v] = g
			}
			g.n++
			g.byts += len(b)
		}
		var gs []struct {
			k uint64
			g *grp
		}
		for k, g := range m {
			gs = append(gs, struct {
				k uint64
				g *grp
			}{k, g})
		}
		sort.Slice(gs, func(i, j int) bool { return gs[i].g.byts > gs[j].g.byts })
		for _, x := range gs {
			fmt.Printf("  id=%-5d 条数=%-5d 字节=%-7d 均长=%d\n",
				x.k, x.g.n, x.g.byts, x.g.byts/x.g.n)
		}
	}

	// -out：把 -cmd 的全部 body 落成二进制，交给 Python 做深度解析。
	// 格式与 unrel 落盘一致：重复 [u32le 长度][body]，便于直接按偏移走查。
	if *outPath != "" && *wantCmd >= 0 {
		bodies := allBodies[uint32(*wantCmd)]
		var buf []byte
		for _, b := range bodies {
			var h [4]byte
			binary.LittleEndian.PutUint32(h[:], uint32(len(b)))
			buf = append(buf, h[:]...)
			buf = append(buf, b...)
		}
		if err := os.WriteFile(*outPath, buf, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "写 %s 失败: %v\n", *outPath, err)
		} else {
			fmt.Printf("\n已把 cmd=%d 的 %d 条 body（%d 字节，u32le 长度前缀）写到 %s\n",
				*wantCmd, len(bodies), len(buf), *outPath)
		}
	}

	if *doUnrel {
		fmt.Printf("\n===== 不可靠消息：%d 个 Num =====\n", len(unrelOrder))
		single, multi, lastN := 0, 0, 0
		var sizes []int
		for _, n := range unrelOrder {
			b := unrels[n]
			if len(b.parts) == 1 {
				single++
			} else {
				multi++
			}
			if b.last {
				lastN++
			}
			tot := 0
			for _, p := range b.parts {
				tot += len(p)
			}
			sizes = append(sizes, tot)
		}
		sort.Ints(sizes)
		fmt.Printf("  单分片 %d｜多分片 %d｜带 Last 标记 %d\n", single, multi, lastN)
		if len(sizes) > 0 {
			fmt.Printf("  重组后长度 min/中位/max = %d/%d/%d\n",
				sizes[0], sizes[len(sizes)/2], sizes[len(sizes)-1])
		}
		fmt.Println("  前 5 个 Num 的头部：")
		for i, n := range unrelOrder {
			if i >= 5 {
				break
			}
			b := unrels[n]
			var all []byte
			for _, p := range b.parts {
				all = append(all, p...)
			}
			head := all
			if len(head) > 24 {
				head = head[:24]
			}
			fmt.Printf("    Num=%d 分片=%d last=%v 总长=%d head=%s\n",
				n, len(b.parts), b.last, len(all), hex.EncodeToString(head))
		}
	}
	_ = binary.LittleEndian
}

// dumpProto 用最小的 protobuf 走查打印字段，用来判断某个 cmd 里有没有队伍/血量。
func dumpProto(b []byte, indent string) {
	i := 0
	for i < len(b) {
		start := i
		tag, n := readUvarint(b[i:])
		if n <= 0 {
			fmt.Printf("%s[%d] 非法 tag\n", indent, start)
			return
		}
		i += n
		field := tag >> 3
		wire := tag & 7
		switch wire {
		case 0:
			v, n := readUvarint(b[i:])
			if n <= 0 {
				fmt.Printf("%s[%d] varint 截断\n", indent, start)
				return
			}
			i += n
			fmt.Printf("%s[%d] field%-3d varint %d\n", indent, start, field, v)
		case 1:
			if i+8 > len(b) {
				fmt.Printf("%s[%d] fixed64 截断\n", indent, start)
				return
			}
			v := binary.LittleEndian.Uint64(b[i:])
			i += 8
			fmt.Printf("%s[%d] field%-3d fixed64 0x%x\n", indent, start, field, v)
		case 2:
			l, n := readUvarint(b[i:])
			if n <= 0 || i+n+int(l) > len(b) {
				fmt.Printf("%s[%d] len-delimited 截断 (len=%d)\n", indent, start, l)
				return
			}
			i += n
			data := b[i : i+int(l)]
			i += int(l)
			fmt.Printf("%s[%d] field%-3d bytes[%d] %s%s\n", indent, start, field, l,
				hex.EncodeToString(data), printable(data))
		case 5:
			if i+4 > len(b) {
				fmt.Printf("%s[%d] fixed32 截断\n", indent, start)
				return
			}
			v := binary.LittleEndian.Uint32(b[i:])
			i += 4
			fmt.Printf("%s[%d] field%-3d fixed32 0x%x\n", indent, start, field, v)
		default:
			fmt.Printf("%s[%d] field%-3d wire=%d（跳过解析）\n", indent, start, field, wire)
			return
		}
	}
}

func printable(b []byte) string {
	ok := 0
	for _, c := range b {
		if c >= 32 && c < 127 {
			ok++
		}
	}
	if len(b) == 0 || ok*100/len(b) < 80 {
		return ""
	}
	return "  " + string(b)
}

func readUvarint(b []byte) (uint64, int) {
	var v uint64
	var s uint
	for i := 0; i < len(b); i++ {
		c := b[i]
		v |= uint64(c&0x7F) << s
		if c < 0x80 {
			return v, i + 1
		}
		s += 7
		if s >= 64 {
			return 0, -1
		}
	}
	return 0, 0
}
