// gnsdiag 是 GNS 派生失败现场的离线复现工具。
//
// 现场失败一次是不可再生的：会话一结束私钥就没了，光看日志没法验证 KDF
// 到底差在哪。所以 tryGNS 失败时会落一个 `gns-diag-*.json`（握手材料 +
// 私钥 + 12 帧真实密文），这个工具就吃那个文件，在本地把各种写法都试一遍。
//
// 用法：
//
//	gnsdiag gns-diag-20261019-090000.json
//
// 输出：
//	- 每个「预主密钥写法 × 变体」的可解帧数，按可解数从高到低
//	- 最好那一组的四把材料（key / IV）
//	- 最好那一组解出来的第一帧明文（hex + 可打印字符）
//
// 只要有一组能解出 ≥1 帧，就说明握手材料和私钥是对的，只是变体还没覆盖到；
// 一帧都解不出，问题就在握手材料本身（字段取错 / 私钥不是这次的）。
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"local/cs2-radar/internal/cs2crypto"
)

type diag struct {
	Session      string   `json:"session"`
	ClientConnID string   `json:"client_conn_id"`
	ServerConnID string   `json:"server_conn_id"`
	ClientPub    string   `json:"client_eph_pub"`
	ServerPub    string   `json:"server_eph_pub"`
	ClientNonce  string   `json:"client_nonce"`
	ServerNonce  string   `json:"server_nonce"`
	ClientCert   string   `json:"client_cert"`
	ServerCert   string   `json:"server_cert"`
	ClientCrypt  string   `json:"client_crypt"`
	ServerCrypt  string   `json:"server_crypt"`
	ClientPriv   string   `json:"client_priv"`
	BestVariant  string   `json:"best_variant"`
	BestOKFrames int      `json:"best_ok_frames"`
	Frames       []string `json:"frames"`
}

type hit struct {
	name string
	ok   int
	keys *cs2crypto.GNSKeys
	pt   []byte
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "坏 hex: %v\n", err)
		os.Exit(2)
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: gnsdiag <gns-diag-*.json>")
		os.Exit(2)
	}
	os.Exit(run(os.Args[1]))
}

// run 是 main 的可测试内核：返回进程退出码。
func run(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读文件失败: %v\n", err)
		return 1
	}
	var d diag
	if err := json.Unmarshal(raw, &d); err != nil {
		fmt.Fprintf(os.Stderr, "解析失败: %v\n", err)
		return 1
	}

	h := &cs2crypto.GNSHandshake{
		ClientConnID: unhex(d.ClientConnID),
		ServerConnID: unhex(d.ServerConnID),
		ClientPub:    unhex(d.ClientPub),
		ServerPub:    unhex(d.ServerPub),
		ClientNonce:  unhex(d.ClientNonce),
		ServerNonce:  unhex(d.ServerNonce),
		ClientCert:   unhex(d.ClientCert),
		ServerCert:   unhex(d.ServerCert),
		ClientCrypt:  unhex(d.ClientCrypt),
		ServerCrypt:  unhex(d.ServerCrypt),
	}
	priv := unhex(d.ClientPriv)

	fmt.Printf("会话 %s\n", d.Session)
	fmt.Printf("  connID    %x → %x\n", h.ClientConnID, h.ServerConnID)
	fmt.Printf("  客户端临时公钥 %x\n", h.ClientPub)
	fmt.Printf("  服务器临时公钥 %x\n", h.ServerPub)
	fmt.Printf("  材料长度  cert=%d/%d  crypt=%d/%d\n",
		len(h.ClientCert), len(h.ServerCert), len(h.ClientCrypt), len(h.ServerCrypt))
	if err := h.Valid(); err != nil {
		fmt.Printf("  🔴 材料不合法: %v\n", err)
		return 1
	}

	frames := make([][]byte, 0, len(d.Frames))
	for _, s := range d.Frames {
		frames = append(frames, unhex(s))
	}
	fmt.Printf("  帧数      %d（上次最好一组「%s」解出 %d 帧）\n\n",
		len(frames), d.BestVariant, d.BestOKFrames)

	pms, pmNames, err := cs2crypto.GNSPremasters(priv, h)
	if err != nil {
		fmt.Printf("🔴 预主密钥算不出来: %v\n", err)
		fmt.Printf("   说明这把私钥和握手里的两个临时公钥都不配对 —— 私钥取错了，不是 KDF 的问题。\n")
		return 1
	}
	fmt.Printf("预主密钥两种写法都算出来了（sha256(dh) = %x…）\n", pms[0][:8])

	variants := cs2crypto.GNSVariants()
	var hits []hit
	for pi, pm := range pms {
		for _, v := range variants {
			keys := cs2crypto.GNSDeriveFromPremaster(pm, h, v)
			for _, dir := range []string{"recv", "send"} {
				key, iv := keys.RecvKey, keys.RecvIV
				if dir == "send" {
					key, iv = keys.SendKey, keys.SendIV
				}
				sch, err := cs2crypto.SchemeFromGNS(key, iv)
				if err != nil {
					continue
				}
				ok := 0
				var first []byte
				for _, f := range frames {
					if pt, err := sch.OpenFrame(0, f); err == nil {
						ok++
						if first == nil {
							first = pt
						}
					}
				}
				if ok > 0 {
					hits = append(hits, hit{
						name: pmNames[pi] + "/" + v.Name + "/" + dir,
						ok:   ok, keys: keys, pt: first,
					})
				}
			}
		}
	}

	if len(hits) == 0 {
		fmt.Printf("\n🔴 %d 组变体 × %d 帧，一帧都解不开。\n", len(pms)*len(variants)*2, len(frames))
		fmt.Printf("   下一步按这个顺序查：\n")
		fmt.Printf("   1) 握手材料是不是这次连接的（connID 对不上就会全灭）\n")
		fmt.Printf("   2) cert/crypt 是不是**线上原始子消息字节**（重新序列化会变）\n")
		fmt.Printf("   3) 私钥是不是客户端的临时密钥（不是 cert 里那把静态 Ed25519）\n")
		fmt.Printf("   4) 帧是不是真的 GNS 加密数据包（flags & 0x80）\n")
		return 1
	}

	sort.Slice(hits, func(i, j int) bool { return hits[i].ok > hits[j].ok })
	fmt.Printf("\n命中 %d 组（按可解帧数排序，前 10）：\n", len(hits))
	for i, x := range hits {
		if i >= 10 {
			break
		}
		fmt.Printf("  %3d/%d  %s\n", x.ok, len(frames), x.name)
	}
	top := hits[0]
	fmt.Printf("\n最好一组：%s（%d/%d 帧）\n", top.name, top.ok, len(frames))
	fmt.Printf("  SendKey %x\n  RecvKey %x\n  SendIV  %x\n  RecvIV  %x\n",
		top.keys.SendKey, top.keys.RecvKey, top.keys.SendIV, top.keys.RecvIV)
	if top.pt != nil {
		fmt.Printf("  首帧明文（%d 字节）%x\n", len(top.pt), top.pt)
		fmt.Printf("  可打印：%q\n", printable(top.pt))
	}
	return 0
}

func printable(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, '.')
		}
	}
	return string(out)
}
