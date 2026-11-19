// 在「已知指针附近」定向扫 32 字节会话密钥。
//
// 为什么这条路能成
// --------------
// 10:12 现场把两件事同时钉死了：
//
//  1. `gnskdf` 证明 conn 对象里四个槽位（+0x1798/+0x17b8/+0x1988/+0x19b8）
//     **不是 blob 本体**，它们是指向别处的指针，而四段 cert/crypt 的字节
//     在 conn 对象（0x1a20 字节）里一个字都找不到。
//  2. 诊断报告里「指针槽位」那一节暴露了真正的位置：客户端私钥在
//     `0x22f3bdfecc0`，而四个槽位指针 `0x22f3bdfeaa0 / e940 / ebe0 / eb40`
//     **全在同一个 32 KB 区域** `0x22f3bdf7000` 里。
//
// 也就是说：**握手状态（含派生出来的密钥材料）集中在那个 32 KB 区域**。
// 而 GNS 的 CCrypto 用的是 OpenSSL `AES_KEY`（240 字节扩展密钥），
// 扩展密钥的前 32 字节就是原始密钥本身 —— 所以在 4 KB 窗口里扫不到
// 并不奇怪：CCrypto 只持有指向 AES_KEY 的指针，密钥在别处。
//
// 所以不猜 KDF 了：拿内存 IV 当 nonce、拿真实帧的 GCM 认证当判据，
// 在这几百 KB 里把密钥**找出来**。找到就能解密，不需要 KDF 正确。
//
// 这条路和 KDF 互不干扰：KDF 修好了用 KDF，修不好用这条。
package main

import (
	"sort"
	"time"

	"local/cs2-radar/internal/memscan"
)

// gnsNearSpan 是每个锚点向两侧各扩多少字节。
//
// 32 KB 的依据：现场那个握手区域本身就是 32 KB（`region_size: 32768`），
// 而私钥落在区域偏移 0x7cc0 —— 也就是说区域末尾附近。锚点都在区域里，
// 向两侧各扩 32 KB 必然把整个区域包住。
const gnsNearSpan = 0x8000

// gnsAnchorPointers 从 conn 里收集「可能指向密钥材料」的指针。
//
// 顺序有意义：先握手状态（四个槽位指针，私钥就在同一区域），
// 再 CCrypto，最后 conn 自己。先命中就先返回，省掉后面的扫描。
func gnsAnchorPointers(c gnsConn) []uintptr {
	var out []uintptr
	add := func(p uintptr) {
		if !plausiblePtr(p) {
			return
		}
		for _, q := range out {
			if q == p {
				return
			}
		}
		out = append(out, p)
	}

	// 四个槽位：第一个 qword 是数据指针；+0x1988 / +0x19b8 的第二个 qword
	// 现场看也是可读指针（像是一对 {data, end}），一并当锚点。
	for _, off := range []int{gnsOffBlob0, gnsOffBlob1, gnsOffBlob2, gnsOffBlob3} {
		if off+16 > len(c.Raw) {
			continue
		}
		add(uintptr(gnsLE64(c.Raw[off:])))
		add(uintptr(gnsLE64(c.Raw[off+8:])))
	}
	add(c.CryptT)
	add(c.CryptR)
	add(c.Addr)
	return out
}

// gnsMergeWindows 把 [lo,hi) 区间排序合并，避免重复扫描重叠部分。
func gnsMergeWindows(w [][2]uintptr) [][2]uintptr {
	if len(w) == 0 {
		return nil
	}
	sort.Slice(w, func(i, j int) bool { return w[i][0] < w[j][0] })
	out := [][2]uintptr{w[0]}
	for _, cur := range w[1:] {
		last := &out[len(out)-1]
		if cur[0] <= last[1] {
			if cur[1] > last[1] {
				last[1] = cur[1]
			}
			continue
		}
		out = append(out, cur)
	}
	return out
}

// gnsScanBufForKeys 在一个已读入的缓冲里逐字节开窗找密钥。
//
// 判据只有一条：GCM 认证标签。错一个字节必然失败，所以
// 「先 1 帧过 → 再用 3 帧复核」的两段式既快又不会误判。
func gnsScanBufForKeys(buf []byte, base uintptr, frames [][]byte, iv []byte,
	dir string, deadline time.Time, tried *int) (gnsMemResult, bool) {

	if len(buf) < 32 || len(frames) < 3 || len(iv) != 12 {
		return gnsMemResult{}, false
	}
	// 初筛只用**最新一帧**。
	//
	// gnsTryKey 对每帧都要试十几个 nonce 修正，帧数越多单次失败越贵：
	// 24 帧 × 12 修正 = 288 次 GCM，乘上几万个候选就是十几秒。
	// 而最新帧和「读内存那一刻」的序号差最小，修正量落在 0 附近的概率最高，
	// 所以单帧初筛既便宜又不会漏掉正确候选。
	last := frames[len(frames)-1:]
	for off := 0; off+32 <= len(buf); off++ {
		if off&0x3ff == 0 && time.Now().After(deadline) {
			return gnsMemResult{}, false
		}
		key := buf[off : off+32]
		if !plausibleKey(key) {
			continue
		}
		*tried++
		if gnsTryKey(key, iv, last, 1) < 1 {
			continue
		}
		// 再用 3 帧复核。GCM 误命中概率 2^-128，这里只是把「偶然」彻底排除。
		if n := gnsTryKey(key, iv, frames, 3); n >= 3 {
			return gnsMemResult{
				Key: append([]byte(nil), key...), IV: append([]byte(nil), iv...),
				Dir: dir, KeyAt: base + uintptr(off), Frames: n, Src: "锚点邻域",
			}, true
		}
	}
	return gnsMemResult{}, false
}

// gnsRecoverNearby 是这条路的主入口。
//
// framesByDir 里 "c2s" 用发送侧 IV、"s2c" 用接收侧 IV，但两把 IV 谁对应
// 哪个方向并没有现场证据（两端槽位是互换的），所以两种都试 ——
// 认证会判胜负，不用猜。
func gnsRecoverNearby(proc *memscan.Process, c gnsConn,
	framesByDir map[string][][]byte, deadline time.Time) (gnsMemResult, bool) {

	anchors := gnsAnchorPointers(c)
	if len(anchors) == 0 {
		return gnsMemResult{}, false
	}

	// 按方向组好 (帧, IV) 组合。某个方向帧不足 3 就跳过那组。
	type combo struct {
		dir    string
		frames [][]byte
		iv     []byte
	}
	var combos []combo
	if f := framesByDir["c2s"]; len(f) >= 3 {
		combos = append(combos, combo{"c2s", f, c.IV1}, combo{"c2s", f, c.IV2})
	}
	if f := framesByDir["s2c"]; len(f) >= 3 {
		combos = append(combos, combo{"s2c", f, c.IV2}, combo{"s2c", f, c.IV1})
	}
	if len(combos) == 0 {
		return gnsMemResult{}, false
	}

	// 每个锚点向两侧各扩 gnsNearSpan，合并重叠区间。
	wins := make([][2]uintptr, 0, len(anchors))
	for _, a := range anchors {
		lo, hi := uintptr(0), a+gnsNearSpan
		if a > gnsNearSpan {
			lo = a - gnsNearSpan
		}
		wins = append(wins, [2]uintptr{lo, hi})
	}
	wins = gnsMergeWindows(wins)

	var totalBytes, totalTried int
	t0 := time.Now()
	for _, w := range wins {
		if time.Now().After(deadline) {
			break
		}
		buf := gnsReadLenient(proc, w[0], int(w[1]-w[0]))
		if len(buf) < 32 {
			continue
		}
		totalBytes += len(buf)
		for _, cb := range combos {
			tried := 0
			if res, ok := gnsScanBufForKeys(buf, w[0], cb.frames, cb.iv, cb.dir,
				deadline, &tried); ok {
				totalTried += tried
				privateDiagnosticf(
					"[gnsnear] 命中：%d 个锚点 / 扫 %.1f KB / 试 %d 个窗口 / 耗时 %s\n",
					len(anchors), float64(totalBytes)/1024, totalTried,
					time.Since(t0).Truncate(time.Millisecond))
				res.Conn = c
				return res, true
			}
			totalTried += tried
		}
	}

	privateDiagnosticf(
		"[gnsnear] 锚点 %d 个 / 扫 %.1f KB / 试 %d 个窗口，都没通过 GCM 认证（耗时 %s）\n",
		len(anchors), float64(totalBytes)/1024, totalTried,
		time.Since(t0).Truncate(time.Millisecond))
	return gnsMemResult{}, false
}
