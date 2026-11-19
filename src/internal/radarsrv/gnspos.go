package radarsrv

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"local/cs2-radar/internal/cs2proto"
)

// 本文件解 CS2 的 `svc_SosStartSoundEvent`（现场定案：cmd=208）。
//
// 🔴🔴 语义纠正（硬规则 290，2026-10-20 12:00）：
// 这个文件原来叫「实体位置消息」，那是错的。cmd=208 是**声音开始事件**。
// 字段号逐项对得上公开定义 `CMsgSosStartSoundEvent`：
//
//	field 1  varint   —— soundevent_guid（现场每条 +1）
//	field 2  fixed32  —— soundevent_hash（现场 0x473554ca = 声音种类）
//	field 3  varint   —— source_entity_index（发声实体，现场范围 66..511）
//	field 4  varint   —— seed（与 field 1 相同）
//	field 5  bytes    —— packed_params（位打包声音参数，**内含发声原点**）
//
// blob（packed_params）的字节布局（30 字节，1709/1722 条如此）：
//
//	[0..3]   4d ce 7c 5a     4 字节常量 —— 固定 schema 头（147 条样本里只有 1 种取值）
//	[4..5]   0a 0c           常量
//	[6]      00              常量
//	[7..18]  x, y, z         三个 float32 小端 —— **声音原点**
//	[19..21] 41 e1 1b        多数恒定
//	[22..25] d9 02 04 00     恒定
//	[26..29] 4 字节          声音种类哈希长尾（147 条样本里 40 种）
//
// 判据（三条都成立才采信）：
//   - blob[4]==0x0a && blob[5]==0x0c（这是参数块的位置标记）；
//   - 三个 float 都是有限数且 |v| < 20000（CS2 地图量级）；
//   - x、y 不同时接近 0（过滤掉空槽位的零值）。
//
// 🔴 为什么它不能当人物位置用（三条独立证据）：
//  1. **数据形态**：packed_params 前 4 字节 147 条里只有 1 种（固定 schema 头），
//     后 4 字节 40 种（声音种类）—— 不是坐标该有的形态。
//  2. **决定性反证**：`ent=366 (246.3,439.5,1652.0)` 与 `ent=78 (246.3,439.5,1616.0)`
//     —— 两个不同 entity 同一瞬间 **XY 完全相同、Z 差 36**（脚下 vs 上身）。
//     pawn 只有一个位置 ⇒ 只能是同一处发出的两个声音。
//  3. **吞吐曲线**：9 人局 964→990 条，1v1 局整局 **41 条**。人少→声音少。
//
// ⇒ 产物只进 `Snapshot.Sounds`（声音层），**绝不进 `Snapshot.Players`**。
const (
	// gnsCmdEntityPos 是位置消息的 netmessage cmd。
	gnsCmdEntityPos = 208
	// gnsPosBlobMark0/1 是 blob 里坐标块的位置标记。
	gnsPosBlobMark0 = 0x0a
	gnsPosBlobMark1 = 0x0c
	// gnsPosBlobMin 是能装下坐标块的最小 blob 长度（7 + 12）。
	gnsPosBlobMin = 19
	// gnsPosBlobFull 是**带尾部标签**的完整 blob 长度。
	//
	// 08:14 那局实测：292 条里 257 条是 30 字节、29 条是 19 字节（没有尾部）。
	// 尾部 = [19:23] 41 e1 1b d9（常量）+ [23:26] 02 04 00（常量）+ [26:30] 变值。
	gnsPosBlobFull = 30
	// gnsPosBlobOff 是声音原点在 blob 里的偏移。
	gnsPosBlobOff = 7
	// gnsPosLimit 是坐标的合理量级上限（CS2 最大地图也就几万单位）。
	gnsPosLimit = 20000.0
	// gnsPosFresh 是「这个声源还在活跃发声」的判定阈值，**只用于统计和日志**。
	gnsPosFresh = 6 * time.Second
	// gnsPosTTL 是诊断层（gnsPlayerSnapshot）保留条目的时长。
	//
	// 🔴 它**不控制画面**了 —— 硬规则 290 之后画面画的是声音层，用 gnsSoundTTL=5 秒。
	// 这个值现在只影响「诊断保留多少个声源」那几行日志。
	//
	// 历史：原来是 6 秒，10:04 那局证明太短（用户确认现场 5 人）：
	//
	//	过滤后 5 个玩家中 2 个在 6 秒内更新过；较旧： 47:32.0s 266:24.8s 510:19.6s
	//
	// 当时的解释是「cmd=208 是增量下发」—— **那个解释已被硬规则 290 推翻**：
	// 208 是**声音事件**，32 秒没消息的真实含义是「这 32 秒没有发出声音」，
	// 和玩家动没动没有必然关系。所以放宽 TTL 从来就不是正解。
	gnsPosTTL = 20 * time.Second
	// gnsSoundTTL 是声音事件在「声音层」里保留多久（硬规则 290）。
	//
	// 声音是瞬时事件：脚步、枪声各响一下就过去了。留 20 秒会把画面堆成一团，
	// 而且会让人误以为那是「当前位置」。5 秒足够看出「那边刚才有人活动」，
	// 又不会积累成假目标。年龄照常传给前端做渐隐。
	gnsSoundTTL = 5 * time.Second
	// gnsPosMax 是同时保留的实体上限，防止异常数据把内存吃满。
	gnsPosMax = 1024

	// ---- 道具过滤（硬规则 276）----
	//
	// 判据是**采样密度**，不是实体索引范围。09:26 那局实测：
	//   43 个实体，采样数前 5 名 = 331 / 303 / 151 / 99 / 70
	//   第 6 名直接掉到 13 条  ⇒ 断崖 5.4 倍
	// 而 cmd=60 恰好 5 个玩家；同一局「索引 0-63」只有 4 个实体，**对不上**。
	// ⇒ 索引范围那条路是错的，采样密度才是真的。
	//
	// 但这三个门槛必须都在，否则就是把「猜」写进了渲染：
	//
	// 🔴 gnsFilterMinTotal 原来是 40，11:24 那局（用户确认「最开始 2 人，后面持续 1 人」）
	// 把它顶死了：那局整局只有 **39 条**采样（1v1 里 cmd=208 几乎不出数据），
	// 39 < 40 ⇒ 函数在第一个门槛就静默返回，**过滤一次都没跑过**，
	// 画面上 16 个实体全画出来，而现场只有 1~2 个人。
	// 现在降到 12，并且把「样本够不够」的判据移到**榜首条数**上（见 gnsFilterMinTopN）——
	// 总量被一堆 1 条的道具稀释时，真正决定排名可信度的是第一名有多少条。
	gnsFilterMinTotal = 12
	// gnsFilterMinTopN 是「榜首至少要有这么多条采样」，否则排名就是噪声。
	//
	// 11:24 局榜首 `0:19`、第二名 `213:3` —— 19 条足够支撑 7.6× 的断崖；
	// 而开局头两秒榜首只有 1~2 条时，谁排第一纯属偶然。
	gnsFilterMinTopN = 6
	// gnsFilterMinTop 是「参与比值的实体至少这么多条」。
	//
	// 🔴 原来是 8，10:52 局证明这个值直接把判据毁掉了：那局第 8 名只有 3 条，
	// 循环在那里 break，**真正的 3.0× 分界（第 9/10 名之间）根本没被看到**，
	// 于是选了头部玩家区内部的假断崖 2.0× ⇒ 画面上只剩 2 个点（用户说 9 人）。
	// 现在只要 2 条 —— 1 条 vs 1 条没有意义，2 条 vs 1 条已经是 2 倍。
	gnsFilterMinTop   = 2
	gnsFilterCliff    = 2.0  // 相邻速率的最大断崖必须 ≥ 这个倍数
	// gnsFilterMinRate 是「玩家区」的速率下限（条/秒）。
	//
	// 实测：真人 0.26~1.45 条/秒；道具 0.05~0.12 条/秒（10:14 局 110 秒里道具 13 条）。
	//
	// 🔴 硬规则 288 之后它**只剩一个用途**：`gnsFilterPremiseSlack` 那道前提校验
	// （无断崖时按 cmd=60 兜底，要求边界后实体速率 <= 0.15×1.5）。
	// 原来还拿它当「断崖候选」的筛选条件，11:04 局道具速率 0.17~0.29 直接把全部候选否掉了。
	gnsFilterMinRate = 0.15
	// gnsRateMinSpan 是算速率时观察窗口的下限。
	//
	// 🔴 为什么要这个下限：中途加入的人只观察了几秒，条数除以极小的秒数会算出
	// 虚高的速率（1 条 / 2 秒 = 0.5 条/秒，比老玩家还快）。
	// 给它 20 秒的地板，既不会冤枉新人，也不会让「刚出现 1 条的道具」冲到榜首。
	gnsRateMinSpan = 20 * time.Second
	// gnsFilterSlack 是「cmd=60 人数」允许的偏差余量。
	//
	// 🔴 09:39 局实测 cmd=60 报 9 人、现场实际 8 人（用户确认），偏 +1。
	// 所以人数不能当准数用，只当上限兜底：真正的 N 由最大断崖自己找，
	// 搜索范围给到 cmd=60 的人数 + 这个余量。
	gnsFilterSlack = 4
	// gnsAnchorSlack 是「用 cmd=60 人数锚定断崖结果」时允许的**向下**余量（硬规则 287）。
	//
	// 断崖切出的数量和 cmd=60 的人数差在这个范围内就信断崖，
	// 超出就按 cmd=60 修正：
	//   - 断崖 > cmd=60  ⇒ 压回 cmd=60（多出来的实体速率介于真人和道具之间，画上去只会变花）
	//   - 断崖 < cmd=60-2 ⇒ 抬到 cmd=60-2（宁可多画道具，不能藏真人）
	//
	// 七局验证：09:26→5｜09:39→8（cmd60 报 9）｜09:47→9｜10:04→5｜10:14→7｜
	// 10:52→9｜10:44→8（断崖切 9，压回 8）
	gnsAnchorSlack = 2
	// gnsFilterPremiseSlack 是「没有断崖时按 cmd=60 人数兜底」的前提校验余量（硬规则 287）。
	//
	// 兜底之前要确认「cmd=60 边界后面的实体确实已经是道具」，判据是它的速率
	// <= gnsFilterMinRate × 这个系数 = 0.225。
	//
	// 为什么要留 1.5 倍：10:44 局那个实体在相邻两次统计里是 0.15 / 0.14
	// （3 条 ÷ 20.0 秒 与 3 条 ÷ 20.5 秒）。卡在 0.15 上会被 0.01 的抖动翻转，
	// 留 1.5 倍就不会。而平滑衰减场景（0.40→0.21）里边界后是 0.35，
	// 离 0.225 还有距离 —— 该拦住的一个都不会漏。
	gnsFilterPremiseSlack = 1.5
)

// gnsPosEntry 是一个声源实体的最新声音原点。
type gnsPosEntry struct {
	Pos cs2proto.Vec3
	At  time.Time
}

// gnsParsePosMsg 从 cmd=208 的 body 里取出「声源实体索引 + 声音原点 + 种类标签」。
//
// 🔴 硬规则 290：cmd=208 是 `svc_SosStartSoundEvent`，取出来的是**声音原点**，
// 不是人物位置。函数名里的 Pos 沿用旧名，语义已按 290 纠正。
//
// 只用最保守的判据：field 3 当 source_entity_index、field 5 当 packed_params、
// 里面 0a 0c 之后是 xyz。任何一步不合规就返回 false ——
// 宁可少画一个声音圈，也不要画幽灵。
//
// 第三个返回值是 blob 尾部 4 字节（blob[26:30]，blob 不足 30 字节时为 0）。
// 147 条样本里它有 **40 种取值**（`ac596a70×24 91b642a1×21 3ed3f792×14 …`），
// 长尾分布 ⇒ 是**声音种类哈希**，不是坐标也不是类哈希。
func gnsParsePosMsg(body []byte) (ent uint32, pos cs2proto.Vec3, tail uint32, ok bool) {
	var (
		haveEnt bool
		blob    []byte
	)
	off := 0
	for off < len(body) {
		key, n, ok2 := readGNSVarint(body[off:])
		if !ok2 || n == 0 {
			return 0, pos, 0, false
		}
		off += n
		tag, wt := key>>3, key&7
		switch wt {
		case 0:
			v, n2, ok3 := readGNSVarint(body[off:])
			if !ok3 {
				return 0, pos, 0, false
			}
			off += n2
			if tag == 3 {
				ent = uint32(v)
				haveEnt = true
			}
		case 1:
			off += 8
		case 5:
			off += 4
		case 2:
			l, n2, ok3 := readGNSVarint(body[off:])
			if !ok3 || off+n2+int(l) > len(body) {
				return 0, pos, 0, false
			}
			off += n2
			if tag == 5 {
				blob = body[off : off+int(l)]
			}
			off += int(l)
		default:
			return 0, pos, 0, false
		}
		if off > len(body) {
			return 0, pos, 0, false
		}
	}
	if !haveEnt || len(blob) < gnsPosBlobMin {
		return 0, pos, 0, false
	}
	if blob[4] != gnsPosBlobMark0 || blob[5] != gnsPosBlobMark1 {
		return 0, pos, 0, false
	}
	x := math.Float32frombits(binary.LittleEndian.Uint32(blob[gnsPosBlobOff:]))
	y := math.Float32frombits(binary.LittleEndian.Uint32(blob[gnsPosBlobOff+4:]))
	z := math.Float32frombits(binary.LittleEndian.Uint32(blob[gnsPosBlobOff+8:]))
	for _, v := range []float32{x, y, z} {
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > gnsPosLimit {
			return 0, pos, 0, false
		}
	}
	if math.Abs(float64(x)) < 0.01 && math.Abs(float64(y)) < 0.01 {
		return 0, pos, 0, false
	}
	if len(blob) >= gnsPosBlobFull {
		tail = binary.LittleEndian.Uint32(blob[gnsPosBlobFull-4:])
	}
	return ent, cs2proto.Vec3{X: x, Y: y, Z: z}, tail, true
}

// noteGNSPlayerPos 记录一个实体的位置。调用方必须持有 sess.mu。
func (sess *Session) noteGNSPlayerPos(ent uint32, pos cs2proto.Vec3, now time.Time) {
	if sess.gnsPos == nil {
		sess.gnsPos = make(map[uint32]gnsPosEntry, 128)
	}
	if len(sess.gnsPos) >= gnsPosMax {
		// 简单清理：丢掉已过期的；还满就放弃这一条，不扩容。
		for k, e := range sess.gnsPos {
			if now.Sub(e.At) > gnsPosTTL {
				delete(sess.gnsPos, k)
			}
		}
		if len(sess.gnsPos) >= gnsPosMax {
			return
		}
	}
	sess.gnsPos[ent] = gnsPosEntry{Pos: pos, At: now}
	sess.gnsPosTotal++
	if sess.gnsPosEnts == nil {
		sess.gnsPosEnts = make(map[uint32]int, 128)
	}
	sess.gnsPosEnts[ent]++
	// 第一次见到这个实体时记下时间 —— 算速率要用「它自己的观察窗口」，
	// 不能用会话总时长（中途加入的人会被冤枉成低频，见 gnsEntityRate）。
	if sess.gnsPosSeenAt == nil {
		sess.gnsPosSeenAt = make(map[uint32]time.Time, 128)
	}
	if _, ok := sess.gnsPosSeenAt[ent]; !ok {
		sess.gnsPosSeenAt[ent] = now
	}
}

// noteGNSPosTail 记一次 blob 尾部标签。调用方必须持有 sess.mu。
//
// 只统计、不判定：这个值到底是类哈希、脏位掩码还是别的，08:14 那局的数据
// 还分不出来（同一个实体会换值 ⇒ 不像类哈希；只有 5~6 种取值 ⇒ 也不像随机）。
// 先把它按实体数摊开看，下一局再定。
func (sess *Session) noteGNSPosTail(tail uint32) {
	if tail == 0 {
		return
	}
	if sess.gnsPosTail == nil {
		sess.gnsPosTail = make(map[uint32]int, 16)
	}
	sess.gnsPosTail[tail]++
}

// gnsTopBytes 把「字节值 → 次数」直方图排成日志用的字符串，形如 " 02×2630 04×410"。
//
// 不可靠消息的格式还没定，首字节分布是判断「这批数据是不是同一类」的第一手依据。
func gnsTopBytes(m map[byte]int, n int) string {
	type kv struct {
		k byte
		v int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	if len(arr) > n {
		arr = arr[:n]
	}
	var b strings.Builder
	for _, e := range arr {
		fmt.Fprintf(&b, " %02x×%d", e.k, e.v)
	}
	return b.String()
}

// gnsTopLens 把「长度 → 次数」直方图排成日志用的字符串。
func gnsTopLens(m map[int]int, n int) string {
	type kv struct {
		k int
		v int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	if len(arr) > n {
		arr = arr[:n]
	}
	var b strings.Builder
	for _, e := range arr {
		fmt.Fprintf(&b, " %d×%d", e.k, e.v)
	}
	return b.String()
}

// gnsEntityRate 是某个实体的「平均采样速率」（条/秒），从**它自己第一次出现**算起。
// 调用方必须持有 sess.mu。
//
// 🔴 为什么要除以「自己的观察窗口」而不是会话总时长（硬规则 282）：
// 10:14 局中途有两个人加入（cmd=60 从 5 人 → 6 人 → 7 人），
// 用累计条数排名时，后加入的人条数天然低，和道具撞在一起，
// 最大断崖从 3~7 倍被磨平到 1.7 倍 ⇒ 过滤整个失效、画面上 48 个点。
//
// 换成速率就分得开：真人不管什么时候加入，速率都在 0.2~1.5 条/秒；道具始终在 0.12 以下。
func (sess *Session) gnsEntityRate(ent uint32, now time.Time) float64 {
	n := sess.gnsPosEnts[ent]
	if n <= 0 {
		return 0
	}
	first := sess.gnsPosSeenAt[ent]
	if first.IsZero() {
		return 0
	}
	span := now.Sub(first)
	if span < gnsRateMinSpan {
		span = gnsRateMinSpan
	}
	return float64(n) / span.Seconds()
}

// gnsPlayerLike 按**采样速率**挑出「像玩家」的实体索引（硬规则 276 / 278 / 282）。
// 调用方必须持有 sess.mu。
//
// 依据（多局实测，不是推测）：
//
//	09:26 局  43 实体  331 303 151 99 70 | 13 12 11 ...     断崖 70÷13  = 5.38×  → 5 人
//	09:39 局  46 实体  225 142 141 105 76 70 65 54 | 13 13  断崖 54÷13  = 4.15×  → 8 人
//	10:04 局  44 实体  267 138 126 94 84 | 12 11 11 10      断崖 84÷12  = 7.00×  → 5 人
//	                                                    ↑ 三局都被用户确认人数
//
// 🔴 **N 必须从分布里自己找，不能用 cmd=60 的人数。**
// 09:39 局 cmd=60 报 9 人（userid 1 2 3 5 6 11 13 14 15），而现场实际 8 人。
// 拿 9 当 N 就会去看第 9/10 名（13→13 = 1.0×），判定「没有断崖」而把过滤整个关掉。
//
// 🔴 **排序依据是「条/秒」，不是「条数」（硬规则 282）。**
// 10:14 局中途有两个人加入（userid 8 然后 userid 3），累计条数断崖被磨平到 1.7×，
// 过滤整个失效、画面上 48 个点。原因是：后加入的人只有几十秒的观察窗口，
// 累计条数天然低，和道具撞在一起。换成「条数 ÷ 自己的观察时长」就分得开了 ——
// 真人不管什么时候加入，速率都在 0.2~1.5 条/秒；道具始终在 0.1 以下。
//
// 返回 (保留集合, 说明)。保留集合为 nil 表示**本局不启用过滤**，渲染照旧。
//
// 🔴 为什么必须带断崖校验：如果本局速率平滑衰减（没有明显分界），
// 说明「服务端优先刷真人」这个前提不成立，那排名前 N 就是纯噪声。
// 这种情况下**宁可多画几个道具，也不能把真人藏掉** —— 藏掉真人是致命的，
// 多画一个道具只是碍眼。这也是硬规则 275 的延续。
func (sess *Session) gnsPlayerLike(now time.Time) (map[uint32]bool, string) {
	players := len(sess.gnsPlayers)
	if players < 2 {
		// 人数未知（cmd=60 还没到）或单机 —— 连上限兜底都没有，不做。
		return nil, ""
	}
	total, maxN := 0, 0
	for _, c := range sess.gnsPosEnts {
		total += c
		if c > maxN {
			maxN = c
		}
	}
	// 两道门槛缺一不可（硬规则 289）：
	//   - 总量太小 ⇒ 整局还没开始
	//   - 榜首太少 ⇒ 排名纯噪声（一堆 1~2 条的道具谁排第一都是偶然）
	if total < gnsFilterMinTotal || maxN < gnsFilterMinTopN {
		return nil, ""
	}

	type entRate struct {
		idx  uint32
		n    int
		rate float64
		// fresh 表示这个实体**还在被刷新**（最近 gnsPosFresh 秒内有新位置）。
		//
		// 🔴 这是 11:04 那局（用户确认 8 人）逼出来的（硬规则 288）。
		// 那局的速率榜前 16：
		//
		//	0:1.94  354:1.90  372:1.06  258:1.00  101:0.93  626:0.83  986:0.74  762:0.70
		//	122:0.57  180:0.29  74:0.24  118:0.23  73:0.23  191:0.22  128:0.20  453:0.17
		//
		// 看着像「8 个人 + 一个 0.57 的第 9 人」，其实 122 是**冻结的道具**：
		// 整局它的条数一直是 12（10:47 `122:12@0.60`、11:06 `122:12@0.57`），
		// 一次都没涨过。它的「速率」只是 12 除以越来越长的窗口 —— 纯衰减假象。
		// 74:13、73:13、118:6、453:12 也是同一批冻结条目。
		//
		// 把「还在刷新」排到前面以后，前 8 名之后紧接的是 180:0.29，
		// 断崖 0.70→0.29 = 2.41× ⇒ 正好切出 8 个。**冻结条目根本进不了候选区**。
		fresh bool
	}
	list := make([]entRate, 0, len(sess.gnsPosEnts))
	for ent, c := range sess.gnsPosEnts {
		fresh := false
		if e, ok := sess.gnsPos[ent]; ok {
			fresh = now.Sub(e.At) <= gnsPosFresh
		}
		list = append(list, entRate{ent, c, sess.gnsEntityRate(ent, now), fresh})
	}
	// 排序：**还在刷新的优先**，然后速率降序、条数降序、索引升序。
	// 后三级只是为了让 map 遍历顺序不影响结果。
	sort.Slice(list, func(i, j int) bool {
		if list[i].fresh != list[j].fresh {
			return list[i].fresh
		}
		if list[i].rate != list[j].rate {
			return list[i].rate > list[j].rate
		}
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].idx < list[j].idx
	})
	if len(list) < 3 {
		// 少于 3 个实体时任何排名都没有说服力。
		return nil, ""
	}

	// 找**人/道具分界**：在候选区里取**比值最大**的那个 ≥ gnsFilterCliff 的断崖。
	//
	// 🔴 为什么是「比值最大」而不是「最靠后」（硬规则 289 修正硬规则 288）：
	//
	// 11:24 那局（1v1）道具全是 1~2 条，速率 0.01~0.03。里面随便一个
	// `0.03→0.02` 就是 2.0×，`0.02→0.01` 也是 2.0× —— **道具区内部全是"合格断崖"**。
	// 「最靠后」会一路滑到道具堆里，切出 4 个、被锚点压回 3 个，
	// 而真正的分界是 `0:19@0.38` vs `213:3@0.05` = **7.6×**，只切出 1 个。
	//
	// 10:52 局那个「头部 2.0× 抢了真分界 3.0×」的问题（硬规则 284）**不是"最大比值"造成的**，
	// 是 `gnsFilterMinTop=8` 把搜索范围砍断了造成的 —— MinTop 改成 2 之后
	// 真分界 3.0× > 头部 2.0×，最大比值自然选对。八局实测全部吻合：
	//
	//	09:26 5.38×→5 ｜09:39 4.15×→8 ｜09:47 3.64×→9 ｜10:04 7.00×→5
	//	10:14 2.20×→7 ｜10:52 3.00×→9 ｜10:44 2.80×→9(锚定 8) ｜11:04 2.41×→8
	//
	// 🔴 同时删掉了「切点后面必须 <= gnsFilterMinRate(0.15)」那道绝对门槛（硬规则 288）：
	// 11:04 局的道具速率是 0.17~0.29，**远高于 0.15**，那道门槛让全部候选被否，
	// 日志打成「最多切出 0 个 ⇒ 本局不启用过滤」，画面上 44 个点。
	// 绝对速率不跨局（同硬规则 285 的教训），只能相对比。
	limit := len(list) - 1
	if players+gnsFilterSlack < limit {
		limit = players + gnsFilterSlack
	}
	bestN, bestRatio := 0, 0.0
	// topRatio 只是给日志用：整个候选区里最大的断崖是多少。
	// 它和 bestRatio 的区别只在「最大值没到门槛」时看得出来 ——
	// 那时 bestN 仍是 0，说明里要报 topRatio 而不是 0.0。
	topRatio := 0.0
	for i := 1; i < limit; i++ {
		// 只要求「至少 2 条」—— 1 条 vs 1 条没有意义，2 条 vs 1 条已经是 2 倍。
		// 用 continue 而不是 break：break 会让后面更靠后的真分界永远看不到，
		// 那就是硬规则 284 的 bug 本身。
		if list[i-1].n < gnsFilterMinTop {
			continue
		}
		// 后面是 0 的话比值无穷大，会把「最后一个有数据的实体」永远选成最优。
		// 用 gnsFilterMinRate 当分母估一个有限值。
		den := list[i].rate
		if den <= 0 {
			den = gnsFilterMinRate
		}
		ratio := list[i-1].rate / den
		if ratio > topRatio {
			topRatio = ratio
		}
		if ratio >= gnsFilterCliff && ratio > bestRatio {
			bestN, bestRatio = i, ratio
		}
	}
	// 只留 1 个太激进：那等于把除本地玩家外所有人都藏了。
	// （双人局里一个近一个远，速率比很容易超过 2 倍，但两个人都是真人。）
	// 处理方式不是「整个关掉过滤」，而是让下面的锚点把它抬到 2（见 gnsAnchorSlack）。
	//
	// 🔴 完全没有断崖（bestN==0）时**不直接放弃**（硬规则 287）。10:44 局现场：
	//
	//	0:2.15  626:1.15  101:0.89  986:0.60  258:0.32  350:0.25  349:0.24
	//	271:0.15  1016:0.14 | 280:0.05  381:0.05        ← 用户确认 8 人
	//
	// 前一次统计 1016 是 **0.15**（3 条 / 20.0 秒），后一次是 **0.14**（3 条 / 20.5 秒）。
	// 窗口差 0.5 秒就让「切点速率 < 0.15」这道校验把整个过滤否掉，
	// 画面上从 8 个点变成 11 个 —— 这是**浮点边界抖动**，不是判据失效。
	// 271 和 1016 的速率一个是真人一个是道具，**速率根本分不开**，
	// 所以这时候唯一可用的信息就是 cmd=60 说的人数。
	if bestN == 0 {
		// 硬规则 287：没有可用断崖时，用 cmd=60 的人数兜底 —— **但必须先验证模型前提**。
		//
		// 前提是「服务端优先刷真人、道具速率明显低」。验证方式很直接：
		// cmd=60 边界**后面**那个实体必须已经落进道具区
		// （<= gnsFilterMinRate × gnsFilterPremiseSlack = 0.225）。
		//
		// 为什么必须验证：平滑衰减场景（0.40→0.39→…→0.21，见 TestGNSPlayerLikeNoCliff）
		// 里前 5 名全是道具，按人数硬切就是把真人藏掉 —— 那是硬规则 275 的底线。
		// 七局现场实测里边界后的实体都在 0.05~0.15，这道验证从没误伤过。
		if players >= 2 && players <= len(list)-1 &&
			list[players].rate <= gnsFilterMinRate*gnsFilterPremiseSlack {
			keep := make(map[uint32]bool, players)
			var b strings.Builder
			for i := 0; i < players; i++ {
				keep[list[i].idx] = true
				fmt.Fprintf(&b, " %d", list[i].idx)
			}
			return keep, fmt.Sprintf("没有明显断崖（最大 %.1f×，需 ≥%.1f×）⇒ 直接按 cmd=60 的 %d 人保留｜索引%s",
				topRatio, gnsFilterCliff, players, b.String())
		}
		return nil, fmt.Sprintf("采样速率最大断崖只有 %.1f×（需 ≥%.1f×，且 cmd=60 边界后仍是玩家速率）⇒ 没有明显分界，本局不启用过滤",
			topRatio, gnsFilterCliff)
	}

	// 用 cmd=60 的人数做**锚点修正**（硬规则 287）。
	//
	// 断崖给出「数据上像人」的数量，cmd=60 给出「服务器说有几个人」：
	//   - 断崖切多了（超过 cmd=60）⇒ 压回 cmd=60。多出来的那个实体速率介于
	//     真人和道具之间，画上去只会让画面变花。
	//   - 断崖切少了（< cmd=60 - gnsAnchorSlack）⇒ 抬到 cmd=60 - slack。
	//     宁可多画道具，不能藏真人。
	//
	// 🔴 为什么不再用 `切点速率 < gnsFilterMinRate` 当硬校验：
	// 那个值是按 10:14 局定的（真人 0.26~1.45）。10:44 局真人只有 0.15~2.15，
	// 切点正好落在 0.15 附近，0.01 的抖动就翻转整个结果。
	// **绝对速率门槛不跨局**（同硬规则 285 的教训）。
	anchored := ""
	if players >= 2 && players <= len(list) {
		lo, hi := players-gnsAnchorSlack, players
		// hi 不能等于 len(list)：下面 return 里要读 list[bestN] 打「断崖后一个」的速率。
		// cmd=60 报的人数等于实体总数时本来就没有可切的东西，直接留 len-1。
		if hi > len(list)-1 {
			hi = len(list) - 1
		}
		// 只留 1 个太激进：那等于把除本地玩家外所有人都藏了。
		// 双人局里一个近一个远，速率比很容易超过 2 倍，但两个人都是真人。
		if lo < 2 {
			lo = 2
		}
		if lo > hi {
			lo = hi
		}
		switch {
		case bestN > hi:
			anchored = fmt.Sprintf("｜断崖切出 %d 个 > cmd=60 的 %d 人 ⇒ 压回 %d", bestN, players, hi)
			bestN = hi
		case bestN < lo:
			anchored = fmt.Sprintf("｜断崖只切出 %d 个 < cmd=60 的 %d 人 -%d ⇒ 抬到 %d",
				bestN, players, gnsAnchorSlack, lo)
			bestN = lo
		}
	}

	keep := make(map[uint32]bool, bestN)
	var b strings.Builder
	for i := 0; i < bestN; i++ {
		keep[list[i].idx] = true
		fmt.Fprintf(&b, " %d", list[i].idx)
	}
	// 说明里把 cmd=60 的人数一起写出来，**差几个人要肉眼可见**。
	// 09:39 局就是 cmd=60 报 9、实际 8 —— 不写出来就永远发现不了这个偏差。
	note := ""
	if players != bestN {
		note = fmt.Sprintf("｜cmd=60 报 %d 人（差 %+d）", players, players-bestN)
	}
	return keep, fmt.Sprintf("保留 %d/%d｜索引%s｜断崖 %.2f→%.2f 条/秒（%.1f×）%s%s",
		bestN, len(list), b.String(),
		list[bestN-1].rate, list[bestN].rate, bestRatio, note, anchored)
}

// gnsKeepFreshness 统计「保留集合里有多少个是**活跃刷新**的」。调用方必须持有 sess.mu。
//
// 🔴 为什么要单独打这个：09:47 局 9 个玩家被**正确**保留（用户确认现场 9 人），
// 但同一行 `活跃 6` —— 只有 6 个在 6 秒内更新过。10:04 局更极端：5 个玩家只有 2 个活跃，
// 另外 3 个分别 32.0s / 24.8s / 19.6s 没更新。
//
// 这不是过滤的错（保留数是对的），但**用户看到点数少于人数一定会以为是过滤漏了**。
// 所以必须能区分两种完全不同的情况：
//
//	「过滤保留 9，其中 6 个活跃」  ← 3 个站着不动/死亡/不在 PVS，正常
//	「过滤只保留了 6」              ← 判据出问题，要查
//
// 注意这里的「活跃」用 gnsPosFresh（6 秒），而**不是** gnsPosTTL（20 秒）——
// 后者只决定「要不要从画面移除」，两个概念不能混。
//
// 返回 (活跃数, 不活跃那几个的描述)。
func (sess *Session) gnsKeepFreshness(now time.Time, keep map[uint32]bool) (int, string) {
	type entAge struct {
		idx uint32
		d   time.Duration
	}
	fresh := 0
	olds := make([]entAge, 0, len(keep))
	for ent := range keep {
		e, ok := sess.gnsPos[ent]
		if !ok {
			// 保留集合是从 gnsPosEnts（累计）来的，gnsPos（当前）可能已经把它清掉了。
			olds = append(olds, entAge{ent, -1})
			continue
		}
		d := now.Sub(e.At)
		if d <= gnsPosFresh {
			fresh++
			continue
		}
		olds = append(olds, entAge{ent, d})
	}
	if len(olds) == 0 {
		return fresh, ""
	}
	// 最旧的排前面 —— 那才是真正要关注的（可能已经离开对局了）。
	sort.Slice(olds, func(i, j int) bool { return olds[i].d > olds[j].d })
	var b strings.Builder
	for i, o := range olds {
		if i >= 6 {
			fmt.Fprintf(&b, " …共 %d 个", len(olds))
			break
		}
		if o.d < 0 {
			fmt.Fprintf(&b, " %d:已清出", o.idx)
			continue
		}
		fmt.Fprintf(&b, " %d:%.1fs", o.idx, o.d.Seconds())
	}
	return fresh, b.String()
}

// gnsSoundSnapshot 把已记录的声音事件转成「声音层」条目。调用方必须持有 sess.mu。
//
// 🔴 硬规则 290：`gnsPos` 里存的是**声音事件的原点**，不是人物位置。
// 这个函数产出的是独立的 `Sounds` 列表，前端用不同的画法（空心圈 + 渐隐），
// **绝不进 `Players`**。
//
// 窗口只有 gnsSoundTTL 秒：声音是瞬时事件，超过几秒就不该再出现在画面上，
// 否则又变成「一堆来历不明的点」。年龄照常传下去，前端可以按年龄做渐隐。
func (sess *Session) gnsSoundSnapshot(now time.Time) []cs2proto.Sound {
	if len(sess.gnsPos) == 0 {
		return nil
	}
	out := make([]cs2proto.Sound, 0, len(sess.gnsPos))
	for ent, e := range sess.gnsPos {
		age := now.Sub(e.At)
		if age > gnsSoundTTL {
			continue
		}
		out = append(out, cs2proto.Sound{Ent: ent, Pos: e.Pos, AgeMS: age.Milliseconds()})
	}
	// 按年龄升序（最新的在前），保证列表顺序稳定且有意义。
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgeMS != out[j].AgeMS {
			return out[i].AgeMS < out[j].AgeMS
		}
		return out[i].Ent < out[j].Ent
	})
	return out
}

// gnsPlayerSnapshot 把已记录的声源转成「诊断用目标」。调用方必须持有 sess.mu。
//
// ⚠ **硬规则 290 之后这个函数不再产出正式人物列表。**
// 它现在只被诊断日志（logGNSPosStats）调用，用来观察「按采样密度排名」到底切出了什么。
// 正式 `Players` 必须来自实体表（`svc_PacketEntities` delta），在实体表接通前**一律为空**。
//
// 历史原因保留：过滤判据（gnsPlayerLike）本身没有错，错的是数据源 ——
// 声音事件里根本不存在「哪个实体是玩家」这个信息。等实体表接通后，
// 这套「按更新密度区分 pawn / 道具」的思路可以复用到实体表上。
//
// 返回的 `Source` 仍然是 "gns-208"，但**语义是「声音层」**，不是「真人物坐标」。
// 这个字符串被 gnsplayer_test.go 钉住，改名前要先改测试。
func (sess *Session) gnsPlayerSnapshot(now time.Time) []cs2proto.Player {
	if len(sess.gnsPos) == 0 {
		return nil
	}
	keep, _ := sess.gnsPlayerLike(now)
	out := make([]cs2proto.Player, 0, len(sess.gnsPos))
	for ent, e := range sess.gnsPos {
		if now.Sub(e.At) > gnsPosTTL {
			continue
		}
		if keep != nil && !keep[ent] {
			continue
		}
		age := now.Sub(e.At)
		out = append(out, cs2proto.Player{
			ID:        int(ent),
			Pos:       e.Pos,
			Source:    "gns-208",
			UpdatedAt: e.At,
			AgeMS:     age.Milliseconds(),
			Stale:     age > gnsPosFresh,
		})
	}
	// 按实体索引排序，保证画面稳定（map 遍历顺序是随机的）。
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ID < out[j-1].ID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
