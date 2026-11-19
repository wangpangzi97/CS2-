package radarsrv

import (
	"strings"
	"testing"
	"time"

	"local/cs2-radar/internal/cs2proto"
)

// 现场真实载荷（2026-10-20 08:14 那局，cmd=60，133 字节，7 个玩家）。
//
// 这条夹具的作用是把「userid → SteamID64」的字段布局钉死：
//
//	0a 11                 field1 len 17
//	  08 01               field1 userid = 1
//	  11 0b591a3001001001 field2 fixed64 = 0x01100001301A590B
//	  20 00 28 00 30 00   field4/5/6 三个标志位
const fxGNSPlayerList = "0a110801110b591a3001001001200028003000" +
	"0a11080611e5291d4a01001001200128003000" +
	"0a11080711646b8a5801001001200128013000" +
	"0a110808111e3cd56e01001001200028003000" +
	"0a11080911b750644b01001001200028003000" +
	"0a11080a113c08742a01001001200028003000" +
	"0a11080b115e28bc6801001001200028003000"

// TestGNSParsePlayerList 用现场载荷锁死玩家名单的解析。
func TestGNSParsePlayerList(t *testing.T) {
	list := gnsParsePlayerList(mustHexPos(t, fxGNSPlayerList))
	if len(list) != 7 {
		t.Fatalf("条目 = %d，期望 7", len(list))
	}
	wantUser := []uint32{1, 6, 7, 8, 9, 10, 11}
	wantSteam := []uint64{
		0x01100001301A590B,
		0x011000014A1D29E5,
		0x01100001588A6B64,
		0x011000016ED53C1E,
		0x011000014B6450B7,
		0x011000012A74083C,
		0x0110000168BC285E,
	}
	for i, e := range list {
		if e.UserID != wantUser[i] {
			t.Fatalf("#%d userid = %d，期望 %d", i, e.UserID, wantUser[i])
		}
		if e.SteamID != wantSteam[i] {
			t.Fatalf("#%d SteamID64 = 0x%016X，期望 0x%016X", i, e.SteamID, wantSteam[i])
		}
	}
	// 现场这 7 条里 userid 6、7 的 field4=1，7 的 field5=1，其余全 0。
	// 这不是队伍（队伍只会取 2/3），是别的标志位。
	if list[1].Flags[0] != 1 || list[2].Flags[0] != 1 || list[2].Flags[1] != 1 {
		t.Fatalf("标志位解析错：%+v %+v", list[1], list[2])
	}
	if list[0].Flags[0] != 0 || list[0].Flags[1] != 0 {
		t.Fatalf("userid 1 的标志位应全 0，实际 %+v", list[0])
	}
}

// TestGNSParsePlayerListRejects 保证「结构碰巧对上」的载荷不会被当玩家名单。
//
// 判据里最关键的一条是 SteamID64 高位必须是 0x01100001：
// 没有它，任何 field2 是 fixed64 的消息都会被误认成玩家。
func TestGNSParsePlayerListRejects(t *testing.T) {
	cases := []struct{ name, hex string }{
		{"空载荷", ""},
		{"cmd=208 的声音事件消息", "08957a15ca54354718b90320957a2a1e4dce7c5a0a0c0051bc8844c0ad1945be1fc04241e11bd902040055bede90"},
		{"顶层字段号不是 1", "0b110801110b591a3001001001200028003000"},
		{"SteamID 高位不是 0x01100001", "0a11080111" + "0b591a3001001002" + "200028003000"},
		{"条目被截断", "0a110801110b591a300100100120"},
	}
	for _, c := range cases {
		if got := gnsParsePlayerList(mustHexPos(t, c.hex)); got != nil {
			t.Fatalf("%s 不该解析成功，实际得到 %d 条", c.name, len(got))
		}
	}
}

// TestGNSPlayerCountFromSession 走一遍 feedMsg 的落库路径。
func TestGNSPlayerCountFromSession(t *testing.T) {
	sess := &Session{}
	list := gnsParsePlayerList(mustHexPos(t, fxGNSPlayerList))
	if len(list) == 0 {
		t.Fatal("夹具解析失败")
	}
	sess.mu.Lock()
	sess.noteGNSPlayers(list)
	n := sess.gnsPlayerCount()
	sess.mu.Unlock()
	if n != 7 {
		t.Fatalf("名单人数 = %d，期望 7", n)
	}
	// 同一个 userid 再来一次不能变成 8 人（名单是全量覆盖，不是累加）。
	sess.mu.Lock()
	sess.noteGNSPlayers(list)
	n = sess.gnsPlayerCount()
	sess.mu.Unlock()
	if n != 7 {
		t.Fatalf("重复收到同一份名单后人数 = %d，期望仍是 7", n)
	}
}

// TestGNSPosTailExtracted 钉住 blob 尾部标签的取值。
//
// 尾部 4 字节语义未定，但**偏移**必须稳定：blob 30 字节时取 [26:30]，
// 19 字节（无尾部）时返回 0。偏移一错，下一轮的分型统计就全是垃圾。
func TestGNSPosTailExtracted(t *testing.T) {
	// 08:14 现场：实体 441，blob 尾部 55 be de 90 ⇒ LE u32 = 0x90debe55
	withTail := "08957a15ca54354718b90320957a2a1e4dce7c5a0a0c0051bc8844c0ad1945be1fc04241e11bd902040055bede90"
	ent, pos, tail, ok := gnsParsePosMsg(mustHexPos(t, withTail))
	if !ok {
		t.Fatal("带尾部的坐标消息应解析成功")
	}
	if ent != 441 {
		t.Fatalf("实体 = %d，期望 441", ent)
	}
	if tail != 0x90debe55 {
		t.Fatalf("尾部标签 = 0x%08X，期望 0x90DEBE55", tail)
	}
	if !almost(pos.X, 1093.8844) || !almost(pos.Z, 96.0625) {
		t.Fatalf("坐标 = %+v，与现场不符", pos)
	}

	// 19 字节 blob（没有尾部）⇒ tail 必须是 0，不能拿越界字节凑。
	noTail := "08d87a157ce61c33180020d87a2a134dce7c5a0a0c00eafb75c47cda82c42a8ec043"
	_, _, tail2, ok2 := gnsParsePosMsg(mustHexPos(t, noTail))
	if !ok2 {
		t.Fatal("19 字节 blob 也应解析成功（坐标块完整）")
	}
	if tail2 != 0 {
		t.Fatalf("无尾部时 tail = 0x%08X，期望 0", tail2)
	}
}

// TestGNSPosDistinctEntities 钉住「累计实体数」这个指标。
//
// 08:14 那局 `解出坐标 476 条 / 当前实体 5 个` 被算成 95.2 条/实体，
// 实际是 22 个实体轮流刷新。这条测试保证累计表按**实体索引**分桶。
func TestGNSPosDistinctEntities(t *testing.T) {
	sess := &Session{}
	now := time.Now()
	sess.mu.Lock()
	for i := 0; i < 5; i++ {
		sess.noteGNSPlayerPos(27, cs2proto.Vec3{X: float32(i), Y: 1, Z: 0}, now)
	}
	for i := 0; i < 3; i++ {
		sess.noteGNSPlayerPos(258, cs2proto.Vec3{X: float32(i), Y: 2, Z: 0}, now)
	}
	sess.noteGNSPlayerPos(441, cs2proto.Vec3{X: 9, Y: 3, Z: 0}, now)
	distinct := len(sess.gnsPosEnts)
	c27 := sess.gnsPosEnts[27]
	c258 := sess.gnsPosEnts[258]
	sess.mu.Unlock()

	if distinct != 3 {
		t.Fatalf("累计实体 = %d，期望 3", distinct)
	}
	if c27 != 5 || c258 != 3 {
		t.Fatalf("每实体采样 27=%d 258=%d，期望 5/3", c27, c258)
	}
	if sess.gnsPosTotal != 9 {
		t.Fatalf("累计条数 = %d，期望 9", sess.gnsPosTotal)
	}
}

// ---- 硬规则 276：采样密度 = 玩家/道具区分器 ----
//
// 这组测试用的数字**全部来自 09:26 那局的现场日志**，不是编的：
//
//	[gnspos] 采样数前 16 的实体（索引:条数，玩家 5 个）：
//	    207:331 0:303 334:151 491:99 504:70 282:13 236:12 272:11 274:11 ...
//	[gnspos] 索引 0-63 的实体 4 个（玩家 5 个）：对不上
//
// 关键：前 5 名断崖（70 → 13），而「索引<64」只有 4 个 —— 证明索引范围判据是错的。

// newFilterSession 造一个「43 个实体 / 5 个玩家」的会话，采样数按现场日志填。
func newFilterSession(t *testing.T, counts map[uint32]int, players int) *Session {
	t.Helper()
	sess := &Session{}
	sess.gnsPlayers = make(map[uint32]gnsPlayerEntry, players)
	for i := 0; i < players; i++ {
		sess.gnsPlayers[uint32(i)] = gnsPlayerEntry{UserID: uint32(i)}
	}
	now := time.Now()
	sess.gnsPos = make(map[uint32]gnsPosEntry, len(counts))
	sess.gnsPosEnts = make(map[uint32]int, len(counts))
	// gnsPosSeenAt 必须填：速率 = 条数 ÷ 自己的观察窗口（硬规则 282）。
	// 这里统一给 gnsTestSpan，等价于「所有实体从同一时刻就在场」。
	sess.gnsPosSeenAt = make(map[uint32]time.Time, len(counts))
	for ent, c := range counts {
		sess.gnsPosEnts[ent] = c
		sess.gnsPosSeenAt[ent] = now.Add(-gnsTestSpan)
		sess.gnsPos[ent] = gnsPosEntry{Pos: cs2proto.Vec3{X: float32(ent), Y: 1}, At: now}
	}
	return sess
}

// gnsTestSpan 是测试里默认的观察窗口长度。
//
// 取 100 秒只是为了「速率 = 条数 ÷ 100」好算，不承载任何产品含义。
// 真实时长由 gnsPosSeenAt 逐实体记录，中途加入的人窗口更短（见 TestGNSPlayerLikeMidJoin）。
const gnsTestSpan = 100 * time.Second

// siteCounts 是 09:26 那局的真实分布（前 16 名 + 其余道具补到 43 个）。
func siteCounts() map[uint32]int {
	m := map[uint32]int{
		207: 331, 0: 303, 334: 151, 491: 99, 504: 70, // ← 这 5 个是玩家
		282: 13, 236: 12, 272: 11, 274: 11, 124: 9, 180: 6,
		119: 5, 255: 5, 284: 5, 470: 5, 106: 4,
	}
	// 再补 27 个只有 1~3 条的道具，凑到 43 个实体。
	for i := uint32(0); i < 27; i++ {
		m[900+i] = 1 + int(i%3)
	}
	return m
}

// TestGNSPlayerLikeCliffOnSiteData 钉住现场判据：断崖成立 ⇒ 正好留下那 5 个玩家。
func TestGNSPlayerLikeCliffOnSiteData(t *testing.T) {
	now := time.Now()
	sess := newFilterSession(t, siteCounts(), 5)
	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("现场数据断崖 70→13 应判定成立，实际未启用：%s", why)
	}
	want := []uint32{0, 207, 334, 491, 504}
	if len(keep) != len(want) {
		t.Fatalf("保留 %d 个，期望 %d 个（%s）", len(keep), len(want), why)
	}
	for _, w := range want {
		if !keep[w] {
			t.Fatalf("玩家实体 %d 被漏掉（%s）", w, why)
		}
	}
	// 反证：索引范围判据是错的 —— 0..63 里只有 0 和 504 之外的 0 一个玩家。
	// （现场「索引 0-63」共 4 个实体，但玩家只有 1 个在里面。）
	if keep[900] {
		t.Fatal("道具 900 不应被当成玩家")
	}
}

// TestGNSPlayerLikeNoCliff 采样数平滑衰减时必须**不过滤**。
//
// 这是安全底线：判据不成立时宁可多画道具，也不能把真人藏掉。
func TestGNSPlayerLikeNoCliff(t *testing.T) {
	now := time.Now()
	counts := map[uint32]int{}
	for i := uint32(0); i < 20; i++ {
		counts[100+i] = 40 - int(i) // 40,39,38... 平滑衰减
	}
	sess := newFilterSession(t, counts, 5)
	keep, why := sess.gnsPlayerLike(now)
	if keep != nil {
		t.Fatalf("平滑衰减不该启用过滤，实际保留了 %d 个（%s）", len(keep), why)
	}
	if why == "" {
		t.Fatal("未启用时必须给出原因，否则用户不知道发生了什么")
	}
}

// TestGNSPlayerLikeTooFewSamples 开局样本不足时不过滤。
func TestGNSPlayerLikeTooFewSamples(t *testing.T) {
	now := time.Now()
	counts := map[uint32]int{10: 3, 20: 2, 30: 2, 40: 1, 50: 1, 60: 1, 70: 1}
	sess := newFilterSession(t, counts, 5)
	if keep, _ := sess.gnsPlayerLike(now); keep != nil {
		t.Fatalf("总样本 11 条（<%d）不该启用过滤，实际保留 %d 个",
			gnsFilterMinTotal, len(keep))
	}
}

// TestGNSPlayerLikeNoPlayers 玩家数未知（cmd=60 还没到）时不过滤。
func TestGNSPlayerLikeNoPlayers(t *testing.T) {
	now := time.Now()
	sess := newFilterSession(t, siteCounts(), 0)
	if keep, _ := sess.gnsPlayerLike(now); keep != nil {
		t.Fatal("玩家数 0 时没有排名依据，不该过滤")
	}
}

// TestGNSSnapshotAppliesFilter 快照必须真的少画点。
//
// 这条是**端到端**的：gnsPlayerLike 判定成立后，gnsPlayerSnapshot 的输出条数
// 必须从 43 掉到 5。否则过滤只写在日志里、画面上没生效。
func TestGNSSnapshotAppliesFilter(t *testing.T) {
	now := time.Now()
	sess := newFilterSession(t, siteCounts(), 5)
	snap := sess.gnsPlayerSnapshot(now)
	if len(snap) != 5 {
		t.Fatalf("快照 %d 个目标，期望 5 个（道具没被滤掉？）", len(snap))
	}
	// ID 必须是那 5 个玩家，且按索引升序（画面稳定）。
	want := []int{0, 207, 334, 491, 504}
	for i, w := range want {
		if snap[i].ID != w {
			t.Fatalf("快照第 %d 个 ID = %d，期望 %d（实际 %v）", i, snap[i].ID, w, snap)
		}
	}
}

// TestGNSSnapshotNoFilterKeepsAll 判据不成立时快照必须保持原样（43 个）。
func TestGNSSnapshotNoFilterKeepsAll(t *testing.T) {
	now := time.Now()
	counts := map[uint32]int{}
	for i := uint32(0); i < 20; i++ {
		counts[100+i] = 40 - int(i)
	}
	sess := newFilterSession(t, counts, 5)
	if snap := sess.gnsPlayerSnapshot(now); len(snap) != 20 {
		t.Fatalf("未启用过滤时快照应保持 20 个，实际 %d 个", len(snap))
	}
}

// ---- 硬规则 278：N 必须从分布里自己找，不能用 cmd=60 的人数 ----
//
// 09:39 那局的真实数字（用户确认现场「一共 8 个人」）：
//
//	[gnspos] 采样数前 16 的实体（索引:条数，玩家 9 个）：
//	    0:225 246:142 511:141 405:105 455:76 47:70 147:65 232:54 | 155:13 212:13 ...
//	[gnspos] 玩家名单（cmd=60）：9 人｜userid 1 2 3 5 6 11 13 14 15
//
// 断崖在 8/9 之间（54→13 = 4.15×），正好 8 个人 —— **cmd=60 多报了 1 个**。
// 上一版拿 players=9 去看第 9/10 名（13→13=1.0×），判定「没有断崖」把过滤整个关掉，
// 数据里明明有 4.15× 的分界。这条测试就是为了钉死这个错误。

// siteCounts0939 是 09:39 局的真实分布（46 个实体）。
func siteCounts0939() map[uint32]int {
	m := map[uint32]int{
		0: 225, 246: 142, 511: 141, 405: 105, 455: 76, 47: 70, 147: 65, 232: 54, // ← 这 8 个是玩家
		155: 13, 212: 13, 98: 11, 117: 10, 211: 10, 384: 9, 192: 5, 419: 5,
	}
	// 再补 30 个低采样道具，凑到 46 个实体。
	for i := uint32(0); i < 30; i++ {
		m[700+i] = 1 + int(i%3)
	}
	return m
}

// TestGNSPlayerLikeCmd60OffByOne 是本轮最关键的回归测试。
//
// cmd=60 报 9 人、现场实际 8 人；过滤必须仍然切在 8，**不能因为人数多报就整个关掉**。
func TestGNSPlayerLikeCmd60OffByOne(t *testing.T) {
	now := time.Now()
	sess := newFilterSession(t, siteCounts0939(), 9) // ← 故意用 cmd=60 的 9
	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("现场有 4.15× 断崖，必须启用过滤，实际未启用：%s", why)
	}
	if len(keep) != 8 {
		t.Fatalf("保留 %d 个，期望 8 个（用户确认现场 8 人）：%s", len(keep), why)
	}
	want := []uint32{0, 246, 511, 405, 455, 47, 147, 232}
	for _, w := range want {
		if !keep[w] {
			t.Fatalf("玩家实体 %d 被漏掉（%s）", w, why)
		}
	}
	// 第 9 名（155:13）及以下都是道具，不能被留下。
	if keep[155] || keep[212] {
		t.Fatalf("采样数 13 的道具不该被当成玩家（%s）", why)
	}
	// 说明里必须写出 cmd=60 的偏差，否则这个 bug 永远看不见。
	if !strings.Contains(why, "cmd=60") {
		t.Fatalf("说明里必须标出 cmd=60 的人数偏差，实际：%s", why)
	}
}

// TestGNSPlayerLikeSingleCutTooAggressive 只切出 1 个实体时**不能**按断崖切。
//
// 双人局里一个近一个远，采样比很容易超过 2 倍，但两个人都是真人。
// 只留 1 个等于把除本地玩家外所有人都藏了 —— 比多画道具糟糕得多。
//
// 🔴 硬规则 287 之后这里的行为变了：不是「整个关掉过滤」，而是
// **按 cmd=60 的 2 人保留**。两者都不藏人，但按人数保留不会把画面留成 4 个假点。
func TestGNSPlayerLikeSingleCutTooAggressive(t *testing.T) {
	now := time.Now()
	counts := map[uint32]int{5: 100, 9: 5, 12: 3, 20: 2}
	sess := newFilterSession(t, counts, 2)
	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("cmd=60 报 2 人时应按人数保留，不该整个否掉：%s", why)
	}
	if len(keep) != 2 {
		t.Fatalf("保留 %d 个，期望 2 个（cmd=60 报 2 人，不能只留本地玩家）：%s", len(keep), why)
	}
	if !keep[5] {
		t.Fatalf("本地玩家 5 必须保留（%s）", why)
	}
}

// ---- 09:47 局：9 个人，断崖在 9/10 之间 ----
//
//	采样数前 16：0:252 354:106 986:90 507:86 614:76 629:73 931:71 57:48 183:40 | 105:11 757:10 ...
//	用户确认现场「一共 9 人」；cmd=60 也报 9 人（userid 0 1 2 3 4 6 7 8 9）
//
// 注意第 1/2 名的比值是 252/106 = 2.38，也超过 2.0 门槛 ——
// 如果代码是「找到第一个 ≥2 的断崖就停」，会切出 N=1（本地玩家），把另外 8 个全藏掉。
// 必须取**最大**比值（40/11 = 3.64），才能切在 9。这条测试钉住这一点。

func siteCounts0947() map[uint32]int {
	m := map[uint32]int{
		0: 252, 354: 106, 986: 90, 507: 86, 614: 76, 629: 73, 931: 71, 57: 48, 183: 40, // ← 9 个玩家
		105: 11, 757: 10, 934: 9, 53: 7, 370: 6, 993: 6, 693: 5,
	}
	for i := uint32(0); i < 26; i++ {
		m[800+i] = 1 + int(i%4)
	}
	return m
}

func TestGNSPlayerLikeNinePlayers(t *testing.T) {
	now := time.Now()
	sess := newFilterSession(t, siteCounts0947(), 9)
	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("断崖 40→11（3.6×）应启用过滤，实际未启用：%s", why)
	}
	if len(keep) != 9 {
		t.Fatalf("保留 %d 个，期望 9 个（用户确认现场 9 人）：%s", len(keep), why)
	}
	want := []uint32{0, 354, 986, 507, 614, 629, 931, 57, 183}
	for _, w := range want {
		if !keep[w] {
			t.Fatalf("玩家实体 %d 被漏掉（%s）", w, why)
		}
	}
	if keep[105] || keep[757] {
		t.Fatalf("采样数 11/10 的道具不该被当成玩家（%s）", why)
	}
	// 这一局 cmd=60 报的就是 9，与实际一致 ⇒ 说明里不该出现偏差提示。
	if strings.Contains(why, "cmd=60") {
		t.Fatalf("cmd=60 与断崖一致时不该提示偏差，实际：%s", why)
	}
}

// TestGNSKeepFreshness 钉住「保留 9 个但只有 6 个新鲜」这个区分。
//
// 09:47 局就是 9 个玩家被正确保留、但只有 6 个在 TTL 内 —— 画面只有 6 个点在动。
// 用户看到点数少于人数会以为过滤漏了，所以日志必须把这两个数分开说。
func TestGNSKeepFreshness(t *testing.T) {
	now := time.Now()
	sess := &Session{gnsPos: map[uint32]gnsPosEntry{}}
	keep := map[uint32]bool{}
	// 3 个新鲜
	for _, ent := range []uint32{0, 354, 986} {
		sess.gnsPos[ent] = gnsPosEntry{At: now.Add(-1 * time.Second)}
		keep[ent] = true
	}
	// 2 个不活跃（10 秒、20 秒 —— 超过 gnsPosFresh 6 秒；注意 TTL 是 20 秒，另一个概念）
	sess.gnsPos[507] = gnsPosEntry{At: now.Add(-10 * time.Second)}
	sess.gnsPos[614] = gnsPosEntry{At: now.Add(-20 * time.Second)}
	keep[507] = true
	keep[614] = true
	// 1 个已经被 gnsPos 清出去了
	keep[999] = true

	fresh, stale := sess.gnsKeepFreshness(now, keep)
	if fresh != 3 {
		t.Fatalf("新鲜数 = %d，期望 3", fresh)
	}
	if stale == "" {
		t.Fatal("有 3 个不新鲜，必须给出描述")
	}
	// 最旧的排最前面：614（20s）在 507（10s）之前。
	i614 := strings.Index(stale, "614")
	i507 := strings.Index(stale, "507")
	if i614 < 0 || i507 < 0 {
		t.Fatalf("描述里应包含 614 和 507，实际：%s", stale)
	}
	if i614 > i507 {
		t.Fatalf("最旧的应排前面（614 在 507 之前），实际：%s", stale)
	}
	if !strings.Contains(stale, "已清出") {
		t.Fatalf("被 gnsPos 清掉的实体应标「已清出」，实际：%s", stale)
	}

	// 全部新鲜时不该有描述（避免每次统计都刷一行废话）。
	allFresh := map[uint32]bool{0: true}
	if _, s := sess.gnsKeepFreshness(now, allFresh); s != "" {
		t.Fatalf("全部新鲜时不该有描述，实际：%s", s)
	}
}

// ---- 硬规则 281：站着不动的玩家不能从画面上消失 ----
//
// 10:04 局（用户确认现场 5 人）：
//
//	过滤后 5 个玩家中 2 个在 6 秒内更新过；较旧： 47:32.0s 266:24.8s 510:19.6s
//
// 当时的解释是「cmd=208 是增量下发」—— **这个解释已被硬规则 290 推翻**：
// cmd=208 是 `svc_SosStartSoundEvent`，32 秒没消息的真实含义是
// 「这 32 秒没有发出声音」，和玩家动没动没有必然关系。
// 下面这些用例测的是**过滤判据本身**（按更新密度切 pawn / 道具），
// 判据没有错，错的是数据源 —— 所以用例保留，等实体表接通后复用到实体表上。
//
// TTL 与 Stale 的行为仍按原样钉住：TTL=20 秒保留条目、gnsPosFresh=6 秒标 Stale。

// TestGNSStaleButStillDrawn 钉住：超过 6 秒但不到 20 秒的点**必须还在**，且标 stale。
func TestGNSStaleButStillDrawn(t *testing.T) {
	now := time.Now()
	sess := &Session{
		gnsPos: map[uint32]gnsPosEntry{
			// 刚更新 —— 新鲜
			10: {Pos: cs2proto.Vec3{X: 1}, At: now.Add(-1 * time.Second)},
			// 站着不动 15 秒 —— 旧，但还在 TTL 内
			20: {Pos: cs2proto.Vec3{X: 2}, At: now.Add(-15 * time.Second)},
			// 超过 TTL —— 应该被移除
			30: {Pos: cs2proto.Vec3{X: 3}, At: now.Add(-gnsPosTTL - time.Second)},
		},
	}
	snap := sess.gnsPlayerSnapshot(now)
	if len(snap) != 2 {
		t.Fatalf("快照 %d 个，期望 2 个（15 秒的应保留、超 TTL 的应移除）：%+v", len(snap), snap)
	}
	byID := map[int]cs2proto.Player{}
	for _, p := range snap {
		byID[p.ID] = p
	}
	if p, ok := byID[10]; !ok || p.Stale {
		t.Fatalf("实体 10（1 秒前）应存在且不 stale，实际 %+v", p)
	}
	p20, ok := byID[20]
	if !ok {
		t.Fatal("实体 20（15 秒前）在 TTL 20 秒内，必须仍然出现在画面上 —— 否则站着不动的敌人会凭空消失")
	}
	if !p20.Stale {
		t.Fatal("实体 20 超过 gnsPosFresh(6s)，必须标 stale，否则旧坐标会被当成实时坐标")
	}
	if p20.AgeMS < 14000 || p20.AgeMS > 16000 {
		t.Fatalf("实体 20 的 age_ms = %d，期望约 15000", p20.AgeMS)
	}
	if _, ok := byID[30]; ok {
		t.Fatal("实体 30 已超 TTL，不该还在画面上（否则会留一串永久幽灵）")
	}
}

// TestGNSFreshThresholdIsNotTTL 防止有人把 gnsPosFresh 和 gnsPosTTL 又合并成一个。
//
// 这两个是不同的概念：gnsPosFresh 决定「算不算活跃刷新」（日志/Stale 标记），
// gnsPosTTL 决定「要不要从画面移除」。合并的后果是二选一：
//   - 用 6 秒 → 站着不动的玩家消失（10:04 局的 bug）
//   - 用 20 秒 → 20 秒前的坐标被当成实时坐标（更危险）
func TestGNSFreshThresholdIsNotTTL(t *testing.T) {
	if gnsPosFresh >= gnsPosTTL {
		t.Fatalf("gnsPosFresh(%v) 必须小于 gnsPosTTL(%v) —— 合并成一个就会二选一地出问题",
			gnsPosFresh, gnsPosTTL)
	}
	if gnsPosTTL < 15*time.Second {
		t.Fatalf("gnsPosTTL = %v，10:04 局实测有玩家 32 秒不动；TTL 太短会让站着不动的人凭空消失",
			gnsPosTTL)
	}
}

// ---- 硬规则 282：中途加入的人会把「累计条数」的断崖磨平 ----
//
// 10:14 局（用户确认：中途有人加入，最后 7 人）：
//
//	[gnspos] 采样数前 16：0:159 295:105 391:99 144:77 368:45 456:26 383:17 | 463:13 413:12 ...
//	[gnspos] ⚪ 道具过滤未启用：采样数最大断崖只有 1.7×（需 ≥2.0×）⇒ 画面上仍有 48 个点
//
// cmd=60 的时间线证明中途进了两个人：5 人（userid 0 6 7 14 15）→ 6 人（+8）→ 7 人（+3）。
//
// 用**累计条数**排名时，后加入的人只有几十秒的观察窗口，条数天然低（17 条），
// 和道具（13 条）撞在一起 ⇒ 断崖 17÷13 = 1.31× ⇒ 过滤失效。
// 换成**速率**（条数 ÷ 自己的观察窗口）后：17 条 / 65 秒 = 0.26 条/秒，
// 道具 13 条 / 110 秒 = 0.118 条/秒 ⇒ 断崖 2.2× ⇒ 过滤恢复。

// newFilterSessionFirsts 允许给每个实体指定「第一次被看到的时间」。
func newFilterSessionFirsts(t *testing.T, counts map[uint32]int, firsts map[uint32]time.Time, players int) *Session {
	t.Helper()
	sess := newFilterSession(t, counts, players)
	for ent, f := range firsts {
		sess.gnsPosSeenAt[ent] = f
	}
	return sess
}

func TestGNSPlayerLikeMidJoin(t *testing.T) {
	now := time.Now()
	const span = 110 * time.Second
	counts := map[uint32]int{
		0: 159, 295: 105, 391: 99, 144: 77, 368: 45, // 开局就在
		456: 26, // userid 8，约 21 秒时加入
		383: 17, // userid 3，约 45 秒时加入
		463: 13, 413: 12, 422: 12, 123: 10, 197: 9, 448: 9, 135: 5, 155: 5, 359: 5, // 道具
	}
	firsts := map[uint32]time.Time{
		456: now.Add(-89 * time.Second), // 加入 21 秒后
		383: now.Add(-65 * time.Second), // 加入 45 秒后
	}
	// 其余实体（开局就在）由 newFilterSession 统一设为 now-100s，这里覆盖成 110s。
	for ent := range counts {
		if _, ok := firsts[ent]; !ok {
			firsts[ent] = now.Add(-span)
		}
	}
	sess := newFilterSessionFirsts(t, counts, firsts, 7)

	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("用速率排名应该能切出 7 人，实际未启用：%s", why)
	}
	if len(keep) != 7 {
		t.Fatalf("保留 %d 个，期望 7 个（用户确认最后 7 人）：%s", len(keep), why)
	}
	for _, w := range []uint32{0, 295, 391, 144, 368, 456, 383} {
		if !keep[w] {
			t.Fatalf("玩家实体 %d 被漏掉（%s）", w, why)
		}
	}
	if keep[463] || keep[413] {
		t.Fatalf("采样数 13/12 的道具不该被当成玩家（%s）", why)
	}

	// 反证：如果按**累计条数**切，17 和 13 之间只有 1.31 倍，根本过不了 2.0 门槛。
	// 这条断言把这个「为什么必须用速率」的证据固定在测试里。
	if r := 17.0 / 13.0; r >= gnsFilterCliff {
		t.Fatalf("构造有误：累计条数断崖 %.2f 应该低于门槛 %.1f，否则这局证明不了速率更好",
			r, gnsFilterCliff)
	}
}

// TestGNSEntityRateUsesOwnWindow 直接钉住速率的算法：分母是这个实体自己的观察窗口。
func TestGNSEntityRateUsesOwnWindow(t *testing.T) {
	now := time.Now()
	sess := &Session{
		gnsPosEnts: map[uint32]int{10: 20, 20: 20},
		gnsPosSeenAt: map[uint32]time.Time{
			10: now.Add(-100 * time.Second), // 一直在场
			20: now.Add(-20 * time.Second),  // 刚加入
		},
	}
	r10 := sess.gnsEntityRate(10, now)
	r20 := sess.gnsEntityRate(20, now)
	if r10 < 0.19 || r10 > 0.21 {
		t.Fatalf("实体 10 速率 = %.3f，期望 0.20（20 条 / 100 秒）", r10)
	}
	if r20 < 0.95 || r20 > 1.05 {
		t.Fatalf("实体 20 速率 = %.3f，期望 1.00（20 条 / 20 秒）—— 同样 20 条，刚加入的速率应高 5 倍", r20)
	}
	// 观察窗口短于 gnsRateMinSpan 时用下限兜底，避免「1 条 / 2 秒 = 0.5」这种虚高。
	sess.gnsPosSeenAt[30] = now.Add(-2 * time.Second)
	sess.gnsPosEnts[30] = 1
	if r := sess.gnsEntityRate(30, now); r > 1.0/gnsRateMinSpan.Seconds()+0.001 {
		t.Fatalf("实体 30 速率 = %.3f，观察窗口 2 秒应被 gnsRateMinSpan(%.0fs) 兜底",
			r, gnsRateMinSpan.Seconds())
	}
}

// TestGNSPlayerLikeHeadCliffIsNotTheSplit 是硬规则 284 的核心测试。
//
// 10:52 局现场（用户说「最开始 9 个后来 8 个」），13 个实体的速率：
//
//	0:2.85  481:1.70  429:0.85  108:0.60  308:0.60  374:0.55
//	386:0.35  427:0.15  487:0.15 | 145:0.05  315:0.05  366:0.05  469:0.05
//	          ↑1.68×   ↑2.0×                              ↑3.0×
//
// 头部的 `1.70→0.85 = 2.0×` 不是人/道具分界，只是玩家区内部的波动
// （索引 0 是本地玩家、481 是特殊实体，它们的速率天然远高于其他人）。
// **真正的分界是 `0.15→0.05 = 3.0×`，切出 9 个。**
//
// 旧代码在这里给出 **2 个**，两个原因叠加：
//  1. `gnsFilterMinTop=8` 在第 8 名（只有 3 条）就 break，真分界根本没被看到
//  2. 「取最大比值」让头部那个 2.0× 胜出
func TestGNSPlayerLikeHeadCliffIsNotTheSplit(t *testing.T) {
	now := time.Now()
	// 现场速率 = 条数 / 20 秒（gnsRateMinSpan 兜底窗口），所以窗口统一设 20 秒。
	const span = 20 * time.Second
	counts := map[uint32]int{
		0: 57, 481: 34, 429: 17, 108: 12, 308: 12, 374: 11,
		386: 7, 427: 3, 487: 3, // ← 玩家区到这里为止（9 个）
		145: 1, 315: 1, 366: 1, 469: 1, // ← 道具
	}
	firsts := make(map[uint32]time.Time, len(counts))
	for ent := range counts {
		firsts[ent] = now.Add(-span)
	}
	sess := newFilterSessionFirsts(t, counts, firsts, 9)

	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("过滤没启用：%s", why)
	}
	if len(keep) != 9 {
		t.Fatalf("保留 %d 个，期望 9（用户确认 9 人）｜%s", len(keep), why)
	}
	want := []uint32{0, 481, 429, 108, 308, 374, 386, 427, 487}
	for _, ent := range want {
		if !keep[ent] {
			t.Errorf("实体 %d 应该在保留集合里｜%s", ent, why)
		}
	}
	// 道具必须全被切掉
	for _, ent := range []uint32{145, 315, 366, 469} {
		if keep[ent] {
			t.Errorf("实体 %d 是道具，不该保留｜%s", ent, why)
		}
	}
	// 说明里要能看到 3.0× 这个真分界
	if !strings.Contains(why, "3.0×") {
		t.Errorf("说明里应体现 3.0× 的断崖，实际：%s", why)
	}
}

// TestGNSPlayerLikeHeadCliffRegression 是上一条的**反证**：
// 把 gnsFilterMinTop 调回 8，同样数据必须切出 2 个（复现旧 bug）。
//
// 这条测试的价值是：如果哪天有人觉得「MinTop 太小会误判」又调大，
// 这里会立刻告诉他调大会让 9 人局只剩 2 个点。
func TestGNSPlayerLikeHeadCliffRegression(t *testing.T) {
	if gnsFilterMinTop > 2 {
		t.Fatalf("gnsFilterMinTop = %d，必须是 2 —— 调大就会重演「9 人局只剩 2 个点」", gnsFilterMinTop)
	}
	now := time.Now()
	const span = 20 * time.Second
	counts := map[uint32]int{
		0: 57, 481: 34, 429: 17, 108: 12, 308: 12, 374: 11,
		386: 7, 427: 3, 487: 3,
		145: 1, 315: 1, 366: 1, 469: 1,
	}
	firsts := make(map[uint32]time.Time, len(counts))
	for ent := range counts {
		firsts[ent] = now.Add(-span)
	}
	sess := newFilterSessionFirsts(t, counts, firsts, 9)

	// 手工按旧逻辑算一遍：MinTop=8 ⇒ 只扫到 i=5，最大断崖 1.70→0.85=2.0× ⇒ 切 2 个。
	list := make([]struct {
		idx  uint32
		n    int
		rate float64
	}, 0, len(counts))
	for ent, c := range counts {
		list = append(list, struct {
			idx  uint32
			n    int
			rate float64
		}{ent, c, sess.gnsEntityRate(ent, now)})
	}
	// 按速率降序排（与 gnsPlayerLike 一致）
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].rate > list[i].rate {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	oldBest, oldRatio := 0, 0.0
	for i := 0; i < len(list)-1; i++ {
		if list[i].n < 8 { // ← 旧门槛
			break
		}
		r := list[i].rate / list[i+1].rate
		if r > oldRatio {
			oldRatio, oldBest = r, i+1
		}
	}
	if oldBest != 2 {
		t.Fatalf("旧逻辑（MinTop=8）应切出 2 个，实际 %d —— 反证失效，检查排序是否一致", oldBest)
	}
	if oldRatio < 1.9 || oldRatio > 2.1 {
		t.Fatalf("旧逻辑的断崖 = %.2f，期望 2.0（1.70/0.85）", oldRatio)
	}
}

// TestGNSPlayerLikeAnchorOnCmd60 是硬规则 287 的核心测试。
//
// 10:44 那局用户确认 8 人，现场采样速率（100 秒窗口换算成条数）：
//
//	0:2.15  626:1.15  101:0.89  986:0.60  258:0.32  350:0.25  349:0.24
//	271:0.15  1016:0.14 | 280:0.05  381:0.05
//
// 两个**相邻统计**里 1016 一个是 0.15（3 条 / 20.0 秒）、一个是 0.14（3 条 / 20.5 秒）。
// 0.01 的窗口抖动会让「切点速率必须 < 0.15」这道校验时而成立时而不成立，
// 画面上 8 个点 / 11 个点来回跳。断崖本身在 0.14→0.05 = 2.8× 上，
// 切出 9 个（比 8 多 1）—— 必须用 cmd=60 压回 8。
func TestGNSPlayerLikeAnchorOnCmd60(t *testing.T) {
	// 两个 tick 的差别只有 1016 这一个实体的条数（15 vs 14）。
	ticks := []struct {
		name string
		last int
	}{
		{"1016=0.15", 15},
		{"1016=0.14", 14},
	}
	for _, tk := range ticks {
		t.Run(tk.name, func(t *testing.T) {
			counts := map[uint32]int{
				0: 215, 626: 115, 101: 89, 986: 60, 258: 32, 350: 25, 349: 24,
				271: 15, 1016: tk.last,
				280: 5, 381: 5,
			}
			now := time.Now()
			sess := newFilterSession(t, counts, 8)
			keep, why := sess.gnsPlayerLike(now)
			if keep == nil {
				t.Fatalf("8 人局不该整个否掉过滤：%s", why)
			}
			if len(keep) != 8 {
				t.Fatalf("保留 %d 个，期望 8 个（用户确认 8 人）：%s", len(keep), why)
			}
			// 前 8 名必须是保留的；280/381（0.05 道具）必须被滤掉。
			for _, want := range []uint32{0, 626, 101, 986, 258, 350, 349, 271} {
				if !keep[want] {
					t.Fatalf("实体 %d 被漏掉（%s）", want, why)
				}
			}
			for _, bad := range []uint32{280, 381} {
				if keep[bad] {
					t.Fatalf("道具 %d 不该保留（%s）", bad, why)
				}
			}
		})
	}
}

// TestGNSPlayerLikeRaisesToCmd60 覆盖锚点的**反方向**：断崖切少了要抬回来。
//
// 断崖切出 4 个、cmd=60 报 8 人 ⇒ 抬到 8-2 = 6。
// 宁可多画两个道具，不能把真人藏掉（硬规则 275 的底线）。
func TestGNSPlayerLikeRaisesToCmd60(t *testing.T) {
	counts := map[uint32]int{
		0: 200, 1: 190, 2: 180, 3: 90, // 断崖在 3 后面：0.9 → 0.05
		4: 5, 5: 5, 6: 5, 7: 5, 8: 5, 9: 5,
	}
	now := time.Now()
	sess := newFilterSession(t, counts, 8)
	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("cmd=60 报 8 人时应按锚点抬起来，不该整个否掉：%s", why)
	}
	if len(keep) != 8-gnsAnchorSlack {
		t.Fatalf("保留 %d 个，期望 %d 个（cmd=60 报 8 人 -%d）：%s",
			len(keep), 8-gnsAnchorSlack, gnsAnchorSlack, why)
	}
	for i := uint32(0); i < uint32(8-gnsAnchorSlack); i++ {
		if !keep[i] {
			t.Fatalf("实体 %d 被漏掉（%s）", i, why)
		}
	}
}

// TestGNSAnchorSlackIsTwo 钉住余量常量。
//
// 余量太大等于放弃过滤（cmd=60 报 8、实际只切出 2 也放行），
// 太小则一次窗口抖动就回到「藏真人」的老问题。
func TestGNSAnchorSlackIsTwo(t *testing.T) {
	if gnsAnchorSlack != 2 {
		t.Fatalf("gnsAnchorSlack = %d，必须是 2", gnsAnchorSlack)
	}
	if gnsFilterMinTop != 2 {
		t.Fatalf("gnsFilterMinTop = %d，必须是 2（硬规则 286）", gnsFilterMinTop)
	}
}

// ---- 硬规则 288：冻结条目的「衰减速率」会顶掉真人 ----
//
// 11:04 那局（用户确认 8 人，cmd=60 报 9 人 userid 0 1 4 5 7 8 9 10 11）现场：
//
//	[gnspos] 采样速率前 16：0:200@1.94 354:122@1.90 372:87@1.06 258:106@1.00
//	        101:98@0.93 626:85@0.83 986:78@0.74 762:55@0.70
//	        122:12@0.57 180:9@0.29 74:13@0.24 118:6@0.23 73:13@0.23
//	        191:6@0.22 128:4@0.20 453:12@0.17
//	[gnspos] ⚪ 道具过滤未启用：没有「切点后落入道具区」的断崖 ⇒ 画面上仍有 44 个点
//
// 两个独立的原因让过滤彻底失效：
//  1. 这道门槛是**绝对速率** 0.15，而这局道具速率是 0.17~0.29 —— 全部候选被否；
//  2. 122 / 74 / 73 / 118 / 191 / 128 / 453 这 7 个是**冻结条目**：整局条数一次没涨
//     （10:47 `122:12@0.60`、11:06 `122:12@0.57`）。它们的「速率」只是 12 除以
//     越来越长的窗口，是衰减假象。122 的 0.57 甚至压过真玩家的 0.70 那一档，
//     把 8/9 分界磨成了 1.23×。
//
// 修法：排名先按「还在刷新」分组，冻结条目永远排在刷新条目之后；
// 同时把绝对速率门槛换成「取最靠后的那个 ≥2.0× 断崖」。
func gnsCounts1104() map[uint32]int {
	m := map[uint32]int{
		// 还在刷新的 8 个真人
		0: 194, 354: 190, 372: 106, 258: 100, 101: 93, 626: 83, 986: 74, 762: 70,
		// 还在刷新的道具（180 的条数一直在涨：5→7→8→9）
		180: 29, 300: 15, 301: 14, 302: 12, 303: 10, 304: 9, 305: 8, 306: 7,
		// 冻结条目：整局条数不变，速率只是窗口衰减出来的假象
		122: 57, 74: 24, 118: 23, 73: 23, 191: 22, 128: 20, 453: 17,
	}
	// 再补 21 个低采样道具，凑到 44 个实体（与现场一致）。
	for i := uint32(0); i < 21; i++ {
		m[900+i] = 1 + int(i%3)
	}
	return m
}

// gnsFrozen1104 是「整局条数没涨过」的那批索引。
func gnsFrozen1104() []uint32 {
	return []uint32{122, 74, 118, 73, 191, 128, 453}
}

// newFilterSession1104 把冻结条目的 lastSeen 推到很久以前，模拟「不再刷新」。
func newFilterSession1104(t *testing.T, players int) *Session {
	t.Helper()
	sess := newFilterSession(t, gnsCounts1104(), players)
	now := time.Now()
	for _, ent := range gnsFrozen1104() {
		e := sess.gnsPos[ent]
		e.At = now.Add(-3 * time.Minute)
		sess.gnsPos[ent] = e
	}
	return sess
}

// TestGNSPlayerLikeFrozenEntriesNotRanked 是本轮核心测试：8 个人必须切出 8 个。
func TestGNSPlayerLikeFrozenEntriesNotRanked(t *testing.T) {
	now := time.Now()
	sess := newFilterSession1104(t, 9) // cmd=60 报 9，实际 8
	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("现场有 2.41× 断崖（0.70→0.29），必须启用过滤：%s", why)
	}
	if len(keep) != 8 {
		t.Fatalf("保留 %d 个，期望 8 个（用户确认现场 8 人）：%s", len(keep), why)
	}
	for _, w := range []uint32{0, 354, 372, 258, 101, 626, 986, 762} {
		if !keep[w] {
			t.Fatalf("玩家实体 %d 被漏掉（%s）", w, why)
		}
	}
	// 冻结条目一个都不能留 —— 它们就是「画面上多出来的假点」。
	for _, bad := range gnsFrozen1104() {
		if keep[bad] {
			t.Fatalf("冻结条目 %d 不该保留（%s）", bad, why)
		}
	}
}

// TestGNSPlayerLikeFrozenEntriesRegression 是上一条的**反证**：
// 不做「刷新优先」排序时，同样的数据切不出任何断崖 ⇒ 整个过滤失效。
//
// 这条把「为什么必须区分刷新/冻结」钉死 —— 否则以后有人删掉 fresh 字段，
// 测试还是绿的，现场却又变回 44 个点。
func TestGNSPlayerLikeFrozenEntriesRegression(t *testing.T) {
	now := time.Now()
	sess := newFilterSession1104(t, 9)

	type entRate struct {
		idx  uint32
		rate float64
	}
	list := make([]entRate, 0, len(sess.gnsPosEnts))
	for ent := range sess.gnsPosEnts {
		list = append(list, entRate{ent, sess.gnsEntityRate(ent, now)})
	}
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].rate > list[i].rate {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	// 旧逻辑：纯速率排名 + 只看前 players+4 个切点。
	maxRatio := 0.0
	for i := 1; i < len(list) && i < 9+gnsFilterSlack; i++ {
		if list[i].rate <= 0 {
			continue
		}
		if r := list[i-1].rate / list[i].rate; r > maxRatio {
			maxRatio = r
		}
	}
	if maxRatio >= gnsFilterCliff {
		t.Fatalf("旧逻辑（纯速率）应切不出断崖（实际最大 %.2f×）—— 反证失效，"+
			"检查冻结条目的速率是否被构造得不对", maxRatio)
	}
}

// TestGNSPlayerLikePropRateAboveGate 钉住「绝对速率门槛必须删掉」。
//
// 这局道具速率 0.17~0.29，全部高于 gnsFilterMinRate(0.15)。
// 只要还有人用 `nxt <= gnsFilterMinRate` 当候选条件，这条就会失败。
func TestGNSPlayerLikePropRateAboveGate(t *testing.T) {
	now := time.Now()
	sess := newFilterSession1104(t, 9)
	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("道具速率 0.29 高于 0.15 时不该让过滤整个失效：%s", why)
	}
	if keep[180] {
		t.Fatalf("道具 180（0.29 条/秒）不该被当成玩家（%s）", why)
	}
}

// ---- 硬规则 289：1v1 里 cmd=208 几乎不出数据，旧门槛把过滤整个挡在门外 ----
//
// 11:24 那局（用户：**最开始 2 人 → 1 人 → 2 人 → 1 人，后面持续 1 人**）现场：
//
//	[gnspos] cmd=208 收到 41 条｜解出坐标 39 条（命中 95.1%）｜累计实体 16 个（活跃 5）
//	[gnspos] 采样速率前 16：0:19@0.38  213:3@0.05  65:1@0.05  66:1@0.05
//	        491:3@0.04  207:2@0.04  324:1@0.02 …（其余全是 1 条）
//	（**没有**「⚪ 道具过滤未启用」这一行 —— 说明函数在第一个门槛就静默返回了）
//
// 两个问题：
//  1. 整局只有 **39 条**采样，`gnsFilterMinTotal = 40` ⇒ `39 < 40` 直接 return，
//     过滤一次都没跑过，画面上 16 个实体全画出来，而现场只有 1~2 个人。
//  2. 即使跑起来，榜首 `0:19` vs 次席 `213:3` 是 **7.6×** 的断崖，只切出 1 个，
//     旧代码把「只切出 1 个」当成「太激进」直接放弃 ⇒ 又回到 16 个点。
//
// 修法：门槛从「总样本」改成「总样本 + **榜首条数**」双判据（12 / 6），
// 并把「只切出 1 个」交给锚点抬到 2，而不是整个放弃。
func gnsCounts1124() map[uint32]int {
	m := map[uint32]int{
		0: 19, 213: 3, 491: 3, 207: 2,
		65: 1, 66: 1, 68: 1, 324: 1, 321: 1, 322: 1,
		216: 1, 217: 1, 218: 1, 210: 1, 211: 1, 212: 1,
	}
	return m
}

// TestGNSPlayerLikeTinySession 1v1 局：16 个实体必须被压到 2 个。
func TestGNSPlayerLikeTinySession(t *testing.T) {
	now := time.Now()
	sess := newFilterSession(t, gnsCounts1124(), 3) // cmd=60 报 3 人（userid 0 1 2）
	keep, why := sess.gnsPlayerLike(now)
	if keep == nil {
		t.Fatalf("榜首 19 条、断崖 7.6×，必须启用过滤（旧代码在这里静默返回）：%s", why)
	}
	if len(keep) != 2 {
		t.Fatalf("保留 %d 个，期望 2 个（只切出 1 个由锚点抬到 2）：%s", len(keep), why)
	}
	if !keep[0] {
		t.Fatalf("实体 0（19 条，唯一的真人）必须保留（%s）", why)
	}
	for _, bad := range []uint32{65, 66, 68, 324, 321, 322, 216, 217, 218, 210, 211, 212} {
		if keep[bad] {
			t.Fatalf("1 条的道具 %d 不该保留（%s）", bad, why)
		}
	}
}

// TestGNSFilterMinTotalAllowsTinySession 钉住「39 条也要能过滤」。
//
// 现场就是 39 条：`gnsFilterMinTotal` 只要回到 40，这条立刻失败。
func TestGNSFilterMinTotalAllowsTinySession(t *testing.T) {
	total := 0
	for _, c := range gnsCounts1124() {
		total += c
	}
	if total >= 40 {
		t.Fatalf("构造有误：现场是 39 条，实际 %d", total)
	}
	if total < gnsFilterMinTotal {
		t.Fatalf("现场 %d 条必须过得了门槛（gnsFilterMinTotal=%d）—— "+
			"卡在 40 就是这局过滤一次没跑的直接原因", total, gnsFilterMinTotal)
	}
}

// TestGNSFilterMinTopNGuardsNoise 榜首样本太少时仍然不过滤。
//
// 这是把门槛从「总量」挪到「榜首」之后必须补的安全网：
// 开局两秒里所有实体都是 1~2 条，谁排第一纯属偶然。
func TestGNSFilterMinTopNGuardsNoise(t *testing.T) {
	now := time.Now()
	counts := map[uint32]int{}
	for i := uint32(0); i < 20; i++ {
		counts[500+i] = 1 + int(i%3) // 最多 3 条，全是噪声
	}
	sess := newFilterSession(t, counts, 2)
	if keep, why := sess.gnsPlayerLike(now); keep != nil {
		t.Fatalf("榜首只有 3 条（<%d）不该启用过滤，实际保留 %d 个（%s）",
			gnsFilterMinTopN, len(keep), why)
	}
}

// TestGNSFilterTinySessionStillBeatsProps 端到端：16 个实体 → 快照只剩 2 个。
func TestGNSFilterTinySessionStillBeatsProps(t *testing.T) {
	now := time.Now()
	sess := newFilterSession(t, gnsCounts1124(), 3)
	snap := sess.gnsPlayerSnapshot(now)
	if len(snap) != 2 {
		t.Fatalf("快照 %d 个目标，期望 2 个（1v1 局不该画出 16 个点）", len(snap))
	}
}
