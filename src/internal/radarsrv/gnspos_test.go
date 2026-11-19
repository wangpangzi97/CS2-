package radarsrv

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
	"time"

	"local/cs2-radar/internal/cs2proto"
)

// 夹具全部是**现场原样字节**（2026-10-19 16:41 那一局的 cmd=208 body），
// 不是构造出来的。它们是硬规则 225 的锚点：一旦 blob 布局或字段号被改动，
// 这三条会立刻失败。
const (
	// len=47，实体 116，坐标 (-2184.22, 621.53, -144.01)
	fxGNSPos0 = "08c4dc0115ca543547187420c4dc012a1e4dce7c5a0a0c00928308c5f1611b44a40210c341e11bd9020400c58533c6"
	// len=48，实体 366，坐标 (-667.40, -2202.30, -179.97)
	fxGNSPos1 = "08c5dc0115ca54354718ee0220c5dc012a1e4dce7c5a0a0c00cfd926c4cda409c500f833c341e11bd90204005b3b8864"
	// len=48，实体 222，坐标 (949.30, -1978.71, -71.97)
	fxGNSPos2 = "08c6dc0115247a584518de0120c6dc012a1e4dce7c5a0a0c0067536d44aa56f7c400f08fc241e11bd90204009241cad5"
)

func mustHexPos(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("夹具 hex 解不开：%v", err)
	}
	return b
}

func almost(a, b float32) bool {
	return math.Abs(float64(a-b)) < 0.01
}

// TestGNSParsePosMsgRealBytes 钉住「cmd=208 body → 实体索引 + 世界坐标」。
func TestGNSParsePosMsgRealBytes(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		ent  uint32
		x    float32
		y    float32
		z    float32
	}{
		{"#0", fxGNSPos0, 116, -2184.2231, 621.5303, -144.0103},
		{"#1", fxGNSPos1, 366, -667.4033, -2202.3, -179.9688},
		{"#2", fxGNSPos2, 222, 949.3032, -1978.7083, -71.9688},
	}
	for _, c := range cases {
		ent, pos, _, ok := gnsParsePosMsg(mustHexPos(t, c.hex))
		if !ok {
			t.Fatalf("%s 应解析成功，实际失败", c.name)
		}
		if ent != c.ent {
			t.Fatalf("%s 实体 = %d，期望 %d", c.name, ent, c.ent)
		}
		if !almost(pos.X, c.x) || !almost(pos.Y, c.y) || !almost(pos.Z, c.z) {
			t.Fatalf("%s 坐标 = (%v, %v, %v)，期望 (%v, %v, %v)",
				c.name, pos.X, pos.Y, pos.Z, c.x, c.y, c.z)
		}
	}
}

// TestGNSParsePosMsgRejects 钉住「宁可少画一个，也不画幽灵」。
//
// 每一种改动都对应一个现场见过的坏情况：
//   - 砍掉 blob 里的 0a 0c 标记 → 别的消息也会被误当坐标消息；
//   - 把坐标换成 NaN/Inf → 雷达页面会直接画出界；
//   - 坐标量级超限 → 那是别的字段被当成浮点读了。
func TestGNSParsePosMsgRejects(t *testing.T) {
	good := mustHexPos(t, fxGNSPos0)

	// 1. 不是 protobuf（随便一段位打包数据）
	if _, _, _, ok := gnsParsePosMsg([]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}); ok {
		t.Fatal("非 protobuf 不该解析成功")
	}

	// 2. blob 位置标记被破坏：把 blob 里 0a 0c 改成 0a 0d
	bad := append([]byte(nil), good...)
	idx := -1
	for i := 0; i+1 < len(bad); i++ {
		if bad[i] == 0x0a && bad[i+1] == 0x0c && i > 20 {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("夹具里找不到 0a 0c 标记，夹具本身坏了")
	}
	bad[idx+1] = 0x0d
	if _, _, _, ok := gnsParsePosMsg(bad); ok {
		t.Fatal("blob 标记被破坏后不该解析成功")
	}

	// 3. 坐标被改成 NaN（0x7fc00000）
	nan := append([]byte(nil), good...)
	// 坐标在 blob 内偏移 7，而 blob 起点是 body 里 `2a 1e` 之后第 2 字节
	body := nan
	blobStart := -1
	for i := 0; i+1 < len(body); i++ {
		if body[i] == 0x2a {
			blobStart = i + 2
			break
		}
	}
	if blobStart < 0 {
		t.Fatal("夹具里找不到 field5，夹具本身坏了")
	}
	copy(body[blobStart+7:], []byte{0x00, 0x00, 0xc0, 0x7f})
	if _, _, _, ok := gnsParsePosMsg(body); ok {
		t.Fatal("NaN 坐标不该解析成功")
	}

	// 4. 坐标量级超限（1e6）
	big := append([]byte(nil), good...)
	copy(big[blobStart+7:], []byte{0x00, 0x24, 0x74, 0x49}) // 1e6f
	if _, _, _, ok := gnsParsePosMsg(big); ok {
		t.Fatal("超限坐标不该解析成功")
	}
}

// TestGNSPlayerPosTTL 钉住「实体消失后必须从画面上掉下去」。
func TestGNSPlayerPosTTL(t *testing.T) {
	sess := &Session{}
	now := time.Now()
	sess.noteGNSPlayerPos(116, cs2proto.Vec3{X: -2184.22, Y: 621.53, Z: -144.01}, now)
	sess.noteGNSPlayerPos(366, cs2proto.Vec3{X: -667.4, Y: -2202.3, Z: -179.97}, now)

	got := sess.gnsPlayerSnapshot(now)
	if len(got) != 2 {
		t.Fatalf("应有两个目标，实际 %d", len(got))
	}
	// 按实体索引升序
	if got[0].ID != 116 || got[1].ID != 366 {
		t.Fatalf("顺序不对：%d, %d", got[0].ID, got[1].ID)
	}
	if got[0].Source != "gns-208" {
		t.Fatalf("来源标记 = %q，期望 gns-208", got[0].Source)
	}

	// 超过 TTL 后必须清空
	later := now.Add(gnsPosTTL + time.Second)
	if n := len(sess.gnsPlayerSnapshot(later)); n != 0 {
		t.Fatalf("超过 TTL 后应为空，实际 %d 个", n)
	}
}

// TestSnapshotSoundLayerOnly 锁死硬规则 290 的核心行为：
// **cmd=208 的产物只进 Sounds，Players 一律为空**。
//
// 🔴 过去两轮的逻辑是「gnsPos 有货就当真人物，没有就回退启发式浮点扫描」。
// 硬规则 290 定案 cmd=208 = `svc_SosStartSoundEvent`（声音事件）之后，
// 这条路整个作废：声音原点不能冒充人物位置，启发式浮点扫描的幽灵更不能。
//
// 这个用例同时钉住三件事：
//  1. 启发式喂 40 条幽灵 → Players 必须还是 0（不许任何兜底）；
//  2. 2 个声源 → Sounds 必须有 2 个，且按 Ent 升序；
//  3. Synced 必须是 false 且 Status 非空（前端靠它显示「未同步」告警条）。
func TestSnapshotSoundLayerOnly(t *testing.T) {
	sess := newTestSession(t, 1)
	now := time.Now()

	// 先塞启发式结果：它会扫出几十个幽灵。
	for i := 0; i < 40; i++ {
		sess.decoder.Feed(&cs2proto.Msg{
			Cmd:  1,
			Data: gnsPosTestFloat3(float32(i*300), float32(i*300), 64),
			Raw:  gnsPosTestFloat3(float32(i*300), float32(i*300), 64),
		}, "s2c")
	}

	sess.mu.Lock()
	sess.noteGNSPlayerPos(238, cs2proto.Vec3{X: -2014.56, Y: -457.68, Z: -167.97}, now)
	sess.noteGNSPlayerPos(239, cs2proto.Vec3{X: -1938.10, Y: -499.07, Z: -167.97}, now)
	sess.mu.Unlock()

	sn := sess.Snapshot()
	// ① Players 必须空 —— 这是硬规则 290 最重要的一条。
	if len(sn.Players) != 0 {
		t.Fatalf("实体表没接通，Players 必须为 0，实际 %d 个"+
			"（启发式幽灵或声音原点混进人物层了）", len(sn.Players))
	}
	// ② 声源进 Sounds。
	if len(sn.Sounds) != 2 {
		t.Fatalf("声音层应有 2 个声源，实际 %d 个", len(sn.Sounds))
	}
	if sn.Sounds[0].Ent != 238 || sn.Sounds[1].Ent != 239 {
		t.Fatalf("声源应按 Ent 升序，得到 %d, %d", sn.Sounds[0].Ent, sn.Sounds[1].Ent)
	}
	// ③ 未同步标志 + 状态文案。
	if sn.Synced {
		t.Fatalf("实体表未接通时 Synced 必须为 false")
	}
	if sn.Status == "" {
		t.Fatalf("Synced=false 时必须给出 Status 说明，否则前端只能显示空白")
	}
}

// TestSnapshotDropsStaleSounds 锁死「过期的声音事件不许留在声音层」。
//
// 声音是瞬时事件（硬规则 290），所以声音层用 gnsSoundTTL=5 秒，
// 比诊断层的 gnsPosTTL=20 秒短得多。这个用例把两个 TTL 的分离钉住：
// 一条 10 秒前的条目 —— 诊断层还在，声音层必须已经没了。
func TestSnapshotDropsStaleSounds(t *testing.T) {
	sess := newTestSession(t, 1)
	old := time.Now().Add(-2 * gnsPosTTL)
	sess.mu.Lock()
	sess.noteGNSPlayerPos(238, cs2proto.Vec3{X: 100, Y: 200, Z: -167.97}, old)
	sess.mu.Unlock()

	for _, s := range sess.Snapshot().Sounds {
		if s.Ent == 238 {
			t.Fatalf("声源 238 已经 %.0f 秒没发声，仍然留在声音层里", (2 * gnsPosTTL).Seconds())
		}
	}
}

// TestSoundTTLShorterThanPosTTL 钉住「声音层 TTL 比诊断层短」这个分离。
//
// 🔴 为什么不许两者相等：声音层是**给人看的画面**，留久了会把画面堆成一团
// 灰圈，让人误以为那是「当前位置」；诊断层是给日志看的，要留长一点才能
// 观察「谁还在活跃发声」。混用会让这两个目标互相打架。
func TestSoundTTLShorterThanPosTTL(t *testing.T) {
	if gnsSoundTTL >= gnsPosTTL {
		t.Fatalf("声音层 TTL（%v）必须短于诊断层 TTL（%v），否则画面会堆满过期的灰圈",
			gnsSoundTTL, gnsPosTTL)
	}
	// 5 秒是现场定的：够看出「那边刚才有人活动」，又不会积累成假目标。
	if gnsSoundTTL != 5*time.Second {
		t.Fatalf("声音层 TTL = %v，期望 5s", gnsSoundTTL)
	}

	// 一条 10 秒前的条目：诊断层留着，声音层已剔除。
	sess := newTestSession(t, 1)
	mid := time.Now().Add(-10 * time.Second)
	sess.mu.Lock()
	sess.noteGNSPlayerPos(300, cs2proto.Vec3{X: 1, Y: 2, Z: 3}, mid)
	keep, _ := sess.gnsPlayerLike(time.Now())
	hasDiag := false
	for ent := range sess.gnsPos {
		if ent == 300 && (keep == nil || keep[ent]) {
			hasDiag = true
		}
	}
	sess.mu.Unlock()

	if !hasDiag {
		t.Fatalf("10 秒前的条目应仍在诊断层（gnsPosTTL=20s）")
	}
	for _, s := range sess.Snapshot().Sounds {
		if s.Ent == 300 {
			t.Fatalf("10 秒前的条目不该出现在声音层（gnsSoundTTL=5s）")
		}
	}
}

// gnsPosTestFloat3 造一段「三个 float32 小端」的载荷，给启发式解码器喂。
//
// 注意它不是真实协议数据 —— 只用来证明「启发式会产出大量条目」，
// 从而验证 Snapshot 在真坐标存在时不会把它们混进来。
func gnsPosTestFloat3(x, y, z float32) []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:], math.Float32bits(x))
	binary.LittleEndian.PutUint32(b[4:], math.Float32bits(y))
	binary.LittleEndian.PutUint32(b[8:], math.Float32bits(z))
	return b
}
