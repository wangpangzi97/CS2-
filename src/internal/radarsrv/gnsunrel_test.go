package radarsrv

// 不可靠通道解码器的测试。**全部用 2026-10-20 10:28 那局的真实载荷**，
// 不用合成数据 —— 合成数据只能证明代码自洽，证明不了格式对。

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
)

// gnsUnrelSampleA 是现场一条 308 字节的 s2c 不可靠载荷。
//
// 解出来是 `(4,33) (45,45) (55,212)`，**起点在 10 不是 11** ——
// 这条正是「头部长度可变、起点必须扫」的直接证据。
const gnsUnrelSampleA = "0250cf01000000000000440842aa03c86c048ae90050a01e54aa8316c3" +
	"55985c5b1d1c54995cda1b1918001a40272d080210011a270ca444c1201df3377db2358" +
	"23a04162200002200e320843a041622000022000500060009000a00d750072000124024" +
	"60048000a000c0903ae840061c5ca90e16b13103610859e68ab35eca6c40cf7700107d8" +
	"07f40c1c60c842164999492a1f01f50b03103610859a652c206030816cdb8721d4977e2" +
	"f9277d003666200c21cb544a66c07500c2a219194481f2006ccc401842966abd942fff0" +
	"0be82fd8d190443c8329956369e3360ce1667cd698716b8143f299d0116fb0129ff0188" +
	"01b7018801b70101b4018801b70120054019602581a53aa82d58880678556175d194e50b" +
	"68061020004800800600a00600c80634a0a0a0b0a83c3d07000a221826b4"

func mustHexUnrel(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("样本 hex 写错了：%v", err)
	}
	return b
}

// TestGNSDecodeUnrelSampleA 盯住现场样本的**全部关键数字**。
//
// 这条测试的价值在于：任何一个位规则改动（ReadUBitVar 的 6 位/选择器、
// ReadVarInt32 的 7 位续读、位序 LSB-first）都会让它失败。
func TestGNSDecodeUnrelSampleA(t *testing.T) {
	m := mustHexUnrel(t, gnsUnrelSampleA)
	if len(m) != 308 {
		t.Fatalf("样本长度 = %d，期望 308", len(m))
	}
	d := gnsDecodeUnrel(m)
	if d == nil {
		t.Fatal("gnsDecodeUnrel 返回 nil")
	}
	// 🔴 起点是 10，不是 11。写死 11 会漏掉这条。
	if d.Start != 10 {
		t.Fatalf("位链起点 = %d，期望 10", d.Start)
	}
	if d.LeftBits >= 16 {
		t.Fatalf("解完剩 %d 位，不算吃满", d.LeftBits)
	}
	if len(d.Msgs) != 3 {
		t.Fatalf("消息条数 = %d，期望 3", len(d.Msgs))
	}
	wantCmd := []uint32{4, 45, 55}
	wantSize := []int{33, 45, 212}
	for i, w := range wantCmd {
		if d.Msgs[i].Cmd != w {
			t.Errorf("第 %d 条 cmd = %d，期望 %d", i, d.Msgs[i].Cmd, w)
		}
		if len(d.Msgs[i].Body) != wantSize[i] {
			t.Errorf("第 %d 条 size = %d，期望 %d", i, len(d.Msgs[i].Body), wantSize[i])
		}
	}
}

// TestGNSDecodeUnrelTick 验证 cmd=4 就是 CNETMsg_Tick。
//
// 字段号能逐个对上不是巧合：field11 解出来是 "WarmupPeriod"，
// 而 CSVCMsg 里只有 CNETMsg_Tick 的 expected_long_tick_reason 是这个语义。
func TestGNSDecodeUnrelTick(t *testing.T) {
	m := mustHexUnrel(t, gnsUnrelSampleA)
	d := gnsDecodeUnrel(m)
	if d == nil || len(d.Msgs) == 0 {
		t.Fatal("解码失败")
	}
	var tick *gnsUnrelMsg
	for i := range d.Msgs {
		if d.Msgs[i].Cmd == gnsUnrelCmdTick {
			tick = &d.Msgs[i]
			break
		}
	}
	if tick == nil {
		t.Fatal("没有 cmd=4")
	}
	got := map[int]uint64{}
	var reason string
	gnsUnrelPB(tick.Body, func(field, wire int, v uint64, data []byte) {
		if wire == 0 {
			got[field] = v
		}
		if field == 11 && wire == 2 {
			reason = string(data)
		}
	})
	if got[1] != 1833 {
		t.Errorf("tick = %d，期望 1833", got[1])
	}
	if got[4] != 2227 {
		t.Errorf("host_computationtime = %d，期望 2227", got[4])
	}
	if got[8] != 15617 {
		t.Errorf("host_framestarttime = %d，期望 15617", got[8])
	}
	// field10 必须等于 field1 —— CNETMsg_Tick 的 expected_long_tick
	// 在「整 tick 预期耗时长」时才和 tick 相等，现场就是这样。
	if got[10] != got[1] {
		t.Errorf("expected_long_tick(%d) 应等于 tick(%d)", got[10], got[1])
	}
	if reason != "WarmupPeriod" {
		t.Errorf("expected_long_tick_reason = %q，期望 \"WarmupPeriod\"", reason)
	}
}

// TestGNSDecodePacketEnts 验证 cmd=55 就是 CSVCMsg_PacketEntities。
func TestGNSDecodePacketEnts(t *testing.T) {
	m := mustHexUnrel(t, gnsUnrelSampleA)
	d := gnsDecodeUnrel(m)
	if d == nil {
		t.Fatal("解码失败")
	}
	var body []byte
	for _, msg := range d.Msgs {
		if msg.Cmd == gnsUnrelCmdPacketEnts {
			body = msg.Body
			break
		}
	}
	if body == nil {
		t.Fatal("没有 cmd=55")
	}
	pe := gnsDecodePacketEnts(body)
	if pe.MaxEntries != 512 {
		t.Errorf("max_entries = %d，期望 512", pe.MaxEntries)
	}
	if pe.UpdatedEntries != 9 {
		t.Errorf("updated_entries = %d，期望 9", pe.UpdatedEntries)
	}
	if !pe.IsDelta {
		t.Error("is_delta 应为 true（现场 5190/5190 全是 delta）")
	}
	if pe.DeltaFrom != 1828 {
		t.Errorf("delta_from = %d，期望 1828", pe.DeltaFrom)
	}
	if pe.EntityDataLen != 144 {
		t.Errorf("entity_data 长度 = %d，期望 144", pe.EntityDataLen)
	}
	if len(pe.EntityData) != pe.EntityDataLen {
		t.Errorf("entity_data 切片长度 %d ≠ 记录长度 %d", len(pe.EntityData), pe.EntityDataLen)
	}
}

// TestGNSDecodeUnrelStartScanNeeded 盯住「起点必须扫」这条。
//
// 写死 11 时这条样本解不出来（11 处读出的链走不到末尾），
// 所以这条测试是「不要回退成常量」的护栏。
func TestGNSDecodeUnrelStartScanNeeded(t *testing.T) {
	m := mustHexUnrel(t, gnsUnrelSampleA)
	msgs, left, ok := gnsParseUnrelChain(m, 11*8)
	if ok && left < 16 {
		t.Fatalf("起点 11 也能吃满（%d 条，剩 %d 位）—— 若真如此，"+
			"这条测试的前提就变了，要重新确认起点 10 的唯一性", len(msgs), left)
	}
	if _, _, ok := gnsParseUnrelChain(m, 10*8); !ok {
		t.Fatal("起点 10 应该能解出来")
	}
}

// TestGNSDecodeUnrelRejectsGarbageCmd 验证「垃圾 cmd 一刀切」。
//
// 起点错位时 ReadUBitVar 会读出 40 亿这种值，必须判负，
// 否则「吃满率高」会把错位起点选成最佳起点。
func TestGNSDecodeUnrelRejectsGarbageCmd(t *testing.T) {
	// 造一条头部对、但从任何起点读出来都是垃圾 cmd 的载荷：
	// 0x3F 的低 6 位是 111111 ⇒ 选择器 0x30 ⇒ 再读 28 位全 1，
	// cmd = 15 | (0xFFFFFFF<<4)，远超 gnsUnrelMaxCmd。
	m := make([]byte, 0, 64)
	m = append(m, gnsUnrelFlag, 0x01, 0x02) // [02][seq=1][tick=2]
	for len(m) < gnsUnrelMinStart {
		m = append(m, 0x00)
	}
	m = append(m, 0x3F)
	for i := 0; i < 32; i++ {
		m = append(m, 0xFF)
	}
	if d := gnsDecodeUnrel(m); d != nil {
		t.Fatalf("垃圾 cmd 应该判负，却解出了 %d 条（起点 %d）", len(d.Msgs), d.Start)
	}
}

// TestGNSDecodeUnrelRejectsAllZeroChain 验证「全 cmd=0 的链判负」。
//
// 一段零填充从某些位偏移开始能凑出「很多条 cmd=0 size=0」的假链，
// 而且恰好走到末尾（剩 0 位）。不挡掉它，错位起点会以「条数最多」胜出。
func TestGNSDecodeUnrelRejectsAllZeroChain(t *testing.T) {
	m := make([]byte, 0, 64)
	m = append(m, gnsUnrelFlag, 0x01, 0x02)
	for i := 0; i < 48; i++ {
		m = append(m, 0x00)
	}
	if d := gnsDecodeUnrel(m); d != nil {
		t.Fatalf("全零链应该判负，却解出了 %d 条（起点 %d）", len(d.Msgs), d.Start)
	}
}

// buildVec3 造一个 CMsgVector / CMsgQAngle 的嵌套消息：
// `0d <f32 x> 15 <f32 y> 1d <f32 z>`，共 15 字节。
func buildVec3(x, y, z float32) []byte {
	b := make([]byte, 15)
	b[0] = 0x0d
	binary.LittleEndian.PutUint32(b[1:], math.Float32bits(x))
	b[5] = 0x15
	binary.LittleEndian.PutUint32(b[6:], math.Float32bits(y))
	b[10] = 0x1d
	binary.LittleEndian.PutUint32(b[11:], math.Float32bits(z))
	return b
}

// appendField 往 protobuf 里追加一个 len-delimited 字段。
func appendField(dst []byte, field int, payload []byte) []byte {
	dst = append(dst, byte(field<<3|2), byte(len(payload)))
	return append(dst, payload...)
}

// TestGNSDecodeUnrelPos 验证 cmd=452 的三元组解析。
//
// 坐标值取自现场：眼睛 z=1678、脚底 z=1614，差 64（CS2 玩家身高）。
func TestGNSDecodeUnrelPos(t *testing.T) {
	var body []byte
	body = appendField(body, 1, buildVec3(100, 200, 1678))
	body = appendField(body, 2, buildVec3(-1.5, -90.5, 0))
	body = appendField(body, 13, buildVec3(100, 200, 1614))

	p := gnsDecodeUnrelPos(body)
	if p == nil || !p.Has {
		t.Fatal("没解出 field1")
	}
	if p.Eye[0] != 100 || p.Eye[1] != 200 || p.Eye[2] != 1678 {
		t.Errorf("眼睛位置 = %v，期望 (100, 200, 1678)", p.Eye)
	}
	if p.Angle[1] != -90.5 {
		t.Errorf("pitch = %v，期望 -90.5", p.Angle[1])
	}
	if !p.HasFeet || p.Feet[2] != 1614 {
		t.Errorf("脚底 z = %v，期望 1614", p.Feet[2])
	}
	if d := p.Eye[2] - p.Feet[2]; d != 64 {
		t.Errorf("眼睛与脚底差 = %v，期望 64", d)
	}
}

// TestGNSUnrelPosSane 盯住坐标合理性检查。
//
// 🔴 这条检查曾经写死「z 在 1200~2100」，结果 10:52 局换地图（z=95）
// 之后 26 条坐标**全部**被判定不合理（硬规则 285）。
// 现在判据是「眼睛与脚底的 z 差在 40~90 之间」—— 跨地图稳定。
func TestGNSUnrelPosSane(t *testing.T) {
	cases := []struct {
		name string
		pos  *gnsUnrelPos
		want bool
	}{
		// 10:28 局：z=1678，脚底 1614，差 64
		{"10:28 局（z=1678）", &gnsUnrelPos{
			Has: true, HasFeet: true,
			Eye:  [3]float32{-1524.3, 794.8, 1678.0},
			Feet: [3]float32{-1524.3, 794.8, 1614.0},
		}, true},
		// 10:52 局：**换地图**，z=95.35，脚底 31.79，差 63.56
		{"10:52 局（z=95，换地图了）", &gnsUnrelPos{
			Has: true, HasFeet: true,
			Eye:  [3]float32{-1996.78, 1677.34, 95.35},
			Feet: [3]float32{-1996.78, 1677.34, 31.79},
		}, true},
		// 差太小 = 不是「眼睛 vs 脚底」
		{"z 差只有 5", &gnsUnrelPos{
			Has: true, HasFeet: true,
			Eye:  [3]float32{100, 200, 100},
			Feet: [3]float32{100, 200, 95},
		}, false},
		// 差太大 = 不是身高
		{"z 差 200", &gnsUnrelPos{
			Has: true, HasFeet: true,
			Eye:  [3]float32{100, 200, 300},
			Feet: [3]float32{100, 200, 100},
		}, false},
		// 没有 field13 时退化成「三个值有限且不太大」，z=95 也该通过
		{"只有眼睛没有脚底", &gnsUnrelPos{Has: true, Eye: [3]float32{100, 200, 95}}, true},
		{"x 越界", &gnsUnrelPos{Has: true, Eye: [3]float32{99999, 200, 1678}}, false},
		{"NaN", &gnsUnrelPos{Has: true, Eye: [3]float32{float32(math.NaN()), 200, 1678}}, false},
		{"nil", nil, false},
		{"没读到 field1", &gnsUnrelPos{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := gnsUnrelPosSane(c.pos); got != c.want {
				t.Errorf("gnsUnrelPosSane = %v，期望 %v", got, c.want)
			}
		})
	}
}

// TestGNSDecodeUnrelNotFlag02 验证只处理 0x02。
func TestGNSDecodeUnrelNotFlag02(t *testing.T) {
	for _, flag := range []byte{0x00, 0x01, 0x04, 0xff} {
		m := make([]byte, 32)
		m[0] = flag
		if d := gnsDecodeUnrel(m); d != nil {
			t.Errorf("首字节 0x%02x 不该被当成 0x02 解码", flag)
		}
	}
}

// TestGNSNoteUnrelStats 验证统计累计（用样本 A 喂三次）。
func TestGNSNoteUnrelStats(t *testing.T) {
	m := mustHexUnrel(t, gnsUnrelSampleA)
	sess := &Session{}
	for i := 0; i < 3; i++ {
		sess.noteGNSUnrel(m)
	}
	st := &sess.gnsUnrel
	if st.Seen != 3 {
		t.Errorf("Seen = %d，期望 3", st.Seen)
	}
	if st.Decoded != 3 {
		t.Errorf("Decoded = %d，期望 3", st.Decoded)
	}
	if st.StartHist[10] != 3 {
		t.Errorf("起点 10 计数 = %d，期望 3", st.StartHist[10])
	}
	if st.CmdHist[gnsUnrelCmdPacketEnts] != 3 {
		t.Errorf("cmd=55 计数 = %d，期望 3", st.CmdHist[gnsUnrelCmdPacketEnts])
	}
	if st.PE != 3 {
		t.Errorf("PacketEntities 条数 = %d，期望 3", st.PE)
	}
	// updated_entries = 9 × 3
	if st.PEUpdated != 27 {
		t.Errorf("updated_entries 累计 = %d，期望 27", st.PEUpdated)
	}
	// entity_data = 144 × 3
	if st.PEEntData != 432 {
		t.Errorf("entity_data 累计 = %d，期望 432", st.PEEntData)
	}
	if st.PEUpdMin != 9 || st.PEUpdMax != 9 {
		t.Errorf("updated 范围 = %d..%d，期望 9..9", st.PEUpdMin, st.PEUpdMax)
	}
	if st.PETickMin != 1828 || st.PETickMax != 1828 {
		t.Errorf("delta_from 范围 = %d..%d，期望 1828..1828", st.PETickMin, st.PETickMax)
	}
	if st.PEMaxEntMin != 512 || st.PEMaxEntMax != 512 {
		t.Errorf("max_entries 范围 = %d..%d，期望 512..512", st.PEMaxEntMin, st.PEMaxEntMax)
	}
	if len(st.PEEntDataBuf) != 144 {
		t.Errorf("保留的 entity_data 长度 = %d，期望 144", len(st.PEEntDataBuf))
	}
}

// TestGNSUnrelEntityDataIsNotFloatArray 是「entity_data 不是 float 数组」的护栏。
//
// 现场 5190 条、159 万个字节对齐位置上，只有 0.04% 像 CS2 坐标（随机水平）。
// 如果哪天有人想「直接扫 float 拿坐标」，这条测试会提醒他这条路已经封死。
//
// 🔴 **这里不能复用 `gnsUnrelPosSane`**：那个判据已经改成「眼睛与脚底 z 差 40~90」，
// 对单组 float 不适用（没脚底时退化成「值有限」，太宽松）。
// 盲扫要用**该局地图的窄范围**才有区分度 —— 这条样本来自 10:28 局，z 在 1656~1812。
func TestGNSUnrelEntityDataIsNotFloatArray(t *testing.T) {
	m := mustHexUnrel(t, gnsUnrelSampleA)
	d := gnsDecodeUnrel(m)
	if d == nil {
		t.Fatal("解码失败")
	}
	var data []byte
	for _, msg := range d.Msgs {
		if msg.Cmd == gnsUnrelCmdPacketEnts {
			data = gnsDecodePacketEnts(msg.Body).EntityData
		}
	}
	if len(data) < 12 {
		t.Fatalf("entity_data 太短：%d", len(data))
	}
	const zLo, zHi = 1200.0, 2100.0 // 10:28 那局的地图高度范围
	hits := 0
	for off := 0; off+12 <= len(data); off++ {
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[off:]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[off+4:]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[off+8:]))
		if math.IsNaN(float64(x)) || math.IsNaN(float64(z)) {
			continue
		}
		if math.Abs(float64(x)) < 8000 && math.Abs(float64(y)) < 8000 &&
			float64(z) > zLo && float64(z) < zHi {
			hits++
		}
	}
	// 这条样本里 0 个命中。放宽到「不超过 3 个」是给不同地图留余量，
	// 一旦某个改动让这里飙到几十，就说明有人在按 float 解析，方向错了。
	if hits > 3 {
		t.Errorf("entity_data 里像坐标的 float 三元组有 %d 个（%d 字节）—— "+
			"若显著变多，说明 entity_data 被当成 float 数组了，但现场实测只有 0.04%%，"+
			"它是位打包 delta", hits, len(data))
	}
}
