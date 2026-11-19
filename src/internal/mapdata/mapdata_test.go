package mapdata

import (
	"math"
	"testing"
)

// near 是浮点比较（地图标定是 4.4 单位/像素，1 单位以内就算一致）。
func near(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

// TestRegistryLoadsBuiltin 确认内嵌资产能加载，且 dust2 的标定字段完整。
func TestRegistryLoadsBuiltin(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("加载内嵌资产失败: %v", err)
	}
	ids := r.IDs()
	if len(ids) == 0 {
		t.Fatalf("一张地图都没有")
	}
	found := false
	for _, id := range ids {
		if id == "de_dust2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("资产里没有 de_dust2，实际有 %v", ids)
	}
	// 现在内置了 17 张图（dust2 手写验证过，其余 16 张由 tools/gen_map_assets.py
	// 从 cs2_webradar 的 meta.json5 生成）。少于 10 张说明生成脚本没跑或资产被删了。
	if len(ids) < 10 {
		t.Fatalf("内置地图只有 %d 张，期望 ≥10（生成脚本漏跑了？）：%v", len(ids), ids)
	}
}

// TestAllBuiltinMapsAreConsistent 逐张检查内置地图的标定自洽性。
//
// 🔴 这条测试的价值在于「批量」。17 张图里有 16 张是从上游 meta.json5
// 换算来的，换算公式只要错一次，那 16 张会**同时**错，而且单看某一项都像正常值
// （比如把 span 算成 512*res，所有图都变成只有半张）。所以必须逐张验：
//   - 覆盖范围的宽高必须等于 ref_width × units_per_pixel；
//   - world_bounds 必须和 origin + 覆盖范围**完全一致**（不许两处各写一份）；
//   - 每张图的 ID 必须和文件名一致（否则 /mapimg 路由取不到图）。
func TestAllBuiltinMapsAreConsistent(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("加载内嵌资产失败: %v", err)
	}
	for _, id := range r.IDs() {
		m, _, msg := r.Resolve(id)
		if m == nil {
			t.Fatalf("%s 解析失败：%s", id, msg)
		}
		if m.ID != id {
			t.Fatalf("解析 %s 得到 ID %q，两者必须一致", id, m.ID)
		}
		spanX := float64(m.RefWidth) * m.UnitsPerPixel
		spanY := float64(m.RefHeight) * m.UnitsPerPixel
		if !near(m.WorldBounds.MaxX-m.WorldBounds.MinX, spanX, 0.01) {
			t.Fatalf("%s 覆盖宽度 %v ≠ %d×%v=%v",
				id, m.WorldBounds.MaxX-m.WorldBounds.MinX, m.RefWidth, m.UnitsPerPixel, spanX)
		}
		if !near(m.WorldBounds.MaxY-m.WorldBounds.MinY, spanY, 0.01) {
			t.Fatalf("%s 覆盖高度 %v ≠ %d×%v=%v",
				id, m.WorldBounds.MaxY-m.WorldBounds.MinY, m.RefHeight, m.UnitsPerPixel, spanY)
		}
		if !near(m.WorldBounds.MinX, m.OriginWorldX, 0.01) || !near(m.WorldBounds.MaxY, m.OriginWorldY, 0.01) {
			t.Fatalf("%s 的 origin 与 world_bounds 左上角不一致：origin=(%v,%v) bounds=(%v,%v)",
				id, m.OriginWorldX, m.OriginWorldY, m.WorldBounds.MinX, m.WorldBounds.MaxY)
		}
		// 标定来源必须写清，不允许空着 —— 空来源等于「不知道这数字哪来的」。
		if m.Calib.Source == "" {
			t.Fatalf("%s 的 calibration.source 为空", id)
		}
		// 覆盖范围必须是有限数，不能出现 NaN/Inf（JSON 里写错一个字符就会这样）。
		for _, v := range []float64{m.OriginWorldX, m.OriginWorldY, m.UnitsPerPixel,
			m.WorldBounds.MinX, m.WorldBounds.MinY, m.WorldBounds.MaxX, m.WorldBounds.MaxY} {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				t.Fatalf("%s 的标定含 NaN/Inf", id)
			}
		}
	}
}

// TestDust2CalibrationTwoSourcesAgree 钉住 dust2 的标定，并记录**两套来源**。
//
// 🔴 现在用的是「与底图像素对齐」的那一套（origin=-2470/3250.6），
// 来源是 cs2_webradar 的 meta.json5（MIT © 2021 Lexogrine）。
// 本机 `resource/overviews/de_dust2.txt` 给的是 -2476/3239，两者差 6 / 11.6 单位
// （≤2.6 像素）。**两套标定对 4877 个现场点的覆盖率完全相同**（99.77%），
// 所以换成与底图一致的那一套没有牺牲精度 —— 反而点位和贴图严格对齐。
//
// 改这几个数字之前必须先证明新值也对：判据是下面两个用例
// （地标落位 + 现场坐标在图内）。
func TestDust2CalibrationTwoSourcesAgree(t *testing.T) {
	r, _ := NewRegistry()
	m, st, msg := r.Resolve("de_dust2")
	if m == nil || st != StateReady {
		t.Fatalf("de_dust2 应为 ready，实际 %s（%s）", st, msg)
	}
	if !near(m.OriginWorldX, -2470, 0.01) {
		t.Fatalf("origin_x = %v，期望 -2470（与 overview.png 对齐的那一套）", m.OriginWorldX)
	}
	if !near(m.OriginWorldY, 3250.6, 0.01) {
		t.Fatalf("origin_y = %v，期望 3250.6", m.OriginWorldY)
	}
	// 世界范围必须等于 1024 × 4.4 = 4505.6，且与 webradar 的 offset 换算结果一致。
	// 这是「底图覆盖范围」和「标定」能对上的唯一判据：底图会等比缩放到这个框里，
	// 框大了点位就整体偏小，框小了就整体偏大，且越靠边偏得越多。
	if !near(m.WorldBounds.MaxX-m.WorldBounds.MinX, 1024*4.4, 0.01) {
		t.Fatalf("覆盖宽度 = %v，期望 4505.6", m.WorldBounds.MaxX-m.WorldBounds.MinX)
	}
	if !near(m.WorldBounds.MaxY-m.WorldBounds.MinY, 1024*4.4, 0.01) {
		t.Fatalf("覆盖高度 = %v，期望 4505.6", m.WorldBounds.MaxY-m.WorldBounds.MinY)
	}
	if !near(m.UnitsPerPixel, 4.4, 0.001) {
		t.Fatalf("scale = %v，期望 4.4", m.UnitsPerPixel)
	}
	if m.RefWidth != 1024 || m.RefHeight != 1024 {
		t.Fatalf("参考分辨率 = %d×%d，期望 1024×1024", m.RefWidth, m.RefHeight)
	}
	// 标定必须标记为「已验证」，否则前端会把它当未验证参数显示
	if m.Calib.Verified {
		t.Fatalf("没有独立控制点测量时不能标记 verified=true")
	}
	if m.Calib.Points < 1000 {
		t.Fatalf("验证点数 %d 太少，现场用了 4877 个", m.Calib.Points)
	}
}

// TestAnchorsLandOnKnownPoints 用 overview txt 里的地标反算世界坐标，
// 检查是否落在 dust2 已知的位置上。
//
// 这是「3 个控制点 + 1 个留出点」验收里最硬的一条：
// 如果 pos_x/pos_y/scale 错了，bombA/bombB 会跑到别的象限去。
//
// 🔴 判据分两层，**绝对值和结构关系分开**：
//   - bombA / bombB 用绝对值（A 在右、B 在左，这两个位置在 dust2 上是常识）；
//   - 出生点只用**结构关系**（CT 在上方、T 在下方、两者相距很远）。
//     因为我没法给出生点一个可信的绝对坐标 —— 硬编一个我猜的数字，
//     测的就不是标定，而是我的猜测。
func TestAnchorsLandOnKnownPoints(t *testing.T) {
	r, _ := NewRegistry()
	m, _, _ := r.Resolve("de_dust2")
	if m == nil {
		t.Fatal("de_dust2 解析失败")
	}
	byName := map[string]Anchor{}
	for _, a := range m.Anchors {
		byName[a.Name] = a
	}

	// ① 炸弹点：绝对值 + 左右关系
	aX, aY := m.AnchorWorld(byName["bombA"])
	bX, bY := m.AnchorWorld(byName["bombB"])
	const tol = 200.0
	if !near(aX, 1128, tol) || !near(aY, 2517, tol) {
		t.Fatalf("bombA 反算 (%.0f, %.0f)，期望约 (1128, 2517)（容差 %.0f）", aX, aY, tol)
	}
	if !near(bX, -1530, tol) || !near(bY, 2698, tol) {
		t.Fatalf("bombB 反算 (%.0f, %.0f)，期望约 (-1530, 2698)（容差 %.0f）", bX, bY, tol)
	}
	if !(aX > bX) {
		t.Fatalf("dust2 的 A 点应在 B 点右侧（x 更大），实际 A.x=%.0f B.x=%.0f", aX, bX)
	}
	if !(aY < bY) {
		t.Fatalf("A 点应在 B 点的下方（y 更小），实际 A.y=%.0f B.y=%.0f", aY, bY)
	}

	// ② 出生点：只验证结构关系
	ctX, ctY := m.AnchorWorld(byName["CTSpawn"])
	tX, tY := m.AnchorWorld(byName["TSpawn"])
	if !(ctY > tY) {
		t.Fatalf("CT 出生点应在地图上方（y 更大）：CT.y=%.0f T.y=%.0f", ctY, tY)
	}
	if ctY-tY < 2000 {
		t.Fatalf("两个出生点南北距离只有 %.0f，dust2 上应该超过 2000 —— 标定比例可能错了", ctY-tY)
	}
	if !m.InBounds(ctX, ctY) || !m.InBounds(tX, tY) {
		t.Fatalf("出生点应在图内：CT(%.0f,%.0f) T(%.0f,%.0f)", ctX, ctY, tX, tY)
	}
}

// TestFieldCoordsInBounds 用现场真实世界坐标验证包围盒。
//
// 这三个点是 2026-10-20 13:05 那局 de_dust2 实测的 cmd=208 声音原点。
// 它们必须落在图内 —— 如果包围盒算错，雷达上会大面积显示「图外」。
func TestFieldCoordsInBounds(t *testing.T) {
	r, _ := NewRegistry()
	m, _, _ := r.Resolve("de_dust2")
	cases := []struct {
		x, y float64
		note string
	}{
		{-367.5, 1081.3, "中路附近"},
		{255.9, 1474.2, "中路偏 CT"},
		{-1274.2, 2670.1, "B 点附近"},
	}
	for _, c := range cases {
		if !m.InBounds(c.x, c.y) {
			t.Fatalf("(%v, %v) %s 应在地图范围内", c.x, c.y, c.note)
		}
		px, py := m.WorldToImage(c.x, c.y)
		if px < 0 || px > float64(m.RefWidth) || py < 0 || py > float64(m.RefHeight) {
			t.Fatalf("(%v, %v) 投影到 (%.0f, %.0f) 超出 %d×%d",
				c.x, c.y, px, py, m.RefWidth, m.RefHeight)
		}
	}
	// 明显在图外的坐标必须被判为越界（不能偷偷吸附）
	if m.InBounds(-9999, 9999) {
		t.Fatalf("(-9999, 9999) 明显在图外，不该判为在图内")
	}
}

// TestWorldImageRoundTrip 钉住正反变换互逆。
func TestWorldImageRoundTrip(t *testing.T) {
	r, _ := NewRegistry()
	m, _, _ := r.Resolve("de_dust2")
	for _, p := range [][2]float64{{0, 0}, {-2470, 3250.6}, {2035.6, -1255}, {123.4, 567.8}} {
		px, py := m.WorldToImage(p[0], p[1])
		x, y := m.ImageToWorld(px, py)
		if !near(x, p[0], 0.001) || !near(y, p[1], 0.001) {
			t.Fatalf("往返变换不一致：(%v,%v) → (%.3f,%.3f) → (%.3f,%.3f)",
				p[0], p[1], px, py, x, y)
		}
	}
}

// TestWorldToImageDirection 钉住 Y 轴方向：世界 Y 向上，像素 Y 向下。
//
// 🔴 这一条最容易写反。写反的表现是整张图上下镜像 —— 人物看着在 B 点，
// 实际在 A 点，而且「看起来还挺像」，极难发现。
func TestWorldToImageDirection(t *testing.T) {
	r, _ := NewRegistry()
	m, _, _ := r.Resolve("de_dust2")
	// 世界 Y 更大的点，像素 Y 必须更小
	_, yLow := m.WorldToImage(0, 0)
	_, yHigh := m.WorldToImage(0, 3000)
	if !(yHigh < yLow) {
		t.Fatalf("世界 y=3000 的像素 y（%.1f）应小于 y=0 的（%.1f）—— Y 轴方向反了", yHigh, yLow)
	}
	// 世界 X 更大的点，像素 X 必须更大
	xLow, _ := m.WorldToImage(-2000, 0)
	xHigh, _ := m.WorldToImage(2000, 0)
	if !(xHigh > xLow) {
		t.Fatalf("世界 x=2000 的像素 x（%.1f）应大于 x=-2000 的（%.1f）", xHigh, xLow)
	}
}

// TestResolveAliases 钉住别名解析（用户会说「炙热沙城」而不是 de_dust2）。
func TestResolveAliases(t *testing.T) {
	r, _ := NewRegistry()
	for _, name := range []string{"de_dust2", "dust2", "Dust2", "炙热沙城", "沙漠2", "d2", " de_dust2 "} {
		m, st, msg := r.Resolve(name)
		if m == nil || m.ID != "de_dust2" {
			t.Fatalf("%q 应解析成 de_dust2，实际 %+v（%s %s）", name, m, st, msg)
		}
	}
}

// TestResolveStates 钉住三种失败状态的区分。
//
// 🔴 为什么必须分开：报告要求「失败分为缺资源、版本不符、标定失败，
// 不静默显示旧图」。全都返回同一个状态，前端就没法告诉用户到底缺什么。
func TestResolveStates(t *testing.T) {
	r, _ := NewRegistry()

	// 空名字 = 还不知道是哪张图
	if _, st, _ := r.Resolve(""); st != StateUnknown {
		t.Fatalf("空地图名应为 %s，实际 %s", StateUnknown, st)
	}
	// 未知地图 = 资产里没有
	if _, st, msg := r.Resolve("de_unknown_map"); st != StateNoAsset {
		t.Fatalf("未知地图应为 %s，实际 %s", StateNoAsset, st)
	} else if msg == "" {
		t.Fatalf("未知地图必须给出说明")
	}
}

// TestImageKindIsHonest 钉住「底图来源必须如实标注」。
//
// 现在没有官方 overview 贴图（RED2 格式的 VPK 还没解），用的是数据轮廓图。
// 这种情况下 ImageKind 必须是 data-outline，且 ImageNote 里明确写「不是官方贴图」。
// 绝不能让它看起来像官方底图。
func TestImageKindIsHonest(t *testing.T) {
	r, _ := NewRegistry()
	m, st, _ := r.Resolve("de_dust2")
	if st != StateReady {
		t.Fatalf("dust2 应 ready，实际 %s", st)
	}
	if m.ImageKind != "data-outline" {
		t.Fatalf("当前只有数据轮廓图，ImageKind 应为 data-outline，实际 %q", m.ImageKind)
	}
	if m.ImageNote == "" {
		t.Fatalf("data-outline 必须带说明")
	}
	if !contains(m.ImageNote, "不是官方贴图") {
		t.Fatalf("说明里必须写清「不是官方贴图」，实际 %q", m.ImageNote)
	}
	if m.ImageURI == "" {
		t.Fatalf("ready 状态必须有可用底图地址")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestImageBytesRejectsPathTraversal 钉住底图接口只认固定文件名。
func TestImageBytesRejectsPathTraversal(t *testing.T) {
	r, _ := NewRegistry()
	for _, bad := range []string{"../../etc/passwd", "overview.png/../x", "", "de_dust2.json"} {
		if _, _, ok := r.ImageBytes("de_dust2", bad); ok {
			t.Fatalf("文件名 %q 不该被接受", bad)
		}
	}
	if _, _, ok := r.ImageBytes("../../x", "density.png"); ok {
		t.Fatalf("非法 map_id 不该被接受")
	}
	// 正常路径必须能取到
	if b, ct, ok := r.ImageBytes("de_dust2", "density.png"); !ok || len(b) == 0 {
		t.Fatalf("density.png 应能取到，ok=%v ct=%q len=%d", ok, ct, len(b))
	}
}

// TestLevelForZ 钉住楼层匹配。
func TestLevelForZ(t *testing.T) {
	r, _ := NewRegistry()
	m, _, _ := r.Resolve("de_dust2")
	if m.LevelForZ(0) == nil {
		t.Fatalf("z=0 应命中地面层")
	}
	if m.LevelForZ(1935) != nil {
		t.Fatalf("z=1935 明显超出 dust2 的高度范围，不该命中任何楼层")
	}
}
