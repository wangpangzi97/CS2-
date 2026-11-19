package radarsrv

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/mapdata"
)

// newMapStore 建一个带内嵌地图资产的 Store。
func newMapStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	if cfg.MapRegistry == nil {
		reg, err := mapdata.NewRegistry()
		if err != nil {
			t.Fatalf("加载内嵌地图资产失败：%v", err)
		}
		cfg.MapRegistry = reg
	}
	return NewStore(cfg)
}

// seedSounds 往会话里塞 n 个「声音原点」。调用方不需要持锁。
func seedSounds(sess *Session, n int, fx func(i int) (float32, float32)) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	now := time.Now()
	for i := 0; i < n; i++ {
		x, y := fx(i)
		sess.noteGNSPlayerPos(uint32(100+i), cs2proto.Vec3{X: x, Y: y, Z: -100}, now)
	}
}

// TestSnapshotMapFromManualName 钉住「手选地图」这条路径。
//
// 场景：svc_ServerInfo 还没解出，用户在页面上选了「炙热沙城」。
func TestSnapshotMapFromManualName(t *testing.T) {
	st := newMapStore(t, Config{MapName: "炙热沙城"})
	sn := st.Get("s1").Snapshot()
	if sn.Map == nil {
		t.Fatalf("手选地图后 Map 不应为 nil，state=%s status=%s", sn.MapState, sn.MapStatus)
	}
	if sn.Map.ID != "de_dust2" {
		t.Fatalf("地图 ID = %q，期望 de_dust2（别名 炙热沙城 应被解析）", sn.Map.ID)
	}
	if sn.MapState != string(mapdata.StateReady) {
		t.Fatalf("MapState = %q，期望 ready", sn.MapState)
	}
	if sn.MapSource != "manual" {
		t.Fatalf("MapSource = %q，期望 manual", sn.MapSource)
	}
	// 标定参数必须是「能直接用于投影」的，缺一个前端就算不出位置。
	if sn.Map.UnitsPerPixel <= 0 || sn.Map.RefWidth <= 0 || sn.Map.RefHeight <= 0 {
		t.Fatalf("标定不完整：upp=%v ref=%dx%d", sn.Map.UnitsPerPixel, sn.Map.RefWidth, sn.Map.RefHeight)
	}
	// 底图地址必须指向 /mapimg/，否则前端拿不到图。
	if sn.Map.ImageURI == "" {
		t.Fatalf("ImageURI 为空，前端无法加载底图")
	}
}

// TestSnapshotMapInferredFromCoords 钉住「坐标反推」这条路径。
//
// 场景：什么都没配，但声音原点全部落在 dust2 的标定范围内 ⇒ 认成 dust2，
// 并且 MapSource 必须是 "inferred"（前端据此标注「反推」，不能装成确定）。
func TestSnapshotMapNotInferredFromCoords(t *testing.T) {
	st := newMapStore(t, Config{})
	sess := st.Get("s2")
	seedSounds(sess, 20, func(i int) (float32, float32) { return float32(-2000 + i*150), float32(1000 + i*100) })
	for k, e := range sess.gnsPos {
		e.At = time.Now().Add(-time.Hour)
		sess.gnsPos[k] = e
	}
	sn := sess.Snapshot()
	if sn.Map != nil || sn.MapSource == "inferred" {
		t.Fatalf("声音包围盒不能识别地图: %+v", sn)
	}
}

// TestMapNotInferredFromTooFewPoints 钉住「样本不足不认图」。
//
// 三个点可能只是巧合落在框里，不能凭这个把底图换掉。
func TestMapNotInferredFromTooFewPoints(t *testing.T) {
	st := newMapStore(t, Config{})
	sess := st.Get("s3")
	seedSounds(sess, mapInferMinPoints-1, func(i int) (float32, float32) {
		return float32(-2000 + i*150), float32(1000 + i*100)
	})
	sn := sess.Snapshot()
	if sn.Map != nil {
		t.Fatalf("%d 个点就认了地图（%s），阈值 mapInferMinPoints=%d 没生效",
			mapInferMinPoints-1, sn.Map.ID, mapInferMinPoints)
	}
	if sn.MapState != string(mapdata.StateUnknown) {
		t.Fatalf("MapState = %q，期望 unknown", sn.MapState)
	}
}

// TestMapNotInferredFromOutsideCoords 钉住「坐标在图外就不认」。
//
// 这是反推最容易出错的方向：只要「有点就认图」，玩别的图时也会显示 dust2 底图，
// 于是所有点都跑到图外，看的人会以为是解码错了。
func TestMapNotInferredFromOutsideCoords(t *testing.T) {
	st := newMapStore(t, Config{})
	sess := st.Get("s4")
	seedSounds(sess, 30, func(i int) (float32, float32) {
		return float32(9000 + i*10), float32(-9000 - i*10)
	})
	sn := sess.Snapshot()
	if sn.Map != nil {
		t.Fatalf("坐标全在 dust2 范围外，却认成了 %s", sn.Map.ID)
	}
}

// TestSetMapNameManualOverride 钉住手动选图接口的语义。
func TestSetMapNameManualOverride(t *testing.T) {
	st := newMapStore(t, Config{})
	state, _ := st.SetMapName("s5", "d2")
	if state != "ready" {
		t.Fatal(state)
	}
	state, _ = st.SetMapName("s5", "<b>marker</b>")
	if state != "invalid" {
		t.Fatal(state)
	}
	sn := st.Get("s5").Snapshot()
	if sn.Map == nil || sn.Map.ID != "de_dust2" {
		t.Fatal("invalid mutation changed prior map")
	}
	state, _ = st.SetMapName("s5", "")
	if state != "unknown" || st.Get("s5").Snapshot().Map != nil {
		t.Fatal("clear failed")
	}
}

// TestMapImageRoute 钉住底图路由的三条边界：正常、路径穿越、未知文件。
func TestMapImageRoute(t *testing.T) {
	st := newMapStore(t, Config{})
	h := st.fixtureHandler("")

	cases := []struct {
		path string
		code int
		why  string
	}{
		{"/mapimg/de_dust2/density.png", http.StatusOK, "内嵌轮廓图应可取"},
		{"/mapimg/de_dust2/overview.png", http.StatusNotFound, "没有官方贴图时必须 404，不能回退成轮廓图冒充"},
		{"/mapimg/de_dust2/whatever.png", http.StatusNotFound, "只认固定文件名"},
		{"/mapimg/de_nuke/density.png", http.StatusNotFound, "未知地图必须 404"},
		{"/mapimg/de_dust2", http.StatusNotFound, "缺文件名必须 404"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.code {
			t.Fatalf("%s：状态码 %d，期望 %d（%s）", c.path, rec.Code, c.code, c.why)
		}
		if c.code == http.StatusOK {
			if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
				t.Fatalf("%s：Content-Type = %q，期望 image/png", c.path, ct)
			}
			if rec.Body.Len() < 100 {
				t.Fatalf("%s：返回体只有 %d 字节，不像 PNG", c.path, rec.Body.Len())
			}
		}
	}
}

// TestMapImageRejectsTraversal 直接打 handleMapImage，绕开 ServeMux 的路径清理。
//
// 🔴 为什么不能只测 mux 那一层：`http.ServeMux` 会把含 `..` 的路径 301 到清理后的
// 地址，于是「穿越被拒」看起来成立 —— 但那只是 mux 的副作用，handler 自己的
// 守卫**从来没被执行过**。以后换了路由实现（或直接挂 handler），守卫漏了也测不出来。
func TestMapImageRejectsTraversal(t *testing.T) {
	st := newMapStore(t, Config{})
	for _, p := range []string{
		"/mapimg/de_dust2/../../etc/passwd",
		"/mapimg/../de_dust2/density.png",
		"/mapimg/de_dust2/..%2f..%2fetc/passwd",
		"/mapimg/./density.png",
		"/mapimg/de_dust2/density.png/extra",
	} {
		req := httptest.NewRequest(http.MethodGet, "/mapimg/", nil)
		req.URL.Path = p // 绕过 mux 的清理，直接喂原始路径
		rec := httptest.NewRecorder()
		st.handleMapImage(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s：handler 状态码 %d，期望 404（穿越/多余层级必须被拒）", p, rec.Code)
		}
	}
}

// TestMapIDsRoute 钉住 /api/v1/maps —— 前端下拉框靠它填选项。
func TestMapIDsRoute(t *testing.T) {
	st := newMapStore(t, Config{})
	h := st.fixtureHandler("")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/maps", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "de_dust2") {
		t.Fatalf("返回里没有 de_dust2：%s", body)
	}
}

// TestRadarHTTPIntegration checks HTTP, JSON and PNG bytes only; it does not execute JavaScript.
func TestRadarHTTPIntegration(t *testing.T) {
	st := newMapStore(t, Config{MapName: "de_dust2"})
	sess := st.Get("e2e")
	seedSounds(sess, 16, func(i int) (float32, float32) {
		return float32(-1800 + i*180), float32(800 + i*120)
	})
	srv := httptest.NewServer(st.fixtureHandler(""))
	defer srv.Close()

	// ① 页面本身
	resp, err := http.Get(srv.URL + "/radar?session=e2e")
	if err != nil {
		t.Fatalf("取 /radar 失败：%v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/radar 状态码 %d", resp.StatusCode)
	}
	html := string(page)
	for _, want := range []string{"drawMapLayer", "origin_world_x", "units_per_pixel", "image_uri"} {
		if !strings.Contains(html, want) {
			t.Fatalf("页面里没有 %q —— 前端没接上标定参数", want)
		}
	}
	// 旧的固定投影必须消失：它会把世界坐标硬塞进方框，等于没有地图。
	if strings.Contains(html, "const R=8000;") {
		t.Fatalf("页面里还有 const R=8000 旧投影，说明底图层没替换干净")
	}

	// ② 快照 JSON
	resp, err = http.Get(srv.URL + "/api/v1/radar?session=e2e")
	if err != nil {
		t.Fatalf("取 /api/v1/radar 失败：%v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var sn struct {
		Map struct {
			ID            string  `json:"id"`
			OriginWorldX  float64 `json:"origin_world_x"`
			OriginWorldY  float64 `json:"origin_world_y"`
			UnitsPerPixel float64 `json:"units_per_pixel"`
			ImageURI      string  `json:"image_uri"`
		} `json:"map"`
		MapState  string `json:"map_state"`
		MapSource string `json:"map_source"`
		Players   []any  `json:"players"`
		Sounds    []any  `json:"sounds"`
	}
	if err := json.Unmarshal(raw, &sn); err != nil {
		t.Fatalf("快照 JSON 解不开：%v\n%s", err, raw)
	}
	if sn.Map.ID != "de_dust2" || sn.MapState != "ready" {
		t.Fatalf("快照地图不对：id=%q state=%q", sn.Map.ID, sn.MapState)
	}
	if sn.Map.OriginWorldX != -2470 || sn.Map.OriginWorldY != 3250.6 || sn.Map.UnitsPerPixel != 4.4 {
		t.Fatalf("标定参数没传到前端：%+v", sn.Map)
	}
	if sn.Map.ImageURI != "/mapimg/de_dust2/density.png" {
		t.Fatalf("ImageURI = %q，前端拿不到底图", sn.Map.ImageURI)
	}
	// 硬规则 290：实体表没接通，Players 必须为空 —— 这一条在端到端层面再钉一次。
	if len(sn.Players) != 0 {
		t.Fatalf("Players 应为空（实体表未接通），实际 %d 个", len(sn.Players))
	}
	if len(sn.Sounds) == 0 {
		t.Fatalf("声音层应有数据，实际 0 条")
	}

	// ③ 页面里写的那个 image_uri 必须真能取到
	resp, err = http.Get(srv.URL + sn.Map.ImageURI)
	if err != nil {
		t.Fatalf("取底图失败：%v", err)
	}
	img, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("底图状态码 %d（页面写着 %s，但取不到）", resp.StatusCode, sn.Map.ImageURI)
	}
	if len(img) < 8 || string(img[1:4]) != "PNG" {
		t.Fatalf("底图不是 PNG（%d 字节）", len(img))
	}
}

// TestRadarPageWithExternalOverview 验证「放好 maps 目录之后」的真实路径。
//
// 🔴 这条用例用的是**交付包里真实存在的** dist/maps，不是造的假文件。
// 它回答的是产品问题：用户把包解开、双击 exe 之后，页面上到底有没有底图。
// 三个环节必须同时对：Registry 扫到 overview.png → Snapshot 的 image_uri 指向它
// → /mapimg 真能取到 2048 像素的 PNG。
func TestRadarPageWithExternalOverview(t *testing.T) {
	mapsDir := filepath.Join("..", "..", "dist", "maps")
	if fi, err := os.Stat(filepath.Join(mapsDir, "de_dust2", "overview.png")); err != nil || fi.IsDir() {
		t.Skip("dist/maps/de_dust2/overview.png 不存在（没跑 tools/gen_map_assets.py），跳过")
	}
	st := newMapStore(t, Config{MapName: "de_dust2", MapImageDir: mapsDir})
	sess := st.Get("ext")
	seedSounds(sess, 16, func(i int) (float32, float32) {
		return float32(-1800 + i*180), float32(800 + i*120)
	})
	sn := sess.Snapshot()
	if sn.Map == nil || sn.MapState != "ready" {
		t.Fatalf("有 overview.png 时应为 ready，实际 state=%s status=%s", sn.MapState, sn.MapStatus)
	}
	if sn.Map.ImageKind != "external-overview" {
		t.Fatalf("有外部底图时 ImageKind = %q，期望 external-overview", sn.Map.ImageKind)
	}
	if !strings.HasPrefix(sn.Map.ImageURI, "/mapimg/de_dust2/overview.png?v=") {
		t.Fatalf("ImageURI = %q", sn.Map.ImageURI)
	}
	// 底图说明必须写清来源，不能假装是「从游戏里提取的官方贴图」。
	if !strings.Contains(sn.Map.ImageNote, "LICENSE") {
		t.Fatalf("ImageNote 应说明来源/许可：%q", sn.Map.ImageNote)
	}

	h := st.fixtureHandler("")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, sn.Map.ImageURI, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("取底图状态码 %d", rec.Code)
	}
	if rec.Body.Len() < 10000 {
		t.Fatalf("底图只有 %d 字节，不像真实 overview", rec.Body.Len())
	}
}

// TestAllBuiltinMapsResolveWithoutImage 钉住「只有标定、没有底图」时的行为。
//
// 16 张非 dust2 的图在内嵌资产里没有轮廓图。这时**必须**如实报 resource_missing，
// 而不是退回某个别的图的底图 —— 画错图的底图比不画更糟。
func TestAllBuiltinMapsResolveWithoutImage(t *testing.T) {
	st := newMapStore(t, Config{}) // 不给 MapImageDir
	for _, id := range st.MapIDs() {
		state, _ := st.SetMapName("noimg", id)
		sn := st.Get("noimg").Snapshot()
		if sn.Map == nil {
			t.Fatalf("%s 应有标定定义（Map 不为 nil）", id)
		}
		if id == "de_dust2" {
			continue // 内嵌了轮廓图，是 ready
		}
		if state != string(mapdata.StateNoAsset) {
			t.Fatalf("%s 无底图时 state = %q，期望 resource_missing", id, state)
		}
		if sn.Map.ImageURI != "" {
			t.Fatalf("%s 无底图却给了 ImageURI=%q", id, sn.Map.ImageURI)
		}
	}
}
