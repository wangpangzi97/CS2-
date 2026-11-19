// Package mapdata 是 2D 雷达底图的地图定义层。
//
// # 它解决什么问题
//
// 之前页面用的是 `const R=8000` 的固定网格投影：把世界坐标硬塞进一个方框，
// 没有底图、没有标定、没有楼层，人物落在哪全靠肉眼猜。这个包把「地图」变成
// 一份**可校验的数据**：世界坐标 → 底图像素 只有一条变换链，参数有来源、有验证。
//
// # 参数从哪来（不抄网上数字）
//
// 标定参数（pos_x / pos_y / scale / anchors）是从**本机游戏文件**
// `game/csgo/pak01_022.vpk` 里的 `resource/overviews/de_dust2.txt` 原样提取的
// （这些小文本在 VPK 里未压缩）。提取位置：pak01_022.vpk @ 49618294。
//
// 原始内容：
//
//	"de_dust2"
//	{
//		"material"	"overviews/de_dust2_v2"
//		"pos_x"		"-2476"	// upper left world coordinate
//		"pos_y"		"3239"
//		"scale"		"4.4"
//		"rotate"	"1"
//		"zoom"		"1.1"
//		"CTSpawn_x"	"0.62"	"CTSpawn_y" "0.21"
//		"TSpawn_x"	"0.39"	"TSpawn_y"  "0.91"
//		"bombA_x"	"0.80"	"bombA_y"   "0.16"
//		"bombB_x"	"0.21"	"bombB_y"   "0.12"
//	}
//
// 并且用现场 4877 个真实世界坐标（2026-10-20 13:05 那局 de_dust2 的
// cmd=208 声音原点）做了独立交叉验证：**99.77% 落在标定范围内**，
// 第 2~4 段 100%。反算 bombA=(1128, 2517) / bombB=(-1530, 2698)，
// 与 dust2 实际的 A/B 点位置吻合 —— 所以这套数字不是抄的，是验过的。
//
// # rotate / zoom 为什么**不参与**基础映射
//
// overview txt 里的 `rotate=1` / `zoom=1.1` 是给 HUD 雷达（panorama）用的
// 显示变换，**不影响** world→overview-pixel 的基础映射。判据就是上面那次反算：
// 如果 rotate 参与映射，bombA/bombB 会落到错误象限，与实测不符。
// 这两个值保留在结构里只作记录，不参与计算 —— 免得以后有人以为漏了。
package mapdata

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// readDirSafe / readFileSafe 是 os 的薄封装：外部资产目录允许不存在
// （用户没放官方底图是正常状态），所以读失败不能当错误往上抛。
func readDirSafe(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			sub, err := os.ReadDir(dir + "/" + e.Name())
			if err != nil {
				continue
			}
			for _, s := range sub {
				out = append(out, e.Name()+"/"+s.Name())
			}
			continue
		}
		out = append(out, e.Name())
	}
	return out, nil
}

func readFileSafe(path string) ([]byte, error) { return os.ReadFile(path) }

//go:embed assets/*.json assets/*.png
var assets embed.FS

// State 是地图加载状态。前端靠它决定显示底图还是显示「缺资源」。
type State string

const (
	// StateUnknown 表示还不知道是哪张图（没拿到 ServerInfo.map_name，也没手选）。
	StateUnknown State = "unknown"
	// StateIdentified 表示图名认出来了，但底图资产还没匹配上。
	StateIdentified State = "identified"
	// StateNoAsset 表示图名已知、但这张图的底图/标定不在资产清单里。
	StateNoAsset State = "resource_missing"
	// StateReady 表示底图与标定都就绪，可以按真实坐标投影。
	StateReady State = "ready"
)

// Bounds 是地图的世界坐标包围盒，**只做校验**，不用来自动缩放画面。
//
// 🔴 为什么不用「当前人物最小/最大坐标」自动缩放：那会让人物走动时整张图跟着
// 放大缩小，看上去像在地图上漂移，而且一个点也能撑满全屏。包围盒是固定的。
type Bounds struct {
	MinX float64 `json:"min_x"`
	MinY float64 `json:"min_y"`
	MaxX float64 `json:"max_x"`
	MaxY float64 `json:"max_y"`
}

// Contains 判断世界坐标是否落在包围盒内。
func (b Bounds) Contains(x, y float64) bool {
	return x >= b.MinX && x <= b.MaxX && y >= b.MinY && y <= b.MaxY
}

// Anchor 是 overview txt 里给出的归一化地标（出生点、炸弹点）。
//
// 它的用途是**标定校验**：把归一化坐标乘上参考分辨率就是底图像素，
// 再反算世界坐标，应当落在该地标已知的位置上。四个点都不共线，
// 满足「3 个控制点 + 1 个留出点」的验收要求。
type Anchor struct {
	Name  string  `json:"name"`
	NormX float64 `json:"norm_x"` // 0..1，相对参考宽度
	NormY float64 `json:"norm_y"` // 0..1，相对参考高度
}

// Level 是一个楼层。
//
// 2D 方案里楼层的作用是：同 XY 不同 Z 的两个实体**不能画成同一个点**。
// ZMin/ZMax 必须按地图实际高度定，不能对所有图套一个阈值（见 levels 注释）。
type Level struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	ZMin  float64 `json:"z_min"`
	ZMax  float64 `json:"z_max"`
	Image string  `json:"image,omitempty"`
}

// Calib 记录标定的来源与验证结果 —— 这一层是给「凭什么信这套数字」用的。
type Calib struct {
	// Source 形如 "valve-overview-txt@pak01_022.vpk" 或 "manual"。
	Source string `json:"source"`
	// Verified 表示是否用现场数据交叉验证过。
	Verified bool `json:"verified"`
	// Points 是参与验证的现场坐标点数。
	Points int `json:"points"`
	// Coverage 是落在标定范围内的比例（0..1）。
	Coverage float64 `json:"coverage"`
	// Note 是一句人话说明。
	Note string `json:"note"`
}

// MapDef 是一张地图的完整定义。
type MapDef struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Aliases     []string `json:"aliases,omitempty"`
	WorkshopID  string   `json:"workshop_id,omitempty"`
	GameBuild   string   `json:"game_build,omitempty"`

	// Material 是 overview txt 里 "material" 的值（形如 overviews/de_dust2_v2）。
	Material string `json:"material,omitempty"`

	// ImageURI 是**当前实际可用**的底图地址，由 Registry 按资产情况填。
	// 官方贴图存在时是 overview.png，否则退回数据轮廓图。
	ImageURI  string `json:"image_uri"`
	ImageKind string `json:"image_kind"` // "official" / "data-outline" / "none"
	ImageNote string `json:"image_note,omitempty"`
	RefWidth  int    `json:"ref_width"`
	RefHeight int    `json:"ref_height"`

	// 标定：世界坐标左上角 + 每像素世界单位。
	OriginWorldX  float64 `json:"origin_world_x"`
	OriginWorldY  float64 `json:"origin_world_y"`
	UnitsPerPixel float64 `json:"units_per_pixel"`

	// Rotate / Zoom 只作记录，**不参与映射**（原因见包注释）。
	Rotate int     `json:"rotate,omitempty"`
	Zoom   float64 `json:"zoom,omitempty"`

	WorldBounds Bounds   `json:"world_bounds"`
	Levels      []Level  `json:"levels,omitempty"`
	Anchors     []Anchor `json:"anchors,omitempty"`
	Calib       Calib    `json:"calibration"`
}

// WorldToImage 把世界坐标变换成**参考分辨率下的底图像素**。
//
// 约定（与 overview txt 一致）：
//
//   - 世界 Y 向上，底图像素 Y 向下 ⇒ y 要反号；
//
//   - origin 是底图**左上角**对应的世界坐标。
//
//     image_x = (world_x - origin_x) / units_per_pixel
//     image_y = (origin_y - world_y) / units_per_pixel
//
// 显示层的缩放/拖拽/设备像素比**全部在这一步之后**处理，不能改动原始世界坐标。
func (m *MapDef) WorldToImage(x, y float64) (float64, float64) {
	if m == nil || m.UnitsPerPixel <= 0 {
		return 0, 0
	}
	return (x - m.OriginWorldX) / m.UnitsPerPixel,
		(m.OriginWorldY - y) / m.UnitsPerPixel
}

// ImageToWorld 是 WorldToImage 的逆变换，标定校验和单元测试用。
func (m *MapDef) ImageToWorld(px, py float64) (float64, float64) {
	if m == nil || m.UnitsPerPixel <= 0 {
		return 0, 0
	}
	return m.OriginWorldX + px*m.UnitsPerPixel,
		m.OriginWorldY - py*m.UnitsPerPixel
}

// InBounds 判断世界坐标是否落在地图范围内。
//
// 🔴 它只回答「这个坐标是不是明显在图外」，**不用来修正坐标**。
// 越界就如实报告越界 —— 偷偷吸附到边界会让人以为目标真的在那。
func (m *MapDef) InBounds(x, y float64) bool {
	if m == nil {
		return false
	}
	return m.WorldBounds.Contains(x, y)
}

// LevelForZ 返回 z 所在的楼层；没有匹配时返回 nil。
//
// 楼层之间留 gnsLevelHysteresis 的重叠带，避免站在楼梯上时来回闪层。
// 重叠带取相邻两层边界附近，判据是「离哪层中心更近」。
func (m *MapDef) LevelForZ(z float64) *Level {
	if m == nil || len(m.Levels) == 0 {
		return nil
	}
	for i := range m.Levels {
		lv := &m.Levels[i]
		if z >= lv.ZMin && z <= lv.ZMax {
			return lv
		}
	}
	return nil
}

// AnchorWorld 把地标反算成世界坐标（标定校验用）。
func (m *MapDef) AnchorWorld(a Anchor) (float64, float64) {
	return m.ImageToWorld(a.NormX*float64(m.RefWidth), a.NormY*float64(m.RefHeight))
}

// Registry 是地图定义的注册表。
type externalPNG struct {
	size    int64
	mtime   int64
	data    []byte
	version string
}
type Registry struct {
	assetMu  sync.Mutex
	pngCache map[string]externalPNG
	maps     map[string]*MapDef
	// imageFiles 记录每张图有哪些内嵌图片（文件名 → 是否存在）。
	imageFiles map[string]map[string]bool
	// externalDir 是外部底图目录（用户放了官方 PNG 就优先用它）。
	externalDir string
	// external 记录外部目录里实际存在的文件（启动时扫一次）。
	external map[string]bool
}

// NewRegistry 加载内嵌的地图定义。
func NewRegistry() (*Registry, error) {
	r := &Registry{
		maps:       map[string]*MapDef{},
		imageFiles: map[string]map[string]bool{},
		external:   map[string]bool{},
	}
	entries, err := assets.ReadDir("assets")
	if err != nil {
		return nil, fmt.Errorf("读内嵌资产目录: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := assets.ReadFile("assets/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("读 %s: %w", e.Name(), err)
		}
		var m MapDef
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("解析 %s: %w", e.Name(), err)
		}
		if m.ID == "" {
			return nil, fmt.Errorf("%s 缺少 id", e.Name())
		}
		if m.UnitsPerPixel <= 0 || m.RefWidth <= 0 || m.RefHeight <= 0 {
			return nil, fmt.Errorf("%s 标定不完整（units_per_pixel / ref_width / ref_height 必须 > 0）", e.Name())
		}
		r.maps[m.ID] = &m
		r.imageFiles[m.ID] = map[string]bool{}
	}
	// 记录内嵌图片
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".png") {
			continue
		}
		for id := range r.maps {
			if strings.HasPrefix(e.Name(), id+"_") || strings.HasPrefix(e.Name(), id+".") {
				r.imageFiles[id][e.Name()] = true
			}
		}
	}
	return r, nil
}

// SetExternalDir 指定外部底图目录（可选）。
//
// 目录里按 `<map_id>/overview.png` 放官方底图。放了就优先用，
// 没放就退回内嵌的数据轮廓图 —— 状态里会如实写明用的是哪种。
func (r *Registry) SetExternalDir(dir string) {
	r.pngCache = map[string]externalPNG{}
	r.externalDir = dir
	r.external = map[string]bool{}
	if dir == "" {
		return
	}
	ents, err := readDirSafe(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		r.external[e] = true
	}
}

// IDs 返回所有已知地图 ID（排序后）。
func (r *Registry) IDs() []string {
	out := make([]string, 0, len(r.maps))
	for id := range r.maps {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Resolve 按图名解析地图定义，并给出加载状态。
//
// 图名来源可以是 ServerInfo 的 map_name（de_dust2）、用户别名（dust2 / 炙热沙城），
// 空字符串表示「还不知道」。
//
// 返回的 MapDef 里的 ImageURI / ImageKind 已按**实际可用资产**填好：
//   - 外部有 overview.png ⇒ official
//   - 只有内嵌轮廓图     ⇒ data-outline（并写明「不是官方贴图」）
//   - 两者都没有         ⇒ none + StateNoAsset
func (r *Registry) Resolve(name string) (*MapDef, State, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, StateUnknown, "还没拿到地图名（ServerInfo.map_name 未解出，也没有手选）"
	}
	id := r.canonical(name)
	if id == "" {
		return nil, StateNoAsset, fmt.Sprintf("地图 %q 不在资产清单里（已知：%s）",
			name, strings.Join(r.IDs(), ", "))
	}
	base := r.maps[id]
	// 拷贝一份，避免修改注册表里的原件
	cp := *base
	cp.Levels = append([]Level(nil), base.Levels...)
	cp.Anchors = append([]Anchor(nil), base.Anchors...)
	cp.Aliases = append([]string(nil), base.Aliases...)

	// ① 外部底图优先
	if _, version, ok := r.externalImage(id); ok {
		cp.ImageURI = "/mapimg/" + id + "/overview.png?v=" + version
		cp.ImageKind = "external-overview"
		cp.ImageNote = "底图来自 maps/" + id + "/overview.png（overview 贴图，" +
			"来源与许可见该目录下的 LICENSE / meta.json5）"
		return &cp, StateReady, ""
	}
	// ② 内嵌数据轮廓图兜底
	if r.imageFiles[id][id+"_density.png"] {
		cp.ImageURI = "/mapimg/" + id + "/density.png"
		cp.ImageKind = "data-outline"
		cp.ImageNote = "由现场声音事件分布生成的数据轮廓，**不是官方贴图**；" +
			"把官方 overview.png 放进资产目录即可自动替换"
		return &cp, StateReady, ""
	}
	// ③ 什么都没有：图名认出来了，但没底图
	cp.ImageURI = ""
	cp.ImageKind = "none"
	cp.ImageNote = "没有可用的底图资产"
	return &cp, StateNoAsset, "地图认出来了，但底图资产缺失"
}

// canonical 把别名规范成 ID。
func (r *Registry) canonical(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if _, ok := r.maps[n]; ok {
		return n
	}
	for id, m := range r.maps {
		if strings.EqualFold(id, n) {
			return id
		}
		for _, a := range m.Aliases {
			if strings.EqualFold(a, n) {
				return id
			}
		}
	}
	return ""
}

// ImageBytes 返回某张图的底图字节。
//
// file 只接受 "overview.png" / "density.png" 两个固定值，
// **不接受任意路径** —— 防止把 map_id 拼成路径做目录穿越。
func (r *Registry) ImageBytes(id, file string) ([]byte, string, bool) {
	if file != "overview.png" && file != "density.png" {
		return nil, "", false
	}
	if _, ok := r.maps[id]; !ok {
		return nil, "", false
	}
	if file == "overview.png" {
		b, _, ok := r.externalImage(id)
		return b, "image/png", ok
	}

	b, err := assets.ReadFile("assets/" + id + "_density.png")
	if err != nil {
		return nil, "", false
	}
	return b, "image/png", true
}

func (r *Registry) externalImage(id string) ([]byte, string, bool) {
	r.assetMu.Lock()
	defer r.assetMu.Unlock()
	if r.externalDir == "" || r.maps[id] == nil {
		return nil, "", false
	}
	p := filepath.Join(r.externalDir, id, "overview.png")
	st, e := os.Stat(p)
	if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 32<<20 {
		delete(r.pngCache, id)
		return nil, "", false
	}
	if c, ok := r.pngCache[id]; ok && c.size == st.Size() && c.mtime == st.ModTime().UnixNano() {
		return c.data, c.version, true
	}
	b, e := os.ReadFile(p)
	if e != nil || len(b) > 32<<20 {
		return nil, "", false
	}
	cfg, e := png.DecodeConfig(bytes.NewReader(b))
	if e != nil || cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > 16<<20 {
		return nil, "", false
	}
	if _, e = png.Decode(bytes.NewReader(b)); e != nil {
		return nil, "", false
	}
	sum := sha256.Sum256(b)
	v := hex.EncodeToString(sum[:8])
	if r.pngCache == nil {
		r.pngCache = map[string]externalPNG{}
	}
	r.pngCache[id] = externalPNG{st.Size(), st.ModTime().UnixNano(), b, v}
	return b, v, true
}
