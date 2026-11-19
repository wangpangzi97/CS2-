package cs2proto

import (
	"encoding/binary"
	"math"
	"sync"
	"time"

	"local/cs2-radar/internal/handshake"
	"local/cs2-radar/internal/mapdata"
)

// Vec3 是一个三维坐标（CS2 用 float32）。
type Vec3 struct {
	X float32 `json:"x"`
	Y float32 `json:"y"`
	Z float32 `json:"z"`
}

// Player 是雷达要展示的一个目标。
type Player struct {
	Name    string `json:"name,omitempty"`
	SteamID string `json:"steam_id,omitempty"`
	PawnID  int    `json:"pawn_id,omitempty"`
	Serial  int    `json:"serial,omitempty"`
	Health  int    `json:"health"`
	Alive   bool   `json:"alive"`

	ID        int       `json:"id"`
	Team      int       `json:"team"`
	Pos       Vec3      `json:"pos"`
	Source    string    `json:"source"` // 坐标来源：真实解码器名 or "heuristic"
	UpdatedAt time.Time `json:"updated_at"`
	// AgeMS 是「这个坐标有多旧」，单位毫秒。
	//
	// 🔴 保留这个字段的原因变了（硬规则 290）：原来以为 cmd=208 是「增量下发的位置」，
	// 玩家站着不动就不发；现在知道 208 是**声音事件**，所以「没有更新」的真实含义是
	// 「这段时间没有发出声音」，和玩家动没动没有必然关系。
	// 无论如何，「最后已知位置有多旧」必须传给前端，否则画面上
	// 「站着的敌人」和「刚看到的敌人」长得一模一样。
	AgeMS int64 `json:"age_ms"`
	// Stale 表示这个坐标已经超出「活跃刷新」阈值（服务端暂时没再发它的位置）。
	// 前端应当把它画得淡一些，或者加个圈，让「旧位置」一眼可辨。
	Stale bool `json:"stale,omitempty"`
}

// Sound 是一条**声音事件**（`svc_SosStartSoundEvent`，cmd=208）的原点。
//
// 🔴 硬规则 290（2026-10-20 12:00）：cmd=208 **不是人物位置消息**。
// 它的 body 是 `CMsgSosStartSoundEvent`：
//
//	field1 soundevent_guid / field2 soundevent_hash(fixed32) /
//	field3 source_entity_index / field4 seed / field5 packed_params（内含原点）
//
// 过去八轮把它当「实体位置」是错的。三条独立证据见
// `report/20261020-1200-对第三方静态分析的独立核验.md`。
//
// 它仍然有信息量：玩家发出的声音（脚步/枪声/换弹）原点**通常就是玩家当时的位置**。
// 但它是**离散事件**、**发声者未必是玩家**（门/投掷物/子弹掠过/环境音都能发）、
// 而且掠过音的原点根本不在人身上。
//
// ⇒ 只能作为**独立的声音事件层**展示，绝不能冒充人物持续位置。
type Sound struct {
	// Ent 是 source_entity_index（发声者，不保证是玩家）。
	Ent uint32 `json:"ent"`
	Pos Vec3   `json:"pos"`
	// AgeMS 是这条声音距今多久。
	AgeMS int64 `json:"age_ms"`
}

// Snapshot 是某一刻的雷达画面。
type Snapshot struct {
	Performance map[string]any `json:"performance,omitempty"`
	Session     string         `json:"session"`
	Players     []Player       `json:"players"`
	Sounds      []Sound        `json:"sounds,omitempty"`
	Decoded     uint64         `json:"decoded_msgs"`
	Encrypted   uint64         `json:"encrypted_frames"`
	Scheme      string         `json:"scheme"` // 当前选中的加解密方案名
	UpdatedAt   time.Time      `json:"updated_at"`
	// Synced 表示「players 是不是可信的人物状态」。
	//
	// 🔴 在实体表（svc_PacketEntities delta）接通之前，这个值**永远是 false**。
	// 前端必须据此显示「未同步」，而不是画一堆来源不明的点。
	// 启发式浮点扫描的结果**永远不进 players**（硬规则 290 附带要求）。
	Synced bool `json:"synced"`
	// Status 是给人看的一句话状态，说明为什么没有可信人物。
	Status string `json:"status,omitempty"`

	// Map 是当前地图的 2D 底图定义（标定参数 + 地标 + 楼层）。
	//
	// 🔴 它是 nil 的时候前端**不能**画任何「假地图」网格 —— 那会让人以为
	// 那个方框就是地图。nil + MapState 说明原因，前端显示空画布与提示。
	Map *mapdata.MapDef `json:"map,omitempty"`
	// MapState 是地图加载状态：unknown / identified / resource_missing / ready。
	MapState string `json:"map_state"`
	// MapSource 说明图名是怎么来的：serverinfo / manual / inferred / ""。
	//
	// 🔴 这三种来源的**可信度不同**：serverinfo 是服务端给的（确定），
	// manual 是用户选的（确定但可能选错），inferred 是拿坐标反推的（可能误判）。
	// 前端必须把 inferred 单独标出来，不能和确定来源混在一起显示。
	MapSource string `json:"map_source,omitempty"`
	// MapStatus 是一句人话，说明地图为什么是这个状态。
	MapStatus string `json:"map_status,omitempty"`
}

// Decoder 是"明文消息 → 玩家坐标"的接缝。
//
// 真实的 CS2 实体解码器（把 netmessage 里的 entity snapshot / delta 还原成玩家位置）
// 需要 CS2 协议资料，不在 v2.0.5 这两个 EXE 内。实现这个接口即可替换掉启发式解码器，
// 服务器其余部分无需改动。
type Decoder interface {
	Name() string
	Feed(m *Msg, dir string) error
	Snapshot() []Player
}

// ---- 启发式解码器 ----

// HeuristicDecoder 不依赖 CS2 协议定义，直接在消息载荷里扫描"像坐标的 float32 三元组"。
//
// 它的定位是**信号探针**，不是真解码器：
//   - 如果加解密方案选对了，扫出来的坐标会稳定、连续、聚集在合理区域；
//   - 如果方案选错了，解出来的是随机字节，几乎不会出现稳定的合法三元组。
//
// 因此它既能给雷达页面提供可看的内容，也能当作"方案是否正确"的第二重佐证。
//
// 槽位存活时间记在 Player.UpdatedAt 里（而不是另开一张以下标为键的表）：
// Snapshot 会压缩 slots 数组，任何按下标索引的旁路表都会随之错位，
// 导致"槽位被误判过期→删除→同一实体重新建槽"的重复目标。
type HeuristicDecoder struct {
	mu       sync.Mutex
	slots    []Player
	nextID   int
	maxSlots int
	ttl      time.Duration
	decoded  uint64

	// OnNewSlot 在新建槽位时回调，用于诊断"为什么多出一个目标"。
	// 回调在解锁后触发，实现里可以安全地打日志或再调用本解码器的方法。
	OnNewSlot func(id int, cmd uint64, pos Vec3)
}

// NewHeuristicDecoder 创建启发式解码器（默认槽位存活 10 秒）。
func NewHeuristicDecoder(maxSlots int) *HeuristicDecoder {
	return NewHeuristicDecoderWithTTL(maxSlots, 10*time.Second)
}

// NewHeuristicDecoderWithTTL 创建启发式解码器并指定槽位存活时长。
//
// 存活时长决定"多久没更新就从画面上消失"：实时链路用 10 秒；
// 离线回放/一次性分析可以调大，否则回放结束后画面会立刻清空。
func NewHeuristicDecoderWithTTL(maxSlots int, ttl time.Duration) *HeuristicDecoder {
	if maxSlots <= 0 {
		maxSlots = 64
	}
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &HeuristicDecoder{
		maxSlots: maxSlots,
		ttl:      ttl,
	}
}

func (d *HeuristicDecoder) Name() string { return "heuristic-float3" }

// Feed 扫描一条消息，把找到的候选坐标塞进槽位。
func (d *HeuristicDecoder) Feed(m *Msg, dir string) error {
	cands := ScanFloat3(m.Data)
	if len(cands) == 0 {
		return nil
	}
	now := time.Now()
	d.mu.Lock()
	d.decoded++
	var created []Player
	for _, c := range cands {
		// 与已有槽位做最近邻匹配（同一实体的连续位置）。
		// 关联半径取 256 单位：相邻两次更新之间玩家不可能瞬移超过这个距离，
		// 同时足以容纳全速奔跑（CS2 约 250 单位/秒，62.5 Hz 下约 4 单位/帧）。
		best, bestD := -1, float32(assocRadius2)
		for i := range d.slots {
			dist := d.slots[i].Pos.dist2(c)
			if dist < bestD {
				best, bestD = i, dist
			}
		}
		if best >= 0 {
			d.slots[best].Pos = c
			d.slots[best].UpdatedAt = now
			continue
		}
		if len(d.slots) >= d.maxSlots {
			continue
		}
		p := Player{ID: d.nextID, Pos: c, Source: d.Name(), UpdatedAt: now}
		d.slots = append(d.slots, p)
		d.nextID++
		created = append(created, p)
	}
	cb := d.OnNewSlot
	cmd := m.Cmd
	d.mu.Unlock()

	if cb != nil {
		for _, p := range created {
			cb(p.ID, cmd, p.Pos)
		}
	}
	return nil
}

// Reset 清空全部槽位与计数，保留配置与回调。
//
// 用在"喂入方向发生切换"时：新方向的帧序列与旧方向没有位置连续性，
// 直接续喂会让每个目标在新方向的第一帧处多建一个槽位。
func (d *HeuristicDecoder) Reset() {
	d.mu.Lock()
	d.slots = nil
	d.decoded = 0
	d.mu.Unlock()
}

// Len 返回当前槽位数量（不做过期剔除，仅供诊断）。
func (d *HeuristicDecoder) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.slots)
}

// Snapshot 返回当前画面（剔除过期槽位）。
func (d *HeuristicDecoder) Snapshot() []Player {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	alive := d.slots[:0:0]
	for _, p := range d.slots {
		if now.Sub(p.UpdatedAt) <= d.ttl {
			alive = append(alive, p)
		}
	}
	d.slots = alive
	out := make([]Player, len(alive))
	copy(out, alive)
	return out
}

// Decoded 返回已处理的候选消息数。
func (d *HeuristicDecoder) Decoded() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.decoded
}

// assocRadius2 是槽位关联半径的平方（256 单位）。
const assocRadius2 = 256 * 256

func (v Vec3) dist2(o Vec3) float32 {
	dx, dy, dz := v.X-o.X, v.Y-o.Y, v.Z-o.Z
	return dx*dx + dy*dy + dz*dz
}

// ScanFloat3 在载荷里找"像坐标的 float32 三元组"。
//
// 两段式，先精后粗：
//
//  1. **结构化**：把载荷按 protobuf 走一遍，长度恰好 12 的 length-delimited 字段
//     直接解释成 3 个 float32（可递归两层）。这条路不会出现跨字段边界的误读，
//     因此不会产生假阳性。
//  2. **滑窗兜底**：结构走不通（或没有 12 字节字段）时，才退回全偏移扫描。
//     这条路会误读边界，假阳性靠下面的保守判据压制。
//
// 真实 CS2 的实体数据未必是"12 字节 blob"，也可能是三个独立 float 字段或量化整数，
// 所以两条路都得留着；接上真正的实体解码器后本函数即可退休。
func ScanFloat3(b []byte) []Vec3 {
	if out := scanProtoFloat3(b, 0); len(out) > 0 {
		return out
	}
	return scanBlindFloat3(b)
}

func scanProtoFloat3(b []byte, depth int) []Vec3 {
	if depth > 2 || len(b) == 0 {
		return nil
	}
	entries, err := handshake.ParsePB(b)
	if err != nil || len(entries) == 0 {
		return nil
	}
	var out []Vec3
	for _, e := range entries {
		if e.Wire != 2 {
			continue
		}
		if len(e.Bytes) == 12 {
			if v, ok := floats3(e.Bytes); ok {
				out = append(out, v)
			}
			continue
		}
		if len(e.Bytes) > 12 {
			out = append(out, scanProtoFloat3(e.Bytes, depth+1)...)
		}
	}
	return out
}

// floats3 把 12 字节解释成 3 个 float32，并按坐标判据校验。
func floats3(b []byte) (Vec3, bool) {
	if len(b) < 12 {
		return Vec3{}, false
	}
	x := math.Float32frombits(binary.LittleEndian.Uint32(b[0:]))
	y := math.Float32frombits(binary.LittleEndian.Uint32(b[4:]))
	z := math.Float32frombits(binary.LittleEndian.Uint32(b[8:]))
	if !plausible(x, 20000) || !plausible(y, 20000) || !plausible(z, 5000) {
		return Vec3{}, false
	}
	if significantCount(x, y, z) < 2 {
		return Vec3{}, false
	}
	if x == y && y == z {
		return Vec3{}, false
	}
	if isInt(x) && isInt(y) && isInt(z) {
		return Vec3{}, false
	}
	return Vec3{X: x, Y: y, Z: z}, true
}

// scanBlindFloat3 是滑窗兜底：全偏移扫描。
//
// 判据（保守）：
//   - 三个值都有限（非 NaN / Inf）
//   - |x|,|y| <= 20000 且 |z| <= 5000（CS2 地图尺度）
//   - 三分量里至少有两个绝对值 >= 1（地图坐标的 x/y 总是有量级的；这一条专门挡掉
//     "跨字段边界读出的非规格化浮点"）
//   - 至少一个是非整数（真实坐标是连续量，整数多半是别的字段）
//   - 三个值不全相等
func scanBlindFloat3(b []byte) []Vec3 {
	var out []Vec3
	for off := 0; off+12 <= len(b); off++ {
		v, ok := floats3(b[off : off+12])
		if !ok {
			continue
		}
		out = append(out, v)
		if len(out) >= 256 {
			break
		}
	}
	return out
}

// significantCount 统计绝对值 >= 1 的分量个数。
func significantCount(a, b, c float32) int {
	n := 0
	for _, v := range []float32{a, b, c} {
		if v >= 1 || v <= -1 {
			n++
		}
	}
	return n
}

func plausible(v float32, limit float32) bool {
	if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
		return false
	}
	if v > limit || v < -limit {
		return false
	}
	return true
}

func isInt(v float32) bool { return v == float32(int32(v)) }
