package radarsrv

import (
	"fmt"
	"strings"

	"local/cs2-radar/internal/mapdata"
)

// 地图反推的判据（只在「没有确定来源」时用）。
//
// 🔴 为什么要有反推：`svc_ServerInfo` 还没解出来，`map_name` 拿不到。
// 而现场坐标本身就是一张「指纹」—— dust2 的世界包围盒是
// x∈[-2476, 2029.6] / y∈[-1266.6, 3239]，别的图不会刚好把几千个声音原点
// 全包在同一个框里。2026-10-20 13:05 那局实测覆盖率 99.77%（4877 点）。
//
// 阈值取法：
//   - minPoints 12：点太少时一两个巧合就能凑出 100%，必须等样本够；
//   - hitRatio 0.90：留 10% 余量给「图外的合法位置」（出界、贴边、z 抬得很高）；
//   - margin 0.10：多图时次优图必须明显更差，否则宁可不认。
const (
	mapInferMinPoints = 12
	mapInferHitRatio  = 0.90
	mapInferMargin    = 0.10
)

// mapInfo 是一次地图解析的完整结果。
type mapInfo struct {
	Def    *mapdata.MapDef
	State  mapdata.State
	Source string // "serverinfo" / "manual" / "inferred" / ""
	Status string
}

// mapInfoLocked 解析当前会话该用哪张地图。调用方必须持有 sess.mu。
//
// 优先级：ServerInfo（暂未接通）> 手选 > 坐标反推 > 未知。
func (sess *Session) mapInfoLocked() mapInfo {
	if sess.serverMapName != "" && sess.mapReg != nil {
		def, state, msg := sess.mapReg.Resolve(sess.serverMapName)
		return mapInfo{Def: def, State: state, Source: "serverinfo", Status: msg}
	}

	if sess.mapReg == nil {
		return mapInfo{
			State:  mapdata.StateNoAsset,
			Status: "地图资产未加载（内嵌资产读取失败），画面退化为无底图网格",
		}
	}
	// ① 确定来源：ServerInfo 或手选
	if name := strings.TrimSpace(sess.mapName); name != "" {
		def, state, msg := sess.mapReg.Resolve(name)
		src := sess.mapNameSrc
		if src == "" {
			src = "manual"
		}
		return mapInfo{Def: def, State: state, Source: src, Status: msg}
	}
	// ② 坐标反推（粘性：认出来之后不再改，避免画面底图来回跳）
	if sess.mapInferred != "" {
		def, state, msg := sess.mapReg.Resolve(sess.mapInferred)
		return mapInfo{
			Def:    def,
			State:  state,
			Source: "inferred",
			Status: inferNote(msg, sess.mapInferIn, sess.mapInferTot),
		}
	}
	// ③ 还不知道
	def, state, msg := sess.mapReg.Resolve("")
	return mapInfo{Def: def, State: state, Source: "", Status: msg}
}

// inferNote 把反推结果说清楚 —— 反推是猜的，不能和确定来源一样口气。
func inferNote(msg string, in, tot int) string {
	base := fmt.Sprintf("地图是**按坐标反推**的（%d/%d 个声音原点落在标定范围内），不是服务端告诉的",
		in, tot)
	if msg != "" {
		base += "；" + msg
	}
	return base
}

// updateMapInferLocked 尝试用当前的声音原点反推地图。调用方必须持有 sess.mu。
//
// 只在「没有确定来源、还没反推成功」时跑，成功一次就粘住。
// 数据源用 gnsPos（当前仍存活的声音原点，TTL 20 秒），不需要额外累积状态。
// Bounding-box containment is not a unique map fingerprint.
func (sess *Session) updateMapInferLocked() {
	sess.mapInferred = ""
	sess.mapInferIn = 0
	sess.mapInferTot = 0
}

// logMapOnce 在第一次拿到可用地图时打一行日志（每会话一次）。
func (sess *Session) logMapOnce(mi mapInfo) {
	if sess.mapLogged || mi.Def == nil || mi.State != mapdata.StateReady {
		return
	}
	sess.mapLogged = true
	gnsLogf("[map] 底图就绪：%s（%s）｜来源=%s｜标定 origin=(%.0f, %.0f) 每像素 %.2f 单位｜"+
		"参考分辨率 %d×%d｜底图类型=%s",
		mi.Def.DisplayName, mi.Def.ID, mi.Source,
		mi.Def.OriginWorldX, mi.Def.OriginWorldY, mi.Def.UnitsPerPixel,
		mi.Def.RefWidth, mi.Def.RefHeight, mi.Def.ImageKind)
	if mi.Def.ImageKind == "data-outline" {
		gnsLogf("[map] ⚠ 当前底图是**数据轮廓图**（由声音事件分布生成），不是官方贴图。" +
			"想要真底图：把官方 overview.png 放到 <地图资产目录>/" + mi.Def.ID + "/overview.png")
	}
}
