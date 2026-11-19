package radarsrv

// cmd=207 是 svc_GameEvent 通道，里面混着**两类完全不同的东西**。
//
// 2026-10-20 07:55 现场用 tools/netdump 定案（全量明文 4104 帧 / 5253 条 netmessage）：
//
//	cmd=207 按 eventid 聚合：
//	  id=226   2897 条 / 938628 字节  ← 完美平台注入的 HTML
//	  id=267    642 条 /  30627 字节
//	  id=160    310 条 /  15110 字节
//	  id=16      60 条 /   4980 字节
//	  ...
//
// eventid=226 的载荷长这样（可直接打印）：
//
//	<font class='fontSize-s'>击杀时间：</font>...<img src='http://pwacdn.wmpvp.com/...'>
//
// 也就是说：**cmd=207 里 94.4% 的字节是平台往游戏里塞的广告 HTML**，
// 折算到整条 s2c 载荷约 90%。它对雷达没有任何价值，但会：
//  ① 每帧都被喂进 protobuf 解码器（白烧 CPU）；
//  ② 把 `[gnsmsg] 按字节量排` 的第一名永远占住，真实信号被挤到看不见
//     （这正是硬规则 235 要解决的问题，只是根因在数据而不是排序）。
//
// 所以这里按 eventid 把它摘出来单独计数，并从解码路径上跳过。
const (
	// gnsCmdGameEvent 是 svc_GameEvent 在本版本里的 cmd 号。
	gnsCmdGameEvent = 207
	// gnsEventPlatformHTML 是完美平台注入 HTML 的 eventid。
	gnsEventPlatformHTML = 226
)

// gnsGameEventID 从 CMsgSource1LegacyGameEvent 里取 eventid（field 2）。
//
// 只做最小走查：够跳过长度前缀字段、找到 field2 的 varint 即可。
// 解析失败返回 false —— 调用方按「不是游戏事件」处理，不会误伤。
func gnsGameEventID(b []byte) (uint32, bool) {
	i := 0
	for i < len(b) {
		tag, n, ok := readGNSVarint(b[i:])
		if !ok || n <= 0 {
			return 0, false
		}
		i += n
		field := tag >> 3
		switch tag & 7 {
		case 0: // varint
			v, m, ok := readGNSVarint(b[i:])
			if !ok {
				return 0, false
			}
			i += m
			if field == 2 {
				return v, true
			}
		case 1: // fixed64
			i += 8
		case 2: // length-delimited
			l, m, ok := readGNSVarint(b[i:])
			if !ok || i+m+int(l) > len(b) {
				return 0, false
			}
			i += m + int(l)
		case 5: // fixed32
			i += 4
		default:
			return 0, false
		}
	}
	return 0, false
}
