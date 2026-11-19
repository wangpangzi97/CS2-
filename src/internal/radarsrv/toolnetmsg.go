package radarsrv

// 导出给诊断工具（tools/netdump）用的 netmessage 视图。
//
// 为什么要有这一层：位级解码器（gnsbitmsg.go）是 package 私有，
// 而离线分析必须和线上走**同一份实现** —— 各写一份的后果是
// 「工具解出来 3000 条、线上解出来 0 条」，然后花几轮去找不存在的问题。
// 2026-10-20 之前就踩过这个坑（msgdump 与 store 两套切分逻辑）。

// ToolNetMsg 是一条 netmessage 的只读视图。
type ToolNetMsg struct {
	Cmd     uint32
	Body    []byte
	HdrBits int
}

// ToolParseNetMsgs 把一条 SNP 可靠消息的载荷切成 netmessage 链。
//
// 与线上完全同源：直接调用 gnsParseNetMsgs。
func ToolParseNetMsgs(m []byte) (msgs []ToolNetMsg, tick uint32, err error) {
	inner, tick, err := gnsParseNetMsgs(m)
	if err != nil {
		return nil, tick, err
	}
	out := make([]ToolNetMsg, 0, len(inner))
	for _, x := range inner {
		out = append(out, ToolNetMsg{Cmd: x.Cmd, Body: x.Body, HdrBits: x.HdrBits})
	}
	return out, tick, nil
}

// ToolGameEventID 从一条 svc_GameEvent（cmd=207）的 body 里取 eventid。
//
// 与线上同源：直接调用 gnsGameEventID。离线按 eventid 筛样本（-ev 226）
// 必须走这一份，否则「工具筛出来的 226」和「线上判定的 226」可能不是一回事。
func ToolGameEventID(b []byte) (uint32, bool) { return gnsGameEventID(b) }
