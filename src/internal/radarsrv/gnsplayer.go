package radarsrv

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// 本文件解 CS2 的**玩家名单消息**（现场定案：cmd=60）。
//
// 🔴 2026-10-20 08:14 现场定案。
//
// 08:12 那局 4096 帧明文里 cmd=60 出现 7 次，每次 133 字节、7 个条目，
// 条目结构完全一致（17 字节载荷 + 3 字节头 = 20 字节）：
//
//	0a 11                     field 1, len 17      —— 一条玩家记录
//	  08 01                   field 1 varint       —— userid（1,6,7,8,9,10,11）
//	  11 0b591a3001001001     field 2 fixed64      —— SteamID64（0x01100001301A590B）
//	  20 00                   field 4 varint       —— 标志位 a
//	  28 00                   field 5 varint       —— 标志位 b
//	  30 00                   field 6 varint       —— 标志位 c
//
// 判据（两条都成立才采信）：
//   - 顶层字段号必须是 1、wire 必须是 2（长度前缀）；
//   - 条目里 field2 必须是 fixed64 且高位形如 SteamID64（0x01100001xxxxxxxx）。
//
// **这里没有队伍字段。** 7 条记录 × 3 个 0/1 标志，没有一个是 2/3 这种
// 队伍取值（现场 userid 6、7 的 field4=1，7 的 field5=1，其余全 0）。
// 所以「分不出敌我」不是解析漏了，是这条消息里就没有 —— 队伍只能来自
// 游戏事件（player_team）或实体属性，见硬规则 246/247。
const (
	// gnsCmdPlayerList 是玩家名单消息的 netmessage cmd。
	gnsCmdPlayerList = 60
	// gnsSteamID64Base 是个人账号 SteamID64 的高位特征（0x01100001）。
	gnsSteamID64Base = 0x0110000100000000
	// gnsPlayerMax 是名单条目上限，防止异常数据把内存吃满。
	gnsPlayerMax = 256
)

// gnsPlayerEntry 是一条玩家记录。
type gnsPlayerEntry struct {
	UserID  uint32
	SteamID uint64
	Flags   [3]uint32
}

// gnsParsePlayerList 从 cmd=60 的 body 里取出玩家名单。
//
// 返回 nil 表示这条 body 不符合定案结构 —— 调用方应当把它当普通消息继续走。
func gnsParsePlayerList(body []byte) []gnsPlayerEntry {
	var out []gnsPlayerEntry
	off := 0
	for off < len(body) {
		key, n, ok := readGNSVarint(body[off:])
		if !ok || n == 0 {
			return nil
		}
		off += n
		tag, wt := key>>3, key&7
		if wt != 2 || tag != 1 {
			return nil
		}
		l, n2, ok := readGNSVarint(body[off:])
		if !ok || off+n2+int(l) > len(body) {
			return nil
		}
		off += n2
		ent, ok := gnsParsePlayerEntry(body[off : off+int(l)])
		if !ok {
			return nil
		}
		off += int(l)
		out = append(out, ent)
		if len(out) > gnsPlayerMax {
			return nil
		}
	}
	return out
}

// gnsParsePlayerEntry 解一条 17 字节的玩家记录。
func gnsParsePlayerEntry(b []byte) (gnsPlayerEntry, bool) {
	var e gnsPlayerEntry
	var haveUser, haveSteam bool
	off := 0
	for off < len(b) {
		key, n, ok := readGNSVarint(b[off:])
		if !ok || n == 0 {
			return e, false
		}
		off += n
		tag, wt := key>>3, key&7
		switch wt {
		case 0:
			v, n2, ok := readGNSVarint(b[off:])
			if !ok {
				return e, false
			}
			off += n2
			switch tag {
			case 1:
				e.UserID = uint32(v)
				haveUser = true
			case 4:
				e.Flags[0] = uint32(v)
			case 5:
				e.Flags[1] = uint32(v)
			case 6:
				e.Flags[2] = uint32(v)
			}
		case 1:
			if off+8 > len(b) {
				return e, false
			}
			if tag == 2 {
				e.SteamID = binary.LittleEndian.Uint64(b[off:])
				haveSteam = true
			}
			off += 8
		case 2:
			l, n2, ok := readGNSVarint(b[off:])
			if !ok || off+n2+int(l) > len(b) {
				return e, false
			}
			off += n2 + int(l)
		case 5:
			off += 4
		default:
			return e, false
		}
	}
	// SteamID64 高位必须是 0x01100001：这一条判据把「结构碰巧对上」
	// 和「真的是玩家记录」分开。个人账号、群组、GameServer 的高位都不同。
	if !haveUser || !haveSteam || e.SteamID>>32 != gnsSteamID64Base>>32 {
		return e, false
	}
	return e, true
}

// noteGNSPlayers 记录一批玩家名单。调用方必须持有 sess.mu。
func (sess *Session) noteGNSPlayers(list []gnsPlayerEntry) {
	sess.gnsPlayers = make(map[uint32]gnsPlayerEntry, len(list))
	for _, e := range list {
		sess.gnsPlayers[e.UserID] = e
	}
}

// gnsPlayerCount 返回名单人数。调用方必须持有 sess.mu。
func (sess *Session) gnsPlayerCount() int { return len(sess.gnsPlayers) }

// logGNSPlayers 打一行玩家名单。
//
// 这一行的用途不是好看，是**把「声源数 ≠ 玩家数」这件事摆到台面上**：
// cmd=208（svc_SosStartSoundEvent）里的实体是**发声者**，门/投掷物/武器落地
// 都能发声，没有队伍字段也分不出哪几个是玩家（硬规则 290）。
// 08:14 那局 cmd=208 有 22 个声源实体，而 cmd=60 只有 7 个人 ——
// 两者数量天然对不上，谁也不能直接当人数用。
func (sess *Session) logGNSPlayers() {
	sess.mu.Lock()
	if len(sess.gnsPlayers) == 0 {
		sess.mu.Unlock()
		return
	}
	ids := make([]uint32, 0, len(sess.gnsPlayers))
	for id := range sess.gnsPlayers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	first := sess.gnsPlayers[ids[0]]
	ents := len(sess.gnsPlayers)
	sess.mu.Unlock()

	var b strings.Builder
	for i, id := range ids {
		if i >= 10 {
			fmt.Fprintf(&b, " …共%d", len(ids))
			break
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%d", id)
	}
	gnsLogf("[gnsmsg] PeerList（cmd=60，连接槽位不是 userid）：%d 人｜userid %s｜示例 SteamID64 %d｜"+
		"**没有队伍字段** —— 分敌我要靠游戏事件，见硬规则 246",
		ents, b.String(), first.SteamID)
}
