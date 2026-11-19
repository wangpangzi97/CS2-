// 反作弊在场时的硬闸门。
//
// 背景（2026-10-19 14:55，用户现场反馈）
// ------------------------------------
// 「上次读取完账号被封禁了」—— 在完美平台场次里做了一次「冻结 + 读内存」，
// 账号随即被封。这推翻了之前「冻结 ≤700 ms 就安全」的结论：
// 完美平台是 Hypervisor 级反作弊（Ring-1 SHV + Ring0 `ObRegisterCallbacks` +
// Ring3 `PacNova`，见 `2/report/20261019-完美平台反作弊分析.md`），
// 它**能直接看到**「有别的进程打开了 cs2.exe 并申请 PROCESS_VM_READ」这件事，
// 也看得到「全部线程被挂起」。所以时长不是护身符 —— 只要动了就是动了。
//
// 结论（硬规则 212）
// ------------------
// **在有反作弊的场次里，绝不能对 cs2.exe 做任何进程访问**（OpenProcess /
// ReadProcessMemory / NtSuspendProcess 全都算）。此时本工具退化成**纯抓包**：
// 只收网卡上的 UDP，一个字节都不碰游戏进程。
//
// 想恢复密钥提取，只有两条路：
//  1. 换**纯社区服**（无完美 / 5E / Faceit / EAC / BattlEye）去采，那里没有
//     Ring0 回调盯着进程对象；
//  2. 显式加 `-allow-ac` —— 明知风险自负。
//
// 闸门放在 `resolvePID()` 里：所有内存访问都从那里拿 PID，一处拦全拦住。
package main

import (
	"fmt"
	"os"
	"strings"

	"local/cs2-radar/internal/memscan"
)

// acProbes 是已知反作弊 / 竞技平台的进程名（小写，不带 .exe）。
//
// 只列**确定存在且只在 AC 场景出现**的名字，避免误伤（比如 "steam" 不能列）。
// 完美平台：PacNova 是 Ring3 组件；wmpvp 是完美对战平台客户端。
// 5E / Faceit / EAC / BattlEye / Vanguard 一并覆盖 —— 它们同样是内核级，
// 对「别人打开 cs2.exe」这件事一样敏感。
var acProbes = []struct {
	exe   string
	label string
}{
	{"PacNova", "完美平台 PacNova（Ring3 反作弊）"},
	{"PacNovaSvc", "完美平台 PacNova 服务"},
	{"wmpvp", "完美对战平台客户端"},
	{"wmpvp_anticheat", "完美对战平台反作弊"},
	{"5EClient", "5E 对战平台"},
	{"5ECnClient", "5E 对战平台"},
	{"5EAntiCheat", "5E 反作弊"},
	{"FaceitClient", "Faceit 客户端"},
	{"FACEITClient", "Faceit 客户端"},
	{"EasyAntiCheat", "EasyAntiCheat"},
	{"EasyAntiCheat_EOS", "EasyAntiCheat (EOS)"},
	{"BEService", "BattlEye"},
	{"vgc", "Vanguard"},
	{"vgtray", "Vanguard"},
}

// detectAntiCheat 扫一遍进程表，返回第一个在场的反作弊。
func detectAntiCheat() (label string, pid uint32, found bool) {
	for _, p := range acProbes {
		if id, err := memscan.FindPid(p.exe); err == nil {
			return p.label, id, true
		}
	}
	return "", 0, false
}

// acGuardOnce 保证「检测 + 报警」只做一次，之后走缓存。
//
// 为什么缓存：`resolvePID()` 在 hint 快路径里会被反复调用，
// 每次都遍历一遍进程表要 5~15 ms，会把「握手 → 搜索」的延迟拖垮。
var (
	acGuardDone bool
	acGuardMsg  string
	acGuardHit  bool
)

// acBlockReason 判断当前是否禁止碰游戏进程。
//
// 返回非空字符串 = 禁止，字符串是要打进日志的原因。
// 返回空字符串 = 放行。
func acBlockReason() string {
	if *flagAllowAC {
		return ""
	}
	if !acGuardDone {
		acGuardDone = true
		if label, pid, found := detectAntiCheat(); found {
			acGuardHit = true
			acGuardMsg = fmt.Sprintf("%s (pid %d)", label, pid)
		}
	}
	if !acGuardHit {
		return ""
	}
	return acGuardMsg
}

// warnACBlocked 在被拦住时打一次醒目日志（每次进程启动只打一次）。
var acWarned bool

func warnACBlocked(reason string) {
	if acWarned {
		return
	}
	acWarned = true
	fmt.Fprintf(os.Stderr,
		"\n"+
			"🔴 检测到反作弊在场：%s\n"+
			"   已**禁止**对游戏进程做任何访问（OpenProcess / 读内存 / 挂起线程全部跳过）。\n"+
			"   原因：2026-10-19 现场实测 —— 完美平台场次里做一次「冻结 + 读内存」，\n"+
			"         账号随即被封。它是 Ring-1/Ring0 级，能直接看到谁打开了 cs2.exe，\n"+
			"         「冻结时间短」不是护身符。\n"+
			"   现在本工具只做**纯抓包**：只收网卡 UDP，一个字节都不碰游戏进程。\n"+
			"   要恢复密钥提取：换**纯社区服**（无完美/5E/Faceit/EAC/BattlEye）再采；\n"+
			"   明知风险仍要跑，加 -allow-ac。\n\n",
		reason)

	// 🔴 必须把「后果」写清楚，否则用户看到满屏 `已解帧=0` 会以为是雷达坏了。
	// 2026-10-20 07:20 那局就是这样：88 秒、47565 个包、握手材料都齐了，
	// 但 `has_key=false`，一帧都没解开，日志里没有任何一句说清「所以这局没目标」。
	fmt.Fprintf(os.Stderr,
		"   ⚠ 后果：这一局**不会有任何雷达目标**。\n"+
			"     没有会话私钥就解不出一帧，`[dec]` 会一直是 `已解帧=0 消息=0 玩家=0(来源=无)`，\n"+
			"     并且反复出现「GNS 握手材料已齐，但还没有客户端私钥」。\n"+
			"     那不是 bug，是这道闸门在起作用 —— 收包正常，解密没开始。\n\n")

	// 不同反作弊对应完全不同的处置动作，笼统说「换社区服」帮不上忙。
	switch {
	case strings.Contains(reason, "Vanguard"):
		fmt.Fprintf(os.Stderr,
			"   Vanguard 是《无畏契约 / 英雄联盟》的反作弊（vgc 服务），**不保护 cs2.exe**。\n"+
				"   如果你只是在玩 CS2、顺便开着那个游戏，按下面做就能恢复：\n"+
				"     ① 完全退出无畏契约 / 英雄联盟（不是最小化）；\n"+
				"     ② 管理员 PowerShell 执行 `sc stop vgc`（或重启一次电脑）；\n"+
				"     ③ 重开本工具，看到 `[dec] ... has_key=true` 就说明通了。\n\n")
	case strings.Contains(reason, "PacNova") || strings.Contains(reason, "完美"):
		fmt.Fprintf(os.Stderr,
			"   完美平台是 CS2 的直接封号来源（HWID 封禁，换号无效）。\n"+
				"   这一局只能纯抓包、不会出目标。要出目标请换**纯社区服**再采。\n\n")
	}
}
