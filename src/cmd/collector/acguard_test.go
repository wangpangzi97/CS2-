// 反作弊闸门的回归测试。
//
// 为什么必须有这条测试：闸门是**安全边界**，不是功能。它一旦被误删、
// 被改成默认放行、或者 `resolvePID()` 绕开了它，用户下次在完美平台场次里
// 跑一次就会再被封一次号（HWID 级，换号无效）。
// 这种「删掉之后程序照样能跑、只是会封号」的代码，只能靠测试钉住。
//
// 归因见 acguard.go 头部注释与硬规则 212。
package main

import (
	"flag"
	"strings"
	"testing"
)

// forceACHit 把闸门状态强制设成「检测到反作弊」，跑完恢复。
//
// 现场不一定有反作弊进程（本机现在就一个都没有），所以不能靠
// detectAntiCheat() 真去扫进程表来验证 —— 必须能把状态直接摆好。
func forceACHit(t *testing.T, msg string) {
	t.Helper()
	oldDone, oldHit, oldMsg := acGuardDone, acGuardHit, acGuardMsg
	acGuardDone, acGuardHit, acGuardMsg = true, true, msg
	t.Cleanup(func() { acGuardDone, acGuardHit, acGuardMsg = oldDone, oldHit, oldMsg })
}

// setAllowAC 临时改 -allow-ac，跑完恢复。
func setAllowAC(t *testing.T, v bool) {
	t.Helper()
	old := *flagAllowAC
	*flagAllowAC = v
	t.Cleanup(func() { *flagAllowAC = old })
}

// TestACGuardBlocksWhenHit 钉死「检测到反作弊时默认拒绝碰进程」。
func TestACGuardBlocksWhenHit(t *testing.T) {
	forceACHit(t, "完美平台 PacNova（Ring3 反作弊） (pid 1234)")
	setAllowAC(t, false)

	got := acBlockReason()
	if got == "" {
		t.Fatal("检测到反作弊时 acBlockReason() 必须返回非空（禁止碰进程），" +
			"现在返回空 = 闸门失效。2026-10-19 现场就是在这种情况下读了一次内存，账号被封")
	}
	if !strings.Contains(got, "PacNova") {
		t.Fatalf("拦截原因里应带出命中的反作弊名，便于用户判断：%q", got)
	}
}

// TestACGuardAllowACIsEscapeHatch 钉死「-allow-ac 是唯一逃生口」。
//
// 加了 -allow-ac 就必须放行 —— 否则用户明知风险也跑不起来，
// 会去改代码把闸门删掉，反而更危险。
func TestACGuardAllowACIsEscapeHatch(t *testing.T) {
	forceACHit(t, "完美平台 PacNova（Ring3 反作弊） (pid 1234)")
	setAllowAC(t, true)

	if got := acBlockReason(); got != "" {
		t.Fatalf("加了 -allow-ac 之后应放行，现在仍然拦截：%q", got)
	}
}

// TestResolvePIDIsGated 钉死「所有内存访问的唯一入口都过闸门」。
//
// resolvePID() 是枚举区域 / 定位公钥 / 抓快照 / 找会话密钥的共同入口，
// 闸门放在这里才能「一处拦全拦住」。如果哪天有人为了图方便在别处
// 直接调 memscan.FindPid()，这条测试仍然能证明入口本身是安全的。
func TestResolvePIDIsGated(t *testing.T) {
	forceACHit(t, "完美平台 PacNova（Ring3 反作弊） (pid 1234)")
	setAllowAC(t, false)

	// 即使显式给了 -pid，也必须先被闸门拦住（顺序不能反）。
	oldPID := *flagPID
	*flagPID = 4242
	t.Cleanup(func() { *flagPID = oldPID })

	pid, err := resolvePID()
	if err == nil {
		t.Fatalf("反作弊在场时 resolvePID() 必须报错，现在返回 pid=%d, err=nil —— "+
			"闸门被绕开了，用户会再次被封号", pid)
	}
	if !strings.Contains(err.Error(), "反作弊") {
		t.Fatalf("错误信息必须点明是反作弊拦截（用户才知道该换社区服）：%v", err)
	}

	// 开了 -allow-ac 才放行，且放行时应该原样返回 -pid。
	setAllowAC(t, true)
	pid, err = resolvePID()
	if err != nil {
		t.Fatalf("-allow-ac 打开后 resolvePID() 不应报错：%v", err)
	}
	if pid != 4242 {
		t.Fatalf("-allow-ac 打开后应返回 -pid 指定的 4242，现在返回 %d", pid)
	}
}

// TestACProbesCoverMajorPlatforms 钉死探测名单不被裁掉。
//
// 名单少一个平台，就等于在那个平台上默认不安全。
func TestACProbesCoverMajorPlatforms(t *testing.T) {
	want := []string{
		"PacNova",       // 完美
		"wmpvp",         // 完美对战平台客户端
		"5EClient",      // 5E
		"5EAntiCheat",   // 5E 反作弊
		"FaceitClient",  // Faceit
		"EasyAntiCheat", // EAC
		"BEService",     // BattlEye
		"vgc",           // Vanguard
	}
	have := make(map[string]bool, len(acProbes))
	for _, p := range acProbes {
		have[p.exe] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Fatalf("反作弊探测名单里缺 %q —— 缺一个就等于在那个平台上默认不安全", w)
		}
	}
}

// TestAllowACFlagDefaultsFalse 钉死逃生口默认关闭。
//
// 放在这里而不是 keybatch_test.go：这条和「冻结」无关，是闸门自己的契约。
func TestAllowACFlagDefaultsFalse(t *testing.T) {
	f := flag.Lookup("allow-ac")
	if f == nil {
		t.Fatal("找不到 -allow-ac 这个 flag —— 反作弊闸门被删了？")
	}
	if f.DefValue != "false" {
		t.Fatalf("-allow-ac 默认值必须是 false，现在是 %q", f.DefValue)
	}
}
