package main

import (
	"strings"
	"testing"
)

// TestWin32ProcsResolve 逐个校验 GUI/提权用到的 Win32 导出名都能解析。
//
// 为什么值得专门测：syscall.NewLazyDLL 的 .Call() 在**调用时**才去解析导出名，
// 名字写错（大小写不对、DLL 不对）只会在真跑起来那一刻 panic。
// 本项目已经因为 ws2_32 的 `WSARecvFrom`（大写 F）踩过一次 —— 写成
// `WSARecvfrom` 直接 "Failed to find procedure"。
//
// 这里把所有 LazyProc 都 Find() 一遍，把这类错误提前到单元测试里。
func TestWin32ProcsResolve(t *testing.T) {
	procs := map[string]interface{ Find() error }{
		"user32.RegisterClassExW":              pRegisterClassExW,
		"user32.CreateWindowExW":               pCreateWindowExW,
		"user32.DefWindowProcW":                pDefWindowProcW,
		"user32.DestroyWindow":                 pDestroyWindow,
		"user32.PostQuitMessage":               pPostQuitMessage,
		"user32.GetMessageW":                   pGetMessageW,
		"user32.TranslateMessage":              pTranslateMessage,
		"user32.DispatchMessageW":              pDispatchMessageW,
		"user32.SendMessageW":                  pSendMessageW,
		"user32.PostMessageW":                  pPostMessageW,
		"user32.SetWindowTextW":                pSetWindowTextW,
		"user32.GetClientRect":                 pGetClientRect,
		"user32.SetTimer":                      pSetTimer,
		"user32.KillTimer":                     pKillTimer,
		"user32.MessageBoxW":                   pMessageBoxW,
		"gdi32.GetStockObject":                 pGetStockObject,
		"gdi32.CreateFontW":                    pCreateFontW,
		"user32.SetProcessDpiAwarenessContext": pSetDpiAwareness,
		"user32.SetProcessDPIAware":            pSetProcessDpiAwar,
		"shell32.ShellExecuteExW":              pShellExecuteExW,
		"shell32.IsUserAnAdmin":                shell32.NewProc("IsUserAnAdmin"),
		"kernel32.GetModuleHandleW":            pGetModuleHandleW,
		"kernel32.MulDiv":                      pMulDiv,
	}
	for name, p := range procs {
		if err := p.Find(); err != nil {
			t.Errorf("%s 解析失败: %v", name, err)
		}
	}
}

// TestEnsureElevatedAlreadyAdmin 已经是管理员时不得重入、不得报错。
func TestEnsureElevatedAlreadyAdmin(t *testing.T) {
	defer swapIsAdmin(true)()

	launched, err := ensureElevated()
	if err != nil {
		t.Fatalf("已是管理员却报错: %v", err)
	}
	if launched {
		t.Fatal("已是管理员却要重新拉起进程（会死循环）")
	}
}

// TestEnsureElevatedStopsLoopWhenStillNotAdmin 覆盖最危险的一条分支。
//
// 场景：进程带着 `-elevated` 重入，却仍然拿不到管理员权限（用户点了 UAC「否」，
// 或组策略禁止提权）。这时必须**报错退出**，绝不能再 ShellExecuteExW 一次 ——
// 否则就是无限弹 UAC 的死循环。
//
// 注意：本用例刻意只走 flagElevated=true 的分支。flagElevated=false 的那条路会
// 真的调 ShellExecuteExW("runas") 弹 UAC 对话框，不能在单元测试里碰。
func TestEnsureElevatedStopsLoopWhenStillNotAdmin(t *testing.T) {
	defer swapIsAdmin(false)()

	old := *flagElevated
	*flagElevated = true
	defer func() { *flagElevated = old }()

	launched, err := ensureElevated()
	if launched {
		t.Fatal("非管理员却声称已拉起提权实例")
	}
	if err == nil {
		t.Fatal("非管理员 + -elevated 应报错，实际返回 nil（会无限弹 UAC）")
	}
	if !strings.Contains(err.Error(), "管理员权限") {
		t.Fatalf("报错信息没提到管理员权限，用户看不懂: %v", err)
	}
}

// TestBuildArgLine 重建命令行：保留原参数、追加 -elevated、带空格的参数要加引号。
func TestBuildArgLine(t *testing.T) {
	cases := []struct {
		args  []string
		extra string
		want  string
	}{
		{nil, "-elevated", "-elevated"},
		{[]string{"-duration", "10s"}, "-elevated", "-duration 10s -elevated"},
		{[]string{"-config", "C:\\Program Files\\cs2\\capture.json"}, "-elevated",
			`-config "C:\Program Files\cs2\capture.json" -elevated`},
		{[]string{"-gui", "-auto-exit"}, "-elevated", "-gui -auto-exit -elevated"},
	}
	for _, c := range cases {
		if got := buildArgLine(c.args, c.extra); got != c.want {
			t.Errorf("buildArgLine(%q, %q) = %q, 期望 %q", c.args, c.extra, got, c.want)
		}
	}
}

// swapIsAdmin 临时替换提权判定函数，返回恢复用的函数。
func swapIsAdmin(admin bool) func() {
	old := isAdminFn
	isAdminFn = func() bool { return admin }
	return func() { isAdminFn = old }
}

// TestTrimLogLines 覆盖日志框的裁剪逻辑。
//
// 为什么值得测：这条逻辑只在**长时间运行**后才被触发（日志攒到 100 KB 上限）。
// 如果它写错了 —— 比如裁得不够、或者保留了空切片却仍报着旧字符数 —— 现象是
// 窗口在几十分钟后变卡，本地冒烟测试（跑十几秒）根本发现不了。
//
// 计费口径：每行按 len(line)+2 计（"\r\n"）。
func TestTrimLogLines(t *testing.T) {
	size := func(ls []string) int {
		n := 0
		for _, l := range ls {
			n += len(l) + 2
		}
		return n
	}

	t.Run("未超上限时原样返回", func(t *testing.T) {
		in := []string{"a", "bb", "ccc"} // 3+4+5 = 12
		got, n := trimLogLines(in, 1000)
		if len(got) != 3 {
			t.Fatalf("行数 = %d, 期望 3", len(got))
		}
		if n != 12 {
			t.Fatalf("字符数 = %d, 期望 12", n)
		}
	})

	t.Run("超上限时从头部裁到目标以内", func(t *testing.T) {
		var in []string
		for i := 0; i < 10; i++ {
			in = append(in, "0123456789") // 每行 12
		}
		const target = 50
		got, n := trimLogLines(in, target)
		if n > target {
			t.Fatalf("裁剪后 %d 字符，仍超过目标 %d", n, target)
		}
		if n != size(got) {
			t.Fatalf("返回的字符数 %d 与实际 %d 不一致", n, size(got))
		}
		if len(got) == 0 {
			t.Fatal("裁得一个都不剩")
		}
		// 必须是从**头部**裁：留下的应是尾部那些行
		for _, l := range got {
			if l != "0123456789" {
				t.Fatalf("留下了意外内容: %q", l)
			}
		}
		if len(got) != 4 { // 尾部 4 行 = 48 <= 50
			t.Fatalf("留下 %d 行, 期望 4", len(got))
		}
	})

	t.Run("单行就超长时整条丢掉", func(t *testing.T) {
		got, n := trimLogLines([]string{strings.Repeat("x", 500)}, 50)
		if len(got) != 0 || n != 0 {
			t.Fatalf("got=%d 行 n=%d, 期望 0/0", len(got), n)
		}
	})

	t.Run("空输入", func(t *testing.T) {
		got, n := trimLogLines(nil, 50)
		if len(got) != 0 || n != 0 {
			t.Fatalf("got=%d 行 n=%d, 期望 0/0", len(got), n)
		}
	})

	t.Run("返回的是独立副本", func(t *testing.T) {
		backing := []string{"a", "b", "c", "d"} // 每行 3，共 12
		got, _ := trimLogLines(backing, 3)      // 只留尾部 "d"
		if len(got) != 1 || got[0] != "d" {
			t.Fatalf("got=%q, 期望 [d]", got)
		}
		backing[3] = "MUTATED"
		if got[0] != "d" {
			t.Fatal("返回值与入参共享底层数组，裁剪后旧数组无法回收")
		}
	})
}
