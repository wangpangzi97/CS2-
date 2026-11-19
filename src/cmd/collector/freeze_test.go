package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFreezer 记录冻结/解冻的调用情况，并可注入失败。
//
// 为什么要 fake：真实冻结要用 NtSuspendProcess 挂起一个进程，**自己挂起自己会
// 死锁**，挂起别的进程又要求测试环境里恰好有个靶子。而这段逻辑的安全性
// （"无论发生什么都要解冻"）是必须被测试盯住的 —— 所以把 freezer 抽成接口，
// 用 fake 注入各种失败路径。
type fakeFreezer struct {
	mu        sync.Mutex
	freezes   int
	thaws     int
	freezeErr error // 非 nil 时 FreezeFast 直接失败
	thawFails int   // 前 N 次 ThawFast 失败
	frozen    bool
}

func (f *fakeFreezer) FreezeFast() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.freezeErr != nil {
		return f.freezeErr
	}
	f.freezes++
	f.frozen = true
	return nil
}

func (f *fakeFreezer) ThawFast() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.thaws++
	if f.thawFails > 0 {
		f.thawFails--
		return errors.New("fake: NtResumeProcess 失败")
	}
	f.frozen = false
	return nil
}

func (f *fakeFreezer) state() (freezes, thaws int, frozen bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.freezes, f.thaws, f.frozen
}

// TestFreezeRunNormal 确认正常路径：冻一次、解一次、结果正确。
func TestFreezeRunNormal(t *testing.T) {
	fz := &fakeFreezer{}
	ran := false
	out := freezeRun(fz, time.Second, func() {
		ran = true
		time.Sleep(20 * time.Millisecond) // 让 Hold 有可测的值
	})

	if !ran {
		t.Fatal("fn 没有被执行")
	}
	freezes, thaws, frozen := fz.state()
	if freezes != 1 {
		t.Errorf("应冻结 1 次，实际 %d", freezes)
	}
	if thaws != 1 {
		t.Errorf("应解冻 1 次，实际 %d", thaws)
	}
	if frozen {
		t.Error("返回后必须已解冻")
	}
	if !out.Froze || !out.Completed || out.Forced || out.ThawErr != nil || out.Panicked {
		t.Errorf("结果不对: %+v", out)
	}
	// Hold 必须反映真实持有时长（诊断报告靠它判断"游戏被冻了多久"）。
	if out.Hold < 20*time.Millisecond {
		t.Errorf("Hold 应 >= fn 的耗时，实际 %v", out.Hold)
	}
	if !strings.Contains(out.String(), "已恢复") {
		t.Errorf("摘要应含「已恢复」: %s", out.String())
	}
}

// TestFreezeRunPanicStillThaws 是安全底线之一：fn panic 也必须解冻。
//
// 真实场景：搜内存时某个库函数 panic 了。如果没有这层 recover，进程崩溃退出，
// 而 NtSuspendProcess 的挂起计数不绑定句柄 —— **游戏会永久卡住**，
// 用户只能去任务管理器手动结束。
func TestFreezeRunPanicStillThaws(t *testing.T) {
	fz := &fakeFreezer{}
	out := freezeRun(fz, time.Second, func() { panic("模拟搜索中途 panic") })

	freezes, thaws, frozen := fz.state()
	if freezes != 1 || thaws != 1 {
		t.Errorf("冻结/解冻次数不对: freezes=%d thaws=%d", freezes, thaws)
	}
	if frozen {
		t.Fatal("fn panic 后必须仍然解冻 —— 否则游戏永久卡死")
	}
	if !out.Panicked {
		t.Error("应记录 Panicked")
	}
	if out.Completed {
		t.Error("panic 不应标记为正常完成")
	}
}

// TestFreezeRunWatchdogForcesThaw 是安全底线之二：fn 卡死时看门狗必须强解。
//
// 真实场景：ReadProcessMemory 卡在某个不可分页的内存上，或者驱动层面卡住。
// 这时 fn 不返回，只能靠独立 goroutine 到点解冻。
func TestFreezeRunWatchdogForcesThaw(t *testing.T) {
	fz := &fakeFreezer{}
	const hold = 60 * time.Millisecond
	begin := time.Now()
	out := freezeRun(fz, hold, func() {
		time.Sleep(400 * time.Millisecond) // 远超 hold
	})
	el := time.Since(begin)

	if !out.Forced {
		t.Error("超时应标记 Forced（说明是看门狗解的冻）")
	}
	if out.ThawErr != nil {
		t.Errorf("看门狗解冻不应失败: %v", out.ThawErr)
	}
	_, thaws, frozen := fz.state()
	if frozen {
		t.Fatal("看门狗到点后必须已解冻")
	}
	// 看门狗只解一次，主路径的 thaw 必须是幂等的（不能重复调 ThawFast）。
	if thaws != 1 {
		t.Errorf("解冻应恰好 1 次（幂等），实际 %d", thaws)
	}
	if el < 400*time.Millisecond {
		t.Errorf("freezeRun 应等 fn 结束才返回，实际只用了 %v", el)
	}
	t.Logf("看门狗在 %v 时强解，fn 共跑 %v", hold, el.Truncate(time.Millisecond))
}

// TestFreezeRunFreezeFailureStillRunsFn 确认冻不上时照常搜索。
//
// 冻不上通常是进程刚好退出（握手包抓到了但游戏已关），不该因此放弃搜索。
func TestFreezeRunFreezeFailureStillRunsFn(t *testing.T) {
	fz := &fakeFreezer{freezeErr: errors.New("fake: 进程已退出")}
	ran := false
	out := freezeRun(fz, time.Second, func() { ran = true })

	if !ran {
		t.Fatal("冻结失败也必须执行 fn")
	}
	_, thaws, _ := fz.state()
	if thaws != 0 {
		t.Errorf("没冻上就不该解冻，实际调了 %d 次", thaws)
	}
	if out.Froze {
		t.Error("应标记 Froze=false")
	}
	if out.FreezeErr == nil {
		t.Error("应记录冻结失败原因")
	}
	if !strings.Contains(out.String(), "未冻结") {
		t.Errorf("摘要应说明未冻结: %s", out.String())
	}
}

// TestFreezeRunThawRetry 确认解冻失败会重试，不会一次失败就放弃。
func TestFreezeRunThawRetry(t *testing.T) {
	fz := &fakeFreezer{thawFails: 1} // 第一次失败，第二次成功
	out := freezeRun(fz, time.Second, func() {})

	_, thaws, frozen := fz.state()
	if frozen {
		t.Fatal("重试后必须已解冻")
	}
	if thaws != 2 {
		t.Errorf("应重试到成功（共 2 次调用），实际 %d", thaws)
	}
	if out.ThawErr != nil {
		t.Errorf("最终成功则不应报错，实际 %v", out.ThawErr)
	}
}

// TestFreezeRunThawTotalFailure 确认解冻彻底失败时把错误带出去。
//
// 这是最高级别故障：调用方必须据此在 UI/日志/报告里高亮，
// 明确告诉用户"手动结束游戏进程"。
func TestFreezeRunThawTotalFailure(t *testing.T) {
	fz := &fakeFreezer{thawFails: 99} // 一直失败
	out := freezeRun(fz, time.Second, func() {})

	if out.ThawErr == nil {
		t.Fatal("解冻彻底失败必须报错 —— 否则用户永远不知道游戏卡住了")
	}
	_, thaws, frozen := fz.state()
	if !frozen {
		t.Error("fake 一直失败，状态应仍是 frozen")
	}
	if thaws != 3 {
		t.Errorf("应重试 3 次，实际 %d", thaws)
	}
	s := out.String()
	if !strings.Contains(s, "解冻失败") {
		t.Errorf("摘要必须含「解冻失败」: %s", s)
	}
	t.Logf("摘要: %s", s)
}

// TestFreezeRunNilSafe 确认 nil 参数不会 panic。
func TestFreezeRunNilSafe(t *testing.T) {
	if out := freezeRun(nil, time.Second, nil); out.Froze || out.Completed {
		t.Errorf("nil fn 应直接返回零值: %+v", out)
	}
	ran := false
	out := freezeRun(nil, time.Second, func() { ran = true })
	if !ran || !out.Completed {
		t.Errorf("fz 为 nil 时仍应执行 fn: ran=%v out=%+v", ran, out)
	}
}

// TestFreezeRunHoldZeroUsesDefault 确认 hold<=0 时用默认上限，不会"立刻超时"。
func TestFreezeRunHoldZeroUsesDefault(t *testing.T) {
	fz := &fakeFreezer{}
	out := freezeRun(fz, 0, func() { time.Sleep(20 * time.Millisecond) })
	if out.Forced {
		t.Error("hold=0 应取默认上限，不该立刻被看门狗强解")
	}
	if !out.Froze || out.ThawErr != nil {
		t.Errorf("结果不对: %+v", out)
	}
}

// TestFreezeHoldLimitMatchesOriginal 盯住默认冻结上限 = 原版实测值 700 ms。
//
// 这个数字是「反作弊看到的一次挂起有多长」，是当前最值得对齐的参数。
// 数值来源（原版 capture.exe  main.main.func6.3）：
//
//	0x18324d  mov  edi, 0x29b92700    ; 700,000,000 ns
//	0x183252  call time.Time.Add      ; deadline = now + 700ms
//	0x183520  call time.AfterFunc     ; Until(deadline) 到点兜底解冻
//
// 为什么用测试钉死而不是只写注释：我们之前那个 6 秒是拍的，写死在代码里
// 谁也没注意，结果比原版长 8.6 倍。测试至少能在被改大时喊一声。
func TestFreezeHoldLimitMatchesOriginal(t *testing.T) {
	const want = 700 * time.Millisecond
	if freezeHoldLimit != want {
		t.Fatalf("freezeHoldLimit = %v，期望 %v（原版 v2.0.5 实测值）。"+
			"要临时放大请用 -freeze-hold，不要改这个默认值", freezeHoldLimit, want)
	}
}

// TestFreezeRunDefaultWatchdogAt700ms 确认看门狗在 700 ms 量级真的会强解。
//
// 和 TestFreezeRunWatchdogForcesThaw 的区别：那个用 60 ms 验证机制，
// 这个用真实默认值验证「700 ms 之后游戏确实是活的」。
func TestFreezeRunDefaultWatchdogAt700ms(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过（要真等 700 ms）")
	}
	fz := &fakeFreezer{}
	begin := time.Now()
	out := freezeRun(fz, freezeHoldLimit, func() {
		// 模拟 locatePub：本机实测约 2.2 s，远超 700 ms。
		time.Sleep(900 * time.Millisecond)
	})
	el := time.Since(begin)

	if !out.Forced {
		t.Error("超过 700 ms 应被看门狗强制解冻")
	}
	if out.Hold < freezeHoldLimit-time.Millisecond || out.Hold > freezeHoldLimit+150*time.Millisecond {
		t.Errorf("实际持有时长 %v，期望约 %v", out.Hold, freezeHoldLimit)
	}
	if _, thaws, frozen := fz.state(); frozen || thaws != 1 {
		t.Errorf("看门狗后应已解冻且只解一次: thaws=%d frozen=%v", thaws, frozen)
	}
	t.Logf("700 ms 上限生效：持有 %v，fn 共跑 %v", out.Hold.Truncate(time.Millisecond), el.Truncate(time.Millisecond))
}
