package main

import (
	"testing"
	"time"
)

// fakeClock 让节流测试不用真的 sleep。
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestThrottle(minGap time.Duration, maxTries int) (*keyThrottle, *fakeClock) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	th := newKeyThrottle(minGap, maxTries)
	th.Now = c.now
	return th, c
}

// 原版 map3：距上次 < 1 秒 → 跳过（0x182fea cmp rax,0x3b9aca00 / setl）。
func TestThrottleMinInterval(t *testing.T) {
	th, clk := newTestThrottle(time.Second, 0)

	if v := th.Allow("1.2.3.4"); v != throttleAllow {
		t.Fatalf("首次应放行，得到 %v", v)
	}
	if v := th.Allow("1.2.3.4"); v != throttleTooSoon {
		t.Fatalf("间隔 0 应判太近，得到 %v", v)
	}
	clk.advance(999 * time.Millisecond)
	if v := th.Allow("1.2.3.4"); v != throttleTooSoon {
		t.Fatalf("间隔 999ms 应判太近，得到 %v", v)
	}
	clk.advance(2 * time.Millisecond) // 累计 1001ms
	if v := th.Allow("1.2.3.4"); v != throttleAllow {
		t.Fatalf("间隔 1001ms 应放行，得到 %v", v)
	}

	// 不同服务器互不影响 —— 这是"按源 IP 计数"的核心语义。
	if v := th.Allow("5.6.7.8"); v != throttleAllow {
		t.Fatalf("不同目标应放行，得到 %v", v)
	}
}

// 原版 map2：尝试 ≥3 次 → 永久跳过（0x182fa6 cmp qword[rax],3 / jl）。
func TestThrottleMaxAttempts(t *testing.T) {
	th, clk := newTestThrottle(0, 3) // 关掉间隔限制，只看次数

	for i := 0; i < 3; i++ {
		if v := th.Allow("1.2.3.4"); v != throttleAllow {
			t.Fatalf("第 %d 次应放行，得到 %v", i+1, v)
		}
		clk.advance(time.Minute)
	}
	if v := th.Allow("1.2.3.4"); v != throttleExhausted {
		t.Fatalf("第 4 次应判用尽，得到 %v", v)
	}
	// 等再久也不恢复：原版的 map 是进程级、无过期的。
	clk.advance(time.Hour)
	if v := th.Allow("1.2.3.4"); v != throttleExhausted {
		t.Fatalf("等一小时后仍应用尽，得到 %v", v)
	}
	if got := th.Attempts("1.2.3.4"); got != 3 {
		t.Fatalf("尝试计数 %d，期望 3（被拒的那次不该加）", got)
	}
}

// 原版 map1：已找到 → 跳过（0x182f74 cmp byte ptr [rax], 0）。
func TestThrottleMarkFound(t *testing.T) {
	th, _ := newTestThrottle(0, 0)
	if v := th.Allow("1.2.3.4"); v != throttleAllow {
		t.Fatalf("首次应放行，得到 %v", v)
	}
	th.MarkFound("1.2.3.4")
	if v := th.Allow("1.2.3.4"); v != throttleFound {
		t.Fatalf("已找到应跳过，得到 %v", v)
	}
	// 别的服务器不受影响。
	if v := th.Allow("9.9.9.9"); v != throttleAllow {
		t.Fatalf("其他目标应放行，得到 %v", v)
	}
}

// 空目标一律放行且不计数：拿不到源 IP 时不能把功能直接关死。
func TestThrottleEmptyTargetAlwaysAllowed(t *testing.T) {
	th, _ := newTestThrottle(time.Hour, 1)
	for i := 0; i < 5; i++ {
		if v := th.Allow(""); v != throttleNoTarget {
			t.Fatalf("空目标应返回 noTarget，得到 %v", v)
		}
	}
}

// nil 节流器不能 panic —— searchKey 等路径可能在没初始化节流时被调用。
func TestThrottleNilSafe(t *testing.T) {
	var th *keyThrottle
	if v := th.Allow("1.2.3.4"); v != throttleNoTarget {
		t.Fatalf("nil 应返回 noTarget，得到 %v", v)
	}
	th.MarkFound("1.2.3.4")
	if th.Attempts("1.2.3.4") != 0 {
		t.Fatal("nil 的 Attempts 应为 0")
	}
	if th.Summary() != "" {
		t.Fatal("nil 的 Summary 应为空")
	}
}

// 并发调用不能漏计：抓包线程是单线程投递，但 searchKey 那边也可能 MarkFound。
func TestThrottleConcurrent(t *testing.T) {
	th, _ := newTestThrottle(0, 1000)
	const n = 200
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			th.Allow("1.2.3.4")
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
	if got := th.Attempts("1.2.3.4"); got != n {
		t.Fatalf("并发计数 %d，期望 %d", got, n)
	}
}
