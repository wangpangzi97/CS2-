package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// keyThrottle 复刻原版 v2.0.5 的三重节流。
//
// 反汇编依据（`capture.exe` 的 `main.main.func6.3`，0x182f48–0x1831b3）：
//
//	0x182f74  cmp byte ptr [rax], 0        map1[key] bool     已找到 → 跳过
//	0x182fa6  cmp qword ptr [rax], 3       map2[key] int      尝试 ≥3 次 → 跳过
//	0x182fea  cmp rax, 0x3b9aca00          map3[key] time.Time 距上次 <1 秒 → 跳过
//	0x1832d4  inc qword ptr [rax]          真正冻结时尝试计数 +1
//	0x183325  mov qword ptr [rax], rdx     真正冻结时记录本次时刻
//
// 为什么必须有这个模块：
//
// 没有节流时，每换一次图、每次重连都会重新握手，我们就重新冻结一次游戏。
// 一局 30 分钟能握手十几次 —— 反作弊看到的是「同一进程反复被挂起」，
// 这个模式比单次挂起本身可疑得多。原版靠这三个 map 把冻结压到
// 「每个服务器最多 3 次、相邻两次至少隔 1 秒」。
//
// 目标（target）的取法和原版一致：握手包的**源 IP 字符串**。
// 用 IP 而不是公钥，因为每次握手的公钥都不一样，拿公钥当键等于没有节流。
type keyThrottle struct {
	mu    sync.Mutex
	last  map[string]time.Time
	count map[string]int
	found map[string]bool

	// MinInterval 是同一目标两次尝试的最小间隔。原版 1 秒（0x3b9aca00 ns）。
	MinInterval time.Duration
	// MaxAttempts 是同一目标的最大尝试次数，<=0 表示不限。原版 3 次。
	MaxAttempts int
	// Now 可注入，便于测试。nil 时用 time.Now。
	Now func() time.Time
}

func newKeyThrottle(minInterval time.Duration, maxAttempts int) *keyThrottle {
	return &keyThrottle{
		last:        make(map[string]time.Time),
		count:       make(map[string]int),
		found:       make(map[string]bool),
		MinInterval: minInterval,
		MaxAttempts: maxAttempts,
	}
}

func (t *keyThrottle) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// throttleVerdict 是节流判定结果。用枚举而不是 bool，是为了让日志能说清
// 「为什么这次没动静」——现场最常见的问题就是用户以为抓包坏了。
type throttleVerdict int

const (
	// throttleAllow 表示放行，并且已经记了一次尝试。
	throttleAllow throttleVerdict = iota
	// throttleFound 表示该目标已经拿到过密钥，不必再搜。
	throttleFound
	// throttleExhausted 表示该目标的尝试次数已经用尽。
	throttleExhausted
	// throttleTooSoon 表示距上次尝试太近，等一会儿再说。
	throttleTooSoon
	// throttleNoTarget 表示没有可用的目标标识（空字符串），一律放行且不计数。
	throttleNoTarget
)

func (v throttleVerdict) String() string {
	switch v {
	case throttleAllow:
		return "放行"
	case throttleFound:
		return "该服务器已取到密钥"
	case throttleExhausted:
		return "该服务器尝试次数已用尽"
	case throttleTooSoon:
		return "距上次尝试不足最小间隔"
	case throttleNoTarget:
		return "无目标标识"
	}
	return "未知"
}

// Allow 判断是否允许为该目标发起一次密钥搜索。
//
// 放行时会**立刻**记一次尝试（计数 +1、时刻刷新）—— 这是刻意的：
// 原版在真正冻结时才计数，但那样一来「握手到了、进了队列、结果没冻上」
// 这种情况就永远不计数，等于节流失效。宁可计早一点（偏严），
// 也不要出现「反复握手反复冻结」的漏网路径。
func (t *keyThrottle) Allow(target string) throttleVerdict {
	if t == nil || target == "" {
		return throttleNoTarget
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.found[target] {
		return throttleFound
	}
	if t.MaxAttempts > 0 && t.count[target] >= t.MaxAttempts {
		return throttleExhausted
	}
	if t.MinInterval > 0 {
		if last, ok := t.last[target]; ok && t.now().Sub(last) < t.MinInterval {
			return throttleTooSoon
		}
	}
	t.count[target]++
	t.last[target] = t.now()
	return throttleAllow
}

// MarkFound 标记该目标已经成功取到密钥，后续握手直接跳过。
func (t *keyThrottle) MarkFound(target string) {
	if t == nil || target == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.found[target] = true
}

// Attempts 返回该目标已记录的尝试次数（仅用于诊断输出）。
func (t *keyThrottle) Attempts(target string) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count[target]
}

// Summary 返回全部目标的尝试情况，用于诊断报告。
//
// 返回形如 "1.2.3.4: 2/3 次" 的片段；没有记录时返回空串。
func (t *keyThrottle) Summary() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.count) == 0 {
		return ""
	}
	parts := make([]string, 0, len(t.count))
	for k, n := range t.count {
		mark := ""
		if t.found[k] {
			mark = " ✓已取到"
		}
		if t.MaxAttempts > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d/%d 次%s", k, n, t.MaxAttempts, mark))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %d 次%s", k, n, mark))
		}
	}
	sort.Strings(parts)
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "；"
		}
		out += p
	}
	return out
}
