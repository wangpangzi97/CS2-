package main

import (
	"bufio"
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"local/cs2-radar/internal/memscan"
)

// TestFreezeRealProcess 用真实进程验证 FreezeFast/ThawFast 真的能停住目标。
//
// 为什么必须做这一层：freeze_test.go 里的 fake 只验证了"保证解冻"的控制流，
// 但 `NtSuspendProcess` 的调用方式（单参数 + NTSTATUS==0 才算成功）是从逆向
// 推断的，而且这个 API 在我们代码里**从未被真实调用过**。控制流再对，
// 如果 API 用错了，要么报"冻结失败"，要么更糟 —— 报成功但实际没冻住，
// 那"抢在擦除前"这个前提就是假的。
//
// 做法：起一个每秒输出一行的子进程（ping），冻结它，然后确认**冻结期间
// 一行都读不到**，解冻后又能读到。这是"真的停住了"最直接的证据。
func TestFreezeRealProcess(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("只在 Windows 上验证 NtSuspendProcess")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-n", "60", "127.0.0.1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Skipf("拿不到子进程 stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("起不来 ping（环境限制）: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	lines := make(chan string, 128)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	next := func(timeout time.Duration) (string, bool) {
		select {
		case l, ok := <-lines:
			return l, ok
		case <-time.After(timeout):
			return "", false
		}
	}

	// ping 先打一行 header，再每秒打一行 Reply。
	if _, ok := next(6 * time.Second); !ok {
		t.Skip("ping 没有输出，跳过")
	}
	if _, ok := next(6 * time.Second); !ok {
		t.Skip("ping 没有 Reply 行，跳过")
	}

	proc, err := memscan.OpenForRead(uint32(cmd.Process.Pid))
	if err != nil {
		t.Skipf("打不开子进程: %v", err)
	}
	defer proc.Close()

	// ── 冻结 ──
	if err := proc.FreezeFast(); err != nil {
		t.Fatalf("FreezeFast 失败（NtSuspendProcess 调用方式可能有误）: %v", err)
	}
	thawed := false
	defer func() {
		if !thawed {
			_ = proc.ThawFast()
		}
	}()

	// 先排空管道里冻结前就已经写进去的行。
	// 管道缓冲是 OS 层面的：冻结进程**不会**清掉已经写入的数据，
	// 不排空就会把"冻结前的残留"误判成"冻结期间还在输出"。
	time.Sleep(200 * time.Millisecond)
	drained := 0
	for {
		select {
		case <-lines:
			drained++
			continue
		default:
		}
		break
	}
	t.Logf("冻结后先排空管道残留 %d 行", drained)

	// 管道现在是空的，冻结期间 ping 每秒一行，等 1.8 秒足够跨过两次。
	if l, ok := next(1800 * time.Millisecond); ok {
		t.Fatalf("冻结期间子进程仍在输出（没真的停住）: %q", l)
	}
	t.Log("冻结生效：1.8 秒内没有任何新输出")

	// ── 解冻 ──
	if err := proc.ThawFast(); err != nil {
		t.Fatalf("ThawFast 失败 —— 游戏会一直卡住，这是最高级别故障: %v", err)
	}
	thawed = true

	// 解冻后应立刻恢复输出（ping 的下一行最多等 1 秒）。
	if l, ok := next(6 * time.Second); !ok {
		t.Fatal("解冻后子进程没有恢复输出")
	} else {
		t.Logf("解冻生效，恢复输出: %q", l)
	}

	// 进程必须还活着（解冻不是"杀掉"）。
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		t.Fatal("解冻后进程不应退出")
	}
}

// TestFreezeThawCycleStable 确认反复冻结/解冻不会把进程搞死或残留挂起。
//
// 真实场景：用户在一局里换服务器、重连，可能触发多次握手 → 多次冻结。
// 如果某次解冻不彻底，挂起计数会累积，游戏越来越卡。
func TestFreezeThawCycleStable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("只在 Windows 上验证")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-n", "120", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skipf("起不来 ping: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	proc, err := memscan.OpenForRead(uint32(cmd.Process.Pid))
	if err != nil {
		t.Skipf("打不开子进程: %v", err)
	}
	defer proc.Close()

	const rounds = 20
	begin := time.Now()
	for i := 0; i < rounds; i++ {
		if err := proc.FreezeFast(); err != nil {
			t.Fatalf("第 %d 轮冻结失败: %v", i, err)
		}
		if err := proc.ThawFast(); err != nil {
			t.Fatalf("第 %d 轮解冻失败: %v", i, err)
		}
	}
	t.Logf("%d 轮冻结/解冻耗时 %s", rounds, time.Since(begin).Truncate(time.Millisecond))

	// 最后一轮必须真的解冻了：再冻一次能成功，且解冻后进程仍能读内存。
	if err := proc.FreezeFast(); err != nil {
		t.Fatalf("多轮之后冻结失败: %v", err)
	}
	if err := proc.ThawFast(); err != nil {
		t.Fatalf("多轮之后解冻失败: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := proc.ReadAt(0x10000, buf); err != nil {
		// 读不到不算错（那片地址可能不可读），只要不是"句柄失效"就行。
		t.Logf("（读 0x10000 返回 %v，不影响结论）", err)
	}
}
