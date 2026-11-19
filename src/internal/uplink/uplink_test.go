package uplink

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// newTestSender 造一个本机模式的 Sender，ticker 间隔设成 1 小时，
// 保证测试期间只有显式 Close 会触发投递（否则 200ms ticker 会让断言飘）。
func newTestSender(deliver func(*Batch) error) *Sender {
	s := &Sender{
		Session:       "t",
		MaxPackets:    64,
		FlushInterval: time.Hour,
		Deliver:       deliver,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	go s.loop()
	return s
}

// TestCloseIsIdempotent 锁住「重复 Close 不得重复投递」。
//
// 背景：调用点普遍写成「defer Close() + 中途显式 Close()」
// （cmd/collector 的 runReplay / runCapture 都是），
// 旧实现的 Close 每次都会跑一遍 Flush(true)，于是多发一个空批次。
func TestCloseIsIdempotent(t *testing.T) {
	var (
		mu      sync.Mutex
		calls   int
		packets int
	)
	deliver := func(b *Batch) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		packets += len(b.Packets)
		return nil
	}
	s := newTestSender(deliver)

	for i := 0; i < 3; i++ {
		s.Push(Packet{Dir: "s2c", Data: "AA=="})
	}

	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("投递次数 = %d，期望 1（重复 Close 不得重复投递）", calls)
	}
	if packets != 3 {
		t.Fatalf("投递包数 = %d，期望 3", packets)
	}
}

// TestCloseReturnsSameError 锁住「重复 Close 返回首次的结果」。
func TestCloseReturnsSameError(t *testing.T) {
	sentinel := errors.New("boom")
	var calls int
	s := newTestSender(func(b *Batch) error {
		calls++
		return sentinel
	})
	s.Push(Packet{Dir: "s2c", Data: "AA=="})

	if err := s.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("首次 Close 错误 = %v，期望 %v", err, sentinel)
	}
	if err := s.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("二次 Close 错误 = %v，期望仍是 %v", err, sentinel)
	}
	if calls != 1 {
		t.Fatalf("投递次数 = %d，期望 1", calls)
	}
}

// TestLocalModeDoesNotTouchNetwork 锁住「本机模式不发 HTTP」。
// Deliver 非空时 Mode() 必须是 local，且 Push+Close 全程不产生失败计数。
func TestLocalModeDoesNotTouchNetwork(t *testing.T) {
	var got int
	s := newTestSender(func(b *Batch) error {
		got += len(b.Packets)
		return nil
	})
	if s.Mode() != "local" {
		t.Fatalf("Mode() = %q，期望 local", s.Mode())
	}
	// URL 故意留空：一旦误走 HTTP 分支会立刻报错。
	s.Push(Packet{Dir: "s2c", Data: "AA=="})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got != 1 {
		t.Fatalf("本机投递包数 = %d，期望 1", got)
	}
	if st := s.Stats(); st["failed"].(uint64) != 0 {
		t.Fatalf("failed = %v，期望 0（本机模式不应有任何网络失败）", st["failed"])
	}
}
