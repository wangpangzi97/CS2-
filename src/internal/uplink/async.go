package uplink

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
)

const AsyncQueuePackets = 4096
const AsyncQueueBytes = 8 << 20
const maxAsyncPacketCharge = 128 << 10

type backpressureError struct{}

func (backpressureError) Error() string {
	return "remote queue capacity exceeded; reauthentication required"
}
func (backpressureError) DiagnosticFailureCode() uint8 { return 8 }

var ErrBackpressure error = backpressureError{}

// AsyncSender is the production-only adapter. Network I/O and Flush never run
// on Push's caller. A full queue is terminal, never a silent local fallback.
// Close cancels and discards unsent data rather than replaying after a stop.
type AsyncSender struct {
	base     *Sender
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	q        chan Packet
	bytes    int
	maxBytes int
	flush    chan struct{}
	done     chan struct{}
	once     sync.Once
	closeErr error
	rejected atomic.Uint64
}

func NewAsyncAuthenticatedRemote(endpoint, session, ca string, authorize func(*http.Request, []byte) (*http.Response, error)) (*AsyncSender, error) {
	return newAsyncRemote(endpoint, session, ca, authorize, AsyncQueuePackets, AsyncQueueBytes)
}
func newAsyncRemote(endpoint, session, ca string, authorize func(*http.Request, []byte) (*http.Response, error), packets, maxBytes int) (*AsyncSender, error) {
	if authorize == nil || packets <= 0 || packets > AsyncQueuePackets || maxBytes <= 0 || maxBytes > AsyncQueueBytes {
		return nil, errors.New("invalid async remote configuration")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &AsyncSender{ctx: ctx, cancel: cancel, q: make(chan Packet, packets), maxBytes: maxBytes, flush: make(chan struct{}, 1), done: make(chan struct{})}
	wrapped := func(req *http.Request, body []byte) (*http.Response, error) {
		joined, release := context.WithCancel(req.Context())
		stop := context.AfterFunc(ctx, release)
		defer release()
		defer stop()
		if ctx.Err() != nil {
			release()
		}
		return authorize(req.WithContext(joined), body)
	}
	b, e := NewAuthenticatedRemote(endpoint, session, ca, wrapped)
	if e != nil {
		cancel()
		return nil, e
	}
	a.base = b
	go a.run()
	return a, nil
}
func packetCharge(p Packet) int { return 96 + len(p.Data) + len(p.Src) + len(p.Dst) + len(p.Dir) }
func (a *AsyncSender) Push(p Packet) {
	charge := packetCharge(p)
	a.mu.Lock()
	if a.closed || a.base.halted.Load() {
		a.mu.Unlock()
		a.base.droppedPackets.Add(1)
		return
	}
	if charge > maxAsyncPacketCharge || charge > a.maxBytes-a.bytes || len(a.q) == cap(a.q) {
		a.mu.Unlock()
		a.rejected.Add(1)
		a.base.droppedPackets.Add(1)
		a.base.fail(ErrBackpressure)
		a.cancel()
		return
	}
	a.bytes += charge
	// Only producers hold mu; the consumer can only make room. Never block.
	select {
	case a.q <- p:
		a.mu.Unlock()
	default:
		a.bytes -= charge
		a.mu.Unlock()
		a.rejected.Add(1)
		a.base.droppedPackets.Add(1)
		a.base.fail(ErrBackpressure)
		a.cancel()
	}
}
func (a *AsyncSender) release(p Packet) { a.mu.Lock(); a.bytes -= packetCharge(p); a.mu.Unlock() }
func (a *AsyncSender) discard() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for {
		select {
		case p := <-a.q:
			a.bytes -= packetCharge(p)
			a.base.droppedPackets.Add(1)
		default:
			return
		}
	}
}
func (a *AsyncSender) run() {
	defer close(a.done)
	defer a.discard()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.base.Failed():
			return
		case p := <-a.q:
			a.release(p)
			if a.ctx.Err() != nil || a.base.halted.Load() {
				a.base.droppedPackets.Add(1)
				return
			}
			a.base.Push(p)
		case <-a.flush:
			if a.ctx.Err() != nil || a.base.halted.Load() {
				return
			}
			_ = a.base.Flush(false)
		}
	}
}
func (a *AsyncSender) Flush(final bool) error {
	if final {
		return a.Close()
	}
	if a.base.halted.Load() {
		return a.base.Err()
	}
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		return errors.New("remote sender closed")
	}
	select {
	case a.flush <- struct{}{}:
	default:
	}
	return nil
}
func (a *AsyncSender) Close() error {
	a.once.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		if a.base.halted.Load() {
			a.closeErr = a.base.Err()
		}
		a.cancel()
		a.base.Abort()
		<-a.done
	})
	return a.closeErr
}
func (a *AsyncSender) Abort()                        { _ = a.Close() }
func (a *AsyncSender) Failed() <-chan struct{}       { return a.base.Failed() }
func (a *AsyncSender) Err() error                    { return a.base.Err() }
func (a *AsyncSender) Mode() string                  { return a.base.Mode() }
func (a *AsyncSender) SetHandshake(v []byte)         { a.base.SetHandshake(v) }
func (a *AsyncSender) SetServerPub(v []byte)         { a.base.SetServerPub(v) }
func (a *AsyncSender) SetKey(v []byte)               { a.base.SetKey(v) }
func (a *AsyncSender) SetGNS(v *GNSMaterial)         { a.base.SetGNS(v) }
func (a *AsyncSender) SetGNSKeys(v *GNSKeysMaterial) { a.base.SetGNSKeys(v) }
func (a *AsyncSender) SetGNSIVs(v *GNSIVMaterial)    { a.base.SetGNSIVs(v) }
func (a *AsyncSender) Stats() map[string]any {
	m := a.base.Stats()
	a.mu.Lock()
	m["queue_depth"] = len(a.q)
	m["queue_bytes"] = a.bytes
	m["queue_capacity"] = cap(a.q)
	a.mu.Unlock()
	m["queue_rejected"] = a.rejected.Load()
	return m
}
