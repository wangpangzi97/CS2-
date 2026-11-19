package uplink

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func slowAsync(t *testing.T, cap int) (*AsyncSender, <-chan struct{}) {
	t.Helper()
	entered := make(chan struct{}, 1)
	a, e := newAsyncRemote("https://example.invalid/api/v1/ingest", "synthetic", "", func(r *http.Request, _ []byte) (*http.Response, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	}, cap, 4096)
	if e != nil {
		t.Fatal(e)
	}
	a.base.MaxPackets = 1
	t.Cleanup(func() { a.Close() })
	return a, entered
}
func TestAsyncPushAndFlushNeverWaitForTransport(t *testing.T) {
	a, entered := slowAsync(t, 8)
	done := make(chan struct{})
	go func() { a.Push(Packet{Data: "AA=="}); a.Flush(false); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capture caller blocked")
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker not sending")
	}
	closed := make(chan struct{})
	go func() { a.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("context-aware close blocked")
	}
	if a.Stats()["queue_bytes"].(int) != 0 {
		t.Fatal("retained queued bytes")
	}
}
func TestAsyncOverflowIsTerminalAndCountsAllLostPackets(t *testing.T) {
	a, entered := slowAsync(t, 2)
	a.Push(Packet{Data: "AA=="})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("not entered")
	}
	for i := 0; i < 3; i++ {
		a.Push(Packet{Data: "AA=="})
	}
	select {
	case <-a.Failed():
	case <-time.After(time.Second):
		t.Fatal("overflow not terminal")
	}
	if !errors.Is(a.Err(), ErrBackpressure) {
		t.Fatal("overflow cause lost")
	}
	a.Close()
	m := a.Stats()
	if m["dropped_packets"].(uint64) != 4 || m["queue_rejected"].(uint64) != 1 || m["queue_depth"].(int) != 0 || m["queue_bytes"].(int) != 0 {
		t.Fatalf("accounting: %v", m)
	}
}
func TestAsyncByteBoundAndPostCloseAccounting(t *testing.T) {
	a, e := newAsyncRemote("https://example.invalid/api/v1/ingest", "synthetic", "", func(*http.Request, []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	}, 8, 128)
	if e != nil {
		t.Fatal(e)
	}
	a.Push(Packet{Data: strings.Repeat("A", 129)})
	a.Close()
	a.Push(Packet{})
	if !errors.Is(a.Err(), ErrBackpressure) || a.Stats()["dropped_packets"].(uint64) != 2 {
		t.Fatal("byte bound")
	}
}
func TestAsyncHTTPDenialRetainsTypedStatusAndStops(t *testing.T) {
	a, e := NewAsyncAuthenticatedRemote("https://example.invalid/api/v1/ingest", "synthetic", "", func(*http.Request, []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("FAKE_PRIVATE_BODY"))}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	a.base.MaxPackets = 1
	a.Push(Packet{Data: "AA=="})
	select {
	case <-a.Failed():
	case <-time.After(time.Second):
		t.Fatal("denial not terminal")
	}
	var h interface{ HTTPStatus() int }
	if !errors.As(a.Err(), &h) || h.HTTPStatus() != 403 || strings.Contains(a.Err().Error(), "FAKE_PRIVATE_BODY") {
		t.Fatal("status or redaction")
	}
}
func TestAsyncConcurrentCloseProducers(t *testing.T) {
	a, e := NewAsyncAuthenticatedRemote("https://example.invalid/api/v1/ingest", "synthetic", "", func(r *http.Request, _ []byte) (*http.Response, error) {
		select {
		case <-r.Context().Done():
			return nil, context.Canceled
		default:
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		}
	})
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				a.Push(Packet{Data: "AA=="})
				a.Flush(false)
			}
		}()
	}
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() { defer wg.Done(); a.Close() }()
	}
	wg.Wait()
	a.Close()
	if a.Stats()["queue_depth"].(int) != 0 || a.Stats()["queue_bytes"].(int) != 0 {
		t.Fatal("queue retained after concurrent close")
	}
}
