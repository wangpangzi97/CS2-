package main

import (
	"context"
	"errors"
	"local/cs2-radar/internal/uplink"
	"testing"
	"time"
)

type failedFixtureSink struct {
	uplink.Sink
	failure chan struct{}
}

func (f *failedFixtureSink) Failed() <-chan struct{} { return f.failure }
func (f *failedFixtureSink) Err() error              { return errors.New("synthetic denial") }

func TestRemoteFailureStopsSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &failedFixtureSink{failure: make(chan struct{})}
	s := &captureSession{sender: f, stopCh: make(chan struct{}), em: &emitter{}}
	watchUplinkFailure(s, cancel)
	close(f.failure)
	select {
	case <-s.stopCh:
	case <-time.After(time.Second):
		t.Fatal("capture session not stopped")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("lease not cancelled")
	}
	if s.h != nil {
		t.Fatal("unexpected capture handle")
	}
}

func TestRemoteOnlyFactory(t *testing.T) {
	oldURL := *flagUplink
	defer func() { *flagUplink = oldURL }()
	for _, u := range []string{"", "http://127.0.0.1:1/api/v1/ingest", "https://127.0.0.1:1/api/v1/ingest?token=synthetic-fixture", "https://127.0.0.1:1/api/v1/ingest"} {
		*flagUplink = u
		s, e := newSender(nil)
		if s != nil || e == nil {
			t.Fatal("created sender without native data session")
		}
	}
}
