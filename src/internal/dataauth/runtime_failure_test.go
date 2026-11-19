package dataauth

import (
	"context"
	"local/cs2-radar/internal/startupdiag"
	"net/http"
	"testing"
)

func TestRuntimeFailureFirstTypedCauseSurvivesClose(t *testing.T) {
	c := &Client{failure: make(chan struct{}), http: &http.Client{}}
	c.failLocked(&startupdiag.HTTPFailure{Status: 403})
	c.Close()
	k, h := c.FailureInfo()
	if k != 2 || h != 403 {
		t.Fatal("cause overwritten")
	}
	d := &Client{failure: make(chan struct{}), http: &http.Client{}}
	d.failLocked(startupdiag.Network(context.DeadlineExceeded))
	k, h = d.FailureInfo()
	if k != 4 || h != 0 {
		t.Fatal("timeout code")
	}
}
