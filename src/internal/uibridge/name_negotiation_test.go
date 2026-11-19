package uibridge

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type nameProtocolRemote struct {
	*fixtureRemote
	lock     sync.Mutex
	status   int
	text     string
	versions []string
}

func (f *nameProtocolRemote) DoBody(r *http.Request, b []byte) (*http.Response, error) {
	if r.URL.Path == "/api/v1/radar" {
		v := r.Header.Get("X-Gamesense-View-Version")
		f.lock.Lock()
		f.versions = append(f.versions, v)
		f.lock.Unlock()
		if v == "3" {
			return &http.Response{StatusCode: f.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(f.text))}, nil
		}
	}
	return f.fixtureRemote.DoBody(r, b)
}
func TestNameProtocolExactCompatibilityOnly(t *testing.T) {
	for _, tt := range []struct {
		status   int
		text     string
		fallback bool
	}{{400, "unsupported drawing version\n", true}, {403, "unsupported drawing version\n", false}, {400, "other rejection", false}, {503, "unsupported drawing version\n", false}, {200, `{"v":3,"name":"bad"}`, false}} {
		remote := &nameProtocolRemote{fixtureRemote: fixture(), status: tt.status, text: tt.text}
		b, e := Start(context.Background(), "https://fixture.invalid/api/v1/ingest", remote)
		if tt.fallback {
			if e != nil {
				t.Fatal(e)
			}
			b.Close()
			if len(remote.versions) != 2 || remote.versions[0] != "3" || remote.versions[1] != "2" {
				t.Fatal("wrong negotiation", remote.versions)
			}
		} else {
			if e == nil {
				b.Close()
				t.Fatal("error silently downgraded")
			}
			if len(remote.versions) != 1 {
				t.Fatal("error triggered fallback")
			}
		}
	}
}
