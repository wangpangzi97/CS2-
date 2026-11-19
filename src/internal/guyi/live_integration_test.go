package guyi

import (
	"context"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Opt-in fixture only: TLS is terminated by httptest, then forwarded to the
// loopback PHP test server. Never point this at a live deployment or live cards.
func TestLocalPHPControllerInterop(t *testing.T) {
	backend := os.Getenv("GUYI_INTEROP_BACKEND")
	if backend == "" {
		t.Skip("requires explicit loopback PHP test fixture")
	}
	u, e := url.Parse(backend)
	if e != nil || os.Getenv("GUYI_TESTING") != "1" || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		t.Fatal("refusing non-fixture backend")
	}
	p := httputil.NewSingleHostReverseProxy(u)
	c, _ := testClient(t, p.ServeHTTP)
	c.config.AppID = 1 // tests/fixture.php seeds this public ID.
	ctx := context.Background()
	s, e := c.Activate(ctx, "TEST-YEAR-CARD", "go-interop-device")
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Heartbeat(ctx, s, "go-interop-device"); e != nil {
		t.Fatal(e)
	}
	t.Log("PHP + MariaDB: activation, exact HMAC and authenticated AES response accepted")
	wrong := *c
	wrong.config.AppID++
	if e = wrong.Heartbeat(ctx, s, "go-interop-device"); e == nil {
		t.Fatal("wrong app_id accepted")
	}
	if _, e = c.Activate(ctx, "156440000", "go-interop-device"); e == nil {
		t.Fatal("legacy magic card accepted")
	}
	if e = c.Unbind(ctx, s, "go-interop-device"); e != nil {
		t.Fatal(e)
	}
	if e = c.Heartbeat(ctx, s, "go-interop-device"); e == nil {
		t.Fatal("revoked session accepted")
	}
	if strings.Contains(s.Key, c.config.AppKey) {
		t.Fatal("session uses public app key")
	}
	t.Log("PHP + MariaDB: wrong app_id and magic card rejected; unbind confirmed and revoked session rejected")
}
