package uplink

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const remoteTimeout = 15 * time.Second

// ValidateEndpoint is deliberately shared by startup and the delivery boundary.
// Do not include the supplied URL in an error (it may contain a legacy secret).
func ValidateEndpoint(raw string) error {
	const message = "必须配置有效 HTTPS uplink（/api/v1/ingest）；禁止本地回退、明文及URL凭据"
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\\r\n\t") {
		return errors.New(message)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" ||
		u.Path != "/api/v1/ingest" || u.RawPath != "" {
		return errors.New(message)
	}
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p < 1 || p > 65535 {
			return errors.New(message)
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return errors.New(message)
	}
	return nil
}

func secureClient(ca string) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, errors.New("cannot read configured uplink CA")
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid configured uplink CA")
		}
		cfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	tr.MaxConnsPerHost = 2
	return &http.Client{
		Transport: tr, Timeout: remoteTimeout,
		// Redirects are not an authorization/trust boundary and must not carry keys.
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("uplink redirects forbidden") },
	}, nil
}

func NewRemote(endpoint, session, token, ca string) (*Sender, error) {
	if err := ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("data credential required")
	}
	hc, err := secureClient(ca)
	if err != nil {
		return nil, err
	}
	s := New(endpoint, session)
	s.Token, s.CACert = token, ca
	s.hcOnce.Do(func() { s.hc = hc })
	return s, nil
}

// NewAuthenticatedRemote is the production path. NewRemote's static credential
// compatibility remains only for isolated transport fixtures; the server denies it.
func NewAuthenticatedRemote(endpoint, session, ca string, authorize func(*http.Request, []byte) (*http.Response, error)) (*Sender, error) {
	if err := ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if authorize == nil {
		return nil, errors.New("device-bound data session required")
	}
	hc, err := secureClient(ca)
	if err != nil {
		return nil, err
	}
	s := New(endpoint, session)
	s.Authorize = authorize
	s.CACert = ca
	s.hcOnce.Do(func() { s.hc = hc })
	return s, nil
}

func (s *Sender) client() (*http.Client, error) {
	s.hcOnce.Do(func() { s.hc, s.hcErr = secureClient(s.CACert) })
	return s.hc, s.hcErr
}

// Failed is terminal for this sender. No packet retries or local fallback occur.
func (s *Sender) Failed() <-chan struct{} { return s.failureCh }
func (s *Sender) Err() error {
	s.failureMu.Lock()
	defer s.failureMu.Unlock()
	return s.failureErr
}
func (s *Sender) fail(err error) {
	s.failureOnce.Do(func() {
		s.failureMu.Lock()
		s.failureErr = fmt.Errorf("remote stopped; create a new authorized session: %w", err)
		s.failureMu.Unlock()
		s.halted.Store(true)
		s.mu.Lock()
		s.droppedPackets.Add(uint64(len(s.buf)))
		s.buf = nil
		s.clientPub, s.serverPub, s.key = "", "", ""
		s.gns, s.gnsKeys, s.gnsIVs = nil, nil, nil
		s.mu.Unlock()
		if s.failureCh != nil {
			close(s.failureCh)
		}
		if s.hc != nil {
			s.hc.CloseIdleConnections()
		}
	})
}

// Abort is for failed startup: stop without sending an empty final batch.
func (s *Sender) Abort() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.fail(errors.New("sender aborted"))
		close(s.stopCh)
		<-s.doneCh
		s.closeErr = s.Err()
	})
}
