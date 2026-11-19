package startupdiag

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestSafeTypedStages(t *testing.T) {
	secret := "FAKE_CARD_PROXY_PASSWORD_TOKEN_SECRET"
	cases := []struct {
		e    error
		code string
	}{
		{errors.New(secret), "GS-X00"},
		{Wrap(Activation, &HTTPFailure{403, errors.New(secret)}), "GS-A02/HTTP-403"},
		{Wrap(DataChallenge, &HTTPFailure{401, errors.New(secret)}), "GS-D02/HTTP-401"},
		{Wrap(LicenseConfig, Network(&url.Error{Op: "Post", URL: "https://" + secret, Err: &net.OpError{Op: "proxyconnect", Net: "tcp", Err: errors.New(secret)}})), "GS-A01/NET-PROXY"},
		{Wrap(LicenseConfig, Network(x509.UnknownAuthorityError{})), "GS-A01/NET-TLS"},
		{Wrap(LicenseConfig, Network(context.DeadlineExceeded)), "GS-A01/NET-TIMEOUT"},
		{Wrap(SaveCard, errors.New(secret)), "GS-C05"},
		{Wrap(Stage(secret), errors.New(secret)), "GS-X00"},
	}
	for _, c := range cases {
		got := Format(c.e)
		if !strings.Contains(got, c.code) || strings.Contains(got, secret) {
			t.Fatalf("unsafe/wrong diagnostic: %s", got)
		}
	}
}
func TestHTTPFailureRetainsDenial(t *testing.T) {
	sentinel := errors.New("denied")
	e := Wrap(DataLogin, &HTTPFailure{403, sentinel})
	if !errors.Is(e, sentinel) {
		t.Fatal("denial chain lost")
	}
}
