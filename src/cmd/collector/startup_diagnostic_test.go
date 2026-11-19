package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"local/cs2-radar/internal/startupdiag"
	"path/filepath"
	"strings"
	"testing"
)

func TestStudioTypedStartupFailures(t *testing.T) {
	secret := errors.New("FAKE_CARD_TOKEN_DEVICE_PRIVATE_VALUE")
	for _, s := range []startupdiag.Stage{startupdiag.Config, startupdiag.DeviceKey, startupdiag.Activation, startupdiag.LicenseHeartbeat, startupdiag.DataChallenge, startupdiag.DataLogin, startupdiag.ViewMaps, startupdiag.ViewFrame, startupdiag.Capture} {
		got := studioError(&authorizationError{startupdiag.Wrap(s, secret)})
		if !strings.HasPrefix(got, "[GS-"+string(s)+"]") || strings.Contains(got, secret.Error()) {
			t.Fatal(got)
		}
	}
}

func TestConnectionCheckConfigFailureRedactsPathAndNoCapture(t *testing.T) {
	old := *flagLicenseConfig
	defer func() { *flagLicenseConfig = old }()
	*flagLicenseConfig = filepath.Join(t.TempDir(), "FAKE_SENSITIVE_USERNAME_LICENSE_PATH.json")
	var b bytes.Buffer
	if runConnectionCheck(&b) != 1 {
		t.Fatal("invalid config accepted")
	}
	if strings.Contains(b.String(), "FAKE_SENSITIVE_USERNAME_LICENSE_PATH") {
		t.Fatal("local path exposed")
	}
	var v struct {
		Card    bool   `json:"card_used"`
		Capture bool   `json:"capture_started"`
		TLS     bool   `json:"strict_tls"`
		Result  string `json:"result"`
	}
	if json.Unmarshal(b.Bytes(), &v) != nil || v.Card || v.Capture || !v.TLS || !strings.Contains(v.Result, "GS-C01") {
		t.Fatal(b.String())
	}
}
