package restrictedreplay

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Load is an explicit local-operator gate, never an API or environment switch.
// No config file means no sampler. Reusing a consumed job directory fails closed.
func Load(path string) (*Capture, error) {
	fail := func() (*Capture, error) { return nil, errors.New("invalid private replay consent file") }
	if !filepath.IsAbs(path) {
		return fail()
	}
	fi, e := os.Lstat(path)
	if e != nil || !fi.Mode().IsRegular() || !trustedConfig(fi) {
		return fail()
	}
	f, e := os.Open(path)
	if e != nil {
		return fail()
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(fi, actual) || actual.Size() > 4096 {
		return fail()
	}
	cfg, e := decodeConsent(f)
	if e != nil {
		return fail()
	}
	return New(cfg)
}

func decodeConsent(r io.Reader) (Config, error) {
	fail := func() (Config, error) { return Config{}, errors.New("invalid replay consent structure") }
	var in struct {
		Scope                 string    `json:"scope"`
		Directory             string    `json:"directory"`
		DevicePublicKeySHA256 string    `json:"device_public_key_sha256"`
		Expires               time.Time `json:"expires"`
	}
	d := json.NewDecoder(io.LimitReader(r, 4097))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Scope != "one_session_gameplay_plaintext_v1" {
		return fail()
	}
	return Config{Directory: in.Directory, DevicePublicKeySHA256: in.DevicePublicKeySHA256, Expires: in.Expires}, nil
}
