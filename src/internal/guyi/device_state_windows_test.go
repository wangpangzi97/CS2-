package guyi

import (
	"bytes"
	"errors"
	"local/cs2-radar/internal/startupdiag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeviceStateFailureReasonsAndNoAutomaticReset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.bin.device")
	input := []byte("SYNTHETIC_DPAPI_BAD_STATE_NOT_A_KEY")
	if e := os.WriteFile(p, input, 0600); e != nil {
		t.Fatal(e)
	}
	_, e := loadDataKey(p)
	got := startupdiag.Format(startupdiag.Wrap(startupdiag.DeviceKey, e))
	if !strings.Contains(got, "GS-C03/DPAPI-OPEN/WIN32-") {
		t.Fatal(got)
	}
	if strings.Contains(got, string(input)) {
		t.Fatal("state bytes leaked")
	}
	raw, _ := os.ReadFile(p)
	if !bytes.Equal(raw, input) {
		t.Fatal("invalid identity automatically replaced")
	}
}
func TestExplicitDeviceArchivePreservesCiphertextAndRecreate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fixture.bin.device")
	raw := []byte("SYNTHETIC_INVALID_ENCRYPTED_STATE")
	if e := os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
	ok, e := archiveInvalidDataKey(p)
	if e != nil || !ok {
		t.Fatalf("explicit archive failed: %v", e)
	}
	backups, _ := filepath.Glob(p + ".backup-*")
	if len(backups) != 1 {
		t.Fatal("exact backup missing")
	}
	saved, _ := os.ReadFile(backups[0])
	if !bytes.Equal(saved, raw) {
		t.Fatal("backup bytes changed")
	}
	if _, e = os.Stat(p); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("old path not archived")
	}
	a, e := loadDataKey(p)
	if e != nil {
		t.Fatal(e)
	}
	b, e := loadDataKey(p)
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("new identity did not persist")
	}
	// A subsequent explicit reset attempt must refuse the now-valid key.
	before, _ := os.ReadFile(p)
	if ok, e = archiveInvalidDataKey(p); ok || e == nil {
		t.Fatal("valid identity reset")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("valid identity overwritten")
	}
	t.Log("EXPLICIT_ARCHIVE=EXACT_CIPHERTEXT; RECREATE=DPAPI_STABLE; VALID_KEY_RESET=REFUSED")
}
func TestDeviceDiagnosticNeverUsesCardOrExportsKey(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	c := Config{Endpoint: "https://127.0.0.1/api/verify.php", AppKey: strings.Repeat("a", 64), AppID: 1}
	first := CheckLocalDevice(c)
	if first.State != "MISSING" || !first.DPAPIRoundtripOK || !first.StorageProbeOK || first.CardUsed || first.ServerBindingChanged || first.CanArchiveInvalid {
		t.Fatalf("unexpected initial state: %+v", first)
	}
	p, _ := credentialPath(c)
	a, e := loadDataKey(p + ".device")
	if e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(p + ".device")
	report := CheckLocalDevice(c)
	if report.State != "VALID" || report.CanArchiveInvalid || !report.DPAPIRoundtripOK || !report.StorageProbeOK {
		t.Fatalf("valid state rejected: %+v", report)
	}
	repaired := ArchiveInvalidLocalDevice(c)
	if repaired.ArchiveCreated {
		t.Fatal("valid identity archived")
	}
	after, _ := os.ReadFile(p + ".device")
	if !bytes.Equal(before, after) || bytes.Contains(after, a) {
		t.Fatal("identity changed or plaintext written")
	}
	files, _ := os.ReadDir(filepath.Dir(p))
	for _, f := range files {
		if strings.Contains(f.Name(), "probe") {
			t.Fatal("probe file leaked")
		}
	}
}
func TestArchiveRejectsDirectoriesAndMissingState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "directory.device")
	if e := os.Mkdir(p, 0700); e != nil {
		t.Fatal(e)
	}
	if ok, e := archiveInvalidDataKey(p); ok || e == nil {
		t.Fatal("directory moved")
	}
	if ok, e := archiveInvalidDataKey(filepath.Join(t.TempDir(), "missing.device")); ok || e != nil {
		t.Fatal("missing state modified")
	}
}
