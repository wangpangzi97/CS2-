package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"local/cs2-radar/internal/guyi"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeviceRepairFlowRequiresExplicitConfirmation(t *testing.T) {
	for _, accept := range []bool{false, true} {
		calls, asks := 0, 0
		r := deviceRepairFlow(func() guyi.DeviceCheckReport {
			return guyi.DeviceCheckReport{State: "INVALID", CanArchiveInvalid: true}
		}, func() guyi.DeviceCheckReport {
			calls++
			return guyi.DeviceCheckReport{State: "ARCHIVED", ArchiveCreated: true}
		}, func() bool { asks++; return accept })
		if asks != 1 {
			t.Fatal("confirmation not requested")
		}
		if accept {
			if calls != 1 || r.State != "ARCHIVED" {
				t.Fatal("confirmed archive did not run exactly once")
			}
		} else if calls != 0 || r.State != "CANCELLED" {
			t.Fatal("cancel changed identity")
		}
	}
}

func TestDeviceRepairFlowWithRealDPAPIFixture(t *testing.T) {
	profile := t.TempDir()
	t.Setenv("APPDATA", profile)
	c := guyi.Config{Endpoint: "https://127.0.0.1/api/verify.php", AppKey: strings.Repeat("a", 64), AppID: 1}
	sum := sha256.Sum256([]byte(c.Endpoint + "\n" + c.AppKey))
	p := filepath.Join(profile, "GuYiAccess", hex.EncodeToString(sum[:])+".bin.device")
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	input := []byte("SYNTHETIC_INVALID_DEVICE_STATE_UI_FLOW")
	if e := os.WriteFile(p, input, 0600); e != nil {
		t.Fatal(e)
	}
	check := func() guyi.DeviceCheckReport { return guyi.CheckLocalDevice(c) }
	archive := func() guyi.DeviceCheckReport { return guyi.ArchiveInvalidLocalDevice(c) }
	r := deviceRepairFlow(check, archive, func() bool { return false })
	b, _ := os.ReadFile(p)
	if r.State != "CANCELLED" || !bytes.Equal(b, input) {
		t.Fatal("cancel changed state")
	}
	r = deviceRepairFlow(check, archive, func() bool { return true })
	backups, _ := filepath.Glob(p + ".backup-*")
	if r.State != "ARCHIVED" || !r.ArchiveCreated || r.CardUsed || r.ServerBindingChanged || len(backups) != 1 {
		t.Fatalf("unexpected result: %+v", r)
	}
	b, _ = os.ReadFile(backups[0])
	if !bytes.Equal(b, input) {
		t.Fatal("backup not exact")
	}
	t.Log("NATIVE_FLOW_CANCEL=UNCHANGED; CONFIRMED=EXACT_CIPHERTEXT_BACKUP; CARD_USED=false; SERVER_CHANGED=false")
}
func TestDeviceRepairFlowRefusesValidUnreadableOrProbeFailure(t *testing.T) {
	for _, state := range []string{"VALID", "MISSING", "UNKNOWN", "UNREADABLE"} {
		r := deviceRepairFlow(func() guyi.DeviceCheckReport { return guyi.DeviceCheckReport{State: state} }, func() guyi.DeviceCheckReport { t.Fatal("unapproved archive"); return guyi.DeviceCheckReport{} }, func() bool { t.Fatal("unexpected confirmation"); return true })
		if r.State != state {
			t.Fatal("state changed")
		}
	}
}
