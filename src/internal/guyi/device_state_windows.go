package guyi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"local/cs2-radar/internal/license"
	"local/cs2-radar/internal/startupdiag"
)

type deviceStateError struct {
	code  string
	cause error
}

func (e *deviceStateError) Error() string             { return "local device state: " + e.code }
func (e *deviceStateError) Unwrap() error             { return e.cause }
func (e *deviceStateError) LocalDeviceReason() string { return e.code }
func deviceErr(code string, e error) error            { return &deviceStateError{code, e} }

func readDataKey(path string) (ed25519.PrivateKey, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, deviceErr("READ", e)
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return nil, deviceErr("FILE-TYPE", nil)
	}
	if st.Size() == 0 || st.Size() > 16384 {
		return nil, deviceErr("STATE-SIZE", nil)
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, deviceErr("READ", e)
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil {
		return nil, deviceErr("READ", e)
	}
	if len(raw) == 0 || len(raw) > 16384 {
		return nil, deviceErr("STATE-SIZE", nil)
	}
	key, e := license.Unprotect(raw)
	if e != nil {
		return nil, deviceErr("DPAPI-OPEN", e)
	}
	if e = license.VerifyKey(ed25519.PrivateKey(key)); e != nil {
		return nil, deviceErr("KEY-FORMAT", e)
	}
	return ed25519.PrivateKey(key), nil
}

// The diagnostic exercises DPAPI only with a public constant, never a card or key.
func deviceDPAPIProbe() error {
	input := []byte("gamesense-local-dpapi-public-self-test-v1")
	sealed, e := license.Protect(input)
	if e != nil {
		return deviceErr("DPAPI-SEAL", e)
	}
	plain, e := license.Unprotect(sealed)
	if e != nil {
		return deviceErr("DPAPI-OPEN", e)
	}
	if !bytes.Equal(input, plain) {
		return deviceErr("DPAPI-ROUNDTRIP", nil)
	}
	return nil
}
func deviceStorageProbe(path string) error {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return deviceErr("DIR", e)
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return deviceErr("FILE-TYPE", e)
	}
	f, e := os.CreateTemp(dir, ".gamesense-device-probe-*.tmp")
	if e != nil {
		return deviceErr("CREATE", e)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, e = f.Write([]byte("public-write-test")); e != nil {
		return deviceErr("WRITE", e)
	}
	if e = f.Sync(); e != nil {
		return deviceErr("SYNC", e)
	}
	if e = f.Close(); e != nil {
		return deviceErr("CLOSE", e)
	}
	return nil
}

type DeviceCheckReport struct {
	Version              string `json:"diagnostic_version"`
	DPAPIRoundtripOK     bool   `json:"dpapi_roundtrip_ok"`
	StorageProbeOK       bool   `json:"storage_probe_ok"`
	State                string `json:"device_state"`
	CanArchiveInvalid    bool   `json:"can_archive_invalid"`
	ArchiveCreated       bool   `json:"encrypted_backup_created"`
	CardUsed             bool   `json:"card_used"`
	ServerBindingChanged bool   `json:"server_binding_changed"`
	Result               string `json:"result"`
}

func invalidDeviceState(e error) bool {
	var de *deviceStateError
	return errors.As(e, &de) && (de.code == "DPAPI-OPEN" || de.code == "KEY-FORMAT" || de.code == "STATE-SIZE")
}

// CheckLocalDevice does not generate or replace a device key and never contacts a server.
func CheckLocalDevice(c Config) DeviceCheckReport {
	r := DeviceCheckReport{Version: "gamesense-20261024-v8-device", State: "UNKNOWN"}
	fail := func(e error) DeviceCheckReport {
		r.Result = startupdiag.Format(startupdiag.Wrap(startupdiag.DeviceKey, e))
		return r
	}
	p, e := credentialPath(c)
	if e != nil {
		return fail(deviceErr("PROFILE", e))
	}
	if e = deviceDPAPIProbe(); e != nil {
		return fail(e)
	}
	r.DPAPIRoundtripOK = true
	if e = deviceStorageProbe(p + ".device"); e != nil {
		return fail(e)
	}
	r.StorageProbeOK = true
	_, e = readDataKey(p + ".device")
	if errors.Is(e, os.ErrNotExist) {
		r.State = "MISSING"
		r.Result = "[GS-C03/NEW] 本机尚无设备凭据，下一次登录将尝试安全创建。"
		return r
	}
	if e != nil {
		r.State = "UNREADABLE"
		if invalidDeviceState(e) {
			r.State = "INVALID"
			r.CanArchiveInvalid = true
		}
		return fail(e)
	}
	r.State = "VALID"
	r.Result = "[GS-C03/OK] 当前 Windows 账号的本机设备凭据可用。"
	return r
}

// archiveInvalidDataKey is an EXPLICIT offline repair operation. Never called by
// login, loadDataKey, CheckLocalDevice, or a failed authorization. Close all client
// instances first. Valid/unreadable/link state is refused, not reset.
func archiveInvalidDataKey(path string) (bool, error) {
	if filepath.Ext(path) != ".device" {
		return false, deviceErr("FILE-TYPE", nil)
	}
	if _, e := readDataKey(path); e == nil {
		return false, deviceErr("VALID-REFUSED", nil)
	} else if errors.Is(e, os.ErrNotExist) {
		return false, nil
	} else if !invalidDeviceState(e) {
		return false, e
	}
	if e := deviceDPAPIProbe(); e != nil {
		return false, e
	}
	if e := deviceStorageProbe(path); e != nil {
		return false, e
	}
	initial, e := os.Lstat(path)
	if e != nil || !initial.Mode().IsRegular() || initial.Mode()&os.ModeSymlink != 0 {
		return false, deviceErr("FILE-TYPE", e)
	}
	if initial.Size() > 1<<20 {
		// Refuse unusual large files rather than allocating or moving them.
		return false, deviceErr("ARCHIVE", nil)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		return false, deviceErr("READ", e)
	}
	if len(before) == 0 || len(before) <= 16384 {
		// Recheck the exact current state immediately before its no-replace rename.
		if _, e = readDataKey(path); e == nil {
			return false, deviceErr("VALID-REFUSED", nil)
		} else if !invalidDeviceState(e) {
			return false, e
		}
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return false, deviceErr("FILE-TYPE", e)
	}
	again, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, again) {
		return false, deviceErr("CHANGED", e)
	}
	nonce := make([]byte, 8)
	if _, e = rand.Read(nonce); e != nil {
		return false, deviceErr("RANDOM", e)
	}
	backup := path + ".backup-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(nonce)
	from, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return false, deviceErr("ARCHIVE", e)
	}
	to, e := syscall.UTF16PtrFromString(backup)
	if e != nil {
		return false, deviceErr("ARCHIVE", e)
	}
	// MoveFileW refuses an existing destination; no plaintext and no overwrite.
	if e = syscall.MoveFile(from, to); e != nil {
		return false, deviceErr("ARCHIVE", e)
	}
	raw, e := os.ReadFile(backup)
	if e != nil || sha256.Sum256(raw) != sha256.Sum256(before) {
		return false, deviceErr("CHANGED", e)
	}
	return true, nil
}
func ArchiveInvalidLocalDevice(c Config) DeviceCheckReport {
	r := CheckLocalDevice(c)
	if !r.CanArchiveInvalid {
		if r.State == "VALID" {
			r.Result = "[GS-C03/VALID-REFUSED] 设备凭据有效，拒绝重建；换卡不需要更换设备密钥。"
		}
		return r
	}
	p, e := credentialPath(c)
	if e != nil {
		r.Result = startupdiag.Format(startupdiag.Wrap(startupdiag.DeviceKey, deviceErr("PROFILE", e)))
		return r
	}
	ok, e := archiveInvalidDataKey(p + ".device")
	if e != nil {
		r.Result = startupdiag.Format(startupdiag.Wrap(startupdiag.DeviceKey, e))
		return r
	}
	if ok {
		r.ArchiveCreated = true
		r.CanArchiveInvalid = false
		r.State = "ARCHIVED"
		r.Result = "[GS-C03/ARCHIVED] 旧密文已原样备份；请在同一 Windows 账号重新输入卡密登录。服务器绑定未改变。"
	}
	return r
}
