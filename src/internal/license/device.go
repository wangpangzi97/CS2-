package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"local/cs2-radar/internal/winapi"
)

// 设备身份的还原结论（report §4.1）：
//   - 首次运行用 crypto/ed25519.GenerateKey 生成"按设备唯一"的密钥对
//   - 私钥以 Windows DPAPI 加密后存 %AppData%\CS2Radar\device.bin
//   - DPAPI entropy = NULL，flags = 1（CRYPTPROTECT_UI_FORBIDDEN）
//   - MachineGuid 只用于生成设备指纹 sha256("cs2-radar-device-v1:" + MachineGuid)，
//     *不是* DPAPI 熵（实证：带熵解密报 err=13，无熵解密成功）
//   - 绑定锚点是 device.bin 里的 Ed25519 密钥对，不是 MachineGuid
const (
	deviceDirName  = "CS2Radar"
	deviceFileName = "device.bin"
	fingerprintTag = "cs2-radar-device-v1:"

	cryptProtectUIForbidden = 0x1

	keyLocalMachine = 0x80000002
	keyRead         = 0x20019
)

var (
	procLocalFree        = winapi.Kernel32.NewProc("LocalFree")
	procRegOpenKeyExW    = winapi.Advapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueExW = winapi.Advapi32.NewProc("RegQueryValueExW")
	procRegCloseKey      = winapi.Advapi32.NewProc("RegCloseKey")
	procMoveFileExW      = winapi.Kernel32.NewProc("MoveFileExW")
)

// State 对应 device 包读写的那份 JSON。
type State struct {
	Server string `json:"server"`
	Card   string `json:"card"`
	Key    string `json:"key"`
}

// Dir 返回 %AppData%\CS2Radar。
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, deviceDirName), nil
}

// StatePath 对应 device.statePath。
func StatePath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, deviceFileName), nil
}

// LoginPath 对应 device.loginPath：<sha256(login)>-login.bin。
func LoginPath(login string) (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(login))
	return filepath.Join(d, fmt.Sprintf("%x-login.bin", h)), nil
}

// MachineGuid 读 HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid。
func MachineGuid() (string, error) {
	sub, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Cryptography`)
	if err != nil {
		return "", err
	}
	var hKey uintptr
	r, _, _ := procRegOpenKeyExW.Call(keyLocalMachine, uintptr(unsafe.Pointer(sub)), 0, keyRead,
		uintptr(unsafe.Pointer(&hKey)))
	if r != 0 {
		return "", fmt.Errorf("RegOpenKeyExW failed: %d", r)
	}
	defer procRegCloseKey.Call(hKey)

	name, err := syscall.UTF16PtrFromString("MachineGuid")
	if err != nil {
		return "", err
	}
	buf := make([]uint16, 256)
	size := uint32(len(buf) * 2)
	r, _, _ = procRegQueryValueExW.Call(hKey, uintptr(unsafe.Pointer(name)), 0, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return "", fmt.Errorf("RegQueryValueExW failed: %d", r)
	}
	return syscall.UTF16ToString(buf), nil
}

// Fingerprint 返回设备指纹。
func Fingerprint() (string, error) {
	guid, err := MachineGuid()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(fingerprintTag + guid))
	return fmt.Sprintf("%x", h), nil
}

// dpapi 保护/解保护。
func dpapi(protect bool, data []byte) ([]byte, error) {
	var in winapi.DataBlob
	if len(data) > 0 {
		in.Size = uint32(len(data))
		in.Data = &data[0]
	}
	var out winapi.DataBlob
	var r uintptr
	var callErr error
	if protect {
		r, _, callErr = winapi.ProcCryptProtectData.Call(
			uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0,
			uintptr(cryptProtectUIForbidden), uintptr(unsafe.Pointer(&out)))
	} else {
		r, _, callErr = winapi.ProcCryptUnprotectData.Call(
			uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0,
			uintptr(cryptProtectUIForbidden), uintptr(unsafe.Pointer(&out)))
	}
	if r == 0 {
		op := "CryptUnprotectData"
		if protect {
			op = "CryptProtectData"
		}
		code := uint32(0)
		if errno, ok := callErr.(syscall.Errno); ok {
			code = uint32(errno)
		}
		return nil, &DPAPIError{op, code}
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.Data)))
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice(out.Data, out.Size))
	return res, nil
}

// DPAPIError carries only a fixed operation and numeric OS error, never data.
type DPAPIError struct {
	operation string
	code      uint32
}

func (e *DPAPIError) Error() string     { return fmt.Sprintf("%s failed (Win32 %d)", e.operation, e.code) }
func (e *DPAPIError) Win32Code() uint32 { return e.code }

// Protect / Unprotect 暴露给外部（与 device.protect 对应）。
func Protect(data []byte) ([]byte, error)   { return dpapi(true, data) }
func Unprotect(data []byte) ([]byte, error) { return dpapi(false, data) }

// writeConfig 对应 device.writeConfig：临时文件 → 写入 → fsync → 原子替换。
func writeConfig(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".radar-credentials-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// os.Rename 在 Windows 上走 MoveFileEx(MOVEFILE_REPLACE_EXISTING)
	if err := os.Rename(tmp, path); err != nil {
		from, _ := syscall.UTF16PtrFromString(tmp)
		to, _ := syscall.UTF16PtrFromString(path)
		r, _, _ := procMoveFileExW.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 1)
		if r == 0 {
			return err
		}
	}
	return nil
}

// readConfig 对应 device.readConfig。
func readConfig(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plain, err := Unprotect(raw)
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(plain, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Load 对应 device.Load：没有凭据就生成新设备密钥对。
func Load() (*State, ed25519.PrivateKey, error) {
	path, err := StatePath()
	if err != nil {
		return nil, nil, err
	}
	st, err := readConfig(path)
	if err == nil && st.Key != "" {
		raw, err := base64.StdEncoding.DecodeString(st.Key)
		if err == nil && len(raw) == ed25519.PrivateKeySize {
			return st, ed25519.PrivateKey(raw), nil
		}
	}
	// 首次运行：crypto/ed25519.GenerateKey
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	if st == nil {
		st = &State{}
	}
	st.Key = base64.StdEncoding.EncodeToString(priv)
	if err := Save(st); err != nil {
		return nil, nil, err
	}
	return st, priv, nil
}

// Save 对应 device.Save。
func Save(st *State) error {
	path, err := StatePath()
	if err != nil {
		return err
	}
	plain, err := json.Marshal(st)
	if err != nil {
		return err
	}
	blob, err := Protect(plain)
	if err != nil {
		return err
	}
	return writeConfig(path, blob)
}

// VerifyKey 校验 device.bin 里的密钥自洽（seed → pub 推导一致）。
func VerifyKey(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("not a 64-byte ed25519 private key")
	}
	seed := priv.Seed()
	derived := ed25519.NewKeyFromSeed(seed)
	if !strings.EqualFold(base64.StdEncoding.EncodeToString(derived), base64.StdEncoding.EncodeToString(priv)) {
		return errors.New("seed does not derive the embedded public key")
	}
	return nil
}
