package guyi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"local/cs2-radar/internal/license"
	"local/cs2-radar/internal/startupdiag"
	"os"
	"path/filepath"
)

func DefaultConfigPath() string {
	exe, e := os.Executable()
	if e != nil {
		return "license.json"
	}
	return filepath.Join(filepath.Dir(exe), "license.json")
}

func credentialPath(c Config) (string, error) {
	base, e := os.UserConfigDir()
	if e != nil {
		return "", e
	}
	h := sha256.Sum256([]byte(c.Endpoint + "\n" + c.AppKey))
	return filepath.Join(base, "GuYiAccess", hex.EncodeToString(h[:])+".bin"), nil
}

func storeCard(c Config, card string) error {
	p, e := credentialPath(c)
	if e != nil {
		return e
	}
	b, e := license.Protect([]byte(card))
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".card-*.tmp")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(tmp, p)
}

func loadCard(c Config) (string, error) {
	p, e := credentialPath(c)
	if e != nil {
		return "", e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return "", errors.New("尚未激活，请在 gamesense 主程序登录界面输入卡密")
	}
	if len(b) > 16384 {
		return "", errors.New("授权凭据文件过大")
	}
	b, e = license.Unprotect(b)
	if e != nil {
		return "", errors.New("卡密解密失败，请在当前 Windows 账号重新激活")
	}
	if len(b) == 0 || len(b) > 50 {
		return "", errors.New("无效的已保存卡密")
	}
	return string(b), nil
}

type Lease struct {
	client       *Client
	session      Session
	card, device string
}

// Open never consults legacy radar-license state or the original upstream server.
func Open(ctx context.Context, path string) (*Lease, error) {
	c, e := LoadConfig(path)
	if e != nil {
		return nil, startupdiag.Wrap(startupdiag.Config, e)
	}
	card, e := loadCard(c)
	if e != nil {
		return nil, startupdiag.Wrap(startupdiag.SavedCard, e)
	}
	return openCard(ctx, c, card)
}

func openCard(ctx context.Context, c Config, card string) (*Lease, error) {
	client, e := New(c)
	if e != nil {
		return nil, startupdiag.Wrap(startupdiag.TLSConfig, e)
	}
	device, e := license.Fingerprint()
	if e != nil {
		return nil, startupdiag.Wrap(startupdiag.Fingerprint, e)
	}
	p, e := credentialPath(c)
	if e != nil {
		return nil, startupdiag.Wrap(startupdiag.DeviceKey, e)
	}
	key, e := loadDataKey(p + ".device")
	if e != nil {
		return nil, startupdiag.Wrap(startupdiag.DeviceKey, e)
	}
	if e = client.SetDeviceProofKey(key); e != nil {
		return nil, startupdiag.Wrap(startupdiag.DeviceKey, e)
	}
	s, e := client.Activate(ctx, card, device)
	if e != nil {
		return nil, e
	}
	if e = client.Heartbeat(ctx, s, device); e != nil {
		return nil, e
	}
	return &Lease{client, s, card, device}, nil
}

func ActivateAndSave(ctx context.Context, path, card string) (*Lease, error) {
	c, e := LoadConfig(path)
	if e != nil {
		return nil, startupdiag.Wrap(startupdiag.Config, e)
	}
	l, e := openCard(ctx, c, card)
	if e != nil {
		return nil, e
	}
	if e = storeCard(c, card); e != nil {
		return nil, startupdiag.Wrap(startupdiag.SaveCard, e)
	}
	return l, nil
}

func (l *Lease) Maintain(ctx context.Context) error {
	return l.client.Maintain(ctx, l.session, l.card, l.device)
}
func (l *Lease) ExpireTime() string { return l.session.ExpireTime }
func (l *Lease) Unbind(ctx context.Context) error {
	if e := l.client.Unbind(ctx, l.session, l.device); e != nil {
		return e
	}
	p, e := credentialPath(l.client.config)
	if e != nil {
		return e
	}
	return os.Remove(p)
}
