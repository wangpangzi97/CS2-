package guyi

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"local/cs2-radar/internal/dataauth"
	"local/cs2-radar/internal/license"
)

// A separate server/app-scoped DPAPI key, reusing license's audited primitives.
// Existing unreadable or inconsistent state fails closed; never silently replace
// a registered key (replacement requires the server-side reset flow).
func loadDataKey(path string) (ed25519.PrivateKey, error) {
	key, e := readDataKey(path)
	if e == nil {
		return key, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	_, key, e = ed25519.GenerateKey(nil)
	if e != nil {
		return nil, deviceErr("RANDOM", e)
	}
	protected, e := license.Protect(key)
	if e != nil {
		return nil, deviceErr("DPAPI-SEAL", e)
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, deviceErr("DIR", e)
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, deviceErr("CREATE", e)
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, e = f.Write(protected); e != nil {
		return nil, deviceErr("WRITE", e)
	}
	if e = f.Sync(); e != nil {
		return nil, deviceErr("SYNC", e)
	}
	if e = f.Close(); e != nil {
		return nil, deviceErr("CLOSE", e)
	}
	ok = true
	return key, nil
}
func (l *Lease) DataKey() (ed25519.PrivateKey, error) {
	p, e := credentialPath(l.client.config)
	if e != nil {
		return nil, e
	}
	return loadDataKey(p + ".device")
}
func (l *Lease) DataCredential() dataauth.Credential {
	// This closure stays in the native process. No raw key getter is exposed.
	s := l.session
	return dataauth.Credential{SessionID: s.ID, Device: l.device, MAC: func(text string) (string, error) {
		key, e := derive(s.Key, "data-enrollment")
		if e != nil {
			return "", e
		}
		m := hmac.New(sha256.New, key)
		m.Write([]byte(text))
		return hex.EncodeToString(m.Sum(nil)), nil
	}}
}
