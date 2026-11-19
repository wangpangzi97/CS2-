package dataauth

import (
	"crypto/ed25519"
	"crypto/sha256"
)

// DevicePublicKeySelector is private server-side diagnostic selection metadata,
// not an authorization factor, token or public endpoint. Session IDs change on
// restart; the already-enrolled public key lets the operator select ONE intended
// test device before maintenance without collecting the first arbitrary user.
func (p *Permit) DevicePublicKeySelector() [32]byte {
	if p == nil || p.s == nil {
		return [32]byte{}
	}
	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	if len(p.s.pub) != ed25519.PublicKeySize {
		return [32]byte{}
	}
	return sha256.Sum256(p.s.pub)
}
