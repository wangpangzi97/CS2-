package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
)

func rnd(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRunFindsCorrectVariant 用一个**非规范**变体（salt 顺序反了、context 段序换了）
// 封 8 帧，再让 run 去吃这份 diag 文件，验证它能把那一组找出来。
//
// 这条用例的意义：gnsdiag 是"现场失败后唯一能离线调 KDF 的工具"，
// 它自己错了就等于把唯一的退路也堵死了。
func TestRunFindsCorrectVariant(t *testing.T) {
	cp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &cs2crypto.GNSHandshake{
		ClientConnID: rnd(t, 4),
		ServerConnID: rnd(t, 4),
		ClientPub:    cp.PublicKey().Bytes(),
		ServerPub:    sp.PublicKey().Bytes(),
		ClientNonce:  rnd(t, 8),
		ServerNonce:  rnd(t, 8),
		ClientCert:   rnd(t, 97),
		ServerCert:   rnd(t, 97),
		ClientCrypt:  rnd(t, 49),
		ServerCrypt:  rnd(t, 49),
	}

	// 故意的非规范变体：salt 顺序反、context 段序 1、connID 顺序反。
	v := cs2crypto.GNSVariant{SaltSwap: true, ConnSwap: true, Blobs: 1, Label: "Steam datagram"}
	pm, err := cs2crypto.GNSPremaster(cp.Bytes(), h)
	if err != nil {
		t.Fatal(err)
	}
	keys := cs2crypto.GNSDeriveFromPremaster(pm, h, v)

	var frames []string
	for i := 0; i < 8; i++ {
		pt := make([]byte, 48)
		copy(pt, "svc_PacketEntities")
		pt[20] = byte(i)
		seq := uint16(i + 1)
		nonce := cs2crypto.GNSIVForSeq(keys.SendIV, uint64(seq))
		ct := cs2crypto.SealWith(keys.SendKey, nonce, pt, nil)
		f := []byte{0x82}
		f = append(f, h.ClientConnID...)
		var s [2]byte
		binary.LittleEndian.PutUint16(s[:], seq)
		f = append(f, s[:]...)
		f = append(f, 0xe1, 0x0a)
		f = append(f, ct...)
		frames = append(frames, hex.EncodeToString(f))
	}

	d := diag{
		Session:      "test",
		ClientConnID: hex.EncodeToString(h.ClientConnID),
		ServerConnID: hex.EncodeToString(h.ServerConnID),
		ClientPub:    hex.EncodeToString(h.ClientPub),
		ServerPub:    hex.EncodeToString(h.ServerPub),
		ClientNonce:  hex.EncodeToString(h.ClientNonce),
		ServerNonce:  hex.EncodeToString(h.ServerNonce),
		ClientCert:   hex.EncodeToString(h.ClientCert),
		ServerCert:   hex.EncodeToString(h.ServerCert),
		ClientCrypt:  hex.EncodeToString(h.ClientCrypt),
		ServerCrypt:  hex.EncodeToString(h.ServerCrypt),
		ClientPriv:   hex.EncodeToString(cp.Bytes()),
		Frames:       frames,
	}
	body, err := json.Marshal(&d)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "diag.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	if code := run(path); code != 0 {
		t.Fatalf("run 返回 %d，说明一帧都没解开（KDF 或变体覆盖有问题）", code)
	}
}

// TestRunRejectsWrongPriv 私钥取错时必须明确报"私钥不配对"，而不是含糊地报"解不开"。
func TestRunRejectsWrongPriv(t *testing.T) {
	cp, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sp, _ := ecdh.X25519().GenerateKey(rand.Reader)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	h := &cs2crypto.GNSHandshake{
		ClientConnID: rnd(t, 4), ServerConnID: rnd(t, 4),
		ClientPub: cp.PublicKey().Bytes(), ServerPub: sp.PublicKey().Bytes(),
		ClientNonce: rnd(t, 8), ServerNonce: rnd(t, 8),
		ClientCert: rnd(t, 97), ServerCert: rnd(t, 97),
		ClientCrypt: rnd(t, 49), ServerCrypt: rnd(t, 49),
	}
	d := diag{
		ClientConnID: hex.EncodeToString(h.ClientConnID),
		ServerConnID: hex.EncodeToString(h.ServerConnID),
		ClientPub:    hex.EncodeToString(h.ClientPub),
		ServerPub:    hex.EncodeToString(h.ServerPub),
		ClientNonce:  hex.EncodeToString(h.ClientNonce),
		ServerNonce:  hex.EncodeToString(h.ServerNonce),
		ClientCert:   hex.EncodeToString(h.ClientCert),
		ServerCert:   hex.EncodeToString(h.ServerCert),
		ClientCrypt:  hex.EncodeToString(h.ClientCrypt),
		ServerCrypt:  hex.EncodeToString(h.ServerCrypt),
		ClientPriv:   hex.EncodeToString(other.Bytes()),
	}
	body, _ := json.Marshal(&d)
	path := filepath.Join(t.TempDir(), "diag.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run(path); code != 1 {
		t.Fatalf("私钥不配对时应当返回 1，实为 %d", code)
	}
}

// TestDiagJSONShape 钉住 diag 的字段名：它是 tryGNS 与 gnsdiag 之间的契约，
// 改名会让"现场失败后离线复现"这条路静默断掉。
func TestDiagJSONShape(t *testing.T) {
	body, err := json.Marshal(&diag{Session: "s", Frames: []string{"00"}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"session", "client_conn_id", "server_conn_id", "client_eph_pub", "server_eph_pub",
		"client_nonce", "server_nonce", "client_cert", "server_cert",
		"client_crypt", "server_crypt", "client_priv", "frames",
	} {
		if _, ok := m[k]; !ok {
			t.Fatalf("diag JSON 缺字段 %q", k)
		}
	}
	_ = base64.StdEncoding
}
