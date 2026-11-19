package handshake

import (
	"encoding/hex"
	"testing"
)

// 真实抓包（dump2.jsonl，2026-10-19）里的两条连接，逐字节贴进来当回归向量。
//
// 这两条连接同时证明了三件事：
//  1. 0x22 / 0x23 是 GNS 的 ConnectRequest / ConnectOK（消息 ID 32..37）；
//  2. 临时公钥在 crypt.info.key_data（f7→f1→f2），而 cert 里的 f4→f2
//     是**静态** Ed25519 身份密钥（两条连接完全相同）；
//  3. 服务器连接 ID 在 ConnectOK 的 field 5，客户端连接 ID 在 field 1。
const (
	realConnectRequest1 = "220da9d29fcc1195ac13a8f5c524bb19dcc3c1680100100122ae0122610801122090a7d793841f4b2e63d2530bbd0c58aae32821155cbc1cd5f634cace3c17701321dcc3c16801001001450b04d56a4d0ba7d76a50da055a0a8101dcc3c168010010016219737465616d69643a3736353631313939373137373934373830291b39aaf5cf5083b63240b7833838a91ab97065c63c81367ac67c480be716b786f7bf6fd59aeaec488fcaeaee7843c489c7e61dd0920e59b62493ef29420feb5c611bc586bf3e65faba09296a704db8ba020000301b3a750a310801122085e6bd808ccf6bbf4727484eb36c96bdbda6349dbfd1448d21dd76801f2ff661191c2cebceae1e24f8200d280212400aea07d01124a0c5a4fb681f417f58f48952b3759f6829a95e610b7049f77773661fe82bdc6e7e8882bf367d6a068474d4457d6b060bacdfc29ac8c8065d3900"
	realConnectOK1      = "230da9d29fcc11f5bdcf0000003001196a704db8ba02000020d4cb052d79dddd393a750a3108011220cf8b80922c92833d39d9aaf3930b1385c4650224f54f8b9bddddb84e5de2297919238df0e8c978b716200d28021240a79a6ae9e9d9d1de09b718bf4ff1529d1bdffc9e4a3bf63d96cd5898bea2143adce7c48cd96263385f5ca4f788698fddc5e57bc3a5f300c3dbe1136b97d8820342ae0122610801122092428d561504e4331303c4e65aacae974d1498dbd2e657953bcf795911bc862621f5bdcf000000300145978dd46a4d9730d76a50da055a0a8101f5bdcf00000030016219737465616d69643a3835353638333932393333363534303035291b39aaf5cf5083b63240e8f791f07a8391477b04a83a45008d20debb9637390d2062be6a970d8700339c942eb7c80e75d3218ef26b094c76c1208bd4b576cebfb828c9de62c6a8f5ad0a"

	// 第二条连接：客户端临时公钥不同，但 cert 里的静态身份密钥完全相同。
	realConnectRequest2 = "220d8a10f566110bac79e597102e9e19dcc3c1680100100122ae0122610801122090a7d793841f4b2e63d2530bbd0c58aae32821155cbc1cd5f634cace3c17701321dcc3c16801001001450b04d56a4d0ba7d76a50da055a0a8101dcc3c168010010016219737465616d69643a3736353631313939373137373934373830291b39aaf5cf5083b63240b7833838a91ab97065c63c81367ac67c480be716b786f7bf6fd59aeaec488fcaeaee7843c489c7e61dd0920e59b62493ef29420feb5c611bc586bf3e65faba0929f0f027bbba020000301c3a750a310801122036f951fe63d86155c0235a6f46d3190379674fdd1a347533bd871b94c8f86b7e19ed9371ccbb5e5dcb200d28021240a78ef00f7466fdcaa099424fab4bfcc7d6468d59521b035a712fe6402cf18ca3e6936139d2fa6e5fcfb1ec73640d94e6fe0cc9a26a068dec92be4b8959e83a08"
)

func mustHexGNS(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func TestParseGNSConnectRequest(t *testing.T) {
	p, err := ParseGNSHandshake(mustHexGNS(t, realConnectRequest1))
	if err != nil {
		t.Fatalf("ParseGNSHandshake: %v", err)
	}
	if p.Type != TypeGNSConnectRequest {
		t.Fatalf("type = 0x%02x", p.Type)
	}
	if got := hex.EncodeToString(p.ConnID); got != "a9d29fcc" {
		t.Errorf("ConnID = %s", got)
	}
	if got := hex.EncodeToString(p.Pub); got != "85e6bd808ccf6bbf4727484eb36c96bdbda6349dbfd1448d21dd76801f2ff661" {
		t.Errorf("Pub = %s", got)
	}
	if got := hex.EncodeToString(p.Nonce); got != "1c2cebceae1e24f8" {
		t.Errorf("Nonce = %s", got)
	}
	if len(p.Cert) != 97 {
		t.Errorf("Cert len = %d, want 97", len(p.Cert))
	}
	if len(p.Crypt) != 49 {
		t.Errorf("Crypt len = %d, want 49", len(p.Crypt))
	}
	if p.Proto != 13 {
		t.Errorf("Proto = %d, want 13", p.Proto)
	}
	if len(p.Cipher) != 1 || p.Cipher[0] != 2 {
		t.Errorf("Cipher = %v, want [2]", p.Cipher)
	}
}

func TestParseGNSConnectOK(t *testing.T) {
	p, err := ParseGNSHandshake(mustHexGNS(t, realConnectOK1))
	if err != nil {
		t.Fatalf("ParseGNSHandshake: %v", err)
	}
	if p.Type != TypeGNSConnectOK {
		t.Fatalf("type = 0x%02x", p.Type)
	}
	// 服务器自己的连接 ID 在 field 5。
	if got := hex.EncodeToString(p.ConnID); got != "79dddd39" {
		t.Errorf("ConnID = %s, want 79dddd39", got)
	}
	// field 1 是回显的客户端连接 ID，配对用。
	if got := hex.EncodeToString(p.EchoConnID); got != "a9d29fcc" {
		t.Errorf("EchoConnID = %s, want a9d29fcc", got)
	}
	if got := hex.EncodeToString(p.Pub); got != "cf8b80922c92833d39d9aaf3930b1385c4650224f54f8b9bddddb84e5de22979" {
		t.Errorf("Pub = %s", got)
	}
	if got := hex.EncodeToString(p.Nonce); got != "238df0e8c978b716" {
		t.Errorf("Nonce = %s", got)
	}
	if len(p.Cert) != 97 {
		t.Errorf("Cert len = %d, want 97", len(p.Cert))
	}
	if len(p.Crypt) != 49 {
		t.Errorf("Crypt len = %d, want 49", len(p.Crypt))
	}
}

// TestGNSStaticKeyIsNotEphemeral 钉住那个曾经导致「密钥挖到却一条都解不开」的坑：
// cert 里的公钥跨连接不变（静态身份密钥），crypt 里的每次都不一样（临时密钥）。
// ECDH 必须用后者。
func TestGNSStaticKeyIsNotEphemeral(t *testing.T) {
	p1, err := ParseGNSHandshake(mustHexGNS(t, realConnectRequest1))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ParseGNSHandshake(mustHexGNS(t, realConnectRequest2))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(p1.Pub) == hex.EncodeToString(p2.Pub) {
		t.Fatal("两条连接的临时公钥不应该相同")
	}
	if len(p1.Cert) < 40 || len(p2.Cert) < 40 {
		t.Fatal("cert 太短")
	}
	// cert 前 40 字节（key_type + key_data）必须完全一致。
	if hex.EncodeToString(p1.Cert[:40]) != hex.EncodeToString(p2.Cert[:40]) {
		t.Errorf("静态身份密钥应当跨连接相同：\n %x\n %x", p1.Cert[:40], p2.Cert[:40])
	}
}

func TestParseGNSRejectsNonHandshake(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		{0x00},
		{0x82, 1, 2, 3},
		{0x20, 0x0d}, // ChallengeRequest，不是握手
	} {
		if _, err := ParseGNSHandshake(b); err == nil {
			t.Errorf("应当拒绝 %x", b)
		}
	}
}
