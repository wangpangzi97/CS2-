package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/handshake"
	"local/cs2-radar/internal/uplink"
)

// 真实抓包里的两条握手（与 internal/handshake/gns_test.go 同一份数据）。
const (
	testReqHex = "220da9d29fcc1195ac13a8f5c524bb19dcc3c1680100100122ae0122610801122090a7d793841f4b2e63d2530bbd0c58aae32821155cbc1cd5f634cace3c17701321dcc3c16801001001450b04d56a4d0ba7d76a50da055a0a8101dcc3c168010010016219737465616d69643a3736353631313939373137373934373830291b39aaf5cf5083b63240b7833838a91ab97065c63c81367ac67c480be716b786f7bf6fd59aeaec488fcaeaee7843c489c7e61dd0920e59b62493ef29420feb5c611bc586bf3e65faba09296a704db8ba020000301b3a750a310801122085e6bd808ccf6bbf4727484eb36c96bdbda6349dbfd1448d21dd76801f2ff661191c2cebceae1e24f8200d280212400aea07d01124a0c5a4fb681f417f58f48952b3759f6829a95e610b7049f77773661fe82bdc6e7e8882bf367d6a068474d4457d6b060bacdfc29ac8c8065d3900"
	testOKHex  = "230da9d29fcc11f5bdcf0000003001196a704db8ba02000020d4cb052d79dddd393a750a3108011220cf8b80922c92833d39d9aaf3930b1385c4650224f54f8b9bddddb84e5de2297919238df0e8c978b716200d28021240a79a6ae9e9d9d1de09b718bf4ff1529d1bdffc9e4a3bf63d96cd5898bea2143adce7c48cd96263385f5ca4f788698fddc5e57bc3a5f300c3dbe1136b97d8820342ae0122610801122092428d561504e4331303c4e65aacae974d1498dbd2e657953bcf795911bc862621f5bdcf000000300145978dd46a4d9730d76a50da055a0a8101f5bdcf00000030016219737465616d69643a3835353638333932393333363534303035291b39aaf5cf5083b63240e8f791f07a8391477b04a83a45008d20debb9637390d2062be6a970d8700339c942eb7c80e75d3218ef26b094c76c1208bd4b576cebfb828c9de62c6a8f5ad0a"
)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNoteGNSPeerAssemblesMaterial 覆盖采集端「攒料」这一步：
// 两个方向都到齐后才下发，字段必须和抓包一一对应。
func TestNoteGNSPeerAssemblesMaterial(t *testing.T) {
	var got *uplink.Batch
	sender := uplink.NewLocal("t", func(b *uplink.Batch) error {
		if b.GNS != nil {
			got = b
		}
		return nil
	})
	defer sender.Close()

	s := &captureSession{sender: sender}

	req, err := handshake.ParseGNSHandshake(decodeHex(t, testReqHex))
	if err != nil {
		t.Fatal(err)
	}
	okp, err := handshake.ParseGNSHandshake(decodeHex(t, testOKHex))
	if err != nil {
		t.Fatal(err)
	}

	s.noteGNSPeer(req)
	if got != nil {
		t.Fatal("只有客户端材料时不应该下发")
	}
	s.noteGNSPeer(okp)
	if err := sender.Flush(true); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.GNS == nil {
		t.Fatal("两方向齐了却没有下发 GNS 材料")
	}
	if !got.GNS.Complete() {
		t.Fatalf("材料不完整: %+v", got.GNS)
	}

	dec := func(s string) []byte {
		b, _ := base64.StdEncoding.DecodeString(s)
		return b
	}
	checks := []struct {
		name string
		got  []byte
		want string
	}{
		{"ClientConnID", dec(got.GNS.ClientConnID), "a9d29fcc"},
		{"ServerConnID", dec(got.GNS.ServerConnID), "79dddd39"},
		{"ClientPub", dec(got.GNS.ClientPub), "85e6bd808ccf6bbf4727484eb36c96bdbda6349dbfd1448d21dd76801f2ff661"},
		{"ServerPub", dec(got.GNS.ServerPub), "cf8b80922c92833d39d9aaf3930b1385c4650224f54f8b9bddddb84e5de22979"},
		{"ClientNonce", dec(got.GNS.ClientNonce), "1c2cebceae1e24f8"},
		{"ServerNonce", dec(got.GNS.ServerNonce), "238df0e8c978b716"},
	}
	for _, c := range checks {
		if hex.EncodeToString(c.got) != c.want {
			t.Errorf("%s = %x, want %s", c.name, c.got, c.want)
		}
	}
	if len(dec(got.GNS.ClientCert)) != 97 || len(dec(got.GNS.ServerCert)) != 97 {
		t.Error("cert 长度应为 97")
	}
	if len(dec(got.GNS.ClientCrypt)) != 49 || len(dec(got.GNS.ServerCrypt)) != 49 {
		t.Error("crypt 长度应为 49")
	}
}

// TestNoteGNSPeerDropsStaleServer 换连接时必须把上一次的服务器材料作废，
// 否则会拿旧服务器公钥配新客户端私钥，派生出永远解不开的密钥。
func TestNoteGNSPeerDropsStaleServer(t *testing.T) {
	sender := uplink.NewLocal("t", func(*uplink.Batch) error { return nil })
	defer sender.Close()
	s := &captureSession{sender: sender}

	req, _ := handshake.ParseGNSHandshake(decodeHex(t, testReqHex))
	okp, _ := handshake.ParseGNSHandshake(decodeHex(t, testOKHex))
	s.noteGNSPeer(req)
	s.noteGNSPeer(okp)

	// 新连接：连接 ID 不同。
	next := *req
	next.ConnID = []byte{0x11, 0x22, 0x33, 0x44}
	s.noteGNSPeer(&next)

	s.gnsMu.Lock()
	defer s.gnsMu.Unlock()
	if s.gnsServer != nil {
		t.Error("客户端材料变了，服务器材料必须作废")
	}
}

// TestNoteGNSPeerRejectsMismatchedConnID 连接 ID 对不上的 ConnectOK 不能收。
func TestNoteGNSPeerRejectsMismatchedConnID(t *testing.T) {
	sender := uplink.NewLocal("t", func(*uplink.Batch) error { return nil })
	defer sender.Close()
	s := &captureSession{sender: sender}

	req, _ := handshake.ParseGNSHandshake(decodeHex(t, testReqHex))
	okp, _ := handshake.ParseGNSHandshake(decodeHex(t, testOKHex))
	s.noteGNSPeer(req)

	other := *okp
	other.EchoConnID = []byte{0xde, 0xad, 0xbe, 0xef}
	s.noteGNSPeer(&other)

	s.gnsMu.Lock()
	defer s.gnsMu.Unlock()
	if s.gnsServer != nil {
		t.Error("回显连接 ID 不匹配的 ConnectOK 不应被接受")
	}
}

// TestKeepGNSFrameKeepsNewest 钉住「缓冲区满了要留最新帧」。
//
// 这条不是性能优化，是正确性：内存里读到的 IV 是「读的那一刻」的当前 nonce，
// 判据帧越旧，nonce 修正量越大。原来满了就停止追加，缓冲区里留的是一局开头
// 那 24 帧 —— 真去读内存时已经过去几千个包，nonce 无论怎么修都对不上，
// 而现象只是「0 帧可解」，完全看不出错在这。
func TestKeepGNSFrameKeepsNewest(t *testing.T) {
	s := &captureSession{}
	s.gnsClientID = []byte{0x11, 0x22, 0x33, 0x44}
	s.gnsServerID = []byte{0x55, 0x66, 0x77, 0x88}

	mk := func(seq uint16, toConn []byte) []byte {
		f := make([]byte, 40)
		f[0] = 0x82
		copy(f[1:5], toConn)
		binary.LittleEndian.PutUint16(f[5:7], seq)
		return f
	}

	total := gnsMaxFrames + 10
	for i := 0; i < total; i++ {
		if !s.keepGNSFrame("s2c", mk(uint16(i), s.gnsClientID)) {
			t.Fatalf("第 %d 帧应该被收下", i)
		}
	}
	if len(s.gnsS2C) != gnsMaxFrames {
		t.Fatalf("缓冲长度 = %d，期望 %d", len(s.gnsS2C), gnsMaxFrames)
	}
	if seq, _ := cs2crypto.FrameSeq(s.gnsS2C[len(s.gnsS2C)-1]); seq != uint64(total-1) {
		t.Fatalf("最后一帧序号 = %d，期望 %d（缓冲必须留最新）", seq, total-1)
	}
	if seq, _ := cs2crypto.FrameSeq(s.gnsS2C[0]); seq != uint64(total-gnsMaxFrames) {
		t.Fatalf("第一帧序号 = %d，期望 %d（最旧的应被挤掉）", seq, total-gnsMaxFrames)
	}

	// 收方 connID 不对的帧一律不收（这是唯一硬闸门）。
	other := []byte{0xde, 0xad, 0xbe, 0xef}
	before := len(s.gnsS2C)
	if s.keepGNSFrame("s2c", mk(999, other)) {
		t.Fatal("收方 connID 不对的帧被收下了")
	}
	if len(s.gnsS2C) != before {
		t.Fatal("缓冲被不该收的帧改动了")
	}
}
