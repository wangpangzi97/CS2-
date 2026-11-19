// gnsverify —— 用项目自身的 KDF 实现解真实 repro 里的 s2c 帧，确认修复生效。
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"local/cs2-radar/internal/cs2crypto"
)

type repro struct {
	ConnRaw         string   `json:"conn_raw"`
	ClientConnID    string   `json:"client_conn_id"`
	ServerConnID    string   `json:"server_conn_id"`
	ClientPub       string   `json:"client_pub"`
	ServerPub       string   `json:"server_pub"`
	ClientNonce     string   `json:"client_nonce"`
	ServerNonce     string   `json:"server_nonce"`
	ClientPriv      string   `json:"client_priv"`
	WireClientCert  string   `json:"wire_client_cert"`
	WireServerCert  string   `json:"wire_server_cert"`
	WireClientCrypt string   `json:"wire_client_crypt"`
	WireServerCrypt string   `json:"wire_server_crypt"`
	FramesS2C       []string `json:"frames_s2c"`
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var r repro
	if err := json.Unmarshal(raw, &r); err != nil {
		panic(err)
	}

	h := &cs2crypto.GNSHandshake{
		ClientConnID: mustHex(r.ClientConnID),
		ServerConnID: mustHex(r.ServerConnID),
		ClientPub:    mustHex(r.ClientPub),
		ServerPub:    mustHex(r.ServerPub),
		ClientNonce:  mustHex(r.ClientNonce),
		ServerNonce:  mustHex(r.ServerNonce),
		ClientCert:   mustHex(r.WireClientCert),
		ServerCert:   mustHex(r.WireServerCert),
		ClientCrypt:  mustHex(r.WireClientCrypt),
		ServerCrypt:  mustHex(r.WireServerCrypt),
	}

	priv := mustHex(r.ClientPriv)
	pms, names, err := cs2crypto.GNSPremasters(priv, h)
	if err != nil {
		panic(err)
	}

	conn := mustHex(r.ConnRaw)
	memSendIV := conn[0x19f0:0x19fc]
	memRecvIV := conn[0x19fc:0x1a08]

	for i, pm := range pms {
		keys := cs2crypto.GNSDeriveFromPremaster(pm, h, cs2crypto.GNSVariant{Label: "Steam datagram"})
		fmt.Printf("[%s] SendIV=%x (mem %x, 相等=%v)\n", names[i], keys.SendIV, memSendIV,
			hex.EncodeToString(keys.SendIV) == hex.EncodeToString(memSendIV))
		fmt.Printf("[%s] RecvIV=%x (mem %x, 相等=%v)\n", names[i], keys.RecvIV, memRecvIV,
			hex.EncodeToString(keys.RecvIV) == hex.EncodeToString(memRecvIV))

		ok := 0
		for _, fh := range r.FramesS2C {
			pkt := mustHex(fh)
			if pt, err := cs2crypto.GNSOpen(keys.RecvKey, keys.RecvIV, pkt); err == nil {
				ok++
				if ok == 1 {
					fmt.Printf("  首帧明文(%d 字节): %x\n", len(pt), pt[:min(48, len(pt))])
				}
			}
		}
		fmt.Printf("[%s] s2c 解帧 %d/%d\n\n", names[i], ok, len(r.FramesS2C))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
