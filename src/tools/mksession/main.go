// Command mksession 生成一个**合成会话**：一条 JSONL，第一行给出"握手公钥 + 客户端私钥"，
// 后续每行是一个用某个已知方案加密过的 UDP 载荷。
//
// 用途：在没有真实 CS2、没有 Npcap 的情况下，验证「采集器重放上行 → 服务器自动搜索
// 加解密方案 → 解出玩家坐标」整条链路。合成会话用的是真实 X25519 + 真实 AES-GCM，
// 只是"服务端"是本地生成的。
//
// 用法：
//
//	mksession -out session.jsonl -frames 60 -offset 2 \
//	          -kdf hkdf-sha256/info-empty -cipher aes-256-gcm -nonce ctr-le-u64
//
// 然后：
//
//	capture.exe -replay session.jsonl -uplink http://127.0.0.1:8080/api/v1/ingest -session demo
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"time"

	"local/cs2-radar/internal/cs2crypto"
)

var (
	flagOut    = flag.String("out", "session.jsonl", "输出文件")
	flagFrames = flag.Int("frames", 60, "帧数")
	flagOffset = flag.Int("offset", 2, "密文前的头部字节数（模拟真实载荷头）")
	flagKDF    = flag.String("kdf", "hkdf-sha256/info-empty", "真实方案：KDF 名")
	flagCipher = flag.String("cipher", "aes-256-gcm", "真实方案：AEAD 名")
	flagNonce  = flag.String("nonce", "ctr-le-u64", "真实方案：nonce 名")
	flagSalt   = flag.Bool("salt-pub", false, "KDF 是否用服务端公钥当 salt")
	flagPlayer = flag.Int("players", 3, "合成几个玩家")
)

func main() {
	flag.Parse()

	kdfs, ciphers, nonces := cs2crypto.Available()
	fmt.Printf("候选空间：KDF %d 种、AEAD %d 种、nonce %d 种\n", len(kdfs), len(ciphers), len(nonces))

	curve := ecdh.X25519()
	sPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	cPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	serverPub := sPriv.PublicKey().Bytes()
	clientPriv := cPriv.Bytes()

	shared, err := cs2crypto.SharedSecret(clientPriv, serverPub)
	if err != nil {
		panic(err)
	}
	sch, err := cs2crypto.SchemeByName(*flagKDF, *flagCipher, *flagNonce, *flagOffset, *flagSalt, shared, serverPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "方案名无效: %v\n", err)
		fmt.Fprintf(os.Stderr, "KDF: %v\nAEAD: %v\nnonce: %v\n", kdfs, ciphers, nonces)
		os.Exit(2)
	}
	fmt.Printf("合成会话使用的真实方案：%s\n", sch.Name())

	prefix := make([]byte, *flagOffset)
	if _, err := rand.Read(prefix); err != nil {
		panic(err)
	}

	f, err := os.Create(*flagOut)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)

	// 第一行：握手公钥 + 客户端私钥（采集器会把它带在每次上行里）
	_ = enc.Encode(map[string]any{
		"server_pub": base64.StdEncoding.EncodeToString(serverPub),
		"key":        base64.StdEncoding.EncodeToString(clientPriv),
	})

	// 记录真实坐标，供比对
	truth := make([][]float64, *flagPlayer)

	now := time.Now().UnixMilli()
	for i := 0; i < *flagFrames; i++ {
		stream := buildStream(i, *flagPlayer, truth)
		frame, err := sch.SealFrame(i, prefix, stream)
		if err != nil {
			panic(err)
		}
		_ = enc.Encode(map[string]any{
			"dir":   "s2c",
			"src":   "162.254.193.6:27015",
			"dst":   "192.168.1.10:50000",
			"ts_ms": now + int64(i*16),
			"data":  base64.StdEncoding.EncodeToString(frame),
		})
	}

	fmt.Printf("已写出 %s：%d 帧（密文偏移 %d，头部 %x）\n", *flagOut, *flagFrames, *flagOffset, prefix)
	for p := range truth {
		fmt.Printf("  玩家#%d 末帧真实坐标 x=%.2f y=%.2f z=%.2f\n", p, truth[p][0], truth[p][1], truth[p][2])
	}
}

// buildStream 构造一条 netmessage 流：每个玩家一条消息，载荷里含 float32 三元组。
//
// 运动速度按真实量级给：CS2 玩家约 250 单位/秒，62.5 Hz 下约 4 单位/帧。
func buildStream(tick, players int, truth [][]float64) []byte {
	var out []byte
	for p := 0; p < players; p++ {
		ang := float64(tick)*0.004 + float64(p)*2.1
		x := float32(1200*math.Cos(ang) + float64(p)*37)
		y := float32(900*math.Sin(ang*0.8) + float64(p)*53)
		z := float32(64 + p*8)

		payload := make([]byte, 0, 32)
		payload = append(payload, 0x0A, 12) // field1, length-delimited, 12 bytes
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(x))
		payload = append(payload, b[:]...)
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(y))
		payload = append(payload, b[:]...)
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(z))
		payload = append(payload, b[:]...)

		out = append(out, uvarint(uint64(5+p))...)          // cmd
		out = append(out, uvarint(uint64(len(payload)))...) // size
		out = append(out, payload...)

		truth[p] = []float64{float64(x), float64(y), float64(z)}
	}
	return out
}

func uvarint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
