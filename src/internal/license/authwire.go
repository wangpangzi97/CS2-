// Package license 还原启动器侧的卡密/授权链路：
//
//	authwire.SignatureMessage    @0x2c5ba0  "radar-login-v1\n%x\n%s\n%s\n%s\n%t\n%d\n%d"
//	authwire.StreamMessage       @0x2c5fc0  "radar-stream-v2\n%x\n%s\n%s"
//	authwire.RoomPasswordMessage @0x2c5da0  "radar-room-password-v1\n%s\n%x"
//	authwire.RandomToken         @0x2c5b40  base64(crypto/rand 32)
//	device.Load / protect / statePath / loginPath / readConfig / writeConfig
//	agent.signedLogin / LoginDetails / Check / post / serverURL
//
// 流程（report §4）：
//
//	POST /api/client/challenge        → 32 字节 challenge
//	SignatureMessage(...)             → 明文消息
//	ed25519.sign(设备私钥, 消息)       → base64 → 头 X-Radar-Signature
//	POST /api/client/login | /check   → 服务器同时判定卡密与设备绑定
package license

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// SignatureMessage 逐字还原 authwire.SignatureMessage：
//
//	k := strings.ToUpper(strings.TrimSpace(cardKey))
//	h := sha256.Sum256([]byte(k))
//	return []byte(fmt.Sprintf("radar-login-v1\n%x\n%s\n%s\n%s\n%t\n%d\n%d", h, s1, s2, s3, flag, i1, i2))
//
// 已知：第一个 %x 是卡密哈希（大写去空格后 sha256）。
// s1/s2/s3/bool/i1/i2 的语义未从二进制中确定（report §6）。
func SignatureMessage(cardKey, s1, s2, s3 string, flag bool, i1, i2 int64) []byte {
	k := strings.ToUpper(strings.TrimSpace(cardKey))
	h := sha256.Sum256([]byte(k))
	return []byte(fmt.Sprintf("radar-login-v1\n%x\n%s\n%s\n%s\n%t\n%d\n%d", h, s1, s2, s3, flag, i1, i2))
}

// StreamMessage 还原 authwire.StreamMessage。
func StreamMessage(challenge []byte, s1, s2 string) []byte {
	return []byte(fmt.Sprintf("radar-stream-v2\n%x\n%s\n%s", challenge, s1, s2))
}

// RoomPasswordMessage 还原 authwire.RoomPasswordMessage。
func RoomPasswordMessage(s1 string, challenge []byte) []byte {
	return []byte(fmt.Sprintf("radar-room-password-v1\n%s\n%x", s1, challenge))
}

// RandomToken 还原 authwire.RandomToken = base64(32 随机字节)。
func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// CardHash 返回卡密哈希（供 UI/日志用）。
func CardHash(cardKey string) string {
	k := strings.ToUpper(strings.TrimSpace(cardKey))
	h := sha256.Sum256([]byte(k))
	return fmt.Sprintf("%x", h)
}

// 请求头名（report §4.4）。
const (
	HeaderRequest   = "X-Radar-Request"
	HeaderSignature = "X-Radar-Signature"
	HeaderNonce     = "X-Radar-Nonce"
	HeaderStream    = "X-Radar-Stream"
	HeaderAuth      = "Authorization"
)

// 服务端接口。
const (
	PathChallenge = "/api/client/challenge"
	PathLogin     = "/api/client/login"
	PathCheck     = "/api/client/check"
	PathStream    = "/api/client/stream"
	PathUpdate    = "/client/latest.json"
)
