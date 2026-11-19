package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// TestSignatureMessageFormat 校验拼串格式与逆向得到的格式串一致：
// "radar-login-v1\n%x\n%s\n%s\n%s\n%t\n%d\n%d"
func TestSignatureMessageFormat(t *testing.T) {
	msg := SignatureMessage("  abcd  ", "S1", "S2", "S3", true, 11, 22)
	lines := strings.Split(string(msg), "\n")
	if len(lines) != 8 {
		t.Fatalf("应有 8 行，实际 %d：%q", len(lines), msg)
	}
	if lines[0] != "radar-login-v1" {
		t.Fatalf("首行应为 radar-login-v1，实际 %q", lines[0])
	}
	h := sha256.Sum256([]byte("ABCD")) // 大写 + 去空格
	if lines[1] != fmt.Sprintf("%x", h) {
		t.Fatalf("第二行应为 sha256(大写去空格卡密)：\n got %s\nwant %x", lines[1], h)
	}
	if lines[2] != "S1" || lines[3] != "S2" || lines[4] != "S3" {
		t.Fatalf("s1/s2/s3 位置不对：%q", lines[2:5])
	}
	if lines[5] != "true" {
		t.Fatalf("bool 应为 true，实际 %q", lines[5])
	}
	if lines[6] != "11" || lines[7] != "22" {
		t.Fatalf("两个 int64 位置不对：%q", lines[6:8])
	}
	// 与格式串逐字对齐
	want := fmt.Sprintf("radar-login-v1\n%x\n%s\n%s\n%s\n%t\n%d\n%d", h, "S1", "S2", "S3", true, 11, 22)
	if string(msg) != want {
		t.Fatalf("与还原出的格式串不一致\n got %q\nwant %q", msg, want)
	}
}

func TestStreamAndRoomMessages(t *testing.T) {
	ch := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if got := string(StreamMessage(ch, "a", "b")); got != "radar-stream-v2\ndeadbeef\na\nb" {
		t.Fatalf("StreamMessage 不符：%q", got)
	}
	if got := string(RoomPasswordMessage("pw", ch)); got != "radar-room-password-v1\npw\ndeadbeef" {
		t.Fatalf("RoomPasswordMessage 不符：%q", got)
	}
}

func TestRandomToken(t *testing.T) {
	a, err := RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RandomToken()
	if a == b {
		t.Fatal("两次 RandomToken 不应相同")
	}
	raw, err := base64.StdEncoding.DecodeString(a)
	if err != nil || len(raw) != 32 {
		t.Fatalf("token 必须是 base64 的 32 字节：err=%v len=%d", err, len(raw))
	}
}

// TestRecoveredDeviceKey 用逆向时从 device.bin 真实解出的密钥做交叉校验：
// seed(32) || pub(32) 的 base64 必须等于 device.bin 明文里的 key 字段，
// 且 seed 能推导出 pub。这把重构的 device 逻辑钉在了实际产物上。
func TestRecoveredDeviceKey(t *testing.T) {
	const seedHex = "85d09bc259bee0f2f90a4bd386975aacdf5a0a816944618da1d6cc3d4ee84c2e"
	const pubHex = "9b30e5a9e13b1a26385f3f9666ded23f74b96c0a0117b71a0ac7f615a5658de3"
	const wantB64 = "hdCbwlm+4PL5CkvThpdarN9aCoFpRGGNodbMPU7oTC6bMOWp4TsaJjhfP5Zm3tI/dLlsCgEXtxoKx/YVpWWN4w=="

	seed, _ := hex.DecodeString(seedHex)
	pub, _ := hex.DecodeString(pubHex)
	priv := ed25519.NewKeyFromSeed(seed)

	if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != pubHex {
		t.Fatalf("seed 推导出的公钥与 device.bin 记录不一致")
	}
	combined := append(append([]byte(nil), seed...), pub...)
	if got := base64.StdEncoding.EncodeToString(combined); got != wantB64 {
		t.Fatalf("seed||pub 的 base64 与 device.bin 的 key 字段不一致\n got %s\nwant %s", got, wantB64)
	}
	if err := VerifyKey(priv); err != nil {
		t.Fatalf("VerifyKey 失败：%v", err)
	}
	// 把 pub 段改成全零，seed→pub 就不再自洽，VerifyKey 必须报错
	bad := append(append([]byte(nil), seed...), make([]byte, 32)...)
	if err := VerifyKey(bad); err == nil {
		t.Fatal("seed 与 pub 不自洽时 VerifyKey 必须报错")
	}
}
