package handshake

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// 真实报文（2026-10-19 抓包，一条连接的一对握手）。
//
// 这是本项目第一次拿到「ClientHello 与 ServerHello 成对」的样本，
// 它同时暴露了旧实现的致命问题：**服务器的临时公钥从来没被解析过**。
//
// 注意两条报文的字段布局是对称的，但**公钥位置不同**：
//
//	ClientHello  f4→f4→f2 = 客户端静态身份密钥（90a7d793…，跨连接完全相同）
//	             f7→f1→f2 = 客户端临时公钥（每条连接都变）
//	ServerHello  f8→f4→f2 = 服务器静态身份密钥（1efd59fd…，内含服务器 steamid）
//	             f7→f1→f2 = 服务器临时公钥
//
// 只有 f7→f1→f2 那对是 ECDH 用的。拿静态密钥去算共享密钥一样解不出来，
// 而且因为两条报文都能"解析成功"，故障会非常隐蔽。
const (
	realClientHello = "220d3eed84c8116bb1012914f81f4119dcc3c1680100100122ae0122610801122090a7d793841f4b2e63d2530bbd0c58aae32821155cbc1cd5f634cace3c17701321dcc3c16801001001450b04d56a4d0ba7d76a50da055a0a8101dcc3c168010010016219737465616d69643a3736353631313939373137373934373830291b39aaf5cf5083b63240b7833838a91ab97065c63c81367ac67c480be716b786f7bf6fd59aeaec488fcaeaee7843c489c7e61dd0920e59b62493ef29420feb5c611bc586bf3e65faba092979010696ba02000030183a750a3108011220288e2c880f159da375e4cfbad6484be6ce5d11b67beff71b4120609040932c181984c46f563b939b15200d280212408a9116542233469fd0171803de12e8d7301c5e52c7e28f0a24a3c3f057d3f8f5f8bae27966cc93bbe729ed01b8becb8a65919250d1d38f2d4d27741c5395d401"

	realServerHello = "230d3eed84c81143bacc00000030011979010696ba02000020bf80042d9947d09d3a750a3108011220f985d87daa8d11405e27a0b56c78856dd356487727b8bed5cb960088afb6903719028d658319a7744c200d28021240d64220d294f766ec7534cd75bc478675d8a33ce3b9e08487b1ef26461165e31aad2ea54452308d6deebbf77cda95cd2b7af901530fd662ebc9fcb8976e66260b42ae012261080112201efd59fd942368faaa658578886d2e40c65bbbbb42e6e2c910f0df14de5986252143bacc0000003001459635d56a4d96d8d76a50da055a0a810143bacc00000030016219737465616d69643a3835353638333932393333343536343531291b39aaf5cf5083b632405fcc2a7eb5ad31d84e1fde48433e990078247b3a1a02ec176d1aff1e2663ce3f10b7c7fb2a4a9439b4165bcaae3a35d185bdab59b3f81fc60d188016f1db860c"

	// 期望值：两条报文各自的**临时**公钥。
	wantClientEphemeral = "288e2c880f159da375e4cfbad6484be6ce5d11b67beff71b4120609040932c18"
	wantServerEphemeral = "f985d87daa8d11405e27a0b56c78856dd356487727b8bed5cb960088afb69037"

	// 反例：静态身份密钥。三条不同连接里它们完全不变。
	clientStaticKey = "90a7d793841f4b2e63d2530bbd0c58aae32821155cbc1cd5f634cace3c177013"
	serverStaticKey = "1efd59fd942368faaa658578886d2e40c65bbbbb42e6e2c910f0df14de598625"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// TestParseHelloRealClientHello 钉住 ClientHello 取到的是临时公钥。
func TestParseHelloRealClientHello(t *testing.T) {
	raw := mustHex(t, realClientHello)
	info, err := ParseHello(raw)
	if err != nil {
		t.Fatalf("ParseHello: %v", err)
	}
	if got := hex.EncodeToString(info.PublicKey); got != wantClientEphemeral {
		t.Fatalf("ClientHello 临时公钥错\n got %s\nwant %s", got, wantClientEphemeral)
	}
	if info.ProtoOff != 1 {
		t.Errorf("ProtoOff = %d，期望 1（跳过 netchan 类型字节）", info.ProtoOff)
	}
}

// TestParseHelloRealServerHello 是本轮修复的核心：
//
// 旧实现只认首字节 0x22，而 ServerHello 是 0x23 —— 服务器的临时公钥
// 从来没被取出来过，共享密钥只能拿客户端公钥当对端，必然算错。
func TestParseHelloRealServerHello(t *testing.T) {
	raw := mustHex(t, realServerHello)
	if raw[0] != TypeServerHello {
		t.Fatalf("样本首字节 = %#x，期望 %#x", raw[0], TypeServerHello)
	}
	info, err := ParseHello(raw)
	if err != nil {
		t.Fatalf("ParseHello(ServerHello): %v", err)
	}
	if got := hex.EncodeToString(info.PublicKey); got != wantServerEphemeral {
		t.Fatalf("ServerHello 临时公钥错\n got %s\nwant %s", got, wantServerEphemeral)
	}
}

// TestParseHelloRejectsStaticKeys 防止退化成"取静态密钥"。
//
// 静态密钥也能解析成功、长度也对，但它是长期身份密钥：
// 拿它做 ECDH 一样解不出来，而且日志上完全看不出异常。
func TestParseHelloRejectsStaticKeys(t *testing.T) {
	for name, raw := range map[string][]byte{
		"ClientHello": mustHex(t, realClientHello),
		"ServerHello": mustHex(t, realServerHello),
	} {
		info, err := ParseHello(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := hex.EncodeToString(info.PublicKey)
		if got == clientStaticKey || got == serverStaticKey {
			t.Fatalf("%s 取到了静态身份密钥 %s —— 必须取 f7→f1→f2 的临时公钥", name, got)
		}
	}
}

// TestParseHelloClientAndServerDiffer 两端公钥必须不同（同一条连接）。
func TestParseHelloClientAndServerDiffer(t *testing.T) {
	ch, err := ParseHello(mustHex(t, realClientHello))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := ParseHello(mustHex(t, realServerHello))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ch.PublicKey, sh.PublicKey) {
		t.Fatal("ClientHello 与 ServerHello 取到了同一把公钥 —— 说明有一端解析错了")
	}
}

// TestParseHandshakeBlindToServerHello 记录旧解析器为什么不能用。
func TestParseHandshakeBlindToServerHello(t *testing.T) {
	if _, err := ParseHandshake(mustHex(t, realServerHello)); err == nil {
		t.Fatal("ParseHandshake 竟然解析了 ServerHello —— 它的文档说只认 0x22，" +
			"如果这条失败说明实现变了，请同步更新本注释")
	}
}

// TestParseHelloRejectsGarbage 加密后的数据不能误判成握手。
func TestParseHelloRejectsGarbage(t *testing.T) {
	garbage := bytes.Repeat([]byte{0x82}, 64) // 真实密文首字节是 0x82
	if _, err := ParseHello(garbage); err == nil {
		t.Fatal("随机字节被解析成了握手")
	}
	if _, err := ParseHello(nil); err == nil {
		t.Fatal("空载荷不该成功")
	}
}
