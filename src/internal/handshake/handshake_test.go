package handshake

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// build 构造 root.f4 → f4 → f2 = 32 字节 的合成握手。
func buildMainPath(pub []byte) []byte {
	inner := append([]byte{0x12, byte(len(pub))}, pub...)   // field2, wire2
	mid := append([]byte{0x22, byte(len(inner))}, inner...) // field4, wire2
	root := append([]byte{0x22, byte(len(mid))}, mid...)    // field4, wire2
	return root
}

// buildAltPath 构造 root.f7 → f1 → f2 = 32 字节 的合成握手（备用路径）。
// 前面保留一个不含 f4 的 field4，使首字节为 0x22（满足"首字节必须 0x22"），
// 同时让主路径 root.f4→f4→f2 落空，从而真正走到 f7 分支。
func buildAltPath(pub []byte) []byte {
	inner := append([]byte{0x12, byte(len(pub))}, pub...)   // field2
	mid := append([]byte{0x0A, byte(len(inner))}, inner...) // field1
	f7 := append([]byte{0x3A, byte(len(mid))}, mid...)      // field7
	f4 := []byte{0x22, 0x02, 0x08, 0x01}                    // field4 { field1: varint 1 }
	return append(f4, f7...)
}

func TestParsePBMainPath(t *testing.T) {
	pub, _ := hex.DecodeString("9b30e5a9e13b1a26385f3f9666ded23f74b96c0a0117b71a0ac7f615a5658de3")
	payload := buildMainPath(pub)
	info, err := ParseHandshake(payload)
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if !bytes.Equal(info.PublicKey, pub) {
		t.Fatalf("pubkey mismatch: got %x", info.PublicKey)
	}
	if payload[info.ProtoOff] != 0x22 {
		t.Fatalf("proto offset %d does not point at 0x22", info.ProtoOff)
	}
}

func TestParsePBAltPath(t *testing.T) {
	pub := bytes.Repeat([]byte{0xAB}, 32)
	payload := buildAltPath(pub)
	info, err := ParseHandshake(payload)
	if err != nil {
		t.Fatalf("ParseHandshake(alt): %v", err)
	}
	if !bytes.Equal(info.PublicKey, pub) {
		t.Fatalf("pubkey mismatch: got %x", info.PublicKey)
	}
}

func TestParsePBWithLeadingHeader(t *testing.T) {
	pub := bytes.Repeat([]byte{0x5A}, 32)
	// 前面塞 4 字节"包头"，模拟真实 UDP 载荷里 protobuf 不从 0 开始
	payload := append([]byte{0x00, 0x01, 0x02, 0x03}, buildMainPath(pub)...)
	info, err := ParseHandshake(payload)
	if err != nil {
		t.Fatalf("ParseHandshake(header): %v", err)
	}
	if info.ProtoOff != 4 {
		t.Fatalf("expected proto offset 4, got %d", info.ProtoOff)
	}
	if !bytes.Equal(info.PublicKey, pub) {
		t.Fatalf("pubkey mismatch")
	}
}

func TestParsePBRejectsBadFieldNumber(t *testing.T) {
	// field 0 非法
	if _, err := ParsePB([]byte{0x02, 0x00}); err == nil {
		t.Fatal("expected error for field number 0")
	}
	// field 数 > 2000 非法：tag = (2001<<3)|2
	tag := uint64(2001<<3 | 2)
	if _, err := ParsePB([]byte{byte(tag), 0x00}); err == nil {
		t.Fatal("expected error for field number > 2000")
	}
}

func TestParseHandshakeNoPubkey(t *testing.T) {
	if _, err := ParseHandshake([]byte{0x22, 0x02, 0x08, 0x01}); err == nil {
		t.Fatal("expected failure when no 32-byte pubkey present")
	}
}
