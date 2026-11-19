package transport

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, KindUDP, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	fr, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if fr.Kind != KindUDP || string(fr.Payload) != "hello" {
		t.Fatalf("got kind=%#x payload=%q", fr.Kind, fr.Payload)
	}
}

func TestFrameUnsupportedKind(t *testing.T) {
	if err := Write(&bytes.Buffer{}, 0x7F, []byte("x")); err != ErrUnsupportedFrame {
		t.Fatalf("want ErrUnsupportedFrame, got %v", err)
	}
	// 读侧：kind 不在白名单
	var raw bytes.Buffer
	binary.Write(&raw, binary.LittleEndian, uint32(2))
	raw.Write([]byte{0x7F, 'x'})
	if _, err := Read(&raw); err == nil {
		t.Fatal("expected ErrUnsupportedFrame on read")
	}
}

func TestFrameTooLarge(t *testing.T) {
	var raw bytes.Buffer
	binary.Write(&raw, binary.LittleEndian, uint32(MaxFrame+1))
	raw.Write(make([]byte, 8))
	if _, err := Read(&raw); err != ErrFrameTooLarge {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
	if err := Write(&bytes.Buffer{}, KindUDP, make([]byte, MaxFrame)); err != ErrFrameTooLarge {
		t.Fatalf("want ErrFrameTooLarge on write, got %v", err)
	}
}

func TestInvalidFrameZeroLen(t *testing.T) {
	var raw bytes.Buffer
	binary.Write(&raw, binary.LittleEndian, uint32(0))
	if _, err := Read(&raw); err != ErrInvalidFrame {
		t.Fatalf("want ErrInvalidFrame, got %v", err)
	}
}

// 构造一个 IPv4/UDP 包并验证四元组解析。
func TestParseIPv4UDP(t *testing.T) {
	pkt := make([]byte, 20+8+4)
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17 // UDP
	copy(pkt[12:16], []byte{192, 168, 1, 10})
	copy(pkt[16:20], []byte{10, 0, 0, 5})
	binary.BigEndian.PutUint16(pkt[20:22], 27015)
	binary.BigEndian.PutUint16(pkt[22:24], 8766)
	binary.BigEndian.PutUint16(pkt[24:26], 12)
	copy(pkt[28:], []byte{0xDE, 0xAD, 0xBE, 0xEF})

	u, err := ParseIPv4UDP(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if u.SrcIP != [4]byte{192, 168, 1, 10} || u.DstIP != [4]byte{10, 0, 0, 5} {
		t.Fatalf("bad IPs: %v -> %v", u.SrcIP, u.DstIP)
	}
	if u.SrcPort != 27015 || u.DstPort != 8766 {
		t.Fatalf("bad ports: %d -> %d", u.SrcPort, u.DstPort)
	}
	if !bytes.Equal(u.Data, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("bad payload: %x", u.Data)
	}
}

func TestParseIPv4UDPRejectsNonUDP(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = 6 // TCP
	if _, err := ParseIPv4UDP(pkt); err == nil {
		t.Fatal("expected rejection for non-UDP")
	}
}

func TestPackUDPRoundTrip(t *testing.T) {
	p := &UDPPacket{SrcPort: 1, DstPort: 2, Data: []byte("x")}
	b, err := PackUDP(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnpackUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.SrcPort != 1 || got.DstPort != 2 || string(got.Data) != "x" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}
