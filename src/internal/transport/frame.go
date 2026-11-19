// Package transport 还原采集器 → 启动器之间的匿名管道帧协议与事件流。
//
// 对应符号（capture.exe）：
//
//	transport.Read  @?  长度前缀帧；错误 "unsupported capture frame" / "capture frame too large" / "invalid frame"
//	transport.Write @?  同上
//	transport.PackUDP   原始 UDP 包打包
//	main.event          事件对象；编码走 encoding/json/v2 的 (*Encoder).Encode，即 NDJSON
//
// 事件名（report §3.6）：key_ready / pub_check / key_error / capture_ready /
// capture_stats / game_ready / capture_error
//
// 说明：长度前缀（4 字节小端）与三个错误文案是逆向实证；
// 帧内 kind 的具体取值未从二进制中还原，本重构自定义了 kind 常量，
// 属于"形状一致、取值自定"，已在报告 §6 标注。
package transport

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// 帧类型（自定，见包注释）。
const (
	KindUDP   byte = 0x01 // 原始 UDP 包
	KindKey   byte = 0x02 // 密钥/公钥
	KindEvent byte = 0x03 // NDJSON 事件
)

// MaxFrame 对应 "capture frame too large"。
const MaxFrame = 1 << 20

var (
	ErrUnsupportedFrame = errors.New("unsupported capture frame")
	ErrFrameTooLarge    = errors.New("capture frame too large")
	ErrInvalidFrame     = errors.New("invalid frame")
)

// Frame 是一帧。
type Frame struct {
	Kind    byte
	Payload []byte
}

// Write 写一帧：[uint32 LE 长度][kind][payload]。
func Write(w io.Writer, kind byte, payload []byte) error {
	if kind != KindUDP && kind != KindKey && kind != KindEvent {
		return ErrUnsupportedFrame
	}
	if len(payload)+1 > MaxFrame {
		return ErrFrameTooLarge
	}
	hdr := make([]byte, 5)
	binary.LittleEndian.PutUint32(hdr[:4], uint32(len(payload)+1))
	hdr[4] = kind
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// Read 读一帧。
func Read(r io.Reader) (*Frame, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 {
		return nil, ErrInvalidFrame
	}
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	kind := buf[0]
	switch kind {
	case KindUDP, KindKey, KindEvent:
	default:
		return nil, fmt.Errorf("%w: kind=%#x", ErrUnsupportedFrame, kind)
	}
	return &Frame{Kind: kind, Payload: buf[1:]}, nil
}

// Event 是一个 NDJSON 事件。
type Event struct {
	Name string         `json:"event"`
	Data map[string]any `json:"data,omitempty"`
}

// EncodeEvent 对应 main.event：一行一条 JSON。
func EncodeEvent(w io.Writer, name string, data map[string]any) error {
	b, err := json.Marshal(Event{Name: name, Data: data})
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return Write(w, KindEvent, b)
}

// PackUDP 把一个 UDP 包封装成传输载荷（源/目的/数据）。
type UDPPacket struct {
	SrcIP   [4]byte `json:"src"`
	DstIP   [4]byte `json:"dst"`
	SrcPort uint16  `json:"sport"`
	DstPort uint16  `json:"dport"`
	Data    []byte  `json:"data"`
}

// PackUDP 序列化为 JSON 载荷（与原程序同样走 encoding/json）。
func PackUDP(p *UDPPacket) ([]byte, error) { return json.Marshal(p) }

// UnpackUDP 反序列化。
func UnpackUDP(b []byte) (*UDPPacket, error) {
	var p UDPPacket
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseIPv4UDP 从原始 IP 包中提取 UDP 四元组（对应采集器里的手写解析）。
func ParseIPv4UDP(pkt []byte) (*UDPPacket, error) {
	if len(pkt) < 20 {
		return nil, ErrInvalidFrame
	}
	if pkt[0]>>4 != 4 {
		return nil, fmt.Errorf("not IPv4 (version %d)", pkt[0]>>4)
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return nil, ErrInvalidFrame
	}
	if pkt[9] != 17 { // IPPROTO_UDP
		return nil, fmt.Errorf("not UDP (proto %d)", pkt[9])
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl+8 || total > len(pkt) {
		return nil, ErrInvalidFrame
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return nil, ErrInvalidFrame
	}
	u := pkt[ihl:total]
	length := int(binary.BigEndian.Uint16(u[4:6]))
	if length < 8 || length > len(u) {
		return nil, ErrInvalidFrame
	}
	u = u[:length]
	p := &UDPPacket{}
	copy(p.SrcIP[:], pkt[12:16])
	copy(p.DstIP[:], pkt[16:20])
	p.SrcPort = binary.BigEndian.Uint16(u[0:2])
	p.DstPort = binary.BigEndian.Uint16(u[2:4])
	p.Data = append([]byte(nil), u[8:]...)
	return p, nil
}
