// GNS 直连握手报文解析（2026-10-19 按真实抓包 + Valve GameNetworkingSockets 源码定案）。
//
// 早期把 0x22 / 0x23 当成「netchan 的 ClientHello / ServerHello」，方向对了，
// 但只取了 32 字节临时公钥。实际上它们是 ESteamNetworkingUDPMsgID：
//
//	0x20 k_ESteamNetworkingUDPMsg_ChallengeRequest
//	0x21 k_ESteamNetworkingUDPMsg_ChallengeReply
//	0x22 k_ESteamNetworkingUDPMsg_ConnectRequest   ← 客户端 → 服务器
//	0x23 k_ESteamNetworkingUDPMsg_ConnectOK        ← 服务器 → 客户端
//	0x24 k_ESteamNetworkingUDPMsg_ConnectionClosed
//	0x25 k_ESteamNetworkingUDPMsg_NoConnection
//
// 首字节是消息 ID，后面是 protobuf 正文。密钥派生的 context 需要**四段原始字节**
// （双方 cert.cert 与 crypt.info），所以这里必须把原始子消息切片留下来，
// 不能只留公钥。
package handshake

import "errors"

// GNS 消息类型。
const (
	TypeGNSChallengeRequest = 0x20
	TypeGNSChallengeReply   = 0x21
	TypeGNSConnectRequest   = 0x22
	TypeGNSConnectOK        = 0x23
)

// GNSPeer 是一个方向的握手材料（字段全部是线上原始字节）。
type GNSPeer struct {
	Type   byte
	ConnID []byte // ConnectRequest f1（客户端自己的 ID）/ ConnectOK f5（服务器自己的 ID）
	// EchoConnID 只在 ConnectOK 里有值：field 1 是服务器回显的**客户端** ID。
	// 用它来确认这个 ConnectOK 是回应本次 ConnectRequest 的，防串连接。
	EchoConnID []byte
	Pub        []byte // crypt.info.key_data，32 字节临时 X25519 公钥
	Nonce      []byte // crypt.info.nonce，8 字节
	Cert       []byte // certSigned.cert（CMsgSteamDatagramCertificate 的原始序列化）
	Crypt      []byte // cryptSigned.info（CMsgSteamDatagramSessionCryptInfo 的原始序列化）
	Proto      uint64 // crypt.info.protocol_version
	Cipher     []uint64
}

// IsGNSType 判断首字节是不是 GNS 直连握手消息。
func IsGNSType(b byte) bool {
	return b == TypeGNSConnectRequest || b == TypeGNSConnectOK
}

// ErrNotGNS 表示载荷不是 GNS 握手报文。
var ErrNotGNS = errors.New("not a GNS handshake message")

// ParseGNSHandshake 解析 0x22 / 0x23，取出派生会话密钥所需的全部材料。
func ParseGNSHandshake(payload []byte) (*GNSPeer, error) {
	if len(payload) < 2 || !IsGNSType(payload[0]) {
		return nil, ErrNotGNS
	}
	t := payload[0]
	root, err := ParsePB(payload[1:])
	if err != nil && len(root) == 0 {
		return nil, ErrNotGNS
	}

	p := &GNSPeer{Type: t}

	// 连接 ID：ConnectRequest 是 field 1，ConnectOK 是 field 5。
	idField := 1
	if t == TypeGNSConnectOK {
		idField = 5
	}
	if e, ok := field(root, idField); ok && e.Wire == wireFixed32 && len(e.Raw) == 4 {
		p.ConnID = append([]byte(nil), e.Raw...)
	}
	// ConnectOK 的 field 1 回显客户端连接 ID，用来做配对。
	if t == TypeGNSConnectOK {
		if e, ok := field(root, 1); ok && e.Wire == wireFixed32 && len(e.Raw) == 4 {
			p.EchoConnID = append([]byte(nil), e.Raw...)
		}
	}

	// crypt signed → info（原始字节）→ key_data / nonce
	if e, ok := field(root, 7); ok && e.Wire == wireBytes {
		signed, err := ParsePB(e.Bytes)
		if err == nil || len(signed) > 0 {
			if info, ok := field(signed, 1); ok && info.Wire == wireBytes {
				p.Crypt = append([]byte(nil), info.Bytes...)
				cinfo, err := ParsePB(p.Crypt)
				if err == nil || len(cinfo) > 0 {
					if kd, ok := field(cinfo, 2); ok && kd.Wire == wireBytes && len(kd.Bytes) == 32 {
						p.Pub = append([]byte(nil), kd.Bytes...)
					}
					if nn, ok := field(cinfo, 3); ok && nn.Wire == wireFixed64 && len(nn.Raw) == 8 {
						p.Nonce = append([]byte(nil), nn.Raw...)
					}
					p.Proto = u64(cinfo, 4)
					for _, f := range cinfo {
						if f.Field == 5 && f.Wire == wireVarint {
							p.Cipher = append(p.Cipher, f.Varint)
						}
					}
				}
			}
		}
	}

	// cert signed → cert（原始字节）。ConnectRequest 是 field 4，ConnectOK 是 field 8。
	certField := 4
	if t == TypeGNSConnectOK {
		certField = 8
	}
	if e, ok := field(root, certField); ok && e.Wire == wireBytes {
		signed, err := ParsePB(e.Bytes)
		if err == nil || len(signed) > 0 {
			if c, ok := field(signed, 4); ok && c.Wire == wireBytes {
				p.Cert = append([]byte(nil), c.Bytes...)
			}
		}
	}

	if len(p.Pub) != 32 {
		return nil, errors.New("GNS 握手缺少临时公钥")
	}
	return p, nil
}
