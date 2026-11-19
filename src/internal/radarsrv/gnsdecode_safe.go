package radarsrv

import (
	"encoding/binary"
	"errors"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/cs2snp"
	"local/cs2-radar/internal/entitycodec"
	"strings"
	"time"
)

const gnsDecodedLimit = 16 << 20

// A bounded LZ4 block decoder. No allocation is based on an unchecked wire size.
func gnsLZ4Block(src []byte, want int) ([]byte, error) {
	if want < 0 || want > gnsDecodedLimit {
		return nil, errors.New("lz4 output limit")
	}
	out := make([]byte, 0, want)
	i := 0
	length := func(v int) (int, error) {
		if v == 15 {
			for {
				if i >= len(src) {
					return 0, errors.New("lz4 extension truncated")
				}
				x := int(src[i])
				i++
				if v > want-x {
					return 0, errors.New("lz4 length limit")
				}
				v += x
				if x != 255 {
					break
				}
			}
		}
		return v, nil
	}
	for i < len(src) {
		tok := src[i]
		i++
		n, e := length(int(tok >> 4))
		if e != nil {
			return nil, e
		}
		if n > len(src)-i || n > want-len(out) {
			return nil, errors.New("lz4 literal bounds")
		}
		out = append(out, src[i:i+n]...)
		i += n
		if i == len(src) {
			break
		}
		if len(src)-i < 2 {
			return nil, errors.New("lz4 offset truncated")
		}
		off := int(binary.LittleEndian.Uint16(src[i:]))
		i += 2
		n, e = length(int(tok & 15))
		if e != nil {
			return nil, e
		}
		n += 4
		if off == 0 || off > len(out) || n > want-len(out) {
			return nil, errors.New("lz4 match bounds")
		}
		for j := 0; j < n; j++ {
			out = append(out, out[len(out)-off])
		}
	}
	if len(out) != want {
		return nil, errors.New("lz4 size mismatch")
	}
	return out, nil
}
func gnsReliablePayload(m []byte) ([]byte, uint32, error) {
	if len(m) < 2 || (m[0] != 1 && m[0] != 3) {
		return nil, 0, ErrGNSNotNetMsg
	}
	tick, n, ok := readGNSVarint(m[1:])
	if !ok {
		return nil, 0, errors.New("reliable header truncated")
	}
	data := m[1+n:]
	if m[0] == 3 {
		want, k, ok := readGNSVarint(data)
		if !ok || want > gnsDecodedLimit {
			return nil, 0, errors.New("compressed size invalid")
		}
		b, e := gnsLZ4Block(data[k:], int(want))
		return b, tick, e
	}
	if len(data) > gnsDecodedLimit {
		return nil, 0, errors.New("reliable payload limit")
	}
	return data, tick, nil
}

// Strict top-level protobuf walk: no partial fields or overflowing varints accepted.
func gnsWalkPB(b []byte, fn func(int, int, uint64, []byte)) error {
	for i := 0; i < len(b); {
		tag, k := binary.Uvarint(b[i:])
		if k <= 0 || tag>>3 == 0 || tag>>3 >= 1<<29 {
			return errors.New("protobuf tag")
		}
		i += k
		f, w := int(tag>>3), int(tag&7)
		var v uint64
		var data []byte
		switch w {
		case 0:
			v, k = binary.Uvarint(b[i:])
			if k <= 0 {
				return errors.New("protobuf varint")
			}
			i += k
		case 1, 5:
			n := 8
			if w == 5 {
				n = 4
			}
			if n > len(b)-i {
				return errors.New("protobuf fixed")
			}
			data = b[i : i+n]
			i += n
		case 2:
			v, k = binary.Uvarint(b[i:])
			if k <= 0 {
				return errors.New("protobuf length")
			}
			i += k
			if v > uint64(len(b)-i) {
				return errors.New("protobuf truncated")
			}
			data = b[i : i+int(v)]
			i += int(v)
		default:
			return errors.New("protobuf wire type")
		}
		if fn != nil {
			fn(f, w, v, data)
		}
	}
	return nil
}

// A zero-change delta may omit optional entity_data entirely. It still names
// an exact state at ServerTick, which a subsequent delta can acknowledge.
// Accept only an explicit, ordered delta envelope here; the entity decoder
// still requires the matching profile, initial full frame and exact checkpoint.
func gnsEmptyEntityDelta(body []byte) bool {
	if len(body) == 0 || len(body) > gnsDecodedLimit {
		return false
	}
	m := &msg.CSVCMsg_PacketEntities{}
	if proto.Unmarshal(body, m) != nil {
		return false
	}
	return m.GetLegacyIsDelta() && m.GetDeltaFrom() > 0 &&
		m.GetServerTick() > uint32(m.GetDeltaFrom()) &&
		m.GetUpdatedEntries() == 0 && len(m.GetEntityData()) == 0 &&
		m.GetMaxEntries() >= 0 && m.GetMaxEntries() <= 16384
}

func gnsUnrelCandidateScore(msgs []gnsUnrelMsg) (int, bool) {
	score := 0
	for _, m := range msgs {
		tick, ents := false, false
		if gnsWalkPB(m.Body, func(f, w int, v uint64, d []byte) {
			if m.Cmd == 4 && f == 1 && w == 0 {
				tick = true
			}
			if m.Cmd == 55 && f == 7 && w == 2 {
				ents = true
			}
		}) != nil {
			return 0, false
		}
		if m.Cmd == 0 && len(m.Body) != 0 {
			return 0, false
		}
		switch m.Cmd {
		case 4:
			if !tick {
				return 0, false
			}
			score += 10
		case 55:
			if !ents && !gnsEmptyEntityDelta(m.Body) {
				return 0, false
			}
			score += 20
		case 452:
			score += 1
		}
	}
	return score, score > 0
}

// Map identity comes from ServerInfo, never from a sound-coordinate bounding box.
func (sess *Session) noteGNSServerInfoLocked(body []byte) {
	name := ""
	if gnsWalkPB(body, func(f, w int, _ uint64, d []byte) {
		if f == 15 && w == 2 {
			name = string(d)
		}
	}) != nil {
		return
	}
	name = strings.TrimSpace(name)
	if len(name) == 0 || len(name) > 128 || strings.ContainsAny(name, "<>\"'\\\x00\r\n") {
		return
	}
	// A fresh ServerInfo denotes a signon generation, including reconnect to the same map.
	sess.serverMapName = name
	sess.pixelView = nil
	sess.entityDecoder = entitycodec.NewWithTTL(sess.entityTTL)
	_ = sess.entityDecoder.ServerInfo(body)
	sess.applyPendingEntityMetadataLocked()
	sess.gnsSchemaMessages = 0
	sess.gnsFullEntityMessages = 0
	sess.mapInferred = ""
	sess.mapInferIn = 0
	sess.mapInferTot = 0
	sess.mapLogged = false
	sess.gnsPos = nil
	sess.gnsPosSeenAt = nil
	sess.gnsPosEnts = nil
	sess.gnsPosTail = nil
	sess.gnsPlayers = nil
	gnsLogf("[map] ServerInfo map_name=%s；新 signon 清空旧声音/名单，实体仍待 schema/delta 解码", name)
}
func gnsInvalidMap() (string, string) { return "invalid", "未知地图名；请从地图清单选择" }

// Called with cycleMu and mu held. Preserve only explicit manual map selection.
func (sess *Session) resetGNSGenerationLocked() {
	sess.pixelView = nil
	sess.gnsSchemaMessages = 0
	sess.gnsFullEntityMessages = 0
	sess.entityDecoder = nil
	sess.entityLogAt = time.Time{}
	sess.entityLogStage = 0
	sess.pendingEntityMetadata = nil
	sess.pendingEntityBytes = 0
	sess.pendingEntityFault = ""
	sess.pendingEntitySignon = false
	sess.signonDump = nil
	sess.signonDone = false
	sess.plainBin = nil
	sess.plainBinTotal = 0
	sess.plainBuf = nil
	sess.plainDone = false
	sess.unrelDump = nil
	sess.unrelCount = 0
	sess.unrelHead = nil
	sess.unrelSaved = false
	sess.gnsStreamSkips = 0
	sess.gnsStreamSkipBytes = 0
	sess.gnsPosSeen = 0
	sess.gnsPosMsgs = 0
	sess.gnsPosTotal = 0
	sess.gnsPosFirst = time.Time{}

	sess.gns = nil
	sess.schemeS2C = nil
	sess.schemeC2S = nil
	sess.c2s = nil
	sess.s2c = nil
	sess.c2sDropped = 0
	sess.s2cDropped = 0
	sess.stS2C = dirStats{}
	sess.stC2S = dirStats{}
	sess.snpS2C = cs2snp.NewParser()
	sess.snpC2S = cs2snp.NewParser()
	sess.relStreamS2C = cs2snp.NewStream()
	sess.relStreamC2S = cs2snp.NewStream()
	sess.msgSplitS2C = cs2snp.NewMsgSplit()
	sess.msgSplitC2S = cs2snp.NewMsgSplit()
	sess.unrelS2C = nil
	sess.gnsUnrel = gnsUnrelStats{}
	sess.serverMapName = ""
	sess.mapInferred = ""
	sess.mapInferIn = 0
	sess.mapInferTot = 0
	sess.mapLogged = false
	sess.gnsPos = nil
	sess.gnsPosSeenAt = nil
	sess.gnsPosEnts = nil
	sess.gnsPosTail = nil
	sess.gnsPlayers = nil
	sess.gnsSendIV = nil
	sess.gnsRecvIV = nil
	sess.lastGNS = time.Time{}
	sess.gnsDiagDone = false
	sess.netchan = nil
	sess.netchanParsed = 0
	sess.netchanProbed = false
	sess.netchanWarned = false
	sess.netchanDump = false
	sess.msgFramed = nil
	sess.msgCount = 0
	sess.msgDumpAt = 0
	sess.msgHeads = nil
	sess.msgHeadLog = false
}
