package radarsrv

import (
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
)

func gnsOuterTickForTrace(m []byte) (uint32, bool) {
	if len(m) < 3 || (m[0] != 2 && m[0] != 4) {
		return 0, false
	}
	_, n, ok := readGNSVarint(m[1:])
	if !ok || n == 0 || 1+n >= len(m) {
		return 0, false
	}
	tick, _, ok := readGNSVarint(m[1+n:])
	return tick, ok && tick > 0
}
func (sess *Session) traceGNSOuter(m []byte, flags, reason uint8) {
	if sess.entityDecoder == nil {
		return
	}
	if tick, ok := gnsOuterTickForTrace(m); ok {
		sess.entityDecoder.RecordIngressTick(tick, 1, flags, reason)
	}
}
func (sess *Session) traceGNSDecodedChain(d *gnsUnrelDecoded) {
	if sess.entityDecoder == nil || d == nil {
		return
	}
	var net uint32
	for _, m := range d.Msgs {
		switch m.Cmd {
		case 4:
			v := &msg.CNETMsg_Tick{}
			if proto.Unmarshal(m.Body, v) == nil {
				net = v.GetTick()
				if net > 0 {
					sess.entityDecoder.RecordIngressTick(net, 2, 16, 0)
				}
			}
		case 55:
			v := &msg.CSVCMsg_PacketEntities{}
			if proto.Unmarshal(m.Body, v) != nil {
				continue
			}
			if net > 0 {
				flags := uint8(4 | 16)
				if v.GetServerTick() == 0 {
					flags |= 32
				}
				sess.entityDecoder.RecordIngressTick(net, 2, flags, 0)
			}
			sess.entityDecoder.RecordEntityContext(v.GetServerTick(), d.Tick, net)
		}
	}
}
