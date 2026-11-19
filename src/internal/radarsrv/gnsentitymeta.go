package radarsrv

import (
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
)

type entityMetadata struct {
	cmd  uint32
	body []byte
}

// The actual connection sends CreateStringTable BEFORE ServerInfo.
// Stage that signon prefix, then apply it to the newly reset decoder.
func (s *Session) noteEntityMetadataLocked(cmd uint32, body []byte) {
	if cmd == 44 {
		m := &msg.CSVCMsg_CreateStringTable{}
		if proto.Unmarshal(body, m) == nil && m.GetName() == "genericprecache" {
			// At the FIRST signon, ClassInfo may precede the first string table.
			// That queued prefix belongs to this connection and must survive.
			// A live decoder entering a new signon still clears prior staging.
			if s.entityDecoder != nil && !s.pendingEntitySignon {
				s.pendingEntityMetadata = nil
				s.pendingEntityBytes = 0
				s.pendingEntityFault = ""
			}
			s.pendingEntitySignon = true
			s.pixelView = nil
		}
	}
	if s.entityDecoder == nil || s.pendingEntitySignon {
		if len(body) > 16<<20 || s.pendingEntityBytes+len(body) > 32<<20 || len(s.pendingEntityMetadata) >= 256 {
			s.pendingEntityFault = "signon metadata staging limit"
			return
		}
		s.pendingEntityMetadata = append(s.pendingEntityMetadata, entityMetadata{cmd, append([]byte(nil), body...)})
		s.pendingEntityBytes += len(body)
		return
	}
	_ = s.entityDecoder.SignonMessage(cmd, body)
}
func (s *Session) applyPendingEntityMetadataLocked() {
	for _, m := range s.pendingEntityMetadata {
		_ = s.entityDecoder.SignonMessage(m.cmd, m.body)
	}
	if s.pendingEntityFault != "" {
		s.entityDecoder.InvalidateMetadata(s.pendingEntityFault)
	}
	s.pendingEntityMetadata = nil
	s.pendingEntityBytes = 0
	s.pendingEntityFault = ""
	s.pendingEntitySignon = false
}
