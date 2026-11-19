package radarsrv

import (
	"local/cs2-radar/internal/restrictedreplay"
	"time"
)

// Called only from SecureHandler after PoP, live entitlement, body admission and
// Alive checks. Neither legacy Get/Ingest nor unauthenticated requests bind it.
func (s *Store) attachRestrictedReplay(id string, selector [32]byte) {
	if s.cfg.RestrictedReplay == nil {
		return
	}
	sess := s.Get(id)
	sess.cycleMu.Lock()
	defer sess.cycleMu.Unlock()
	if sess.replay == nil && s.cfg.RestrictedReplay.Bind(id, selector) {
		sess.replay = s.cfg.RestrictedReplay
	}
}
func (sess *Session) observeRestrictedReplay(body []byte, reason uint8) {
	if sess.replay == nil {
		return
	}
	m := restrictedreplay.Record{Reason: reason}
	if sess.entityDecoder != nil {
		s := sess.entityDecoder.NumericStatus(time.Now())
		e := sess.entityDecoder.EpisodeStatus()
		m.Stage, m.Fault, m.Active = s.Stage, s.FaultCode, e.Active
		m.Episode, m.Input = e.Number, s.InputPackets
		m.FirstInput, m.FirstFault, m.BaseKnown, m.MissingKind, m.MissingCode = e.FirstInput, e.Code, e.BaseKnown, e.MissingKind, e.MissingCode
		m.OuterFlags, m.OuterReason, m.NetFlags, m.NetReason = e.OuterFlags, e.OuterReason, e.NetFlags, e.NetReason
	}
	sess.replay.Observe(body, m)
}
