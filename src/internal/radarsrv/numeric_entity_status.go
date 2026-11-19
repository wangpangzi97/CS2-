package radarsrv

import (
	"local/cs2-radar/internal/entitycodec"
	"log"
	"time"
)

// Called under sess.mu; emitted at most once per five seconds, normally once
// per state transition / thirty seconds. No session/device/account/peer IDs.
// This does NOT reactivate gnsLogf or any free-text/payload diagnostic sink.
func (sess *Session) logNumericEntityStageLocked(now time.Time, rawPlayers, visiblePlayers int) {
	s := entitycodec.NumericEntityStatus{Stage: 1}
	if sess.entityDecoder != nil {
		s = sess.entityDecoder.NumericStatus(now)
	}
	if sess.pendingEntitySignon {
		s.Stage = 10
	} // waiting staged signon boundary
	if !sess.entityLogAt.IsZero() {
		age := now.Sub(sess.entityLogAt)
		if age < 5*time.Second || (s.Stage == sess.entityLogStage && age < 30*time.Second) {
			return
		}
	}
	sess.entityLogAt = now
	sess.entityLogStage = s.Stage
	log.Printf("[GS-ENTITY] stage=%d protocol=%d classes=%d tables=%d baselines=%d class_ok=%d live=%d accepted=%d raw_players=%d visible_players=%d", s.Stage, s.Protocol, s.Classes, s.Tables, s.Baselines, s.ClassReady, s.LiveBaselines, s.AcceptedPackets, rawPlayers, visiblePlayers)
	log.Printf("[GS-ENTITY-CACHE] frames=%d bytes=%d horizon=%d missing_kind=%d missing_gap=%d misses=%d late_seen=%d late_cached=%d late_rejected=%d", s.CacheFrames, s.CacheBytes, s.CacheHorizon, s.MissingKind, s.MissingGap, s.CacheMisses, s.LateSeen, s.LateCached, s.LateRejected)
	log.Printf("[GS-ENTITY-INPUT] received=%d empty_deltas=%d rejected=%d", s.InputPackets, s.EmptyDeltas, s.RejectedPackets)
	log.Printf("[GS-ENTITY-CAUSE] first_code=%d first_input=%d advance=%d dependency_gap=%d base_known=%d missing_input_kind=%d missing_input_code=%d first_missing_kind=%d first_missing_code=%d first_missing_input=%d", s.FirstFaultCode, s.FirstFaultInput, s.FirstFaultAdvance, s.FirstFaultDependencyGap, s.FirstFaultBaseKnown, s.MissingInputKind, s.MissingInputCode, s.FirstMissingInputKind, s.FirstMissingInputCode, s.FirstMissingInput)
	p := &sess.pipeline
	log.Printf("[GS-ENTITY-ORIGIN] captured=%d outer_flags=%d outer_reason=%d net_flags=%d net_reason=%d outer_matches=%d outer_mismatches=%d net_matches=%d net_mismatches=%d zero_tick_bodies=%d reject1=%d reject2=%d reject3=%d reject4=%d reject5=%d reject6=%d", s.FirstMissingOriginCaptured, s.FirstMissingOuterFlags, s.FirstMissingOuterReason, s.FirstMissingNetFlags, s.FirstMissingNetReason, s.IngressOuterMatches, s.IngressOuterMismatches, s.IngressNetMatches, s.IngressNetMismatches, s.ZeroTickBodies, p.unrelRejectReasons[1].Load(), p.unrelRejectReasons[2].Load(), p.unrelRejectReasons[3].Load(), p.unrelRejectReasons[4].Load(), p.unrelRejectReasons[5].Load(), p.unrelRejectReasons[6].Load())
	log.Printf("[GS-ENTITY-PIPE] decrypt_ok=%d decrypt_failed=%d snp_bad=%d fragments=%d reassembled=%d expired=%d invalid=%d conflicts=%d unrel_seen=%d unrel_decoded=%d unrel_rejected=%d reliable_pe=%d unreliable_pe=%d", p.decryptOK.Load(), p.decryptFailed.Load(), p.snpBad.Load(), p.fragments.Load(), p.reassembled.Load(), p.expired.Load(), p.invalid.Load(), p.conflicts.Load(), p.unrelSeen.Load(), p.unrelDecoded.Load(), p.unrelRejected.Load(), p.reliableEntities.Load(), p.unreliableEntities.Load())
	if s.Stage == 6 {
		// Fixed enum only: 1 envelope,2 count,3 missing base,4 restore,
		// 5 entity parser,6 checkpoint,7 history. Never export error text.
		log.Printf("[GS-ENTITY-FAULT] code=%d", s.FaultCode)
	}
}
