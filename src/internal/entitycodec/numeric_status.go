package entitycodec

import "time"

// NumericEntityStatus is a deliberately narrow diagnostic boundary. It has no
// strings, entities, identities, raw bytes, positions, network endpoints or keys.
type NumericEntityStatus struct {
	FirstMissingOriginCaptured, FirstMissingOuterFlags, FirstMissingOuterReason                          uint8
	FirstMissingNetFlags, FirstMissingNetReason                                                          uint8
	IngressOuterMatches, IngressOuterMismatches, IngressNetMatches, IngressNetMismatches, ZeroTickBodies uint64
	FirstFaultCode, FirstFaultBaseKnown, MissingInputKind, MissingInputCode                              uint8
	FirstMissingInputKind, FirstMissingInputCode                                                         uint8
	FirstFaultInput, FirstMissingInput                                                                   uint64
	FirstFaultAdvance, FirstFaultDependencyGap                                                           uint32
	InputPackets, EmptyDeltas, RejectedPackets                                                           uint64
	Stage                                                                                                uint8
	FaultCode                                                                                            uint8
	MissingKind                                                                                          uint8
	CacheFrames, CacheHorizon, MissingGap                                                                uint32
	CacheBytes                                                                                           uint64
	LateSeen, LateCached, LateRejected, CacheMisses                                                      uint64
	Protocol, Classes, Tables, Baselines                                                                 uint32
	ClassReady, LiveBaselines                                                                            uint8
	AcceptedPackets                                                                                      uint64
}

// Stage1 waiting ServerInfo,2 unsupported profile,3 rejected metadata,
// 4 waiting class map,5 waiting live baselines,6 decode desync,
// 7 waiting full entity frame,8 expired entity stream,9 synchronized.
func (d *Decoder) NumericStatus(now time.Time) NumericEntityStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, profileOK := entityProfile(d.info.GetProtocol(), d.info.GetMaxClasses())
	s := NumericEntityStatus{Stage: 1, Tables: uint32(len(d.tables)), Baselines: uint32(len(d.baselines)), AcceptedPackets: d.packets}
	s.FirstMissingOriginCaptured = d.origin.captured
	s.FirstMissingOuterFlags, s.FirstMissingOuterReason = d.origin.outerFlags, d.origin.outerReason
	s.FirstMissingNetFlags, s.FirstMissingNetReason = d.origin.netFlags, d.origin.netReason
	s.IngressOuterMatches, s.IngressOuterMismatches = d.origin.outerMatches, d.origin.outerMismatches
	s.IngressNetMatches, s.IngressNetMismatches = d.origin.netMatches, d.origin.netMismatches
	s.ZeroTickBodies = d.origin.zeroBodies
	s.FirstFaultCode = d.inputTrace.firstCode
	s.FirstFaultInput = d.inputTrace.firstInput
	s.FirstFaultBaseKnown = d.inputTrace.firstBaseKnown
	s.FirstFaultAdvance = d.inputTrace.firstAdvance
	s.FirstFaultDependencyGap = d.inputTrace.firstDependencyGap
	s.MissingInputKind = d.inputTrace.missingKind
	s.MissingInputCode = d.inputTrace.missingCode
	s.FirstMissingInputKind = d.inputTrace.firstMissingKind
	s.FirstMissingInputCode = d.inputTrace.firstMissingCode
	s.FirstMissingInput = d.inputTrace.firstMissingInput
	s.InputPackets = d.cacheTrace.inputPackets
	s.EmptyDeltas = d.cacheTrace.emptyDeltas
	s.RejectedPackets = d.cacheTrace.rejectedPackets
	s.MissingKind = d.cacheTrace.missingKind
	s.CacheFrames = uint32(len(d.history))
	s.CacheHorizon = d.historyHorizon()
	s.MissingGap = d.cacheTrace.missingGap
	s.CacheBytes = uint64(d.historyBytes)
	s.LateSeen = d.cacheTrace.lateSeen
	s.LateCached = d.cacheTrace.lateCached
	s.LateRejected = d.cacheTrace.lateRejected
	s.CacheMisses = d.cacheTrace.misses
	if d.classOK {
		s.ClassReady = 1
	}
	if d.liveBaselines {
		s.LiveBaselines = 1
	}
	if d.info == nil {
		return s
	}
	if p := d.info.GetProtocol(); p > 0 && p <= 1000000 {
		s.Protocol = uint32(p)
	}
	if n := d.info.GetMaxClasses(); n > 0 && n <= 16384 {
		s.Classes = uint32(n)
	}
	switch {
	case !profileOK || d.parser == nil:
		s.Stage = 2
	case d.metadataFault != "":
		s.Stage = 3
	case d.info.GetMapName() != "de_dust2" && !d.classOK:
		s.Stage = 4
	case d.info.GetMapName() != "de_dust2" && (!d.liveBaselines || d.baselines[44] == nil || d.baselines[45] == nil):
		s.Stage = 5
	case d.syncFault != "":
		s.Stage = 6
		s.FaultCode = d.syncFaultCode
	case !d.ready:
		s.Stage = 7
	case now.Sub(d.last) > d.ttl:
		s.Stage = 8
	default:
		s.Stage = 9
	}
	return s
}
