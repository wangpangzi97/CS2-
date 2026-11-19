package entitycodec

// FaultEpisode is a numeric-only, per-desynchronization snapshot. Historical
// FirstFault* diagnostics deliberately remain unchanged for compatibility.
type FaultEpisode struct {
	Number, FirstInput                                uint64
	Active, Code, BaseKnown, MissingKind, MissingCode uint8
	OuterFlags, OuterReason, NetFlags, NetReason      uint8
}

func (d *Decoder) startFaultEpisode(code uint8, from uint32, known uint8) {
	if d.episode.Active != 0 {
		return
	}
	n := d.episode.Number + 1
	d.episode = FaultEpisode{Number: n, FirstInput: d.cacheTrace.inputPackets, Active: 1, Code: code, BaseKnown: known}
	// Query bounded recent rings, not sticky historical first-fault snapshots.
	p := d.inputTrace
	p.firstMissingKind = 0
	p.missing(from, d.cacheTrace.inputPackets)
	d.episode.MissingKind, d.episode.MissingCode = p.missingKind, p.missingCode
	o := d.origin
	o.captured, o.outerFlags, o.outerReason, o.netFlags, o.netReason = 0, 0, 0, 0, 0
	o.capture(from)
	d.episode.OuterFlags, d.episode.OuterReason = o.outerFlags, o.outerReason
	d.episode.NetFlags, d.episode.NetReason = o.netFlags, o.netReason
}

func (d *Decoder) EpisodeStatus() FaultEpisode {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.episode
}
