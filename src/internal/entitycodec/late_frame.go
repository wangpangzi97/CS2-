package entitycodec

import (
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"sort"
	"time"
)

// Only bounded numeric diagnostics. MissingKind describes the LAST miss:
// 1 recorded eviction (last256),2 gap inside cached horizon,3 older/unknown,
// 4 future reference,5 empty cache. None proves a packet was never received.
type historyDiagnostics struct {
	inputPackets, emptyDeltas, rejectedPackets uint64
	lateSeen, lateCached, lateRejected, misses uint64
	missingKind                                uint8
	missingGap                                 uint32
	evicted                                    [256]uint32
	evictedNext                                uint16
}

func (d *Decoder) historyHorizon() uint32 {
	oldest := d.lastTick
	for tick := range d.history {
		if tick < oldest {
			oldest = tick
		}
	}
	return d.lastTick - oldest
}
func (d *Decoder) recordMissingBase(from uint32) {
	d.origin.capture(from)
	d.inputTrace.missing(from, d.cacheTrace.inputPackets)
	d.cacheTrace.misses++
	d.cacheTrace.missingKind = 2
	d.cacheTrace.missingGap = 0
	switch {
	case len(d.history) == 0:
		d.cacheTrace.missingKind = 5
	case from > d.lastTick:
		d.cacheTrace.missingKind = 4
	default:
		d.cacheTrace.missingGap = d.lastTick - from
		if d.cacheTrace.missingGap > d.historyHorizon() {
			d.cacheTrace.missingKind = 3
		}
	}
	for _, tick := range d.cacheTrace.evicted {
		if tick != 0 && tick == from {
			d.cacheTrace.missingKind = 1
			break
		}
	}
}
func (d *Decoder) pruneHistoryKeeping(keep ...uint32) error {
	if len(keep) > 3 {
		return fmt.Errorf("history protected-set count limit")
	}
	for len(d.historyOrder) > 128 || d.historyBytes > 128<<20 {
		victim := -1
		for i, id := range d.historyOrder {
			protected := false
			for _, k := range keep {
				if id == k {
					protected = true
					break
				}
			}
			if !protected {
				victim = i
				break
			}
		}
		if victim < 0 {
			return fmt.Errorf("entity history protected-set exceeds memory limit")
		}
		id := d.historyOrder[victim]
		d.historyBytes -= d.history[id].checkpoint.Bytes()
		delete(d.history, id)
		d.historyOrder = append(d.historyOrder[:victim], d.historyOrder[victim+1:]...)
		d.cacheTrace.evicted[d.cacheTrace.evictedNext] = id
		d.cacheTrace.evictedNext = (d.cacheTrace.evictedNext + 1) % 256
	}
	return nil
}

// Called under Decoder.mu. A valid older packet is not a display update, but
// a newer packet can explicitly name it as DeltaFrom. Decode it in isolation,
// then restore the current successful parser before touching the cache.
func (d *Decoder) cacheLateDelta(m *msg.CSVCMsg_PacketEntities, now time.Time) error {
	d.cacheTrace.lateSeen++
	tick, from := m.GetServerTick(), uint32(m.GetDeltaFrom())
	if _, exists := d.history[tick]; exists {
		return nil
	}
	reject := func() error { d.cacheTrace.lateRejected++; return nil }
	if !m.GetLegacyIsDelta() || m.GetDeltaFrom() <= 0 || from >= tick || d.lastTick-tick > 128 {
		return reject()
	}
	base, bok := d.history[from]
	live, lok := d.history[d.lastTick]
	fresh := func(h historicalFrame) bool {
		age := now.Sub(h.acceptedAt)
		return h.checkpoint != nil && !h.acceptedAt.IsZero() && age >= 0 && age <= d.ttl
	}
	if !bok || !lok || !fresh(base) || !fresh(live) {
		return reject()
	}
	frame, ok, e := d.decodeLateCandidate(m, now, base, live)
	if e != nil {
		return e
	} // inability to restore the live checkpoint fails closed
	if !ok {
		return reject()
	}
	d.history[tick] = frame
	d.historyOrder = append(d.historyOrder, tick)
	d.historyBytes += frame.checkpoint.Bytes()
	sort.Slice(d.historyOrder, func(i, j int) bool { return d.historyOrder[i] < d.historyOrder[j] })
	// Preserve the current live frame, its active dependency, and this late
	// frame. At most3 bounded32MiB checkpoints fit the SAME128MiB budget.
	if e := d.pruneHistoryKeeping(d.activeBase, d.lastTick, tick); e != nil {
		return e
	}
	d.cacheTrace.lateCached++
	return nil
}
func (d *Decoder) decodeLateCandidate(m *msg.CSVCMsg_PacketEntities, now time.Time, base, live historicalFrame) (out historicalFrame, ok bool, err error) {
	savedLast, savedDeparted := d.last, d.departed
	defer func() {
		p := recover()
		if e := d.parser.RestoreRadarCheckpoint(live.checkpoint); e != nil {
			ok = false
			err = fmt.Errorf("late frame live restore: %w", e)
			return
		}
		d.ents = d.parser.RadarEntities()
		d.departed = savedDeparted
		d.last = savedLast
		if p != nil {
			out = historicalFrame{}
			ok = false
			err = nil
		}
	}()
	if e := d.parser.RestoreRadarCheckpoint(base.checkpoint); e != nil {
		return out, false, nil
	}
	d.ents = d.parser.RadarEntities()
	d.departed = copyDeparted(base.departed)
	d.last = now
	if e := d.parser.OnPacketEntities(m); e != nil {
		return out, false, nil
	}
	cp, e := d.parser.RadarCheckpoint()
	if e != nil {
		return out, false, nil
	}
	return historicalFrame{checkpoint: cp, departed: copyDeparted(d.departed), acceptedAt: now}, true, nil
}
