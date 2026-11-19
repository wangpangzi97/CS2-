package entitycodec

// Diagnostic metadata only. Absolute ticks stay internal and are never logged.
// Ring entries carry no entity state, identities, raw body or error text.
type inputReceipt struct {
	tick          uint32
	outcome, code uint8
}
type entityInputTrace struct {
	receipts                           [128]inputReceipt
	next                               uint8
	count                              uint16
	firstCode, firstBaseKnown          uint8
	firstInput                         uint64
	firstAdvance, firstDependencyGap   uint32
	missingKind, missingCode           uint8
	firstMissingKind, firstMissingCode uint8
	firstMissingInput                  uint64
}

func traceGap(a, b uint32) uint32 {
	if a == 0 || b == 0 || a <= b {
		return 0
	}
	v := a - b
	if v > 1<<20 {
		return 1 << 20
	}
	return v
}
func (p *entityInputTrace) firstFault(code uint8, seq uint64, tick, last, from uint32, known uint8) {
	if p.firstCode != 0 {
		return
	}
	p.firstCode = code
	p.firstInput = seq
	p.firstBaseKnown = known
	p.firstAdvance = traceGap(tick, last)
	p.firstDependencyGap = traceGap(tick, from)
}
func (p *entityInputTrace) remember(tick uint32, outcome, code uint8) {
	if tick == 0 {
		return
	}
	p.receipts[p.next] = inputReceipt{tick, outcome, code}
	p.next = (p.next + 1) % 128
	if p.count < 128 {
		p.count++
	}
}

// 1 last receipt checkpointed,2 rejected,3 ignored,4 absent inside the receipt
// tick horizon,5 unknown/outside. Absence is NOT proof of network loss.
func (p *entityInputTrace) missing(from uint32, seq uint64) {
	kind, code := uint8(5), uint8(0)
	lo, hi := ^uint32(0), uint32(0)
	for i := 0; i < int(p.count); i++ {
		at := (int(p.next) - 1 - i + 128) % 128
		r := p.receipts[at]
		if r.tick < lo {
			lo = r.tick
		}
		if r.tick > hi {
			hi = r.tick
		}
		if r.tick == from {
			kind, code = r.outcome, r.code
			break
		}
	}
	if kind == 5 && p.count > 0 && from >= lo && from <= hi {
		kind = 4
	}
	p.missingKind, p.missingCode = kind, code
	if p.firstMissingKind == 0 {
		p.firstMissingKind = kind
		p.firstMissingCode = code
		p.firstMissingInput = seq
	}
}
