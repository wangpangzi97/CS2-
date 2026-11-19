package entitycodec

// Diagnostic namespaces:1 outer unreliable header,2 validated NET_Tick context.
// Flags:1 first fragment,2 complete,4 selected chain,8 rejected chain,
// 16 NET_Tick present,32 entity body with zero/absent server_tick.
// Outer header equality is a correlation, NOT proof of entity-tick semantics.
type ingressReceipt struct {
	tick                  uint32
	source, flags, reason uint8
}
type ingressOrigin struct {
	entries                                                              [256]ingressReceipt
	next, count                                                          uint16
	captured, outerFlags, outerReason, netFlags, netReason               uint8
	outerMatches, outerMismatches, netMatches, netMismatches, zeroBodies uint64
}

func (o *ingressOrigin) observe(tick uint32, source, flags, reason uint8) {
	if tick == 0 || source < 1 || source > 2 || flags == 0 || flags&^uint8(63) != 0 || reason > 6 {
		return
	}
	for i := 0; i < int(o.count); i++ {
		n := (int(o.next) - 1 - i + 256) % 256
		r := &o.entries[n]
		if r.tick == tick && r.source == source {
			r.flags |= flags
			if reason != 0 {
				r.reason = reason
			}
			return
		}
	}
	o.entries[o.next] = ingressReceipt{tick, source, flags, reason}
	o.next = (o.next + 1) % 256
	if o.count < 256 {
		o.count++
	}
}
func (o *ingressOrigin) capture(from uint32) {
	if o.captured != 0 {
		return
	}
	o.captured = 1
	for i := 0; i < int(o.count); i++ {
		r := o.entries[(int(o.next)-1-i+256)%256]
		if r.tick != from {
			continue
		}
		if r.source == 1 {
			o.outerFlags, o.outerReason = r.flags, r.reason
		} else {
			o.netFlags, o.netReason = r.flags, r.reason
		}
	}
}
func (o *ingressOrigin) reanchor() {
	a, b, c, d, z := o.outerMatches, o.outerMismatches, o.netMatches, o.netMismatches, o.zeroBodies
	*o = ingressOrigin{}
	o.outerMatches, o.outerMismatches, o.netMatches, o.netMismatches, o.zeroBodies = a, b, c, d, z
}

// RecordIngressTick keeps bounded integers only. It is internal server-package
// instrumentation, not an HTTP API, and never supplies entity state or a base.
func (d *Decoder) RecordIngressTick(tick uint32, source, flags, reason uint8) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.origin.observe(tick, source, flags, reason)
}
func (d *Decoder) RecordEntityContext(server, outer, net uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if server > 0 && outer > 0 {
		if server == outer {
			d.origin.outerMatches++
		} else {
			d.origin.outerMismatches++
		}
	}
	if server > 0 && net > 0 {
		if server == net {
			d.origin.netMatches++
		} else {
			d.origin.netMismatches++
		}
	}
}
