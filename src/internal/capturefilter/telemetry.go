package capturefilter

// ClassifyLocal observes the last discovered local-port snapshot only. It does
// not change Match/AutoAdmit, verify a peer or identify a protocol.
// 0 no active filter, 1 process-port snapshot, 2 admitted-only, 3 unmatched.
func (f *Filter) ClassifyLocal(local uint16) uint8 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.ports) == 0 {
		return 0
	}
	if _, ok := f.owned[local]; ok {
		return 1
	}
	if _, ok := f.ports[local]; ok {
		return 2
	}
	return 3
}
func (f *Filter) OwnedPortCount() int { f.mu.RLock(); defer f.mu.RUnlock(); return len(f.owned) }
