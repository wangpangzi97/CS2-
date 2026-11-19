package capturefilter

// MatchOwnedLocal accepts a LOCAL endpoint only, never the remote port number.
// Heuristic AddPort/AutoAdmit cannot establish ownership.
func (f *Filter) MatchOwnedLocal(local uint16) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.pid == 0 || local == 0 {
		return false
	}
	_, ok := f.owned[local]
	return ok
}
