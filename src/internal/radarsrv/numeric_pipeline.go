package radarsrv

import "sync/atomic"

// Cumulative per data-session counters, independent of signon resets. No bytes,
// keys, endpoints, ticks, account IDs, entity IDs or free-text errors are stored.
type numericPipeline struct {
	unrelRejectReasons                                  [7]atomic.Uint64
	decryptOK, decryptFailed, snpBad                    atomic.Uint64
	fragments, reassembled, expired, invalid, conflicts atomic.Uint64
	unrelSeen, unrelDecoded, unrelRejected              atomic.Uint64
	reliableEntities, unreliableEntities                atomic.Uint64
}
