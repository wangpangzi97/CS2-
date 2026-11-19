package radarsrv

import (
	"io"
	"local/cs2-radar/internal/restrictedreplay"
)

// ReplayAudit is aggregate-only. It is not served by any HTTP endpoint.
type ReplayAudit struct {
	Records, Accepted, ClassificationMismatches, MaxEpisode uint64
	RejectedByReason                                        [7]uint64
	Capture                                                 restrictedreplay.Result
	FullEntityReplay                                        bool
}

func AuditRestrictedReplay(r io.Reader) (ReplayAudit, error) {
	records, capture, e := restrictedreplay.Read(r)
	if e != nil {
		return ReplayAudit{}, e
	}
	out := ReplayAudit{Capture: capture, Records: uint64(len(records))}
	for _, v := range records {
		d, reason := gnsDecodeUnrelReason(v.Body)
		if d != nil {
			out.Accepted++
		} else if reason <= 6 {
			out.RejectedByReason[reason]++
		}
		if reason != v.Reason {
			out.ClassificationMismatches++
		}
		if v.Episode > out.MaxEpisode {
			out.MaxEpisode = v.Episode
		}
		clear(v.Body)
	}
	return out, nil
}
