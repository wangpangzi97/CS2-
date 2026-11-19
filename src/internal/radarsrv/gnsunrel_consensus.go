package radarsrv

import "bytes"

// This is not a replacement full-chain decoder: callers must first observe
// reason6 from the unchanged strict classifier. Unknown commands remain rejected.
// Only messages that every top-score valid parse consumes identically survive.
type gnsUnrelConsensusCandidate struct {
	decoded *gnsUnrelDecoded
	score   int
}

func gnsUnrelConsumedProjection(msgs []gnsUnrelMsg) ([]gnsUnrelMsg, bool) {
	out := make([]gnsUnrelMsg, 0, len(msgs))
	tick, entities := false, false
	for _, m := range msgs {
		switch m.Cmd {
		case gnsUnrelCmdTick:
			tick = true
			out = append(out, m)
		case gnsUnrelCmdPacketEnts:
			entities = true
			out = append(out, m)
		case gnsUnrelCmdPos:
			out = append(out, m)
		}
	}
	return out, tick && entities
}

// Keep only one shared projection, not every decoded/decompressed candidate.
// This preserves the old bounded scan's memory shape under compressed input.
type gnsUnrelConsensusBuilder struct {
	top, count      int
	first           *gnsUnrelDecoded
	common          []gnsUnrelMsg
	agrees, invalid bool
}

func (b *gnsUnrelConsensusBuilder) add(c gnsUnrelConsensusCandidate) {
	if c.decoded == nil {
		b.invalid = true
		return
	}
	if c.score <= 0 || c.score < b.top {
		return
	}
	if c.score > b.top {
		b.top, b.count, b.first, b.common, b.agrees = c.score, 0, nil, nil, true
	}
	b.count++
	d := c.decoded
	score, valid := gnsUnrelCandidateScore(d.Msgs)
	projected, ok := gnsUnrelConsumedProjection(d.Msgs)
	if !valid || score != c.score || !ok || d.LeftBits < 0 || d.LeftBits > 8 {
		b.agrees = false
		return
	}
	if b.first == nil {
		b.first, b.common = d, projected
		return
	}
	if d.LeftBits != b.first.LeftBits || d.Seq != b.first.Seq || d.Tick != b.first.Tick || len(projected) != len(b.common) {
		b.agrees = false
		return
	}
	for i, m := range projected {
		if m.Cmd != b.common[i].Cmd || !bytes.Equal(m.Body, b.common[i].Body) {
			b.agrees = false
			return
		}
	}
}

func (b *gnsUnrelConsensusBuilder) result() *gnsUnrelDecoded {
	if b.invalid || !b.agrees || b.count < 2 || b.first == nil {
		return nil
	}
	d := b.first
	return &gnsUnrelDecoded{Start: d.Start, Seq: d.Seq, Tick: d.Tick, LeftBits: d.LeftBits, Msgs: b.common}
}

func gnsUnrelConsensusProjection(cs []gnsUnrelConsensusCandidate) *gnsUnrelDecoded {
	var b gnsUnrelConsensusBuilder
	for _, c := range cs {
		b.add(c)
	}
	return b.result()
}

func gnsDecodeUnrelEntityConsensus(m []byte) *gnsUnrelDecoded {
	if len(m) < 12 || (m[0] != gnsUnrelFlag && m[0] != 4) {
		return nil
	}
	seq, n, ok := readGNSVarint(m[1:])
	if !ok || n == 0 {
		return nil
	}
	tick, _, ok := readGNSVarint(m[1+n:])
	if !ok {
		return nil
	}
	var consensus gnsUnrelConsensusBuilder
	for start := gnsUnrelMinStart; start <= gnsUnrelMaxStart && start < len(m); start++ {
		data, bit := m, start*8
		if m[0] == 4 {
			want, k, ok := readGNSVarint(m[start:])
			if !ok || want == 0 || want > gnsDecodedLimit {
				continue
			}
			var err error
			data, err = gnsLZ4Block(m[start+k:], int(want))
			if err != nil {
				continue
			}
			bit = 0
		}
		msgs, left, ok := gnsParseUnrelChain(data, bit)
		if !ok || left > 8 {
			continue
		}
		score, valid := gnsUnrelCandidateScore(msgs)
		if !valid {
			continue
		}
		consensus.add(gnsUnrelConsensusCandidate{decoded: &gnsUnrelDecoded{Start: start, Seq: seq, Tick: tick, LeftBits: left, Msgs: msgs}, score: score})
	}
	return consensus.result()
}
