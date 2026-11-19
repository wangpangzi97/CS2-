package radarsrv

func originalUnrelForOriginTest(m []byte) *gnsUnrelDecoded {
	if len(m) < 12 || (m[0] != gnsUnrelFlag && m[0] != 0x04) {
		return nil
	}
	seq, n1, ok1 := readGNSVarint(m[1:])
	if !ok1 || n1 == 0 {
		return nil
	}
	tick, _, ok2 := readGNSVarint(m[1+n1:])
	if !ok2 {
		return nil
	}

	var best *gnsUnrelDecoded
	bestScore := -1
	ambiguous := false
	for start := gnsUnrelMinStart; start <= gnsUnrelMaxStart && start < len(m); start++ {
		data, bitStart := m, start*8
		// 0x04 is the compressed counterpart of 0x02. The preserved
		// header is followed by decoded-size varint + an LZ4 block.
		if m[0] == 0x04 {
			want, n, ok := readGNSVarint(m[start:])
			if !ok || want == 0 || want > gnsDecodedLimit {
				continue
			}
			var err error
			data, err = gnsLZ4Block(m[start+n:], int(want))
			if err != nil {
				continue
			}
			bitStart = 0
		}
		msgs, left, ok := gnsParseUnrelChain(data, bitStart)
		if !ok || left > 8 {
			continue
		}
		score, valid := gnsUnrelCandidateScore(msgs)
		if !valid {
			continue
		}
		if score > bestScore {
			bestScore = score
			ambiguous = false
			best = &gnsUnrelDecoded{Start: start, Seq: seq, Tick: tick, Msgs: msgs, LeftBits: left}
		} else if score == bestScore {
			ambiguous = true
		}
	}
	if ambiguous {
		return nil
	}

	return best
}
