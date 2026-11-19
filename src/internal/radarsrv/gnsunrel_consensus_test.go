package radarsrv

import (
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"testing"
)

func phase74Candidate(t *testing.T, prefix uint32, tick uint32, event byte) gnsUnrelConsensusCandidate {
	t.Helper()
	tickBody, _ := proto.Marshal(&msg.CNETMsg_Tick{Tick: proto.Uint32(tick)})
	body, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	ms := []gnsUnrelMsg{{Cmd: prefix}, {Cmd: 4, Body: tickBody}, {Cmd: 55, Body: body}}
	if event != 0 {
		ms = append(ms, gnsUnrelMsg{Cmd: 452, Body: []byte{8, event}})
	}
	score, valid := gnsUnrelCandidateScore(ms)
	if !valid {
		t.Fatal("constructed candidate invalid")
	}
	return gnsUnrelConsensusCandidate{decoded: &gnsUnrelDecoded{Start: 9, Seq: 1, Tick: 74521, Msgs: ms, LeftBits: 0}, score: score}
}
func phase74Clone(c gnsUnrelConsensusCandidate) gnsUnrelConsensusCandidate {
	d := *c.decoded
	d.Msgs = append([]gnsUnrelMsg(nil), c.decoded.Msgs...)
	for i := range d.Msgs {
		d.Msgs[i].Body = append([]byte(nil), d.Msgs[i].Body...)
	}
	return gnsUnrelConsensusCandidate{decoded: &d, score: c.score}
}
func TestPhase74ConsensusAllHighestCandidates(t *testing.T) {
	for n := 2; n <= 12; n++ {
		cs := make([]gnsUnrelConsensusCandidate, n)
		for i := range cs {
			cs[i] = phase74Candidate(t, []uint32{0, 6, 8, 16}[i%4], 74521, 1)
		}
		got := gnsUnrelConsensusProjection(cs)
		if got == nil || len(got.Msgs) != 3 || got.Msgs[0].Cmd != 4 || got.Msgs[1].Cmd != 55 || got.Msgs[2].Cmd != 452 {
			t.Fatal("common consumed projection lost")
		}
		// A disagreement in the LAST top candidate must not be hidden by the first2.
		cs[n-1].decoded.Msgs[2].Body = append(cs[n-1].decoded.Msgs[2].Body, 8, 1)
		if gnsUnrelConsensusProjection(cs) != nil {
			t.Fatal("different entity bytes admitted")
		}
	}
}
func TestPhase74ConsensusNegativeBoundary(t *testing.T) {
	base := phase74Candidate(t, 16, 74521, 1)
	cases := []struct {
		name   string
		change func(*gnsUnrelConsensusCandidate)
	}{
		{"different_tick_message", func(c *gnsUnrelConsensusCandidate) { c.decoded.Msgs[1].Body = []byte{8, 1} }},
		{"different_entity_message", func(c *gnsUnrelConsensusCandidate) { c.decoded.Msgs[2].Body = append(c.decoded.Msgs[2].Body, 8, 1) }},
		{"different_event", func(c *gnsUnrelConsensusCandidate) { c.decoded.Msgs[3].Body = []byte{8, 2} }},
		{"different_order", func(c *gnsUnrelConsensusCandidate) {
			c.decoded.Msgs[1], c.decoded.Msgs[2] = c.decoded.Msgs[2], c.decoded.Msgs[1]
		}},
		{"different_tail", func(c *gnsUnrelConsensusCandidate) { c.decoded.LeftBits = 1 }},
		{"different_seq", func(c *gnsUnrelConsensusCandidate) { c.decoded.Seq = 2 }},
		{"different_header_tick", func(c *gnsUnrelConsensusCandidate) { c.decoded.Tick = 74522 }},
		{"missing_entity", func(c *gnsUnrelConsensusCandidate) { c.decoded.Msgs = []gnsUnrelMsg{c.decoded.Msgs[1]} }},
		{"missing_tick", func(c *gnsUnrelConsensusCandidate) { c.decoded.Msgs = []gnsUnrelMsg{c.decoded.Msgs[2]} }},
		{"invalid_pb", func(c *gnsUnrelConsensusCandidate) { c.decoded.Msgs[2].Body = []byte{0xff} }},
		{"unknown_non_pb", func(c *gnsUnrelConsensusCandidate) { c.decoded.Msgs[0].Body = []byte{0xff} }},
		{"forged_score", func(c *gnsUnrelConsensusCandidate) { c.score++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := phase74Clone(base), phase74Clone(base)
			tc.change(&b)
			if gnsUnrelConsensusProjection([]gnsUnrelConsensusCandidate{a, b}) != nil {
				t.Fatal("unsafe projection accepted")
			}
		})
	}
	if gnsUnrelConsensusProjection(nil) != nil || gnsUnrelConsensusProjection([]gnsUnrelConsensusCandidate{base}) != nil {
		t.Fatal("missing competing proof accepted")
	}
	low := phase74Clone(base)
	low.decoded.Msgs = []gnsUnrelMsg{base.decoded.Msgs[2]}
	low.score = 20
	if gnsUnrelConsensusProjection([]gnsUnrelConsensusCandidate{base, phase74Clone(base), low}) == nil {
		t.Fatal("lower-score candidate changed original maximum-score policy")
	}
}
func TestPhase74ConsensusWireProjection(t *testing.T) {
	dep, _ := phase74Bodies(t)
	wire := phase74PrefixWire(dep, 74521)
	a, la, oka := gnsParseUnrelChain(wire, 9*8)
	b, lb, okb := gnsParseUnrelChain(wire, 13*8)
	if !oka || !okb || la != lb || gnsUnrelEquivalentMessages(a, b) {
		t.Fatal("independent9/13 non-NOP fixture not ambiguous")
	}
	if d, reason := gnsDecodeUnrelReason(wire); d != nil || reason != 6 {
		t.Fatal("strict full-chain classification changed")
	}
	got := gnsDecodeUnrelEntityConsensus(wire)
	if got == nil || len(got.Msgs) != 2 || got.Msgs[0].Cmd != 4 || got.Msgs[1].Cmd != 55 {
		t.Fatal("common messages not recovered")
	}
	for _, bad := range [][]byte{nil, {2}, make([]byte, 20), append([]byte{0x04}, wire[1:3]...)} {
		if gnsDecodeUnrelEntityConsensus(bad) != nil {
			t.Fatal("invalid input admitted")
		}
	}
}
func TestPhase74ConsensusMaximumScoreOrder(t *testing.T) {
	a, b := phase74Candidate(t, 6, 74521, 0), phase74Candidate(t, 8, 74521, 0)
	b.decoded.Msgs[2].Body = append(b.decoded.Msgs[2].Body, 8, 1)
	x, y := phase74Candidate(t, 16, 74521, 1), phase74Candidate(t, 8, 74521, 1)
	orders := [][]gnsUnrelConsensusCandidate{{a, b, x, y}, {x, a, y, b}, {x, y, a, b}, {a, x, b, y}, {a, b, x}, {x, a, b}}
	for i, cs := range orders {
		got := gnsUnrelConsensusProjection(cs)
		if i < 4 && got == nil {
			t.Fatal("lower-score disagreement contaminated a unanimous higher score")
		}
		if i >= 4 && got != nil {
			t.Fatal("one highest candidate cannot form consensus")
		}
	}
}
