package radarsrv

import (
	"encoding/binary"
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/entitycodec"
	"testing"
	"time"
)

func TestEmptyDeltaLongRunKeepsExactDependenciesBounded(t *testing.T) {
	at := time.Unix(100, 0)
	d := emptyDeltaTestDecoder(t, at)
	if e := d.PacketEntities(emptyDeltaTestRead(t, "live-74523.pb"), at); e != nil {
		t.Fatal(e)
	}
	const frames = 20064
	last := uint32(74523)
	for i := 1; i <= frames; i++ {
		next := last + 1
		body, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(int32(last)), ServerTick: proto.Uint32(next)})
		when := at.Add(time.Duration(i) * time.Second / 64)
		if !emptyDeltaTestFeed(d, emptyDeltaTestWire(body, next), when) {
			t.Fatal("zero-change envelope lost in long stream")
		}
		last = next
	}
	when := at.Add(frames * time.Second / 64)
	ps, ok, _ := d.Snapshot(when)
	s := d.NumericStatus(when)
	if !ok || len(ps) != 9 || s.EmptyDeltas != frames || s.RejectedPackets != 0 || s.CacheFrames > 128 || s.CacheBytes > 128<<20 {
		t.Fatal("dependency continuity or unchanged bounded cache failed")
	}
	if _, ok, _ := d.Snapshot(when.Add(11 * time.Second)); ok {
		t.Fatal("original stream TTL was weakened")
	}
	fmt.Printf("EMPTY_DELTA_LONG_RUN=%d PLAYERS=%d REJECTED=%d CACHE_FRAMES=%d CACHE_BYTES=%d ORIGINAL_TTL_ENFORCED=true SYNTHETIC_ONLY=true\n", frames, len(ps), s.RejectedPackets, s.CacheFrames, s.CacheBytes)
}

func emptySafetyHeader() *msg.CSVCMsg_PacketEntities {
	return &msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)}
}
func TestEmptyDeltaHeaderIsNotArbitraryMissingPayload(t *testing.T) {
	for _, kind := range []string{"valid_omitted_count", "valid_explicit_zero_count", "not_delta", "zero_from", "negative_from", "zero_tick", "equal_tick", "backward_tick", "positive_updates", "negative_updates", "too_many_entries", "negative_max", "nonempty_payload"} {
		t.Run(kind, func(t *testing.T) {
			m := emptySafetyHeader()
			good := false
			switch kind {
			case "valid_omitted_count":
				good = true
			case "valid_explicit_zero_count":
				m.UpdatedEntries = proto.Int32(0)
				good = true
			case "not_delta":
				m.LegacyIsDelta = proto.Bool(false)
			case "zero_from":
				m.DeltaFrom = nil
			case "negative_from":
				m.DeltaFrom = proto.Int32(-1)
			case "zero_tick":
				m.ServerTick = nil
			case "equal_tick":
				m.ServerTick = proto.Uint32(74515)
			case "backward_tick":
				m.ServerTick = proto.Uint32(74514)
			case "positive_updates":
				m.UpdatedEntries = proto.Int32(1)
			case "negative_updates":
				m.UpdatedEntries = proto.Int32(-1)
			case "too_many_entries":
				m.MaxEntries = proto.Int32(16385)
			case "negative_max":
				m.MaxEntries = proto.Int32(-1)
			case "nonempty_payload":
				m.EntityData = []byte{1}
			}
			b, _ := proto.Marshal(m)
			if gnsEmptyEntityDelta(b) != good {
				t.Fatal("empty envelope classification mismatch")
			}
			if kind != "nonempty_payload" {
				_, ok := gnsUnrelCandidateScore([]gnsUnrelMsg{{Cmd: 55, Body: b}})
				if ok != good {
					t.Fatal("invalid missing-payload chain accepted")
				}
			}
		})
	}
	for _, b := range [][]byte{nil, {0}, {0xff}, {0x18, 1, 0x30, 0x80}} {
		if gnsEmptyEntityDelta(b) {
			t.Fatal("malformed accepted")
		}
	}
}
func TestEmptyDeltaStillRequiresInitialFullAndExactCheckpoint(t *testing.T) {
	for _, kind := range []string{"no_full", "unknown_checkpoint", "new_generation"} {
		t.Run(kind, func(t *testing.T) {
			at := time.Now()
			d := entitycodec.New()
			if e := d.ServerInfo(emptyDeltaTestRead(t, "live-serverinfo.pb")); e != nil {
				t.Fatal(e)
			}
			if kind != "no_full" {
				if e := d.PacketEntities(emptyDeltaTestRead(t, "live-full.pb"), at); e != nil {
					t.Fatal(e)
				}
			}
			m := emptySafetyHeader()
			if kind == "unknown_checkpoint" {
				m.DeltaFrom = proto.Int32(74514)
			}
			if kind == "new_generation" {
				if e := d.ServerInfo(emptyDeltaTestRead(t, "live-serverinfo.pb")); e != nil {
					t.Fatal(e)
				}
			}
			b, _ := proto.Marshal(m)
			if !emptyDeltaTestFeed(d, emptyDeltaTestWire(b, 74521), at.Add(time.Millisecond)) {
				t.Fatal("envelope lost")
			}
			if ps, ok, _ := d.Snapshot(at.Add(time.Millisecond)); ok || len(ps) != 0 {
				t.Fatal("empty header bypassed exact state boundary")
			}
		})
	}
}
func TestEmptyDeltaBothCompressedAndUncompressed(t *testing.T) {
	body, _ := proto.Marshal(emptySafetyHeader())
	plain := emptyDeltaTestWire(body, 74521)
	chain := plain[11:]
	compressed := append([]byte{}, plain[:11]...)
	compressed[0] = 4
	compressed = binary.AppendUvarint(compressed, uint64(len(chain)))
	if len(chain) < 15 {
		compressed = append(compressed, byte(len(chain)<<4))
	} else {
		compressed = append(compressed, 0xf0)
		n := len(chain) - 15
		for n >= 255 {
			compressed = append(compressed, 255)
			n -= 255
		}
		compressed = append(compressed, byte(n))
	}
	compressed = append(compressed, chain...)
	for _, wire := range [][]byte{plain, compressed} {
		d := gnsDecodeUnrel(wire)
		if d == nil || len(d.Msgs) != 2 || d.Msgs[1].Cmd != 55 || !gnsEmptyEntityDelta(d.Msgs[1].Body) {
			t.Fatal("empty delta lost in envelope")
		}
	}
	if gnsDecodeUnrel(compressed[:len(compressed)-1]) != nil {
		t.Fatal("truncated compressed frame accepted")
	}
}
func TestEmptyDeltaRealSessionInputPath(t *testing.T) {
	at := time.Now()
	s := NewStore(DefaultConfig()).Get("synthetic-empty-delta")
	s.entityDecoder = emptyDeltaTestDecoder(t, at)
	b, _ := proto.Marshal(emptySafetyHeader())
	s.noteGNSUnrel(emptyDeltaTestWire(b, 74521))
	st := s.entityDecoder.NumericStatus(time.Now())
	if st.Stage != 9 || st.InputPackets != 2 || st.EmptyDeltas != 1 || st.RejectedPackets != 0 || st.AcceptedPackets != 2 {
		t.Fatal("session did not retain empty exact state")
	}
}
