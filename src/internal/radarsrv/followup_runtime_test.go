package radarsrv

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"local/cs2-radar/internal/cs2snp"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func followupRead(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(os.Getenv("CS2_FOLLOWUP_DIR"), name))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestFollowupRuntimeReplay(t *testing.T) {
	root := os.Getenv("CS2_FOLLOWUP_DIR")
	if root == "" {
		t.Skip("supplied offline runtime files")
	}
	cfg := DefaultConfig()
	cfg.MapImageDir = filepath.Join(root, "maps")
	raw := followupRead(t, "gns-signon-20261020-164427.bin")
	all, rs, end := gnsSplitReliable(raw)
	max := 0
	server := 0
	for _, m := range all {
		if len(m) > max {
			max = len(m)
		}
		msgs, _, e := gnsParseNetMsgs(m)
		if e != nil {
			continue
		}
		for _, nm := range msgs {
			if nm.Cmd == 40 {
				server++
				gnsWalkPB(nm.Body, func(f, w int, v uint64, d []byte) {
					if f == 1 || f == 11 {
						fmt.Printf("SERVERINFO field=%d value=%d\n", f, v)
					}
					if f == 15 {
						fmt.Printf("RECORDED_MAP=%s\n", string(d))
					}
				})
			}
		}
	}
	fmt.Printf("OFFLINE_WHOLE messages=%d resync=%d end=%d bytes=%d max_message=%d serverinfo=%d\n", len(all), rs, end, len(raw), max, server)
	for _, size := range []int{1200, len(raw)} {
		s := NewStore(cfg).Get(fmt.Sprintf("chunks-%d", size))
		split := cs2snp.NewMsgSplit()
		count := 0
		for off := 0; off < len(raw); off += size {
			e := off + size
			if e > len(raw) {
				e = len(raw)
			}
			for _, m := range split.Feed(raw[off:e]) {
				count++
				s.feedMsg(s.decoder, "s2c", m)
			}
		}
		sn := s.Snapshot()
		id := ""
		if sn.Map != nil {
			id = sn.Map.ID
		}
		fmt.Printf("CHUNK_PROBE chunk=%d messages=%d map=%s source=%s players=%d synced=%v\n", size, count, id, sn.MapSource, len(sn.Players), sn.Synced)
	}
	// Real recorded SNP frame boundaries, not a one-shot message bypass.
	b := followupRead(t, "gns-plainbin-20261020-164520.bin")
	if len(b) < 12 || string(b[:4]) != "GNPB" {
		t.Fatal("GNPB header")
	}
	b = b[12:]
	s := NewStore(cfg).Get("runtime")
	parser := cs2snp.NewParser()
	stream := cs2snp.NewStream()
	split := cs2snp.NewMsgSplit()
	reasm := cs2snp.NewUnrelReassembler()
	frames, bad, records, sounds := 0, 0, 0, 0
	lastStatus := ""
	traces := 0
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatal("length")
		}
		l := int(binary.LittleEndian.Uint32(b))
		b = b[4:]
		if l <= 0 || l > len(b) {
			t.Fatal("record")
		}
		pkt := b[:l]
		b = b[l:]
		frames++
		segs, un, st := parser.Parse(pkt)
		if st.Bad != 0 {
			bad++
			continue
		}
		for _, u := range un {
			if m, ok := reasm.Feed(u, time.Now()); ok && u.Lane == 0 {
				if frames < 235 {
					if d := gnsDecodeUnrel(m); d != nil {
						for _, nm := range d.Msgs {
							if nm.Cmd == 55 {
								var tick, from, delta uint64
								gnsWalkPB(nm.Body, func(f, w int, v uint64, _ []byte) {
									if f == 12 {
										tick = v
									}
									if f == 6 {
										from = v
									}
									if f == 3 {
										delta = v
									}
								})
								fmt.Printf("PE_HEADER frame=%d tick=%d from=%d delta=%d seq=%d outerTick=%d\n", frames, tick, from, delta, d.Seq, d.Tick)
							}
						}
					}
				}
				s.noteGNSUnrel(m)
			}
		}
		for _, seg := range segs {
			stream.Add(seg.Pos, seg.Data)
		}
		for _, m := range split.Feed(stream.Take()) {
			records++
			s.feedMsg(s.decoder, "s2c", m)
			if list, _, e := gnsParseNetMsgs(m); e == nil {
				for _, x := range list {
					if x.Cmd == 208 {
						if _, _, _, ok := gnsParsePosMsg(x.Body); ok {
							sounds++
						}
					}
				}
			}
		}

		if s.entityDecoder != nil {
			_, synced, status := s.entityDecoder.Snapshot(time.Now())
			if status != lastStatus && traces < 12 {
				fmt.Printf("ENTITY_TRANSITION frame=%d synced=%v status=%s\n", frames, synced, status)
				lastStatus = status
				traces++
			}
		}
	}
	sn := s.Snapshot()
	id := ""
	if sn.Map != nil {
		id = sn.Map.ID
	}
	out := map[string]any{"frames": frames, "bad_snp": bad, "messages": records, "decoded_sound_events": sounds, "snapshot": sn}
	data, _ := json.MarshalIndent(out, "", "  ")
	if dest := os.Getenv("CS2_FOLLOWUP_OUTPUT"); dest != "" {
		if e := os.WriteFile(dest, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	visible := 0
	if sn.Map != nil {
		for _, x := range sn.Sounds {
			ix := (float64(x.Pos.X) - sn.Map.OriginWorldX) / sn.Map.UnitsPerPixel
			iy := (sn.Map.OriginWorldY - float64(x.Pos.Y)) / sn.Map.UnitsPerPixel
			if ix >= 0 && iy >= 0 && ix < float64(sn.Map.RefWidth) && iy < float64(sn.Map.RefHeight) {
				visible++
			}
		}
	}
	fmt.Printf("RUNTIME_PROBE frames=%d bad=%d messages=%d map=%s source=%s parsed_sounds=%d active_sounds=%d in_map=%d players=%d synced=%v status=%s\n", frames, bad, records, id, sn.MapSource, sounds, len(sn.Sounds), visible, len(sn.Players), sn.Synced, sn.Status)
	if sn.Map == nil || id != "de_dust2" || sn.MapSource != "serverinfo" || len(sn.Sounds) == 0 || !sn.Synced || len(sn.Players) != 9 {
		t.Fatal("map/sound runtime acceptance not met")
	}
}
