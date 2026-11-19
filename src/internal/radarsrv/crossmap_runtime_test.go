package radarsrv

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/cs2snp"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestCrossMapConnectionReplay(t *testing.T) {
	root := os.Getenv("LATEST_CAPTURE_DIR")
	if root == "" {
		t.Skip("explicit latest capture")
	}
	files, e := filepath.Glob(filepath.Join(root, "gns-plainbin-*.bin"))
	if e != nil || len(files) != 3 {
		t.Fatal("expected three GNPB windows")
	}
	cfg := DefaultConfig()
	cfg.MapImageDir = filepath.Join("..", "..", "dist", "maps")
	store := NewStore(cfg)
	s := store.Get("latest-173549")
	parser := cs2snp.NewParser()
	stream := cs2snp.NewStream()
	split := cs2snp.NewMsgSplit()
	reasm := cs2snp.NewUnrelReassembler()
	var trace []byte
	appendTrace := func(kind byte, data []byte) {
		trace = append(trace, kind)
		trace = binary.LittleEndian.AppendUint32(trace, uint32(len(data)))
		trace = append(trace, data...)
	}
	frames, bad, messages, unrel, pe := 0, 0, 0, 0, 0
	var full []byte
	observed, failures, minPlayers, maxPlayers, identityChecks, identityMissing, moving, healthChanges := 0, 0, 1000, 0, 0, 0, 0, 0
	previous := map[int]cs2proto.Player{}
	peerIDs := map[string]bool{}
	observe := func() {
		if s.entityDecoder == nil {
			return
		}
		ps, ok, _ := s.entityDecoder.Snapshot(time.Now())
		if !ok {
			return
		}
		observed++
		if len(ps) < minPlayers {
			minPlayers = len(ps)
		}
		if len(ps) > maxPlayers {
			maxPlayers = len(ps)
		}
		ids := map[int]bool{}
		for _, p := range ps {
			if ids[p.ID] || p.Team != 2 && p.Team != 3 || math.IsNaN(float64(p.Pos.X)) || math.IsNaN(float64(p.Pos.Y)) || p.Health < 0 || p.Health > 1000 {
				failures++
			}
			ids[p.ID] = true
			if p.SteamID != "" && p.SteamID != "0" {
				identityChecks++
				if !peerIDs[p.SteamID] {
					identityMissing++
				}
			}
			if old, ok := previous[p.ID]; ok {
				if old.Pos != p.Pos {
					moving++
				}
				if old.Health != p.Health || old.Alive != p.Alive {
					healthChanges++
				}
			}
			previous[p.ID] = p
		}
	}

	initialReason := ""
	serverInfoCount := 0
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) < 12 || string(b[:4]) != "GNPB" {
			t.Fatal("GNPB header")
		}
		b = b[12:]
		windowFrames := 0
		for len(b) > 0 {
			if len(b) < 4 {
				t.Fatal("record header")
			}
			l := int(binary.LittleEndian.Uint32(b))
			b = b[4:]
			if l <= 0 || l > len(b) {
				t.Fatal("record size")
			}
			pt := b[:l]
			b = b[l:]
			frames++
			windowFrames++
			segs, us, st := parser.Parse(pt)
			if st.Bad != 0 {
				bad++
				continue
			}
			for _, u := range us {
				if data, ok := reasm.Feed(u, time.Now()); ok && u.Lane == 0 {
					unrel++
					appendTrace(2, data)
					s.noteGNSUnrel(data)
					if d := gnsDecodeUnrel(data); d != nil {
						for _, nm := range d.Msgs {
							if nm.Cmd == 55 {
								pe++
							}
						}
					}
				}
			}
			for _, sg := range segs {
				stream.Add(sg.Pos, sg.Data)
			}
			for _, m := range split.Feed(stream.Take()) {
				messages++
				if list, _, e := gnsParseNetMsgs(m); e == nil {
					for _, nm := range list {
						if nm.Cmd == 60 {
							for _, p := range gnsParsePlayerList(nm.Body) {
								peerIDs[strconv.FormatUint(p.SteamID, 10)] = true
							}
						}
						if nm.Cmd == 42 {
							ci := &msg.CSVCMsg_ClassInfo{}
							e := proto.Unmarshal(nm.Body, ci)
							fmt.Printf("WIRE_CLASS_INFO classes=%d create=%v err=%v\n", len(ci.GetClasses()), ci.GetCreateOnClient(), e)
							_ = os.WriteFile(filepath.Join(filepath.Dir(os.Getenv("LATEST_CAPTURE_OUTPUT")), "wire-classinfo.pb"), nm.Body, 0600)
						}
						if nm.Cmd == 44 {
							ct := &msg.CSVCMsg_CreateStringTable{}
							e := proto.Unmarshal(nm.Body, ct)
							fmt.Printf("WIRE_TABLE %s entries=%d size=%d compressed=%v fixed=%v flags=%d varbits=%v err=%v\n", ct.GetName(), ct.GetNumEntries(), len(ct.StringData), ct.GetDataCompressed(), ct.GetUserDataFixedSize(), ct.GetFlags(), ct.GetUsingVarintBitcounts(), e)
							if ct.GetName() == "instancebaseline" {
								_ = os.WriteFile(filepath.Join(filepath.Dir(os.Getenv("LATEST_CAPTURE_OUTPUT")), "wire-instancebaseline.pb"), nm.Body, 0600)
							}
						}
					}
				}
				appendTrace(1, m)
				s.feedMsg(s.decoder, "s2c", m)
				if list, _, err := gnsParseNetMsgs(m); err == nil {
					for _, nm := range list {
						if nm.Cmd == 40 {
							serverInfoCount++
							if s.entityDecoder != nil {
								_, _, initialReason = s.entityDecoder.Snapshot(time.Now())
							}
							if out := os.Getenv("LATEST_CAPTURE_OUTPUT"); out != "" {
								_ = os.WriteFile(filepath.Join(filepath.Dir(out), "serverinfo.pb"), nm.Body, 0600)
							}
						}
						if nm.Cmd == 55 {
							pe++
							if q := gnsDecodePacketEnts(nm.Body); q != nil && !q.IsDelta {
								full = append([]byte(nil), nm.Body...)
							}
						}
					}
				}
			}
			observe()
		}
		fmt.Printf("WINDOW %s frames=%d stream_next=%d pending=%d\n", filepath.Base(file), windowFrames, stream.Next(), stream.PendingSegs())
	}
	fmt.Printf("CONNECTION_METADATA %s\n", s.entityDecoder.MetadataStatus())
	fmt.Printf("CONTINUITY observations=%d players_min=%d max=%d invalid=%d identity_checks=%d peer_missing=%d peer_ids=%d moving=%d health_changes=%d\n", observed, minPlayers, maxPlayers, failures, identityChecks, identityMissing, len(peerIDs), moving, healthChanges)
	if observed < 1000 || failures != 0 || identityChecks == 0 || identityMissing != 0 || moving == 0 {
		t.Fatal("continuous metadata/identity validation failed")
	}
	if out := os.Getenv("TRAIN_TRACE_OUTPUT"); out != "" {
		if e := os.WriteFile(out, trace, 0600); e != nil {
			t.Fatal(e)
		}
	}
	sn := s.Snapshot()
	mapID := ""
	if sn.Map != nil {
		mapID = sn.Map.ID
	}
	report := map[string]any{"frames": frames, "bad_snp": bad, "reliable_messages": messages, "complete_unreliable": unrel, "entity_messages": pe, "serverinfo_messages": serverInfoCount, "full_entity_messages": s.gnsFullEntityMessages, "compressed_received": s.gnsUnrel.CompressedSeen, "compressed_decoded": s.gnsUnrel.CompressedDecoded, "initial_profile_reason": initialReason, "snapshot": sn, "stream_pending": stream.PendingSegs(), "stream_max_gap": stream.MaxGap(), "map_assets": "current delivered source dist/maps; not assumed present in the desktop log-only directory"}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if out := os.Getenv("LATEST_CAPTURE_OUTPUT"); out != "" {
		if e := os.WriteFile(out, data, 0600); e != nil {
			t.Fatal(e)
		}
		if len(full) > 0 {
			_ = os.WriteFile(filepath.Join(filepath.Dir(out), "full-packetentities.pb"), full, 0600)
		}
	}
	fmt.Printf("LATEST_CAPTURE frames=%d bad=%d reliable=%d complete_unrel=%d entity_messages=%d serverinfo=%d full=%d lz4=%d/%d map=%s source=%s players=%d synced=%v\n", frames, bad, messages, unrel, pe, serverInfoCount, s.gnsFullEntityMessages, s.gnsUnrel.CompressedDecoded, s.gnsUnrel.CompressedSeen, mapID, sn.MapSource, len(sn.Players), sn.Synced)
	fmt.Printf("INITIAL_PROFILE_REASON=%s\nFINAL_STATUS=%s\n", initialReason, sn.Status)
	// Explicit replay of the provided Train capture; not an all-map/version correctness claim.
	if bad != 0 || serverInfoCount != 1 || s.gnsFullEntityMessages == 0 || mapID != "de_train" || sn.MapSource != "serverinfo" || !sn.Synced || len(sn.Players) == 0 || s.gnsUnrel.CompressedSeen != s.gnsUnrel.CompressedDecoded {
		t.Fatal("current connection replay acceptance failed")
	}
}
