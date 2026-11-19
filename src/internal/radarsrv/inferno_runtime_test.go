package radarsrv

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/cs2snp"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestInfernoRuntimeReplay(t *testing.T) {
	root := os.Getenv("INFERNO_INPUT")
	if root == "" {
		t.Skip("explicit current capture")
	}
	files, e := filepath.Glob(filepath.Join(root, "gns-plainbin-*.bin"))
	if e != nil || len(files) != 1 {
		t.Fatal("one current GNPB required")
	}
	cfg := DefaultConfig()
	cfg.MapImageDir = filepath.Join(root, "maps")
	s := NewStore(cfg).Get("inferno-201525")
	parser := cs2snp.NewParser()
	stream := cs2snp.NewStream()
	split := cs2snp.NewMsgSplit()
	reasm := cs2snp.NewUnrelReassembler()
	frames, bad, rel, unrel, pes, fulls := 0, 0, 0, 0, 0, 0
	hist := map[uint32]int{}
	faults := map[string]int{}
	fullEvents := []string{}
	maxPlayers := 0
	maxCacheBytes, maxCacheFrames, syncObservations, lostAfterSync, identityChecks, identityMissing, invalid := int64(0), 0, 0, 0, 0, 0, 0
	hadSync := false
	peers := map[string]bool{}

	var trace []byte
	appendTrace := func(k byte, b []byte) {
		trace = append(trace, k)
		trace = binary.LittleEndian.AppendUint32(trace, uint32(len(b)))
		trace = append(trace, b...)
	}
	monitor := func(channel string, cmd uint32, b []byte, after bool) {
		if after {
			if s.entityDecoder != nil {
				ps, syn, reason := s.entityDecoder.Snapshot(time.Now())
				if len(ps) > maxPlayers {
					maxPlayers = len(ps)
				}
				if syn {
					hadSync = true
					syncObservations++
				} else if hadSync {
					lostAfterSync++
				}
				v := reflect.ValueOf(s.entityDecoder).Elem()
				used := v.FieldByName("historyBytes").Int()
				if used > maxCacheBytes {
					maxCacheBytes = used
				}
				if n := v.FieldByName("history").Len(); n > maxCacheFrames {
					maxCacheFrames = n
				}
				for _, p := range ps {
					if p.Team != 2 && p.Team != 3 || math.IsNaN(float64(p.Pos.X)) || math.IsNaN(float64(p.Pos.Y)) || p.Health < 0 || p.Health > 1000 {
						invalid++
					}
					if p.SteamID != "" && p.SteamID != "0" {
						identityChecks++
						if !peers[p.SteamID] {
							identityMissing++
						}
					}
				}
				if !syn {
					faults[reason]++
					if faults[reason] == 1 {
						v := reflect.ValueOf(s.entityDecoder).Elem()
						fmt.Printf("FIRST_FAULT cache_bytes=%d cache_frames=%d last_tick=%d reason=%s\n", v.FieldByName("historyBytes").Int(), v.FieldByName("history").Len(), v.FieldByName("lastTick").Uint(), reason)
					}
				}
			}
			return
		}
		hist[cmd]++
		if cmd == 60 {
			for _, p := range gnsParsePlayerList(b) {
				peers[strconv.FormatUint(p.SteamID, 10)] = true
			}
		}
		if cmd == 40 || cmd == 42 {
			fmt.Printf("META frame=%d channel=%s cmd=%d bytes=%d\n", frames, channel, cmd, len(b))
		}
		if cmd == 55 {
			pes++
			m := &msg.CSVCMsg_PacketEntities{}
			e := proto.Unmarshal(b, m)
			if !m.GetLegacyIsDelta() || pes < 6 {
				line := fmt.Sprintf("PE frame=%d channel=%s seq=%d bytes=%d delta=%v from=%d tick=%d updated=%d max=%d err=%v", frames, channel, pes, len(b), m.GetLegacyIsDelta(), m.GetDeltaFrom(), m.GetServerTick(), m.GetUpdatedEntries(), m.GetMaxEntries(), e)
				fmt.Println(line)
				if !m.GetLegacyIsDelta() {
					fulls++
					fullEvents = append(fullEvents, line)
					if p := os.Getenv("INFERNO_OUTPUT"); p != "" {
						_ = os.WriteFile(filepath.Join(filepath.Dir(p), fmt.Sprintf("full-%d.pb", fulls)), b, 0600)
					}
				}
			}
		}
	}
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if len(b) < 12 || string(b[:4]) != "GNPB" {
			t.Fatal("header")
		}
		b = b[12:]
		for len(b) > 0 {
			if len(b) < 4 {
				t.Fatal("length")
			}
			n := int(binary.LittleEndian.Uint32(b))
			b = b[4:]
			if n <= 0 || n > len(b) {
				t.Fatal("length bound")
			}
			p := b[:n]
			b = b[n:]
			frames++
			segs, us, st := parser.Parse(p)
			if st.Bad != 0 {
				bad++
				continue
			}
			for _, v := range us {
				if data, ok := reasm.Feed(v, time.Now()); ok && v.Lane == 0 {
					unrel++
					if d := gnsDecodeUnrel(data); d != nil {
						for _, nm := range d.Msgs {
							monitor("unrel", nm.Cmd, nm.Body, false)
						}
					}
					appendTrace(2, data)
					s.noteGNSUnrel(data)
					monitor("", 0, nil, true)
				}
			}
			for _, sg := range segs {
				stream.Add(sg.Pos, sg.Data)
			}
			for _, m := range split.Feed(stream.Take()) {
				rel++
				list, _, _ := gnsParseNetMsgs(m)
				for _, nm := range list {
					monitor("reliable", nm.Cmd, nm.Body, false)
				}
				appendTrace(1, m)
				s.feedMsg(s.decoder, "s2c", m)
				for _, nm := range list {
					if nm.Cmd == 55 {
						ps, sy, why := s.entityDecoder.Snapshot(time.Now())
						pm := &msg.CSVCMsg_PacketEntities{}
						_ = proto.Unmarshal(nm.Body, pm)
						if !pm.GetLegacyIsDelta() {
							fmt.Printf("AFTER_FULL players=%d synced=%v status=%s\n", len(ps), sy, why)
							v := reflect.ValueOf(s.entityDecoder).Elem()
							fmt.Printf("CACHE_AFTER_FULL bytes=%d frames=%d\n", v.FieldByName("historyBytes").Int(), v.FieldByName("history").Len())
						}
					}
				}
				monitor("", 0, nil, true)
			}
		}
	}
	sn := s.Snapshot()
	mapID := ""
	if sn.Map != nil {
		mapID = sn.Map.ID
	}
	meta := "no decoder"
	if s.entityDecoder != nil {
		meta = s.entityDecoder.MetadataStatus()
	}
	fmt.Printf("INFERNO_REPLAY frames=%d bad=%d rel=%d unrel=%d pe=%d full=%d maxplayers=%d finalplayers=%d synced=%v map=%s pending=%d next=%d\n", frames, bad, rel, unrel, pes, fulls, maxPlayers, len(sn.Players), sn.Synced, mapID, stream.PendingSegs(), stream.Next())
	fmt.Printf("METADATA %s\nSTATUS %s\nFAULTS %v\n", meta, sn.Status, faults)
	fmt.Printf("INFERNO_CONTINUITY synchronized_observations=%d lost_after_sync=%d max_cache_bytes=%d max_cache_frames=%d identity_checks=%d identity_missing=%d invalid=%d peer_count=%d\n", syncObservations, lostAfterSync, maxCacheBytes, maxCacheFrames, identityChecks, identityMissing, invalid, len(peers))
	if os.Getenv("INFERNO_EXPECT_SYNC") == "1" && (!sn.Synced || len(sn.Players) != 8 || lostAfterSync != 0 || maxCacheBytes > 128<<20 || maxCacheFrames > 128 || identityMissing != 0 || identityChecks == 0 || invalid != 0) {
		t.Fatal("inferno cache/identity acceptance failed")
	}
	out := map[string]any{"continuity": map[string]any{"sync_observations": syncObservations, "lost_after_sync": lostAfterSync, "max_cache_bytes": maxCacheBytes, "max_cache_frames": maxCacheFrames, "identity_checks": identityChecks, "identity_missing": identityMissing, "invalid": invalid}, "frames": frames, "bad": bad, "reliable": rel, "unreliable": unrel, "pe": pes, "full": fulls, "max_players": maxPlayers, "snapshot": sn, "metadata": meta, "faults": faults, "full_events": fullEvents, "cmd_histogram": hist}
	if p := os.Getenv("INFERNO_OUTPUT"); p != "" {
		b, _ := json.MarshalIndent(out, "", "  ")
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		_ = os.WriteFile(filepath.Join(filepath.Dir(p), "inferno-transaction-stream.bin"), trace, 0600)
	}
}
