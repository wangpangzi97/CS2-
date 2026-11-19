package radarsrv

import (
	"bytes"
	"encoding/binary"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/cs2snp"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRepairMapMutation(t *testing.T) {
	st := newMapStore(t, Config{})
	h := st.fixtureHandler("")
	for _, tc := range []struct {
		method, body string
		want         int
	}{
		{"GET", "", 405}, {"POST", "{\"session\":\"safe\",\"name\":\"<b>marker</b>\"}", 400},
		{"POST", "{\"session\":\"safe\",\"name\":\"d2\"}", 200},
	} {
		req := httptest.NewRequest(tc.method, "/api/v1/map", bytes.NewBufferString(tc.body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("%s: %d %s", tc.method, w.Code, w.Body.String())
		}
	}
	if bytes.Contains([]byte(RadarPage), []byte("mw.innerHTML")) {
		t.Fatal("untrusted HTML sink remains")
	}
}
func TestRepairServerInfoResetsAndWins(t *testing.T) {
	st := newMapStore(t, Config{MapName: "d2"})
	s := st.Get("reset")
	s.noteGNSPlayerPos(1, cs2proto.Vec3{X: 10, Y: 10}, time.Now())
	s.noteGNSPlayers([]gnsPlayerEntry{{UserID: 1}})
	body := append([]byte{0x7a, 7}, []byte("de_nuke")...)
	s.mu.Lock()
	s.noteGNSServerInfoLocked(body)
	s.mu.Unlock()
	sn := s.Snapshot()
	if sn.Map == nil || sn.Map.ID != "de_nuke" || sn.MapSource != "serverinfo" || len(s.gnsPos) != 0 || s.gnsPlayerCount() != 0 {
		t.Fatal("signon generation not reset")
	}
	if sn.Synced || len(sn.Players) != 0 {
		t.Fatal("metadata is not player decoding")
	}
}
func TestRepairPeerListReplacement(t *testing.T) {
	s := &Session{}
	s.noteGNSPlayers([]gnsPlayerEntry{{UserID: 1}, {UserID: 2}})
	s.noteGNSPlayers([]gnsPlayerEntry{{UserID: 2}})
	if s.gnsPlayerCount() != 1 {
		t.Fatal("departed peer retained")
	}
	s.noteGNSPlayers(nil)
	if s.gnsPlayerCount() != 0 {
		t.Fatal("empty peer list ignored")
	}
}
func TestRepairLZ4Boundaries(t *testing.T) {
	b, e := gnsLZ4Block([]byte{0x50, 'h', 'e', 'l', 'l', 'o'}, 5)
	if e != nil || string(b) != "hello" {
		t.Fatal(b, e)
	}
	for _, c := range []struct {
		src []byte
		n   int
	}{{[]byte{0xf0}, 15}, {[]byte{0, 0, 0}, 4}, {[]byte{0x10, 'a', 2, 0}, 5}, {nil, gnsDecodedLimit + 1}} {
		if _, e := gnsLZ4Block(c.src, c.n); e == nil {
			t.Fatal("malformed lz4 accepted")
		}
	}
	if _, _, ok := readGNSVarint([]byte{255, 255, 255, 255, 0x7f}); ok {
		t.Fatal("overflow varint accepted")
	}
}
func TestRepairCapturedReplay(t *testing.T) {
	root := os.Getenv("CS2_REPLAY_DIR")
	if root == "" {
		t.Skip("set CS2_REPLAY_DIR for supplied offline corpus")
	}
	files, e := filepath.Glob(filepath.Join(root, "gns-msgs-*.bin"))
	if e != nil || len(files) == 0 {
		t.Fatal("missing replay")
	}
	records, compressed, decoded, full, server, tables := 0, 0, 0, 0, 0, 0
	replayStore := newMapStore(t, Config{MapImageDir: filepath.Join("..", "..", "dist", "maps")})
	replaySession := replayStore.Get("captured")
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		for len(b) > 0 {
			if len(b) < 4 {
				t.Fatal("record header")
			}
			n := int(binary.LittleEndian.Uint32(b))
			b = b[4:]
			if n > len(b) {
				t.Fatal("record size")
			}
			m := b[:n]
			b = b[n:]
			records++
			if len(m) == 0 || (m[0] != 1 && m[0] != 3) {
				continue
			}
			replaySession.feedMsg(replaySession.decoder, "s2c", m)
			data, _, e := gnsReliablePayload(m)
			if e != nil {
				t.Fatalf("%s: %v", file, e)
			}
			if m[0] == 3 {
				compressed++
				decoded += len(data)
			}
			list, _, e := gnsParseNetMsgs(m)
			if e != nil {
				t.Fatalf("%s: %v", file, e)
			}
			for _, nm := range list {
				switch nm.Cmd {
				case 40:
					server++
				case 44:
					tables++
				case 55:
					pe := gnsDecodePacketEnts(nm.Body)
					if pe != nil && !pe.IsDelta {
						full++
					}
				}
			}
		}
	}
	t.Logf("records=%d compressed=%d decoded_bytes=%d ServerInfo=%d CreateStringTable=%d full_PacketEntities=%d", records, compressed, decoded, server, tables, full)
	if compressed != 49 || decoded != 488690 || server != 1 || tables != 12 || full != 1 {
		t.Fatal("replay differs from independent evidence")
	}
	sn := replaySession.Snapshot()
	if sn.Map == nil || sn.Map.ID != "de_dust2" || sn.MapSource != "serverinfo" || replaySession.gnsPlayerCount() != 10 || replaySession.gnsFullEntityMessages != 1 || replaySession.gnsSchemaMessages != 0 {
		t.Fatalf("production pipeline: map=%+v source=%s peers=%d full=%d schema=%d", sn.Map, sn.MapSource, replaySession.gnsPlayerCount(), replaySession.gnsFullEntityMessages, replaySession.gnsSchemaMessages)
	}
	t.Logf("production snapshot: map=%s source=%s peer_count=%d schema_messages=%d full_entities=%d Synced=%v Players=%d", sn.Map.ID, sn.MapSource, replaySession.gnsPlayerCount(), replaySession.gnsSchemaMessages, replaySession.gnsFullEntityMessages, sn.Synced, len(sn.Players))

	b, e := os.ReadFile(filepath.Join(root, "gns-unrel-20261020-130512-142.bin"))
	if e != nil {
		t.Fatal(e)
	}
	for k := 0; k <= 54; k++ {
		if len(b) < 4 {
			t.Fatal("counterexample header")
		}
		n := int(binary.LittleEndian.Uint32(b))
		b = b[4:]
		if n > len(b) {
			t.Fatal("counterexample size")
		}
		m := b[:n]
		b = b[n:]
		if k == 54 {
			d := gnsDecodeUnrel(m)
			if d == nil || d.Start != 10 || len(d.Msgs) != 2 || d.Msgs[0].Cmd != 4 || d.Msgs[1].Cmd != 55 {
				t.Fatalf("counterexample still wrong: %+v", d)
			}
		}
	}
}

func TestRepairCapturedSNPReplay(t *testing.T) {
	root := os.Getenv("CS2_REPLAY_DIR")
	if root == "" {
		t.Skip("set CS2_REPLAY_DIR")
	}
	files, _ := filepath.Glob(filepath.Join(root, "gns-plainbin-*.bin"))
	if len(files) == 0 {
		t.Fatal("no GNPB replay")
	}
	parser := cs2snp.NewParser()
	reasm := cs2snp.NewUnrelReassembler()
	frames, segs, complete, offsets := 0, 0, 0, 0
	now := time.Unix(0, 0)
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if len(b) < 12 || string(b[:4]) != "GNPB" {
			t.Fatal("GNPB header")
		}
		b = b[12:]
		for len(b) > 0 {
			if len(b) < 4 {
				t.Fatal("GNPB length")
			}
			n := int(binary.LittleEndian.Uint32(b))
			b = b[4:]
			if n > len(b) {
				t.Fatal("GNPB record")
			}
			pkt := b[:n]
			b = b[n:]
			frames++
			_, un, st := parser.Parse(pkt)
			if st.Bad != 0 {
				t.Fatalf("bad SNP at %d", frames)
			}
			for _, u := range un {
				segs++
				if u.Offset != 0 {
					offsets++
				}
				if _, ok := reasm.Feed(u, now.Add(time.Duration(frames)*time.Millisecond)); ok {
					complete++
				}
			}
		}
	}
	t.Logf("GNPB_frames=%d fragments=%d offset_fragments=%d complete_messages=%d conflicts=%d invalid=%d", frames, segs, offsets, complete, reasm.Conflicts, reasm.Invalid)
	if frames != 12302 || segs != 11686 || offsets != 773 || complete != 10913 || reasm.Conflicts != 0 || reasm.Invalid != 0 {
		t.Fatal("SNP replay differs from independent evidence")
	}
}
func TestRepairGenerationReset(t *testing.T) {
	st := newMapStore(t, Config{MapName: "d2"})
	s := st.Get("generation")
	s.serverMapName = "de_nuke"
	s.mapInferred = "de_nuke"
	s.gnsPlayers = map[uint32]gnsPlayerEntry{1: {UserID: 1}}
	s.resetGNSGenerationLocked()
	sn := s.Snapshot()
	if sn.Map == nil || sn.Map.ID != "de_dust2" || sn.MapSource != "manual" || len(s.gnsPlayers) != 0 {
		t.Fatal("reset retained prior generation")
	}
}
