package radarsrv

import (
	"encoding/binary"
	"fmt"
	"local/cs2-radar/internal/cs2snp"
	"os"
	"path/filepath"
	"testing"
)

func TestFollowupAcceptance(t *testing.T) {
	root := os.Getenv("CS2_FOLLOWUP_DIR")
	if root == "" {
		t.Skip("recorded runtime fixture")
	}
	cfg := DefaultConfig()
	cfg.MapImageDir = filepath.Join(root, "maps")
	s := NewStore(cfg).Get("followup-acceptance")
	raw, e := os.ReadFile(filepath.Join(root, "gns-signon-20261020-164427.bin"))
	if e != nil {
		t.Fatal(e)
	}
	split := cs2snp.NewMsgSplit()
	count := 0
	for off := 0; off < len(raw); off += 1200 {
		end := off + 1200
		if end > len(raw) {
			end = len(raw)
		}
		for _, m := range split.Feed(raw[off:end]) {
			count++
			s.feedMsg(s.decoder, "s2c", m)
		}
	}
	b, e := os.ReadFile(filepath.Join(root, "gns-unrel-20261020-164424-71.bin"))
	if e != nil {
		t.Fatal(e)
	}
	records := 0
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatal("header")
		}
		n := int(binary.LittleEndian.Uint32(b))
		b = b[4:]
		if n <= 0 || n > len(b) {
			t.Fatal("length")
		}
		s.noteGNSUnrel(b[:n])
		b = b[n:]
		records++
	}
	sn := s.Snapshot()
	id := ""
	if sn.Map != nil {
		id = sn.Map.ID
	}
	fmt.Printf("FOLLOWUP_ACCEPT chunk=1200 messages=%d unrel_records=%d map=%s source=%s players=%d synced=%v\n", count, records, id, sn.MapSource, len(sn.Players), sn.Synced)
	if count != 258 || records != 71 || id != "de_dust2" || sn.MapSource != "serverinfo" || len(sn.Players) != 9 || !sn.Synced {
		t.Fatal("recorded map/player acceptance not met")
	}
}
func TestFollowupCompressedUnreliable(t *testing.T) {
	b, e := os.ReadFile(filepath.Join("..", "entitycodec", "testdata", "live-compressed04.bin"))
	if e != nil {
		t.Fatal(e)
	}
	d := gnsDecodeUnrel(b)
	if d == nil {
		t.Fatal("compressed packet ignored")
	}
	found := false
	for _, m := range d.Msgs {
		if m.Cmd == 55 {
			p := gnsDecodePacketEnts(m.Body)
			if p == nil || !p.IsDelta {
				t.Fatal("bad entities")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("lost compressed PacketEntities")
	}
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b[:10]...), 255, 255, 255, 255, 127)} {
		if gnsDecodeUnrel(bad) != nil {
			t.Fatal("corrupt compressed block accepted")
		}
	}
}
