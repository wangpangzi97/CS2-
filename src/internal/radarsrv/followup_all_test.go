package radarsrv

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This deliberately omits later reliable cmd55 messages. Real tick75039 and
// tick75040 are present only in the reliable channel; never invent their state.
func TestFollowupUnreliableOnlyFailsClosed(t *testing.T) {
	root := os.Getenv("CS2_FOLLOWUP_DIR")
	if root == "" {
		t.Skip("recorded runtime corpus")
	}
	cfg := DefaultConfig()
	cfg.MapImageDir = filepath.Join(root, "maps")
	s := NewStore(cfg).Get("all-unreliable")
	raw := followupRead(t, "gns-signon-20261020-164427.bin")
	all, _, _ := gnsSplitReliable(raw)
	for _, m := range all {
		s.feedMsg(s.decoder, "s2c", m)
	}
	files, _ := filepath.Glob(filepath.Join(root, "gns-unrel-*.bin"))
	records, compressed, decoded, entities, faults := 0, 0, 0, 0, 0
	start := time.Now()
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		for len(b) > 0 {
			if len(b) < 4 {
				t.Fatal("header")
			}
			n := int(binary.LittleEndian.Uint32(b))
			b = b[4:]
			if n <= 0 || n > len(b) {
				t.Fatal("size")
			}
			m := b[:n]
			b = b[n:]
			records++
			d := gnsDecodeUnrel(m)
			if m[0] == 4 {
				compressed++
				if d != nil {
					decoded++
				}
			}
			if d != nil {
				for _, nm := range d.Msgs {
					if nm.Cmd == 55 {
						entities++
					}
				}
			}
			s.noteGNSUnrel(m)
			if d != nil && s.entityDecoder != nil {
				_, ok, status := s.entityDecoder.Snapshot(time.Now())
				if !ok {
					if faults < 2 {
						fmt.Printf("FIRST_CORPUS_FAULT record=%d file=%s status=%s\n", records, filepath.Base(file), status)
						for _, nm := range d.Msgs {
							if nm.Cmd == 55 {
								gnsWalkPB(nm.Body, func(f, w int, v uint64, _ []byte) {
									if f == 6 || f == 12 {
										fmt.Printf("PE_FIELD %d=%d\n", f, v)
									}
								})
							}
						}
					}
					faults++
				}
			}
		}
	}
	sn := s.Snapshot()
	fmt.Printf("ALL_UNREL records=%d compressed=%d compressed_decoded=%d entities=%d faults=%d players=%d synced=%v elapsed=%s\n", records, compressed, decoded, entities, faults, len(sn.Players), sn.Synced, time.Since(start))
	if records != 7448 || compressed != 287 || decoded != 287 || faults == 0 || len(sn.Players) != 0 || sn.Synced {
		t.Fatal("compression coverage / missing reliable-baseline negative test failed")
	}
}
