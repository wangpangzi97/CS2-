package cs2snp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFollowupLargeMessageAcrossPackets(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 170204)
	h := []byte{0x20 | byte(len(data)&31)}
	h = binary.AppendUvarint(h, uint64(len(data)>>5))
	raw := append(h, data...)
	split := NewMsgSplit()
	var msgs [][]byte
	for off := 0; off < len(raw); off += 1200 {
		end := off + 1200
		if end > len(raw) {
			end = len(raw)
		}
		msgs = append(msgs, split.Feed(raw[off:end])...)
	}
	if len(msgs) != 1 || !bytes.Equal(msgs[0], data) {
		t.Fatalf("large message lost: messages=%d", len(msgs))
	}
	next := split.Feed([]byte{3, 'e', 'n', 'd'})
	if len(next) != 1 || string(next[0]) != "end" {
		t.Fatal("following boundary lost")
	}
}
func TestFollowupDeclaredLengthAndVarintBounds(t *testing.T) {
	b := binary.AppendUvarint([]byte{0x20}, uint64((maxReliableMessage+32)>>5))
	if _, _, ok, more := splitOne(b); ok || more {
		t.Fatal("oversize header accepted or held")
	}
	if _, _, ok, more := splitOne([]byte{0x20, 0x80}); ok || !more {
		t.Fatal("incomplete size lost")
	}
	if _, _, ok, more := splitOne(append([]byte{0x20}, bytes.Repeat([]byte{0xff}, 10)...)); ok || more {
		t.Fatal("overflow held as incomplete")
	}
}
