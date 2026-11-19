package transport

import (
	"encoding/binary"
	"testing"
)

func TestRepairIPv4UDPBounds(t *testing.T) {
	base := make([]byte, 32)
	base[0] = 0x45
	base[9] = 17
	binary.BigEndian.PutUint16(base[2:4], 32)
	binary.BigEndian.PutUint16(base[24:26], 12)
	for _, tc := range []struct {
		at int
		v  uint16
	}{{2, 0}, {2, 20}, {2, 27}, {2, 100}, {24, 0}, {24, 7}, {24, 13}, {6, 0x2000}, {6, 1}} {
		b := append([]byte(nil), base...)
		binary.BigEndian.PutUint16(b[tc.at:tc.at+2], tc.v)
		if _, e := ParseIPv4UDP(b); e == nil {
			t.Fatalf("bad bound accepted: %+v", tc)
		}
	}
}
