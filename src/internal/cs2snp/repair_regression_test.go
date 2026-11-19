package cs2snp

import (
	"bytes"
	"testing"
	"time"
)

func TestRepairUnreliableReassembly(t *testing.T) {
	r := NewUnrelReassembler()
	now := time.Now()
	if _, ok := r.Feed(UnrelMsg{Num: 7, Offset: 3, Last: true, Data: []byte("def")}, now); ok {
		t.Fatal("last fragment isn't full message")
	}
	b, ok := r.Feed(UnrelMsg{Num: 7, Data: []byte("abc")}, now)
	if !ok || string(b) != "abcdef" {
		t.Fatal(string(b), ok)
	}
	if _, ok = r.Feed(UnrelMsg{Num: 7, Last: true, Data: b}, now); ok {
		t.Fatal("duplicate emitted")
	}
}
func TestRepairUnreliableConflictExpiryAndLanes(t *testing.T) {
	now := time.Now()
	r := NewUnrelReassembler()
	r.Feed(UnrelMsg{Num: 1, Data: []byte("abc")}, now)
	if _, ok := r.Feed(UnrelMsg{Num: 1, Offset: 1, Last: true, Data: []byte("XX")}, now); ok || r.Conflicts != 1 {
		t.Fatal("overlap conflict")
	}
	r.Feed(UnrelMsg{Num: 2, Data: []byte("abc")}, now)
	r.Feed(UnrelMsg{Num: 2, Offset: 3, Last: true, Data: []byte("def")}, now.Add(3*time.Second))
	if r.Expired != 1 {
		t.Fatal("no expiry")
	}
	r = NewUnrelReassembler()
	r.Feed(UnrelMsg{Lane: 0, Num: 1, Data: []byte("abc")}, now)
	if _, ok := r.Feed(UnrelMsg{Lane: 1, Num: 1, Offset: 3, Last: true, Data: []byte("def")}, now); ok {
		t.Fatal("lanes merged")
	}
	if _, ok := r.Feed(UnrelMsg{Num: 5, Offset: 1 << 30, Last: true, Data: []byte("a")}, now); ok {
		t.Fatal("huge offset")
	}
}
func TestRepairSNPFragmentMetadata(t *testing.T) {
	p := NewParser()
	_, u, st := p.Parse([]byte{0x2f, 7, 0, 3, 'd', 'e', 'f'})
	if st.Bad != 0 || len(u) != 1 || u[0].Offset != 3 || !u[0].Last {
		t.Fatal(u, st)
	}
	for _, b := range [][]byte{{0x83}, {0x98, 1}} {
		_, _, st = p.Parse(b)
		if st.Bad == 0 {
			t.Fatal("truncated control")
		}
	}
}
func TestRepairReliableOverlap(t *testing.T) {
	s := NewStream()
	s.Add(1, []byte("ab"))
	s.Add(5, []byte("efg"))
	s.Add(3, []byte("cdef"))
	if !bytes.Equal(s.Take(), []byte("abcdefg")) {
		t.Fatal("overlap did not drain")
	}
}

func TestRepairSNPMessageNumberAcrossReliable(t *testing.T) {
	p := NewParser()
	// unrel #17, reliable one-byte payload, then implicit unrel #19.
	_, u, st := p.Parse([]byte{0x20, 17, 0, 1, 'a', 0x40, 1, 0, 0, 1, 'r', 0x27, 'b'})
	if st.Bad != 0 || len(u) != 2 || u[1].Num != 19 {
		t.Fatal(u, st)
	}
}
