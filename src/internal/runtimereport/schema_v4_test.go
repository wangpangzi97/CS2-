package runtimereport

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestV4CountersAndActualV3PrefixCompatibility(t *testing.T) {
	j, e := New(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	j.Record(Sample{Packets: 10, FilterState: 1, DirectionUnknown: 2, OwnershipRejected: 7, OwnershipRefreshes: 1})
	f, e := j.files()
	if e != nil {
		t.Fatal(e)
	}
	raw := f["diagnostic.bin"]
	if len(raw) != 24+280 || string(raw[:8]) != "GSDIAG04" {
		t.Fatal("current layout")
	}
	rows, e := ReadBinary(raw)
	if e != nil || rows[0].DirectionUnknown != 2 || rows[0].OwnershipRejected != 7 || rows[0].OwnershipRefreshes != 1 {
		t.Fatal("new counters", e)
	}
	var old bytes.Buffer
	h := header{Magic: [8]byte{'G', 'S', 'D', 'I', 'A', 'G', '0', '3'}, Version: 3, RecordSize: 256, Count: 1}
	if e = binary.Write(&old, binary.LittleEndian, h); e != nil {
		t.Fatal(e)
	}
	old.Write(raw[24 : 24+256])
	rows, e = ReadBinary(old.Bytes())
	if e != nil || rows[0].Packets != 10 || rows[0].DirectionUnknown != 0 || rows[0].OwnershipRejected != 0 || rows[0].OwnershipRefreshes != 0 {
		t.Fatal("v3 extension not zero filled", e)
	}
}
