package runtimereport

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestV2DetailsAndLegacyRead(t *testing.T) {
	if binary.Size(Sample{}) != 280 {
		t.Fatal("wire size")
	}
	j, e := New(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	j.Record(Sample{OwnedUDP: 3, HeuristicUDP: 4, GNSAttempts: 7, GNSCandidate: 2, GNSParsed: 1, GNSRejected: 1, FilterState: 1, PeerSnapshot: 2, OwnedPorts: 3})
	files, e := j.files()
	if e != nil {
		t.Fatal(e)
	}
	got, e := ReadBinary(files["diagnostic.bin"])
	if e != nil || len(got) != 1 || got[0].OwnedUDP != 3 || got[0].GNSRejected != 1 || got[0].PeerSnapshot != 2 {
		t.Fatal("details")
	}
	var old bytes.Buffer
	h := header{Magic: [8]byte{'G', 'S', 'D', 'I', 'A', 'G', '0', '1'}, Version: 1, RecordSize: 120, Count: 1}
	if binary.Write(&old, binary.LittleEndian, h) != nil {
		t.Fatal("header")
	}
	prefix := make([]byte, 120)
	binary.LittleEndian.PutUint64(prefix, 1)
	prefix[112] = Waiting
	old.Write(prefix)
	legacy, e := ReadBinary(old.Bytes())
	if e != nil || len(legacy) != 1 || legacy[0].Phase != Waiting || legacy[0].PeerSnapshot != 0 || legacy[0].OwnedUDP != 0 {
		t.Fatal("legacy")
	}
	j.Record(Sample{FilterState: 255, PeerSnapshot: 255})
	files, _ = j.files()
	got, e = ReadBinary(files["diagnostic.bin"])
	if e != nil || got[1].FilterState != 0 || got[1].PeerSnapshot != 0 {
		t.Fatal("enum bounds")
	}
}
