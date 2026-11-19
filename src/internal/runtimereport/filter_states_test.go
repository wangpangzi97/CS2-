package runtimereport

import (
	"os"
	"testing"
)

func TestV9FilterStateExtensionAndLegacyV3Layout(t *testing.T) {
	j, e := New(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	for state := uint8(0); state <= 9; state++ {
		j.Record(Sample{FilterState: state})
	}
	if e = j.Flush(); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(j.Dir() + "/diagnostic.bin")
	if e != nil {
		t.Fatal(e)
	}
	if len(b) != 24+10*280 {
		t.Fatal("v3 layout changed")
	}
	rows, e := ReadBinary(b)
	if e != nil || len(rows) != 10 {
		t.Fatal("reader failed", e)
	}
	for i := 0; i < 9; i++ {
		if rows[i].FilterState != uint8(i) {
			t.Fatal("safe enum lost")
		}
	}
	if rows[9].FilterState != 0 {
		t.Fatal("unknown state not clamped")
	}
}
