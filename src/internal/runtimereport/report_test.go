package runtimereport

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestTypedSchemaNoFreeTextAndBinaryRoundtrip(t *testing.T) {
	typ := reflect.TypeOf(Sample{})
	for i := 0; i < typ.NumField(); i++ {
		k := typ.Field(i).Type.Kind()
		if k < reflect.Uint || k > reflect.Uint64 {
			t.Fatal("non-numeric report field")
		}
	}
	j, e := New(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	j.Record(Sample{Packets: 99, Phase: Freezing, Flags: Running, Players: 3})
	f, e := j.files()
	if e != nil {
		t.Fatal(e)
	}
	got, e := ReadBinary(f["diagnostic.bin"])
	if e != nil || len(got) != 1 || got[0].Packets != 99 || got[0].Phase != Freezing {
		t.Fatal("binary roundtrip")
	}
	if e = j.Flush(); e != nil {
		t.Fatal(e)
	}
	p, e := j.Export()
	if e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(p)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	if len(z.File) != 5 {
		t.Fatal("unexpected archive members")
	}
	if filepath.Dir(p) != j.Dir() {
		t.Fatal("archive outside run folder")
	}
	var meta struct {
		Fixture bool `json:"fixture_only"`
	}
	if json.Unmarshal(f["summary.json"], &meta) != nil || !meta.Fixture {
		t.Fatal("synthetic mislabeled")
	}
}
func TestBoundedRingStrictBinaryAndNoPlaintextChannel(t *testing.T) {
	j, e := New(t.TempDir(), false)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < MaxSamples+7; i++ {
		j.Record(Sample{Packets: uint64(i), Phase: 255, Flags: 255, Reserved: 255, View: 255})
	}
	f, e := j.files()
	if e != nil {
		t.Fatal(e)
	}
	r, e := ReadBinary(f["diagnostic.bin"])
	if e != nil || len(r) != MaxSamples || r[0].Sequence != 8 || r[0].Phase != Unknown || r[0].Reserved != 0 {
		t.Fatal("ring or enum bounds")
	}
	for _, raw := range [][]byte{f["diagnostic.bin"][:12], append(append([]byte{}, f["diagnostic.bin"]...), 0)} {
		if _, e = ReadBinary(raw); e == nil {
			t.Fatal("malformed binary accepted")
		}
	}
	for _, b := range f {
		if bytes.Contains(b, []byte("FAKE_PRIVATE_TOKEN_OR_KEY")) {
			t.Fatal("untyped secret channel")
		}
	}
	if e = j.Flush(); e != nil {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(j.Dir())
	if len(entries) != 5 {
		t.Fatal("unexpected persisted files")
	}
}
