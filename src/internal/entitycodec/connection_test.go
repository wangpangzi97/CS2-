package entitycodec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/golang/snappy"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConnectionTrainMetadata(t *testing.T) {
	d := New()
	info, _ := os.ReadFile("testdata/train-serverinfo.pb")
	if e := d.ServerInfo(info); e != nil {
		t.Fatal(e)
	}
	ci, _ := os.ReadFile("testdata/train-classinfo.pb")
	if e := d.SignonMessage(42, ci); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile("testdata/train-instancebaseline.pb")
	if e := d.SignonMessage(44, raw); e != nil {
		t.Fatal(e)
	}
	if len(d.baselines) != 48 || !d.liveBaselines || !d.classOK || d.classMode != "client-cache" {
		t.Fatal(d.MetadataStatus())
	}
	cached, _ := assets.ReadFile("assets/baselines.json")
	var base map[string][]byte
	_ = json.Unmarshal(cached, &base)
	diff := 0
	for id, b := range d.baselines {
		if !bytes.Equal(b, base[fmt.Sprint(id)]) {
			diff++
		}
	}
	fmt.Printf("CURRENT_CONNECTION_BASELINES=%d cached=%d changed=%d controller_changed=%v pawn_changed=%v mode=%s\n", len(d.baselines), len(base), diff, !bytes.Equal(d.baselines[44], base["44"]), !bytes.Equal(d.baselines[45], base["45"]), d.classMode)
	if e := d.ServerInfo(info); e != nil {
		t.Fatal(e)
	}
	if d.liveBaselines || len(d.tables) > 0 || d.classOK {
		t.Fatal("reconnect retained previous connection")
	}
	full, _ := os.ReadFile("testdata/entities-00.pb")
	if e := d.PacketEntities(full, time.Now()); e == nil || !strings.Contains(e.Error(), "当前连接") {
		t.Fatal("cross-map without current baseline accepted", e)
	}
}
func TestConnectionMetadataRejectsIncompatibility(t *testing.T) {
	info, _ := os.ReadFile("testdata/train-serverinfo.pb")
	m := &msg.CSVCMsg_ServerInfo{}
	_ = proto.Unmarshal(info, m)
	m.Protocol = proto.Int32(99999)
	bad, _ := proto.Marshal(m)
	d := New()
	if d.ServerInfo(bad) == nil {
		t.Fatal("unknown protocol accepted")
	}
	before := d.fault
	_ = d.PacketEntities([]byte{}, time.Now())
	if d.fault != before {
		t.Fatal("specific reason overwritten")
	}
	d = New()
	_ = d.ServerInfo(info)
	wrong, _ := proto.Marshal(&msg.CSVCMsg_ClassInfo{CreateOnClient: proto.Bool(false)})
	if d.SignonMessage(42, wrong) == nil {
		t.Fatal("missing explicit class map accepted")
	}
	raw, _ := os.ReadFile("testdata/train-instancebaseline.pb")
	_ = d.SignonMessage(44, raw)
	if _, ok, _ := d.Snapshot(time.Now()); ok {
		t.Fatal("metadata failure published")
	}
	if d.SignonMessage(45, []byte{255}) == nil {
		t.Fatal("malformed update accepted")
	}
	u, _ := proto.Marshal(&msg.CSVCMsg_UpdateStringTable{TableId: proto.Int32(-1)})
	if d.SignonMessage(45, u) == nil {
		t.Fatal("negative table id accepted")
	}
}

type testBits struct {
	b   []byte
	pos int
}

func (w *testBits) put(v uint32, n int) {
	for i := 0; i < n; i++ {
		if w.pos/8 >= len(w.b) {
			w.b = append(w.b, 0)
		}
		w.b[w.pos/8] |= byte(v>>uint(i)&1) << uint(w.pos%8)
		w.pos++
	}
}
func (w *testBits) text(s string) {
	for _, b := range []byte(s) {
		w.put(uint32(b), 8)
	}
	w.put(0, 8)
}
func TestConnectionTableWireBounds(t *testing.T) {
	spec := &msg.CSVCMsg_CreateStringTable{Flags: proto.Int32(1)}
	w := &testBits{}
	w.put(1, 1)
	w.put(1, 1)
	w.put(0, 1)
	w.text("44")
	w.put(1, 1)
	w.put(1, 1)
	payload := snappy.Encode(nil, []byte{1, 2, 3})
	w.put(uint32(len(payload)), 17)
	for _, b := range payload {
		w.put(uint32(b), 8)
	}
	keys, values, e := readTable(connectionTable{spec: spec}, w.b, 1)
	if e != nil || !bytes.Equal(values["44"], []byte{1, 2, 3}) {
		t.Fatal(e)
	}
	update := &testBits{}
	update.put(1, 1)
	update.put(0, 1)
	update.put(1, 1)
	update.put(0, 1)
	update.put(1, 17)
	update.put(9, 8)
	_, values, e = readTable(connectionTable{spec: spec, keys: keys}, update.b, 1)
	if e != nil || !bytes.Equal(values["44"], []byte{9}) {
		t.Fatal("update omitted key", e)
	}
	for i := 0; i < len(w.b)-1; i++ {
		if _, _, e := readTable(connectionTable{spec: spec}, w.b[:i], 1); e == nil {
			t.Fatal("truncated entry accepted", i)
		}
	}
	hist := &testBits{}
	hist.put(1, 1)
	hist.put(1, 1)
	hist.put(1, 1)
	hist.put(31, 5)
	hist.put(31, 5)
	if _, _, e := readTable(connectionTable{spec: spec}, hist.b, 1); e == nil {
		t.Fatal("invalid key history accepted")
	}
	over := &testBits{}
	over.put(1, 1)
	over.put(1, 1)
	over.put(0, 1)
	over.text("44")
	over.put(1, 1)
	over.put(0, 1)
	over.put(63, 6)
	over.put(0xfffffff, 28)
	spec.UsingVarintBitcounts = proto.Bool(true)
	if _, _, e := readTable(connectionTable{spec: spec}, over.b, 1); e == nil {
		t.Fatal("overflow UBitInt accepted")
	}
}

func TestConnectionExplicitClassMap(t *testing.T) {
	raw, _ := assets.ReadFile("assets/classinfo.pb")
	demo := &msg.CDemoClassInfo{}
	_ = proto.Unmarshal(raw, demo)
	wire := &msg.CSVCMsg_ClassInfo{}
	for _, c := range demo.GetClasses() {
		wire.Classes = append(wire.Classes, &msg.CSVCMsg_ClassInfoClassT{ClassId: proto.Int32(c.GetClassId()), ClassName: proto.String(c.GetNetworkName())})
	}
	info, _ := os.ReadFile("testdata/train-serverinfo.pb")
	d := New()
	_ = d.ServerInfo(info)
	b, _ := proto.Marshal(wire)
	if e := d.SignonMessage(42, b); e != nil || d.classMode != "wire-verified" {
		t.Fatal(e)
	}
	wire.Classes[0].ClassName = proto.String("INCOMPATIBLE")
	b, _ = proto.Marshal(wire)
	if d.SignonMessage(42, b) == nil {
		t.Fatal("same class count with changed mapping accepted")
	}
	if e := d.PacketEntities([]byte{}, time.Now()); e == nil || !strings.Contains(e.Error(), "映射不匹配") {
		t.Fatal("class fault not retained", e)
	}
}
