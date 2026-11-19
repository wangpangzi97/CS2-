package radarsrv

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/entitycodec"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type emptyDeltaTestBits struct {
	data []byte
	n    int
}

func (w *emptyDeltaTestBits) put(x uint32, n int) {
	for i := 0; i < n; i++ {
		if w.n/8 >= len(w.data) {
			w.data = append(w.data, 0)
		}
		if x&(1<<i) != 0 {
			w.data[w.n/8] |= 1 << uint(w.n%8)
		}
		w.n++
	}
}
func (w *emptyDeltaTestBits) message(cmd uint32, b []byte) {
	if cmd < 16 {
		w.put(cmd, 6)
	} else if cmd < 256 {
		w.put((cmd&15)|16, 6)
		w.put(cmd>>4, 4)
	} else if cmd < 4096 {
		w.put((cmd&15)|32, 6)
		w.put(cmd>>4, 8)
	} else {
		w.put((cmd&15)|48, 6)
		w.put(cmd>>4, 28)
	}
	var v [10]byte
	n := binary.PutUvarint(v[:], uint64(len(b)))
	for _, x := range v[:n] {
		w.put(uint32(x), 8)
	}
	for _, x := range b {
		w.put(uint32(x), 8)
	}
}
func emptyDeltaTestWire(body []byte, tick uint32) []byte {
	w := &emptyDeltaTestBits{}
	tickBody, _ := proto.Marshal(&msg.CNETMsg_Tick{Tick: proto.Uint32(tick)})
	w.message(4, tickBody)
	w.message(55, body)
	h := []byte{2, 1}
	h = binary.AppendUvarint(h, uint64(tick))
	for len(h) < 11 {
		h = append(h, 0)
	}
	return append(h, w.data...)
}
func emptyDeltaTestRead(t *testing.T, n string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("..", "entitycodec", "testdata", n))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func emptyDeltaTestDecoder(t *testing.T, at time.Time) *entitycodec.Decoder {
	t.Helper()
	d := entitycodec.New()
	if e := d.ServerInfo(emptyDeltaTestRead(t, "live-serverinfo.pb")); e != nil {
		t.Fatal(e)
	}
	if e := d.PacketEntities(emptyDeltaTestRead(t, "live-full.pb"), at); e != nil {
		t.Fatal(e)
	}
	return d
}
func emptyDeltaTestFeed(d *entitycodec.Decoder, b []byte, at time.Time) bool {
	parsed := gnsDecodeUnrel(b)
	if parsed == nil {
		return false
	}
	for _, m := range parsed.Msgs {
		if m.Cmd == 55 {
			_ = d.PacketEntities(m.Body, at)
		}
	}
	return true
}
func TestEmptyDeltaCheckpointDependency(t *testing.T) {
	at := time.Unix(100, 0)
	d := emptyDeltaTestDecoder(t, at)
	empty, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521), UpdatedEntries: proto.Int32(0)})
	// It is a valid no-change delta: entity_data(field7) is absent, not corrupt.
	emptyClassified := emptyDeltaTestFeed(d, emptyDeltaTestWire(empty, 74521), at.Add(time.Millisecond))
	good := emptyDeltaTestRead(t, "live-74523.pb")
	if !emptyDeltaTestFeed(d, emptyDeltaTestWire(good, 74523), at.Add(2*time.Millisecond)) {
		t.Fatal("control real-payload chain rejected")
	}
	future := &msg.CSVCMsg_PacketEntities{}
	if e := proto.Unmarshal(emptyDeltaTestRead(t, "live-74522.pb"), future); e != nil {
		t.Fatal(e)
	}
	future.ServerTick = proto.Uint32(74524)
	future.DeltaFrom = proto.Int32(74521)
	body, _ := proto.Marshal(future)
	if !emptyDeltaTestFeed(d, emptyDeltaTestWire(body, 74524), at.Add(3*time.Millisecond)) {
		t.Fatal("dependent real-payload chain rejected")
	}
	got, ok, _ := d.Snapshot(at.Add(3 * time.Millisecond))
	status := d.NumericStatus(at.Add(3 * time.Millisecond))
	raw, _ := json.Marshal(got)
	ref := emptyDeltaTestDecoder(t, at)
	future.DeltaFrom = proto.Int32(74515)
	reference, _ := proto.Marshal(future)
	if e := ref.PacketEntities(reference, at.Add(3*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	want, wok, _ := ref.Snapshot(at.Add(3 * time.Millisecond))
	expected, _ := json.Marshal(want)
	equal := ok && wok && string(raw) == string(expected)
	fmt.Printf("EMPTY_DELTA_CLASSIFIED=%t DEPENDENT_SYNCED=%t PLAYERS=%d EXACT_REFERENCE_MATCH=%t FAULT=%d MISSING_KIND=%d MISSING_GAP=%d LATE_SEEN=%d SYNTHETIC_DEPENDENCY=true\n", emptyClassified, ok, len(got), equal, status.FaultCode, status.MissingKind, status.MissingGap, status.LateSeen)
	if !emptyClassified || !equal || len(got) != 9 {
		t.Fatal("a valid zero-change tick was filtered before checkpointing and later declared baseline was lost")
	}
}
