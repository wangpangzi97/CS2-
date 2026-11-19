package radarsrv

import (
	"bytes"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIngressOriginClassifierExactlyMatchesOriginal(t *testing.T) {
	var inputs [][]byte
	b, e := os.ReadFile(filepath.Join("..", "entitycodec", "testdata", "live-compressed04.bin"))
	if e != nil {
		t.Fatal(e)
	}
	inputs = append(inputs, b)
	for i := 0; i < len(b); i += 17 {
		inputs = append(inputs, b[:i])
		v := append([]byte{}, b...)
		v[i] ^= 0x55
		inputs = append(inputs, v)
	}
	body, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	good := emptyDeltaTestWire(body, 74521)
	inputs = append(inputs, good)
	rng := rand.New(rand.NewSource(61))
	for i := 0; i < 10000; i++ {
		v := make([]byte, rng.Intn(192))
		rng.Read(v)
		if len(v) > 0 && i%3 != 0 {
			v[0] = []byte{2, 4}[i%2]
		}
		inputs = append(inputs, v)
	}
	for _, v := range inputs {
		want := originalUnrelForOriginTest(v)
		got, reason := gnsDecodeUnrelReason(v)
		if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gnsDecodeUnrel(v), want) || reason > 6 || (got != nil) != (reason == 0) {
			t.Fatal("diagnostics changed chain selection or acceptance")
		}
	}
	cases := [][]byte{nil, bytes.Repeat([]byte{1}, 12), append([]byte{2}, bytes.Repeat([]byte{255}, 11)...), append([]byte{2, 1}, bytes.Repeat([]byte{255}, 10)...), append([]byte{2, 1, 1}, make([]byte, 20)...)}
	for i, v := range cases {
		if _, reason := gnsDecodeUnrelReason(v); reason != uint8(i+1) {
			t.Fatal("fixed rejection enum mismatch")
		}
	}
}
func TestIngressOriginRealCallSitesAndPrivateLogBoundary(t *testing.T) {
	at := time.Now()
	s := NewStore(DefaultConfig()).Get("FAKE_PRIVATE_TOKEN_ID")
	s.entityDecoder = emptyDeltaTestDecoder(t, at)
	b, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	wire := emptyDeltaTestWire(b, 74521)
	s.traceGNSOuter(wire, 1, 0)
	s.noteGNSUnrel(wire)
	before := s.entityDecoder.NumericStatus(at)
	if before.IngressOuterMatches != 1 || before.IngressNetMatches != 1 {
		t.Fatal("actual caller contexts missing")
	}
	// A rejected, header-correlated source before the first missing dependency.
	bad := emptyDeltaTestWire(b, 74522)[:8]
	s.traceGNSOuter(bad, 1, 0)
	s.noteGNSUnrel(bad)
	m := &msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74522), ServerTick: proto.Uint32(74524)}
	payload, _ := proto.Marshal(m)
	if s.entityDecoder.PacketEntities(payload, at) == nil {
		t.Fatal("trace supplied an entity base")
	}
	st := s.entityDecoder.NumericStatus(at)
	if st.FirstMissingOuterFlags != 11 || st.FirstMissingOuterReason != 1 || s.pipeline.unrelRejectReasons[1].Load() != 1 {
		t.Fatal("real rejection receipt lost")
	}
	var out bytes.Buffer
	old := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(old)
	s.logNumericEntityStageLocked(at, 0, 0)
	s.logNumericEntityStageLocked(at.Add(time.Second), 0, 0)
	text := out.String()
	if strings.Contains(text, "FAKE_PRIVATE") || strings.Contains(text, "74522") || strings.Count(text, "[GS-ENTITY-ORIGIN]") != 1 || !strings.Contains(text, "outer_flags=11 outer_reason=1") {
		t.Fatal("privacy or original throttle changed")
	}
}
