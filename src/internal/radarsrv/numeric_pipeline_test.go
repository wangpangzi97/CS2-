package radarsrv

import (
	"bytes"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNumericPipelineUsesAtomicCounters(t *testing.T) {
	var p numericPipeline
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				p.decryptOK.Add(1)
				p.fragments.Add(1)
			}
		}()
	}
	wg.Wait()
	if p.decryptOK.Load() != 32000 || p.fragments.Load() != 32000 {
		t.Fatal("concurrent counters lost")
	}
}
func TestNumericPipelineActualUnreliableIngressAndPrivateLogBoundary(t *testing.T) {
	at := time.Now()
	s := NewStore(DefaultConfig()).Get("FAKE_PRIVATE_SESSION_CARD_TOKEN")
	s.entityDecoder = emptyDeltaTestDecoder(t, at)
	b, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	s.noteGNSUnrel(emptyDeltaTestWire(b, 74521))
	s.noteGNSUnrel([]byte{2, 1})
	if s.pipeline.unrelSeen.Load() != 2 || s.pipeline.unrelDecoded.Load() != 1 || s.pipeline.unrelRejected.Load() != 1 || s.pipeline.unreliableEntities.Load() != 1 {
		t.Fatal("upstream pipeline counters not observed")
	}
	var out bytes.Buffer
	old := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(old)
	s.pendingEntityFault = "FAKE_PRIVATE_ERROR_BODY"
	s.logNumericEntityStageLocked(at, 0, 0)
	s.logNumericEntityStageLocked(at.Add(time.Second), 0, 0)
	text := out.String()
	if strings.Contains(text, "FAKE_PRIVATE") || strings.Count(text, "[GS-ENTITY-CAUSE]") != 1 || strings.Count(text, "[GS-ENTITY-PIPE]") != 1 || !strings.Contains(text, "unrel_seen=2 unrel_decoded=1 unrel_rejected=1") {
		t.Fatal("privacy or existing rate boundary changed")
	}
}
