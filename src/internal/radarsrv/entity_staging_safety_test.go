package radarsrv

import (
	"bytes"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/entitycodec"
	"log"
	"strings"
	"testing"
	"time"
)

func TestEntityInitialMarkerDoesNotEraseFault(t *testing.T) {
	s := NewStore(DefaultConfig()).Get("fixture-not-logged")
	s.pendingEntityFault = "FAKE_PRIVATE_ERROR"
	generic, _ := proto.Marshal(&msg.CSVCMsg_CreateStringTable{Name: proto.String("genericprecache")})
	s.noteEntityMetadataLocked(44, generic)
	if s.pendingEntityFault != "FAKE_PRIVATE_ERROR" {
		t.Fatal("initial marker erased rejection")
	}
	s.resetGNSGenerationLocked()
	if s.pendingEntityFault != "" || len(s.pendingEntityMetadata) != 0 || s.pendingEntitySignon {
		t.Fatal("new generation retained metadata")
	}
}
func TestEntityReconnectMarkerDoesNotReusePreviousClass(t *testing.T) {
	s := NewStore(DefaultConfig()).Get("fixture-not-logged")
	s.entityDecoder = entitycodec.New()
	s.pendingEntityMetadata = []entityMetadata{{42, []byte{1}}}
	s.pendingEntityBytes = 1
	generic, _ := proto.Marshal(&msg.CSVCMsg_CreateStringTable{Name: proto.String("genericprecache")})
	s.noteEntityMetadataLocked(44, generic)
	if len(s.pendingEntityMetadata) != 1 || s.pendingEntityMetadata[0].cmd != 44 || !s.pendingEntitySignon {
		t.Fatal("old class prefix survived new signon")
	}
}
func TestNumericEntityLogNeverEchoesPrivateState(t *testing.T) {
	var out bytes.Buffer
	old := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(old)
	s := NewStore(DefaultConfig()).Get("FAKE_PRIVATE_ID")
	s.pendingEntityFault = "FAKE_PRIVATE_KEY_TOKEN"
	now := time.Now()
	s.logNumericEntityStageLocked(now, 0, 0)
	s.logNumericEntityStageLocked(now.Add(time.Second), 0, 0)
	text := out.String()
	if strings.Contains(text, "FAKE_PRIVATE") || strings.Count(text, "[GS-ENTITY]") != 1 || !strings.Contains(text, "stage=1 protocol=0 classes=0") {
		t.Fatal("numeric log boundary or rate failed")
	}
}
