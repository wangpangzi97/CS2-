package entitycodec

import (
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestNumericEntityStatusStagesAndBoundary(t *testing.T) {
	typ := reflect.TypeOf(NumericEntityStatus{})
	for i := 0; i < typ.NumField(); i++ {
		k := typ.Field(i).Type.Kind()
		if k < reflect.Uint || k > reflect.Uint64 {
			t.Fatal("non-numeric diagnostic")
		}
	}
	now := time.Now()
	d := New()
	if d.NumericStatus(now).Stage != 1 {
		t.Fatal("initial")
	}
	bad, _ := proto.Marshal(&msg.CSVCMsg_ServerInfo{Protocol: proto.Int32(99999), MaxClasses: proto.Int32(222)})
	_ = d.ServerInfo(bad)
	if got := d.NumericStatus(now); got.Stage != 2 || got.Protocol != 99999 {
		t.Fatal("profile cause lost")
	}
	info, _ := os.ReadFile("testdata/serverinfo.pb")
	full, _ := os.ReadFile("testdata/entities-00.pb")
	d = New()
	if e := d.ServerInfo(info); e != nil {
		t.Fatal(e)
	}
	if d.NumericStatus(now).Stage != 7 {
		t.Fatal("full wait")
	}
	if e := d.PacketEntities(full, now); e != nil {
		t.Fatal(e)
	}
	if d.NumericStatus(now).Stage != 9 {
		t.Fatal("ready")
	}
	if d.NumericStatus(now.Add(20*time.Second)).Stage != 8 {
		t.Fatal("TTL")
	}
	d.InvalidateMetadata("FAKE_PRIVATE_ERROR")
	if d.NumericStatus(now).Stage != 3 {
		t.Fatal("metadata rejection")
	}
}
