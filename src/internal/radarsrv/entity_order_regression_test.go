package radarsrv

import (
	"encoding/json"
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"os"
	"sort"
	"strconv"
	"testing"
)

func phase44EntityConnection(t *testing.T, classFirst bool) (int, bool) {
	t.Helper()
	source, e := os.ReadFile("../entitycodec/testdata/serverinfo.pb")
	if e != nil {
		t.Fatal(e)
	}
	info := &msg.CSVCMsg_ServerInfo{}
	if e = proto.Unmarshal(source, info); e != nil {
		t.Fatal(e)
	}
	// A synthetic non-Dust2 connection name activates the existing LIVE metadata
	// requirement. Schema and entity body stay from the same supplied DEM fixture.
	info.MapName = proto.String("de_train")
	source, e = proto.Marshal(info)
	if e != nil {
		t.Fatal(e)
	}
	base, e := os.ReadFile("../entitycodec/assets/baselines.json")
	if e != nil {
		t.Fatal(e)
	}
	var values map[string][]byte
	if e = json.Unmarshal(base, &values); e != nil {
		t.Fatal(e)
	}
	ids := make([]int, 0, len(values))
	for k := range values {
		id, e := strconv.Atoi(k)
		if e != nil {
			t.Fatal(e)
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	bits := txnBits{}
	for _, id := range ids {
		bits.put(1, 1)
		bits.put(1, 1)
		bits.put(0, 1)
		for _, b := range []byte(strconv.Itoa(id)) {
			bits.put(uint32(b), 8)
		}
		bits.put(0, 8)
		bits.put(1, 1)
		body := values[strconv.Itoa(id)]
		bits.put(uint32(len(body)), 17)
		for _, b := range body {
			bits.put(uint32(b), 8)
		}
	}
	instance, e := proto.Marshal(&msg.CSVCMsg_CreateStringTable{Name: proto.String("instancebaseline"), NumEntries: proto.Int32(int32(len(ids))), StringData: bits.b})
	if e != nil {
		t.Fatal(e)
	}
	generic, e := proto.Marshal(&msg.CSVCMsg_CreateStringTable{Name: proto.String("genericprecache"), NumEntries: proto.Int32(0)})
	if e != nil {
		t.Fatal(e)
	}
	classes, e := proto.Marshal(&msg.CSVCMsg_ClassInfo{CreateOnClient: proto.Bool(true)})
	if e != nil {
		t.Fatal(e)
	}
	store := NewStore(DefaultConfig())
	s := store.Get("phase44-local-fixture")
	feed := func(cmd uint32, body []byte) { s.feedMsg(s.decoder, "s2c", txnPayload(cmd, body)) }
	if classFirst {
		feed(42, classes)
	}
	feed(44, generic)
	if !classFirst {
		feed(42, classes)
	}
	feed(44, instance)
	feed(40, source)
	full, e := os.ReadFile("../entitycodec/testdata/entities-00.pb")
	if e != nil {
		t.Fatal(e)
	}
	feed(55, full)
	snapshot := s.Snapshot()
	return len(snapshot.Players), snapshot.Synced
}

func TestEntityClassInfoBeforeFirstStringTable(t *testing.T) {
	control, cs := phase44EntityConnection(t, false)
	before, bs := phase44EntityConnection(t, true)
	fmt.Printf("ENTITY_CONTROL_PLAYERS=%d SYNCED=%t\nCLASSINFO_BEFORE_GENERIC_PLAYERS=%d SYNCED=%t\n", control, cs, before, bs)
	if control != 10 || !cs {
		t.Fatal("control fixture invalid")
	}
	if before != control || !bs {
		t.Fatal("current connection class metadata discarded at genericprecache")
	}
}
