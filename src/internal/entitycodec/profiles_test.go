package entitycodec

import (
	"encoding/json"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"os"
	"strings"
	"testing"
	"time"
)

func Test14192NonDust2StillRequiresLiveMetadata(t *testing.T) {
	raw, e := os.ReadFile("testdata/train-serverinfo.pb")
	if e != nil {
		t.Fatal(e)
	}
	info := &msg.CSVCMsg_ServerInfo{}
	if e = proto.Unmarshal(raw, info); e != nil {
		t.Fatal(e)
	}
	info.Protocol = proto.Int32(14192)
	raw, e = proto.Marshal(info)
	if e != nil {
		t.Fatal(e)
	}
	d := New()
	if e = d.ServerInfo(raw); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	if d.NumericStatus(now).Stage != 4 {
		t.Fatal("missing class map not enforced")
	}
	ci, e := os.ReadFile("testdata/train-classinfo.pb")
	if e != nil {
		t.Fatal(e)
	}
	if e = d.SignonMessage(42, ci); e != nil {
		t.Fatal(e)
	}
	if d.NumericStatus(now).Stage != 5 {
		t.Fatal("current baselines not enforced")
	}
	base, e := os.ReadFile("testdata/train-instancebaseline.pb")
	if e != nil {
		t.Fatal(e)
	}
	if e = d.SignonMessage(44, base); e != nil {
		t.Fatal(e)
	}
	if d.NumericStatus(now).Stage != 7 {
		t.Fatal("full frame wait not enforced")
	}
	if e = d.ServerInfo(raw); e != nil {
		t.Fatal(e)
	}
	if d.NumericStatus(now).Stage != 4 || d.liveBaselines || len(d.tables) > 0 || d.classOK {
		t.Fatal("previous connection reused")
	}
}

func TestValidatedProfilesClosedAndPinned(t *testing.T) {
	if e := verifyProfileAssets(); e != nil {
		t.Fatal(e)
	}
	b, e := assets.ReadFile("assets/validated_profiles.json")
	if e != nil {
		t.Fatal(e)
	}
	var doc struct {
		Profiles []struct {
			Protocol int32  `json:"protocol"`
			Classes  int32  `json:"classes"`
			Build    int32  `json:"build"`
			DemoSHA  string `json:"demo_sha256"`
		}
	}
	if e = json.Unmarshal(b, &doc); e != nil || len(doc.Profiles) != 2 {
		t.Fatal("provenance", e)
	}
	seen := map[int32]bool{}
	for _, p := range doc.Profiles {
		got, ok := entityProfile(p.Protocol, p.Classes)
		if !ok || seen[p.Protocol] || got.build != p.Build || len(p.DemoSHA) != 64 {
			t.Fatal("registry provenance mismatch")
		}
		seen[p.Protocol] = true
	}
	for _, p := range []int32{0, 14190, 14193, 99999} {
		if _, ok := entityProfile(p, 222); ok {
			t.Fatal("unvalidated protocol accepted")
		}
	}
	for _, n := range []int32{0, 221, 223, 1000} {
		if _, ok := entityProfile(14192, n); ok {
			t.Fatal("mismatched classes accepted")
		}
	}
}
func TestValidatedProtocolLabelsAndTTL(t *testing.T) {
	raw, e := os.ReadFile("testdata/serverinfo.pb")
	if e != nil {
		t.Fatal(e)
	}
	full, e := os.ReadFile("testdata/entities-00.pb")
	if e != nil {
		t.Fatal(e)
	}
	for _, protocol := range []int32{14191, 14192} {
		// Registry behavior only. The actual unmodified14192 DEMO replay and schema
		// SHA proof are external transaction evidence, not this relabeled fixture.
		info := &msg.CSVCMsg_ServerInfo{}
		if e = proto.Unmarshal(raw, info); e != nil {
			t.Fatal(e)
		}
		info.Protocol = proto.Int32(protocol)
		b, e := proto.Marshal(info)
		if e != nil {
			t.Fatal(e)
		}
		d := New()
		if e = d.ServerInfo(b); e != nil {
			t.Fatal(e)
		}
		now := time.Now()
		if e = d.PacketEntities(full, now); e != nil {
			t.Fatal(e)
		}
		ps, ok, _ := d.Snapshot(now)
		if !ok || len(ps) != 10 || d.NumericStatus(now).Stage != 9 {
			t.Fatal("valid profile state")
		}
		want := "profile14191-build10924"
		if protocol == 14192 {
			want = "profile14192-build10955"
		}
		for _, p := range ps {
			if !strings.HasSuffix(p.Source, want) {
				t.Fatal("wrong profile label")
			}
		}
		if _, ok, _ = d.Snapshot(now.Add(20 * time.Second)); ok || d.NumericStatus(now.Add(20*time.Second)).Stage != 8 {
			t.Fatal("TTL weakened")
		}
	}
}
