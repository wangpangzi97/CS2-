package viewframe

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNameVersionSanitizationAndIsolation(t *testing.T) {
	for _, s := range []string{"  测试  名称  ", "甲\x00\n乙\u202e丙", strings.Repeat("中", 99), "emoji 😀", string([]byte{0xff, 'a'}), "<img src=x>"} {
		clean := CleanName(s)
		if CleanName(clean) != clean || len([]rune(clean)) > 32 {
			t.Fatal("unsafe cleanup")
		}
	}
	if CleanName("  甲  乙\u202e\x00  ") != "甲 乙" {
		t.Fatal("control cleanup")
	}
	f := fixtureFrame()
	f.Version = NameVersion
	f.State = "ready"
	f.Players = f.Sounds
	f.Sounds = nil
	f.Players[0].Team = 2
	f.Players[0].Name = "玩家 <文字>"
	raw, _ := json.Marshal(f)
	if _, e := Decode(raw); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"\x00bad", "\u202ebad", " bad", strings.Repeat("中", 33)} {
		f.Players[0].Name = name
		if f.Validate() == nil {
			t.Fatal("unsafe name accepted")
		}
	}
	f.Players[0].Name = "name"
	for _, v := range []int{Version, TeamVersion} {
		f.Version = v
		if f.Validate() == nil {
			t.Fatal("name added to old version")
		}
	}
	f.Version = NameVersion
	f.Sounds = f.Players
	f.Players = nil
	f.Sounds[0].Team = 0
	if f.Validate() == nil {
		t.Fatal("sound assigned name")
	}
	legacy := fixtureFrame()
	b, _ := json.Marshal(legacy)
	b = []byte(strings.Replace(string(b), `"px":10`, `"name":"","px":10`, 1))
	if _, e := Decode(b); e == nil {
		t.Fatal("empty legacy name extension accepted")
	}
}
