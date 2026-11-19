package viewframe

import (
	"encoding/json"
	"testing"
)

func TestTeamVersionStrictCompatible(t *testing.T) {
	f := fixtureFrame()
	f.Version = TeamVersion
	f.State = "ready"
	f.Players = f.Sounds
	f.Sounds = nil
	f.Players[0].Team = 2
	if e := f.Validate(); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(f)
	if _, e := Decode(b); e != nil {
		t.Fatal(e)
	}
	f.Players[0].Team = 3
	if e := f.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, team := range []int{0, 1, 4, -1, 99} {
		f.Players[0].Team = team
		if f.Validate() == nil {
			t.Fatal("invalid team accepted")
		}
	}
	f.Players[0].Team = 2
	f.Version = Version
	if f.Validate() == nil {
		t.Fatal("v1 team extension accepted")
	}
	f.Players[0].Team = 0
	if e := f.Validate(); e != nil {
		t.Fatal("legacy neutral", e)
	}
	f.Version = TeamVersion
	f.Players[0].Team = 2
	f.Sounds = f.Players
	f.Players = nil
	if f.Validate() == nil {
		t.Fatal("sound promoted to team")
	}
}
