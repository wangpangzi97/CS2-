package viewframe

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func fixtureFrame() Frame {
	return Frame{Version: 1, Generation: base64.RawURLEncoding.EncodeToString(make([]byte, 16)), Width: 100, Height: 100, State: "sounds_only", MapID: "fixture", Image: "/mapimg/fixture/overview.png", Players: []Point{}, Sounds: []Point{{ID: base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")), PX: 10, PY: 20}}}
}
func TestPixelFrameStrictWhitelist(t *testing.T) {
	f := fixtureFrame()
	raw, _ := json.Marshal(f)
	if _, e := Decode(raw); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{strings.Replace(string(raw), `"px":10`, `"px":10,"pos":{"x":120}`, 1), strings.Replace(string(raw), `"v":1`, `"v":1,"session":"secret"`, 1), string(raw) + `{}`, strings.Replace(string(raw), `"px":10`, `"px":10.5`, 1)} {
		if _, e := Decode([]byte(v)); e == nil {
			t.Fatal("non-whitelist accepted", v)
		}
	}
}
func TestPixelFrameBoundsAndAssets(t *testing.T) {
	for _, change := range []func(*Frame){func(f *Frame) { f.Width = 10000 }, func(f *Frame) { f.Sounds[0].PX = -1 }, func(f *Frame) { f.Sounds[0].PY = 100 }, func(f *Frame) { f.Generation = "42" }, func(f *Frame) { f.Image = "https://elsewhere.invalid/x.png" }, func(f *Frame) { f.Image = "/mapimg/x/overview.png" }, func(f *Frame) { f.MapID = strings.Repeat("a", 64) }, func(f *Frame) { f.Image = "/mapimg/fixture/../overview.png" }, func(f *Frame) { f.MapID = "" }, func(f *Frame) { f.Players = f.Sounds }, func(f *Frame) { f.Sounds = append(f.Sounds, f.Sounds[0]) }} {
		f := fixtureFrame()
		change(&f)
		if f.Validate() == nil {
			t.Fatal("invalid frame accepted", f)
		}
	}
	for _, s := range []string{"", "/", "/mapimg/", "/mapimg/a/x.png", "/mapimg/a/overview.png?x", "//host/mapimg/a/overview.png"} {
		if ImagePath(s) {
			t.Fatal("bad image accepted", s)
		}
	}
}
