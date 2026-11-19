// Package viewframe is the entire public drawing contract. It deliberately has
// no dependency on a game decoder, world coordinates, or authorization secrets.
package viewframe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const Version = 1
const TeamVersion = 2
const NameVersion = 3
const MaxNameRunes = 32
const MaxBytes = 65536
const MaxPlayers = 128
const MaxSounds = 512

type Point struct {
	ID   string `json:"id"`
	PX   int    `json:"px"`
	PY   int    `json:"py"`
	Team int    `json:"team,omitempty"`
	Name string `json:"name,omitempty"`
}
type Frame struct {
	Version    int     `json:"v"`
	Generation string  `json:"generation"`
	Width      int     `json:"width"`
	Height     int     `json:"height"`
	MapID      string  `json:"map_id"`
	Image      string  `json:"image"`
	State      string  `json:"state"`
	Players    []Point `json:"players"`
	Sounds     []Point `json:"sounds"`
}

var mapID = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// CleanName is display-only: never account IDs, raw entity IDs, or HTML.
// Remove controls/bidi formatting, collapse whitespace, and bound rune count.
func CleanName(s string) string {
	s = strings.ToValidUTF8(s, "")
	runes := make([]rune, 0, MaxNameRunes)
	space := false
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if unicode.IsSpace(r) {
			space = len(runes) > 0
			continue
		}
		if space && len(runes) < MaxNameRunes {
			runes = append(runes, ' ')
		}
		space = false
		if len(runes) >= MaxNameRunes {
			break
		}
		runes = append(runes, r)
	}
	return strings.TrimSpace(string(runes))
}

func MapID(s string) bool { return mapID.MatchString(s) }
func ImagePath(s string) bool {
	for _, name := range []string{"overview.png", "density.png"} {
		const prefix = "/mapimg/"
		if len(s) > len(prefix)+len(name)+1 && s[:len(prefix)] == prefix {
			id := s[len(prefix) : len(s)-len(name)-1]
			if MapID(id) && s == prefix+id+"/"+name {
				return true
			}
		}
	}
	return false
}
func opaque(s string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == 16
}
func (f Frame) Validate() error {
	bad := errors.New("invalid drawing frame")
	if (f.Version != Version && f.Version != TeamVersion && f.Version != NameVersion) || !opaque(f.Generation) || f.Width < 1 || f.Width > 4096 || f.Height < 1 || f.Height > 4096 || len(f.Players) > MaxPlayers || len(f.Sounds) > MaxSounds {
		return bad
	}
	switch f.State {
	case "ready", "sounds_only", "waiting", "map_required":
	default:
		return bad
	}
	if f.MapID == "" {
		if f.Image != "" || len(f.Players)+len(f.Sounds) != 0 || (f.State != "map_required" && f.State != "waiting") {
			return bad
		}
	} else if !MapID(f.MapID) || (f.Image != "" && (!ImagePath(f.Image) || !strings.HasPrefix(f.Image, "/mapimg/"+f.MapID+"/"))) {
		return bad
	}
	seen := map[string]bool{}
	for group, points := range [][]Point{f.Players, f.Sounds} {
		for _, p := range points {
			if (group == 1 && p.Team != 0) || (group == 0 && ((f.Version == Version && p.Team != 0) || (f.Version >= TeamVersion && p.Team != 2 && p.Team != 3))) {
				return bad
			}
			if ((group == 1 || f.Version != NameVersion) && p.Name != "") || !utf8.ValidString(p.Name) || utf8.RuneCountInString(p.Name) > MaxNameRunes || p.Name != CleanName(p.Name) {
				return bad
			}
			if !opaque(p.ID) || seen[p.ID] || p.PX < 0 || p.PX >= f.Width || p.PY < 0 || p.PY >= f.Height {
				return bad
			}
			seen[p.ID] = true
		}
	}
	if f.State != "ready" && len(f.Players) != 0 {
		return bad
	}
	return nil
}
func Decode(raw []byte) (Frame, error) {
	var f Frame
	if len(raw) > MaxBytes {
		return f, errors.New("drawing frame too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&f); e != nil {
		return f, e
	}
	if d.Decode(new(any)) != io.EOF {
		return f, errors.New("trailing drawing data")
	}
	// Even an explicitly empty name is a v3 player-only member. Keep the old
	// wire whitelist exact instead of treating zero-value extensions as legacy.
	var members struct {
		Players []map[string]json.RawMessage `json:"players"`
		Sounds  []map[string]json.RawMessage `json:"sounds"`
	}
	if json.Unmarshal(raw, &members) != nil {
		return f, errors.New("invalid drawing members")
	}
	for group, points := range [][]map[string]json.RawMessage{members.Players, members.Sounds} {
		for _, p := range points {
			if value, exists := p["name"]; exists {
				if group == 1 || f.Version != NameVersion {
					return f, errors.New("name outside v3 player")
				}
				var text *string
				if json.Unmarshal(value, &text) != nil || text == nil {
					return f, errors.New("invalid name type")
				}
			}
		}
	}
	return f, f.Validate()
}
