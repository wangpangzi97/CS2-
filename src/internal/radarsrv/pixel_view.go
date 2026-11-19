package radarsrv

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"sort"
	"time"

	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/mapdata"
	"local/cs2-radar/internal/viewframe"
)

// pixelState belongs to exactly one Store Session and is guarded by sess.mu.
// It is dropped on disconnect/revocation, map or decoder generation change.
type pixelState struct {
	generation, key string
	ids             map[string]string
}

func randomViewID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (v *pixelState) project(raw cs2proto.Snapshot) (viewframe.Frame, error) {
	return v.projectVersion(raw, viewframe.Version)
}
func (v *pixelState) projectVersion(raw cs2proto.Snapshot, version int) (viewframe.Frame, error) {
	f := viewframe.Frame{Version: version, Width: 1024, Height: 1024, State: "map_required", Players: []viewframe.Point{}, Sounds: []viewframe.Point{}}
	key := raw.MapState
	m := raw.Map
	usable := m != nil && raw.MapState == string(mapdata.StateReady) && viewframe.MapID(m.ID) && m.RefWidth > 0 && m.RefWidth <= 4096 && m.RefHeight > 0 && m.RefHeight <= 4096 && m.UnitsPerPixel > 0 && !math.IsInf(m.UnitsPerPixel, 0) && !math.IsNaN(m.UnitsPerPixel) && !math.IsInf(m.OriginWorldX, 0) && !math.IsNaN(m.OriginWorldX) && !math.IsInf(m.OriginWorldY, 0) && !math.IsNaN(m.OriginWorldY)
	if usable {
		key = fmt.Sprintf("%s/%s/%d/%d/%g/%g/%g/%s", raw.MapState, m.ID, m.RefWidth, m.RefHeight, m.OriginWorldX, m.OriginWorldY, m.UnitsPerPixel, m.ImageURI)
	}
	if v.generation == "" || v.key != key {
		id, e := randomViewID()
		if e != nil {
			return f, e
		}
		v.generation = id
		v.key = key
		v.ids = map[string]string{}
	}
	f.Generation = v.generation
	if !usable {
		v.ids = map[string]string{}
		return f, f.Validate()
	}
	f.MapID = m.ID
	f.Width = m.RefWidth
	f.Height = m.RefHeight
	if viewframe.ImagePath(m.ImageURI) {
		f.Image = m.ImageURI
	}
	f.State = "sounds_only"
	if raw.Synced {
		f.State = "ready"
	}
	next := map[string]string{}
	used := map[string]bool{}
	for _, id := range v.ids {
		used[id] = true
	}
	add := func(key string, pos cs2proto.Vec3, out *[]viewframe.Point, team int, name string) error {
		x, y := m.WorldToImage(float64(pos.X), float64(pos.Y))
		if math.IsNaN(x) || math.IsNaN(y) || math.IsInf(x, 0) || math.IsInf(y, 0) || x < 0 || y < 0 || x >= float64(f.Width) || y >= float64(f.Height) {
			return nil
		}
		px, py := int(math.Round(x)), int(math.Round(y))
		if px >= f.Width || py >= f.Height {
			return nil
		}
		if _, duplicate := next[key]; duplicate {
			return nil
		}
		id := v.ids[key]
		if id == "" {
			for {
				var e error
				id, e = randomViewID()
				if e != nil {
					return e
				}
				if !used[id] {
					break
				}
			}
		}
		used[id] = true
		next[key] = id
		*out = append(*out, viewframe.Point{ID: id, PX: px, PY: py, Team: team, Name: name})
		return nil
	}
	if raw.Synced {
		for _, p := range raw.Players {
			if len(f.Players) >= viewframe.MaxPlayers {
				break
			}
			if !p.Alive || p.Stale {
				continue
			}
			team := 0
			if version >= viewframe.TeamVersion {
				if p.Team != 2 && p.Team != 3 {
					continue
				}
				team = p.Team
			}
			name := ""
			if version == viewframe.NameVersion {
				name = viewframe.CleanName(p.Name)
			}
			if e := add(fmt.Sprintf("p/%d/%d/%d", p.ID, p.PawnID, p.Serial), p.Pos, &f.Players, team, name); e != nil {
				return f, e
			}
		}
	}
	for _, s := range raw.Sounds {
		if len(f.Sounds) >= viewframe.MaxSounds {
			break
		}
		if s.AgeMS < 0 || s.AgeMS > gnsSoundTTL.Milliseconds() {
			continue
		}
		if e := add(fmt.Sprintf("s/%d", s.Ent), s.Pos, &f.Sounds, 0, ""); e != nil {
			return f, e
		}
	}
	// Sorting by random IDs prevents wire ordering from exposing raw entity order.
	sort.Slice(f.Players, func(i, j int) bool { return f.Players[i].ID < f.Players[j].ID })
	sort.Slice(f.Sounds, func(i, j int) bool { return f.Sounds[i].ID < f.Sounds[j].ID })
	v.ids = next // disappearance retires the ID; returning entities receive a new one
	return f, f.Validate()
}
func (sess *Session) PixelView() (viewframe.Frame, error) {
	return sess.PixelViewVersion(viewframe.Version)
}
func (sess *Session) PixelViewVersion(version int) (viewframe.Frame, error) {
	if version != viewframe.Version && version != viewframe.TeamVersion && version != viewframe.NameVersion {
		return viewframe.Frame{}, fmt.Errorf("unsupported drawing version")
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	mi := sess.mapInfoLocked()
	raw := cs2proto.Snapshot{Map: mi.Def, MapState: string(mi.State), Sounds: sess.gnsSoundSnapshot(time.Now())}
	if sess.pendingEntitySignon {
		raw.Sounds = nil
		raw.Map = nil
		raw.MapState = "unknown"
	} else if sess.entityDecoder != nil {
		raw.Players, raw.Synced, _ = sess.entityDecoder.Snapshot(time.Now())
	}
	if sess.pixelView == nil {
		sess.pixelView = &pixelState{}
	}
	frame, err := sess.pixelView.projectVersion(raw, version)
	sess.logNumericEntityStageLocked(time.Now(), len(raw.Players), len(frame.Players))
	return frame, err
}
