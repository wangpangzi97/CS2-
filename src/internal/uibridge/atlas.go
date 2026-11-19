package uibridge

// Local reference content is separate from signed live drawing frames. This
// package never parses game traffic or sends edits/images to the remote service.
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	_ "image/jpeg"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const atlasLimit = 2 << 20

type atlasProp struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Type string   `json:"type"`
	Side string   `json:"side"`
	Keys []string `json:"keys"`
	Toss []string `json:"toss"`
	Move []string `json:"move"`
	Note string   `json:"note"`
	Imgs []string `json:"imgs"`
}
type atlasSpot struct {
	ID    string      `json:"id"`
	Map   string      `json:"map"`
	X     float64     `json:"x"`
	Y     float64     `json:"y"`
	Props []atlasProp `json:"props"`
}
type atlasState struct {
	Schema   int         `json:"schema"`
	Revision int64       `json:"revision"`
	Spots    []atlasSpot `json:"spots"`
}
type atlasLabel struct {
	ID   string  `json:"id"`
	Text string  `json:"text"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
}
type atlasImage struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Type   string `json:"type"`
}
type atlasCatalog struct {
	atlasState
	Features []string `json:"features"`
	Maps     []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"maps"`
	Labels        map[string][]atlasLabel `json:"labels"`
	Images        map[string]atlasImage   `json:"images"`
	AlignmentNote string                  `json:"alignment_note"`
	SourceSHA256  string                  `json:"source_sha256"`
}
type atlasStore struct {
	mu   sync.Mutex
	root string
	seed atlasCatalog
}

var atlasID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var errAtlasConflict = errors.New("reference revision conflict")

func atlasText(s string, max int) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}
func (s *atlasStore) valid(v atlasState) bool {
	if v.Schema != 1 || v.Revision < 0 || v.Revision > 1<<52 || len(v.Spots) > 1000 {
		return false
	}
	maps := map[string]bool{}
	for _, m := range s.seed.Maps {
		maps[m.ID] = true
	}
	seen := map[string]bool{}
	choices := func(a []string, allowed string) bool {
		if len(a) > 4 {
			return false
		}
		set := map[string]bool{}
		for _, x := range a {
			if !strings.Contains("|"+allowed+"|", "|"+x+"|") || x == "" || set[x] {
				return false
			}
			set[x] = true
		}
		return true
	}
	for _, p := range v.Spots {
		if !atlasID.MatchString(p.ID) || seen[p.ID] || !maps[p.Map] || math.IsNaN(p.X) || math.IsNaN(p.Y) || math.IsInf(p.X, 0) || math.IsInf(p.Y, 0) || p.X < 0 || p.X > 100 || p.Y < 0 || p.Y > 100 || len(p.Props) < 1 || len(p.Props) > 16 {
			return false
		}
		seen[p.ID] = true
		for _, q := range p.Props {
			if !atlasID.MatchString(q.ID) || seen[q.ID] || !atlasText(q.Name, 80) || strings.TrimSpace(q.Name) == "" || !atlasText(q.Note, 1500) || !choices([]string{q.Type}, "smoke|flash|fire|he") || !choices([]string{q.Side}, "T|CT|both") || !choices(q.Keys, "left|right|both") || !choices(q.Toss, "jump|nojump") || !choices(q.Move, "fwd|back|left|right") || len(q.Imgs) > 12 {
				return false
			}
			seen[q.ID] = true
			for _, i := range q.Imgs {
				if _, ok := s.seed.Images[i]; !ok {
					return false
				}
			}
		}
	}
	return true
}
func atlasRead(path string) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() > atlasLimit {
		return nil, errors.New("invalid local reference file")
	}
	return os.ReadFile(path)
}
func (s *atlasStore) load() (atlasState, error) {
	raw, e := atlasRead(filepath.Join(s.root, "data.json"))
	if os.IsNotExist(e) {
		return s.seed.atlasState, nil
	}
	if e != nil {
		return atlasState{}, e
	}
	var v atlasState
	if decode(raw, &v) != nil || !s.valid(v) {
		return atlasState{}, errors.New("local reference file invalid; preserve for recovery")
	}
	return v, nil
}
func atlasAtomic(path string, raw []byte) error {
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return errors.New("unsafe local reference target")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".atlas-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(name, path)
}
func (s *atlasStore) commit(expected int64, spots []atlasSpot, restore bool) (atlasState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, e := os.OpenFile(filepath.Join(s.root, "edit.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return atlasState{}, e
	}
	defer lock.Close()
	if e = acquireAtlasLock(lock); e != nil {
		return atlasState{}, errAtlasConflict
	}
	current, e := s.load()
	if e != nil {
		return atlasState{}, e
	}
	if current.Revision != expected {
		return atlasState{}, errAtlasConflict
	}
	if restore {
		raw, e := atlasRead(filepath.Join(s.root, "data.json.bak"))
		if e != nil {
			return atlasState{}, e
		}
		var old atlasState
		if decode(raw, &old) != nil || !s.valid(old) {
			return atlasState{}, errors.New("invalid local backup")
		}
		spots = old.Spots
	}
	next := atlasState{Schema: 1, Revision: current.Revision + 1, Spots: spots}
	if !s.valid(next) {
		return atlasState{}, errors.New("invalid local reference edits")
	}
	before, _ := json.Marshal(current)
	raw, _ := json.Marshal(next)
	if len(raw) > atlasLimit {
		return atlasState{}, errors.New("local reference size limit")
	}
	if e = atlasAtomic(filepath.Join(s.root, "data.json.bak"), before); e != nil {
		return atlasState{}, e
	}
	if e = atlasAtomic(filepath.Join(s.root, "data.json"), raw); e != nil {
		return atlasState{}, e
	}
	return next, nil
}
func (b *Bridge) atlasStore() (*atlasStore, error) {
	b.atlasOnce.Do(func() {
		raw, e := assets.ReadFile("atlas_seed.json")
		var seed atlasCatalog
		if e == nil {
			e = json.Unmarshal(raw, &seed)
		}
		if e != nil {
			b.atlasErr = e
			return
		}
		root := b.atlasDir
		if root == "" {
			var e error
			root, e = os.UserConfigDir()
			if e != nil {
				b.atlasErr = e
				return
			}
			root = filepath.Join(root, "gamesense", "atlas")
		}
		if e = os.MkdirAll(root, 0700); e != nil {
			b.atlasErr = e
			return
		}
		st, e := os.Lstat(root)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			b.atlasErr = errors.New("invalid local reference directory")
			return
		}
		s := &atlasStore{root: root, seed: seed}
		if !s.valid(seed.atlasState) {
			b.atlasErr = errors.New("invalid packaged reference data")
			return
		}
		b.atlas = s
	})
	return b.atlas, b.atlasErr
}
func (b *Bridge) serveAtlas(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/atlas/") {
		return false
	}
	b.mu.Lock()
	fresh := b.freshLocked()
	b.mu.Unlock()
	if !fresh {
		deny(w)
		return true
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/atlas/map/") {
		b.atlasMap(w, r)
		return true
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/atlas/image/") {
		b.atlasImage(w, r)
		return true
	}
	if r.Header.Get("X-Gamesense-View") != "1" {
		deny(w)
		return true
	}
	s, e := b.atlasStore()
	if e != nil {
		http.Error(w, "local reference storage unavailable; original retained", 503)
		return true
	}
	if r.Method == "GET" && r.URL.Path == "/atlas/data" {
		s.mu.Lock()
		v, e := s.load()
		s.mu.Unlock()
		if e != nil {
			http.Error(w, "local reference data invalid; do not overwrite", 503)
			return true
		}
		out := s.seed
		out.atlasState = v
		reply(w, out)
		return true
	}
	if r.Method != "POST" || (r.URL.Path != "/atlas/save" && r.URL.Path != "/atlas/restore") || r.Header.Get("Origin") != b.local || r.Header.Get("Content-Type") != "application/json" {
		deny(w)
		return true
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, atlasLimit))
	var v struct {
		Revision int64       `json:"revision"`
		Spots    []atlasSpot `json:"spots"`
	}
	if e != nil || decode(raw, &v) != nil || v.Revision < 0 {
		http.Error(w, "invalid local reference request", 400)
		return true
	}
	out, e := s.commit(v.Revision, v.Spots, r.URL.Path == "/atlas/restore")
	if errors.Is(e, errAtlasConflict) {
		http.Error(w, "reference changed; reload before saving", 409)
		return true
	}
	if e != nil {
		http.Error(w, "reference not saved; existing data retained", 400)
		return true
	}
	reply(w, map[string]any{"ok": true, "revision": out.Revision, "backup": true})
	return true
}
func (b *Bridge) atlasMap(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/atlas/map/")
	if b.mapRoot == "" || strings.Contains(id, "/") {
		deny(w)
		return
	}
	s, e := b.atlasStore()
	if e != nil {
		http.Error(w, "local reference unavailable", 503)
		return
	}
	known := false
	for _, m := range s.seed.Maps {
		if m.ID == id {
			known = true
		}
	}
	if !known {
		deny(w)
		return
	}
	b.atlasAsset(w, filepath.Join(b.mapRoot, id, "overview.png"), "image/png", "", 8<<20)
}
func (b *Bridge) atlasImage(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/atlas/image/")
	s, e := b.atlasStore()
	if e != nil || b.mapRoot == "" {
		http.NotFound(w, r)
		return
	}
	v, ok := s.seed.Images[name]
	if !ok || strings.ContainsAny(name, "/\\") {
		deny(w)
		return
	}
	b.atlasAsset(w, filepath.Join(filepath.Dir(b.mapRoot), "atlas", "images", name), v.Type, v.SHA256, 32<<20)
}
func (b *Bridge) atlasAsset(w http.ResponseWriter, path, ctype, hash string, limit int64) {
	for _, p := range []string{filepath.Dir(filepath.Dir(path)), filepath.Dir(path), path} {
		st, e := os.Lstat(p)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			http.Error(w, "local reference asset missing", 404)
			return
		}
	}
	st, e := os.Stat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() > limit {
		http.Error(w, "invalid local reference asset", 404)
		return
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		http.Error(w, "local reference asset missing", 404)
		return
	}
	h := sha256.Sum256(raw)
	if hash != "" && hex.EncodeToString(h[:]) != hash {
		http.Error(w, "local reference asset integrity failed", 503)
		return
	}
	cfg, _, e := image.DecodeConfig(bytes.NewReader(raw))
	if e != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 8192 || cfg.Height > 8192 {
		http.Error(w, "invalid local reference image", 503)
		return
	}
	b.mu.Lock()
	fresh := b.freshLocked()
	b.mu.Unlock()
	if !fresh {
		deny(w)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Write(raw)
}
