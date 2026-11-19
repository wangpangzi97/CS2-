package uibridge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// Explicit opt-in to shipped public images; no production or user-state reads.
func TestAtlasPackagedAssets(t *testing.T) {
	root := os.Getenv("GAMESENSE_ATLAS_ASSET_FIXTURE")
	if root == "" {
		t.Skip("explicit local asset fixture only")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute asset fixture required")
	}
	b, c := atlasFixture(t)
	b.mapRoot = filepath.Join(root, "maps")
	v := atlasLoad(t, b, c)
	for _, m := range v.Maps {
		code, raw := atlasRequest(t, b, c, "/atlas/map/"+m.ID, nil, "")
		original, e := os.ReadFile(filepath.Join(b.mapRoot, m.ID, "overview.png"))
		if e != nil || code != http.StatusOK || !bytes.Equal(raw, original) {
			t.Fatalf("map bytes differ: %s status=%d err=%v", m.ID, code, e)
		}
	}
	for name := range v.Images {
		code, raw := atlasRequest(t, b, c, "/atlas/image/"+name, nil, "")
		original, e := os.ReadFile(filepath.Join(root, "atlas", "images", name))
		if e != nil || code != http.StatusOK || !bytes.Equal(raw, original) {
			t.Fatalf("image bytes differ: %s status=%d err=%v", name, code, e)
		}
	}
	// A valid catalog filename is still refused if its file has been replaced.
	isolated := t.TempDir()
	b.mapRoot = filepath.Join(isolated, "maps")
	if e := os.MkdirAll(filepath.Join(isolated, "atlas", "images"), 0700); e != nil {
		t.Fatal(e)
	}
	for name := range v.Images {
		if e := os.WriteFile(filepath.Join(isolated, "atlas", "images", name), []byte("tampered"), 0600); e != nil {
			t.Fatal(e)
		}
		code, _ := atlasRequest(t, b, c, "/atlas/image/"+name, nil, "")
		if code != 503 {
			t.Fatal("tampered image accepted", code)
		}
		break
	}
	raw, _ := json.Marshal(map[string]any{"maps": len(v.Maps), "images": len(v.Images), "tamper_rejected": true})
	t.Log("PACKAGED_ASSET_BYTES=" + string(raw))
}
