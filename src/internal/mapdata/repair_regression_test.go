package mapdata

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestRepairExternalPNGValidationAndRefresh(t *testing.T) {
	r, _ := NewRegistry()
	dir := t.TempDir()
	d := filepath.Join(dir, "de_dust2")
	os.MkdirAll(d, 0755)
	r.SetExternalDir(dir)
	file := filepath.Join(d, "overview.png")
	os.WriteFile(file, []byte("not PNG"), 0644)
	m, _, _ := r.Resolve("de_dust2")
	if m.ImageKind == "external-overview" {
		t.Fatal("corrupt ready")
	}
	var b bytes.Buffer
	png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 8, 8)))
	os.WriteFile(file, b.Bytes(), 0644)
	m, _, _ = r.Resolve("de_dust2")
	if m.ImageKind != "external-overview" {
		t.Fatal("new image not discovered")
	}
	os.Remove(file)
	m, _, _ = r.Resolve("de_dust2")
	if m.ImageKind != "data-outline" {
		t.Fatal("missing not downgraded")
	}
}
