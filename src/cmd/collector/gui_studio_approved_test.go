package main

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestApprovedBrandFragments(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, v := range []struct {
		at   time.Duration
		want string
	}{{0, "brand"}, {1099 * time.Millisecond, "brand"}, {1100 * time.Millisecond, "fragments"}, {2399 * time.Millisecond, "fragments"}, {2400 * time.Millisecond, "login"}} {
		if studioIntroPhase(v.at) != v.want {
			t.Fatal(v)
		}
	}
	if studioChroma(0) == studioChroma(1) || studioChroma(1) == studioChroma(1.32) {
		t.Fatal("brand color is static")
	}
	studioBuildIntroTiles()
	defer func() { studioIntroTiles = nil }()
	if len(studioIntroTiles) < 100 || studioIntroWordWidth < 200 {
		t.Fatal("glyph sampling empty", len(studioIntroTiles))
	}
	dir := os.Getenv("GS_STUDIO_RENDER_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	os.MkdirAll(dir, 0700)
	for _, v := range []struct {
		name string
		at   time.Duration
	}{{"brand", 600 * time.Millisecond}, {"fragments", 1600 * time.Millisecond}, {"intro-ended", 2400 * time.Millisecond}} {
		const w, h = 700, 280
		dc, _, _ := gdi32.NewProc("CreateCompatibleDC").Call(0)
		header := studioDIB{Size: 40, W: w, H: -h, Planes: 1, Bits: 32}
		var bits uintptr
		bmp, _, _ := gdi32.NewProc("CreateDIBSection").Call(dc, uintptr(unsafe.Pointer(&header)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
		if bmp == 0 || bits == 0 {
			t.Fatal("GDI surface unavailable")
		}
		old, _, _ := gdi32.NewProc("SelectObject").Call(dc, bmp)
		studioPaintIntro(dc, w, h, v.at)
		gdi32.NewProc("GdiFlush").Call()
		raw := unsafe.Slice((*byte)(unsafe.Pointer(bits)), w*h*4)
		img := image.NewNRGBA(image.Rect(0, 0, w, h))
		visible := 0
		for i := 0; i < len(raw); i += 4 {
			a := byte(0)
			if raw[i] != 0 || raw[i+1] != 0 || raw[i+2] != 0 {
				a = 255
				visible++
			}
			img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = raw[i+2], raw[i+1], raw[i], a
		}
		if v.name == "intro-ended" && visible != 0 {
			t.Fatal("fragments did not disappear")
		}
		if v.name != "intro-ended" && visible < 100 {
			t.Fatal("empty animation")
		}
		f, e := os.Create(filepath.Join(dir, v.name+".png"))
		if e != nil {
			t.Fatal(e)
		}
		if e = png.Encode(f, img); e != nil {
			t.Fatal(e)
		}
		f.Close()
		gdi32.NewProc("SelectObject").Call(dc, old)
		gdi32.NewProc("DeleteObject").Call(bmp)
		gdi32.NewProc("DeleteDC").Call(dc)
	}
	t.Logf("brand -> fragments (%d sampled squares) -> empty intro -> login", len(studioIntroTiles))
}
func TestApprovedMinimalNativeControls(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	old := gui
	defer func() { gui = old }()
	a := &guiApp{studio: newStudioUI()}
	gui = a
	if e := a.create(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		a.studio.cancel()
		pDestroyWindow.Call(uintptr(a.hwnd))
		inst, _, _ := pGetModuleHandleW.Call(0)
		user32.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(utf16(className))), inst)
		var m msgT
		user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&m)), 0, 0x12, 0x12, 1)
	}()
	a.studio.revealStart = time.Now().Add(-time.Second)
	a.studioRevealWindow()
	visible := func(h uintptr) bool { v, _, _ := user32.NewProc("IsWindowVisible").Call(h); return v != 0 }
	if !visible(uintptr(a.studio.card)) || visible(uintptr(a.hBtn1)) {
		t.Fatal("login visibility")
	}
	a.studio.page = "runtime"
	a.studioLayout()
	if visible(uintptr(a.studio.card)) || !visible(uintptr(a.hBtn1)) {
		t.Fatal("runtime visibility")
	}
	for _, h := range []uintptr{uintptr(a.studio.login), uintptr(a.hLog), uintptr(a.hBtn2), uintptr(a.studio.export)} {
		if visible(h) {
			t.Fatal("legacy control visible")
		}
	}
	if a.sess != nil || a.studio.busy {
		t.Fatal("capture started without card")
	}
	t.Log("login: masked EDIT only; runtime: open radar only; no session created")
}
