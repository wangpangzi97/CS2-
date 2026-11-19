package main

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestStudioErrorNeverEchoesCardOrToken(t *testing.T) {
	secret := "FAKE_CARD_AND_TOKEN_MUST_NOT_APPEAR"
	got := studioError(studioTestError(secret))
	if strings.Contains(got, secret) {
		t.Fatal("sensitive server message echoed")
	}
}

type studioTestError string

func (e studioTestError) Error() string { return string(e) }

// Draw the same production native painter offscreen. No screen capture or game work.
func TestStudioRenderFixtures(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dir := os.Getenv("GS_STUDIO_RENDER_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	os.MkdirAll(dir, 0700)
	type bitmapHeader struct {
		Size                   uint32
		W, H                   int32
		Planes, Bits           uint16
		Compression, SizeImage uint32
		XP, YP                 int32
		Used, Important        uint32
	}
	for _, page := range []string{"login", "runtime", "intro"} {
		w, h := 1040, 700
		if page == "intro" {
			w, h = 600, 140
		}
		dc, _, _ := gdi32.NewProc("CreateCompatibleDC").Call(0)
		header := bitmapHeader{Size: 40, W: int32(w), H: -int32(h), Planes: 1, Bits: 32}
		var bits uintptr
		bmp, _, _ := gdi32.NewProc("CreateDIBSection").Call(dc, uintptr(unsafe.Pointer(&header)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
		if bmp == 0 || bits == 0 {
			t.Fatal("offscreen surface unavailable")
		}
		old, _, _ := gdi32.NewProc("SelectObject").Call(dc, bmp)
		st := newStudioUI()
		st.page = page
		st.detail = "等待本机收包与完整握手；没有使用真实卡密或游戏数据。"
		st.stats = [6]string{"128", "等待握手包", "96", "de_dust2", "0", "2"}
		app := &guiApp{studio: st}
		if page == "intro" {
			studioFill(dc, 0, 0, w, h, 0)
			studioWord(dc, 106, 25, 72, 2, 1)
		} else {
			app.studioPaint(dc, w, h, 2)
		}
		gdi32.NewProc("GdiFlush").Call()
		raw := unsafe.Slice((*byte)(unsafe.Pointer(bits)), w*h*4)
		img := image.NewNRGBA(image.Rect(0, 0, w, h))
		visible := 0
		for i := 0; i < len(raw); i += 4 {
			alpha := byte(255)
			if page == "intro" && raw[i] == 0 && raw[i+1] == 0 && raw[i+2] == 0 {
				alpha = 0
			} else {
				visible++
			}
			img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = raw[i+2], raw[i+1], raw[i], alpha
		}
		if visible == 0 {
			t.Fatal("empty UI render")
		}
		f, e := os.Create(filepath.Join(dir, page+".png"))
		if e != nil {
			t.Fatal(e)
		}
		if e = png.Encode(f, img); e != nil {
			t.Fatal(e)
		}
		f.Close()
		st.cancel()
		gdi32.NewProc("SelectObject").Call(dc, old)
		gdi32.NewProc("DeleteObject").Call(bmp)
		gdi32.NewProc("DeleteDC").Call(dc)
	}
}
func TestStudioNativeLoginControlsNoCapture(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	oldGUI := gui
	defer func() { gui = oldGUI }()
	a := &guiApp{studio: newStudioUI()}
	gui = a
	if e := a.create(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		a.studio.cancel()
		pDestroyWindow.Call(uintptr(a.hwnd))
		var msg msgT
		user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0x12, 0x12, 1)
	}()
	if a.studio.card == 0 || a.studio.login == 0 || a.hBtn1 == 0 {
		t.Fatal("integrated controls missing")
	}
	index := int32(-16)
	style, _, _ := user32.NewProc("GetWindowLongPtrW").Call(uintptr(a.studio.card), uintptr(index))
	if style&0x20 == 0 {
		t.Fatal("card input not masked")
	}
	if a.sess != nil || a.studio.busy {
		t.Fatal("capture began before card submission")
	}
	// Local timer repaint only, not the collector run loop/submit handler.
	user32.NewProc("UpdateWindow").Call(uintptr(a.hwnd))
	time.Sleep(30 * time.Millisecond)
}
func TestStudioLocalFreezeRemainsGuarded(t *testing.T) {
	if *flagFreeze != "short" || *flagAllowAC {
		t.Fatal("local freeze default or anti-cheat boundary changed")
	}
	raw, e := os.ReadFile("main.go")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), "s.startKeySearch()") || !strings.Contains(string(raw), "newSender(lease)") {
		t.Fatal("local key/remote data boundary missing")
	}
}

func TestStudioTextOnlyFadeTiming(t *testing.T) {
	if studioIntroAlpha(time.Second) != 255 || studioIntroAlpha(1700*time.Millisecond) != 0 {
		t.Fatal("intro transition timing")
	}
	if a := studioIntroAlpha(1400 * time.Millisecond); a <= 0 || a >= 255 {
		t.Fatal("intro does not fade")
	}
}
