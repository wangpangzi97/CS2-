package main

// Approved v3 visual layer only. Credentials stay in the native masked EDIT.
import (
	"math"
	"syscall"
	"time"
	"unsafe"
)

var studioInk = studioRGB(16, 14, 18)
var studioSurface = studioRGB(27, 21, 29)
var studioLine = studioRGB(70, 52, 72)
var studioPalette = [5]uintptr{studioRGB(237, 165, 207), studioRGB(242, 191, 157), studioRGB(231, 216, 141), studioRGB(172, 220, 188), studioRGB(198, 164, 239)}

func studioMix(a, b uintptr, t float64) uintptr {
	t = math.Max(0, math.Min(1, t))
	var c uintptr
	for shift := uint(0); shift < 24; shift += 8 {
		v := float64((a>>shift)&255)*(1-t) + float64((b>>shift)&255)*t
		c |= uintptr(v) << shift
	}
	return c
}
func studioChroma(t float64) uintptr {
	x := math.Mod(t/4.8, 1)
	if x < 0 {
		x++
	}
	v := x * 5
	i := int(v)
	return studioMix(studioPalette[i%5], studioPalette[(i+1)%5], v-float64(i))
}
func studioParticles(dc uintptr, w, h int, t float64) {
	for i := 0; i < 48; i++ {
		seed := float64(i + 1)
		x := int(math.Mod(seed*137.3+math.Sin(t*.12+seed)*5, float64(w)))
		yy := math.Mod(seed*83.7-t*(3+math.Mod(seed, 5)), float64(h))
		if yy < 0 {
			yy += float64(h)
		}
		a := .2 + .16*(math.Sin(t*.6+seed)+1)/2
		c := studioMix(studioInk, studioPalette[i%5], a)
		size := 1 + i%2
		studioFill(dc, x, int(yy), size, size, c)
	}
}
func studioCardRect(w, h int) (int, int, int, int) {
	width := 360
	if width > w-80 {
		width = w - 80
	}
	return (w - width) / 2, (h - 62) / 2, width, 62
}
func studioDashboardRect(w, h int) (int, int, int) {
	width := 800
	if width > w-120 {
		width = w - 120
	}
	return (w - width) / 2, h/2 - 112, width
}
func studioMapLabel(id string) string {
	names := map[string]string{"de_dust2": "炙热沙城Ⅱ", "de_ancient": "远古遗迹", "de_inferno": "炼狱小镇", "de_mirage": "荒漠迷城", "de_anubis": "阿努比斯", "de_nuke": "核子危机", "de_vertigo": "殒命大厦", "de_overpass": "死亡游乐园", "de_train": "列车停放站", "cs_office": "办公室", "de_cache": "死城之谜", "cs_agency": "办公大楼", "cs_italy": "意大利小镇", "de_golden": "黄金城", "de_grail": "圣杯", "de_palacio": "宫殿", "de_thera": "圣托里尼"}
	if v := names[id]; v != "" {
		return v
	}
	if id == "" {
		return "等待地图"
	}
	return id
}
func studioCount(s string) string {
	if s == "" {
		return "0"
	}
	return s
}
func studioButtonFill(dc uintptr, w, h int) {
	for i := 0; i < 24; i++ {
		c := studioMix(studioPalette[0], studioPalette[4], float64(i)/23)
		if i > 12 {
			c = studioMix(studioPalette[4], studioPalette[3], float64(i-12)/11)
		}
		studioFill(dc, i*w/24, 0, (i+1)*w/24-i*w/24+1, h, c)
	}
}
func (a *guiApp) studioPaint(dc uintptr, w, h int, t float64) {
	st := a.studio
	studioFill(dc, 0, 0, w, h, studioInk)
	studioParticles(dc, w, h, t)
	studioWord(dc, 40, 35, 25, t, 1)
	white, muted := studioRGB(248, 244, 248), studioRGB(183, 165, 187)
	if st.page == "login" {
		x, y, cw, ch := studioCardRect(w, h)
		studioFill(dc, x, y, cw, ch, studioLine)
		studioFill(dc, x+1, y+1, cw-2, ch-3, studioSurface)
		for i := 0; i < 5; i++ {
			studioFill(dc, x+i*cw/5, y+ch-2, cw/5+1, 2, studioMix(studioSurface, studioPalette[i], .65))
		}
		if !st.revealStart.IsZero() {
			studioText(dc, "卡密", x+22, y+19, cw-44, 28, 16, muted)
		}
		if st.busy {
			studioText(dc, "正在验证…", x+22, y+19, cw-44, 28, 16, muted)
		}
		if st.errText != "" {
			studioText(dc, st.errText, x, y+ch+12, cw, 66, 12, studioRGB(235, 168, 168))
		}
		return
	}
	x, y, pw := studioDashboardRect(w, h)
	mapx, peoplex, soundx := x, x+pw-236, x+pw-80
	studioText(dc, "地图", mapx, y, pw-276, 24, 14, muted)
	studioText(dc, studioMapLabel(st.stats[3]), mapx, y+34, pw-276, 48, 32, white)
	studioText(dc, "可信人物", peoplex, y, 120, 24, 14, muted)
	studioText(dc, studioCount(st.stats[4]), peoplex, y+34, 112, 48, 32, white)
	studioText(dc, "声音", soundx, y, 80, 24, 14, muted)
	studioText(dc, studioCount(st.stats[5]), soundx, y+34, 80, 48, 32, white)
	studioFill(dc, x, y+116, pw, 1, studioLine)
	// The real button is a native owner-draw child; this is also used by offscreen fixtures.
	oldViewport := [2]int32{}
	gdi32.NewProc("SetViewportOrgEx").Call(dc, uintptr(x), uintptr(y+153), uintptr(unsafe.Pointer(&oldViewport[0])))
	studioButtonFill(dc, pw, 56)
	gdi32.NewProc("SetViewportOrgEx").Call(dc, uintptr(oldViewport[0]), uintptr(oldViewport[1]), 0)
	studioText(dc, "打开雷达", x+pw/2-42, y+169, 110, 28, 16, studioRGB(42, 27, 46))
}

// Window growth uses a native layered window, not a web/card credential bridge.
func (a *guiApp) studioRevealWindow() {
	if a.studio == nil || a.studio.revealStart.IsZero() {
		return
	}
	elapsed := time.Since(a.studio.revealStart)
	p := math.Min(1, float64(elapsed)/float64(740*time.Millisecond))
	ease := 1 - math.Pow(1-p, 3)
	scale := .72 + .28*ease
	w, h := int(1040*scale), int(700*scale)
	user32.NewProc("SetWindowPos").Call(uintptr(a.hwnd), 0, studioCenter(w, 0), studioCenter(h, 1), uintptr(w), uintptr(h), 0x14)
	user32.NewProc("SetLayeredWindowAttributes").Call(uintptr(a.hwnd), 0, uintptr(255*ease), 2)
	if p >= 1 {
		a.studio.revealStart = time.Time{}
		a.studioLayout()
		user32.NewProc("SetFocus").Call(uintptr(a.studio.card))
	}
}

type studioTile struct {
	x, y   int
	owner  int
	vx, vy float64
}
type studioDIB struct {
	Size                   uint32
	W, H                   int32
	Planes, Bits           uint16
	Compression, SizeImage uint32
	XP, YP                 int32
	Used, Important        uint32
}

var studioIntroEpoch time.Time
var studioIntroTiles []studioTile
var studioIntroWordWidth int

func studioBuildIntroTiles() {
	const w, h = 600, 140
	dc, _, _ := gdi32.NewProc("CreateCompatibleDC").Call(0)
	defer gdi32.NewProc("DeleteDC").Call(dc)
	header := studioDIB{Size: 40, W: w, H: -h, Planes: 1, Bits: 32}
	var bits uintptr
	bmp, _, _ := gdi32.NewProc("CreateDIBSection").Call(dc, uintptr(unsafe.Pointer(&header)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == 0 {
		return
	}
	defer gdi32.NewProc("DeleteObject").Call(bmp)
	old, _, _ := gdi32.NewProc("SelectObject").Call(dc, bmp)
	defer gdi32.NewProc("SelectObject").Call(dc, old)
	studioFill(dc, 0, 0, w, h, 0)
	studioWord(dc, 0, 0, 72, 0, 1)
	gdi32.NewProc("GdiFlush").Call()
	fontOld, _, _ := gdi32.NewProc("SelectObject").Call(dc, studioFont(72))
	bounds := []int{0}
	sum := 0
	for _, ch := range "gamesense" {
		var ext [2]int32
		gdi32.NewProc("GetTextExtentPoint32W").Call(dc, uintptr(unsafe.Pointer(utf16(string(ch)))), 1, uintptr(unsafe.Pointer(&ext[0])))
		sum += int(ext[0])
		bounds = append(bounds, sum)
	}
	gdi32.NewProc("SelectObject").Call(dc, fontOld)
	studioIntroWordWidth = sum
	studioIntroTiles = nil
	raw := unsafe.Slice((*byte)(unsafe.Pointer(bits)), w*h*4)
	for y := 0; y < h; y += 4 {
		for x := 0; x < sum && x < w; x += 4 {
			at := (y*w + x) * 4
			if int(raw[at])+int(raw[at+1])+int(raw[at+2]) < 100 {
				continue
			}
			owner := 0
			for owner < 8 && x >= bounds[owner+1] {
				owner++
			}
			seed := float64(x*97 + y*31)
			angle := math.Atan2(float64(y-42), float64(x-sum/2)) + math.Sin(seed)*.6
			speed := 50 + (math.Sin(seed*1.7)+1)*70
			studioIntroTiles = append(studioIntroTiles, studioTile{x: x, y: y, owner: owner, vx: math.Cos(angle) * speed, vy: math.Sin(angle)*speed - 25})
		}
	}
}
func studioIntroPhase(elapsed time.Duration) string {
	if elapsed < 1100*time.Millisecond {
		return "brand"
	}
	if elapsed < 2400*time.Millisecond {
		return "fragments"
	}
	return "login"
}
func studioPaintIntro(dc uintptr, w, h int, elapsed time.Duration) {
	studioFill(dc, 0, 0, w, h, 0)
	t := elapsed.Seconds()
	left, top := (w-studioIntroWordWidth)/2, (h-85)/2
	if studioIntroPhase(elapsed) == "brand" {
		studioWord(dc, left, top, 72, t, 1)
		return
	}
	if studioIntroPhase(elapsed) != "fragments" {
		return
	}
	p := math.Min(1, (t-1.1)/1.3)
	for _, tile := range studioIntroTiles {
		q := p
		travel := q*q*.65 + q*.35
		alpha := 1 - math.Pow(q, 1.4)
		c := studioMix(0, studioChroma(1.1+float64(tile.owner)*.32), alpha)
		x := left + tile.x + int(tile.vx*travel)
		y := top + tile.y + int(tile.vy*travel+110*q*q)
		size := 3
		if q > .7 {
			size = 2
		}
		studioFill(dc, x, y, size, size, c)
	}
}

var studioApprovedIntroProc = syscall.NewCallback(func(hwnd syscall.Handle, msg uint32, wp, lp uintptr) uintptr {
	if msg == 0x000F {
		var ps studioPaintStruct
		dc, _, _ := user32.NewProc("BeginPaint").Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))
		studioPaintIntro(dc, 700, 280, time.Since(studioIntroEpoch))
		user32.NewProc("EndPaint").Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))
		return 0
	}
	if msg == 0x0014 {
		return 1
	}
	v, _, _ := pDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wp, lp)
	return v
})

func showStudioIntro() {
	studioBuildIntroTiles()
	inst, _, _ := pGetModuleHandleW.Call(0)
	name := utf16("GamesenseApprovedFragmentIntroV3")
	wc := wndClassExW{CbSize: uint32(unsafe.Sizeof(wndClassExW{})), LpfnWndProc: studioApprovedIntroProc, HInstance: syscall.Handle(inst), LpszClassName: name}
	pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	hwnd, _, _ := pCreateWindowExW.Call(0x00080000|0x08000000|0x80, uintptr(unsafe.Pointer(name)), 0, 0x80000000, studioCenter(700, 0), studioCenter(280, 1), 700, 280, 0, 0, inst, 0)
	if hwnd == 0 {
		return
	}
	defer pDestroyWindow.Call(hwnd)
	defer func() { studioIntroTiles = nil }()
	studioIntroEpoch = time.Now()
	user32.NewProc("SetLayeredWindowAttributes").Call(hwnd, 0, 255, 3)
	user32.NewProc("ShowWindow").Call(hwnd, 4)
	var msg msgT
	for time.Since(studioIntroEpoch) < 2400*time.Millisecond {
		for {
			n, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
			if n == 0 {
				break
			}
			pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			pDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
		}
		elapsed := time.Since(studioIntroEpoch)
		alpha := 255
		if elapsed < 260*time.Millisecond {
			alpha = int(float64(elapsed) / float64(260*time.Millisecond) * 255)
		}
		user32.NewProc("SetLayeredWindowAttributes").Call(hwnd, 0, uintptr(alpha), 3)
		studioInvalidate(syscall.Handle(hwnd))
		user32.NewProc("UpdateWindow").Call(hwnd)
		time.Sleep(16 * time.Millisecond)
	}
}
