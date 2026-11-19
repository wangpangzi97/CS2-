package main

// Native Gamesense shell. Cards never cross a browser, URL, log or child argv.
import (
	"context"
	"fmt"
	"local/cs2-radar/internal/startupdiag"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const studioLoginID = 1101
const studioExportID = 1102
const studioAnimationTimer = 2
const studioEventMessage = 0x8000 + 29

type studioResult struct {
	session *captureSession
	err     error
}
type studioUI struct {
	ctx          context.Context
	cancel       context.CancelFunc
	card, login  syscall.Handle
	export       syscall.Handle
	page, detail string
	busy         bool
	events       chan studioResult
	stats        [6]string
	errText      string
	revealStart  time.Time
}

func newStudioUI() *studioUI {
	ctx, cancel := context.WithCancel(context.Background())
	return &studioUI{ctx: ctx, cancel: cancel, page: "login", detail: "卡密仅在本机原生窗口处理，加密保存。", events: make(chan studioResult, 2)}
}

var studioFonts = map[int]uintptr{}
var studioDarkBrush uintptr

func studioFont(n int) uintptr {
	if f := studioFonts[n]; f != 0 {
		return f
	}
	size := -int32(n)
	f, _, _ := pCreateFontW.Call(uintptr(size), 0, 0, 0, 500, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(utf16("Microsoft YaHei UI"))))
	studioFonts[n] = f
	return f
}
func studioRGB(r, g, b int) uintptr { return uintptr(r | g<<8 | b<<16) }
func studioFill(dc uintptr, x, y, w, h int, c uintptr) {
	b, _, _ := pGetStockObject.Call(18) // DC_BRUSH: no per-particle GDI allocation.
	gdi32.NewProc("SetDCBrushColor").Call(dc, c)
	rc := rectT{int32(x), int32(y), int32(x + w), int32(y + h)}
	user32.NewProc("FillRect").Call(dc, uintptr(unsafe.Pointer(&rc)), b)
}
func studioText(dc uintptr, text string, x, y, w, h, size int, c uintptr) {
	old, _, _ := gdi32.NewProc("SelectObject").Call(dc, studioFont(size))
	defer gdi32.NewProc("SelectObject").Call(dc, old)
	gdi32.NewProc("SetBkMode").Call(dc, 1)
	gdi32.NewProc("SetTextColor").Call(dc, c)
	rc := rectT{int32(x), int32(y), int32(x + w), int32(y + h)}
	user32.NewProc("DrawTextW").Call(dc, uintptr(unsafe.Pointer(utf16(text))), ^uintptr(0), uintptr(unsafe.Pointer(&rc)), 0x10|0x800)
}
func studioRainbow(t float64, alpha float64) uintptr { return studioMix(0, studioChroma(t), alpha) }
func studioWord(dc uintptr, x, y, size int, t, alpha float64) {
	old, _, _ := gdi32.NewProc("SelectObject").Call(dc, studioFont(size))
	defer gdi32.NewProc("SelectObject").Call(dc, old)
	for i, ch := range "gamesense" {
		studioText(dc, string(ch), x, y, size+20, size+18, size, studioRainbow(t+float64(i)*.32, alpha))
		var extent [2]int32
		letter := utf16(string(ch))
		gdi32.NewProc("GetTextExtentPoint32W").Call(dc, uintptr(unsafe.Pointer(letter)), 1, uintptr(unsafe.Pointer(&extent[0])))
		x += int(extent[0])
	}
}
func studioCenter(size, axis int) uintptr {
	v, _, _ := user32.NewProc("GetSystemMetrics").Call(uintptr(axis))
	return uintptr((int(v) - size) / 2)
}
func studioInvalidate(h syscall.Handle) { user32.NewProc("InvalidateRect").Call(uintptr(h), 0, 0) }
func studioControlColor(dc uintptr) uintptr {
	gdi32.NewProc("SetTextColor").Call(dc, studioRGB(225, 231, 240))
	gdi32.NewProc("SetBkColor").Call(dc, studioRGB(27, 21, 29))
	if studioDarkBrush == 0 {
		studioDarkBrush, _, _ = gdi32.NewProc("CreateSolidBrush").Call(studioRGB(27, 21, 29))
	}
	return studioDarkBrush
}
func studioShow(h syscall.Handle, show bool) {
	v := uintptr(0)
	if show {
		v = 5
	}
	user32.NewProc("ShowWindow").Call(uintptr(h), v)
}
func studioMove(h syscall.Handle, x, y, w, height int) {
	user32.NewProc("MoveWindow").Call(uintptr(h), uintptr(x), uintptr(y), uintptr(w), uintptr(height), 1)
}
func (a *guiApp) studioCreate() {
	st := a.studio
	inst, _, _ := pGetModuleHandleW.Call(0)
	mk := func(class, text string, style, id uintptr) syscall.Handle {
		h, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16(text))), style|wsChild|wsVisible, 0, 0, 10, 10, uintptr(a.hwnd), id, inst, 0)
		pSendMessageW.Call(h, wmSetFont, studioFont(16), 1)
		return syscall.Handle(h)
	}
	st.card = mk("EDIT", "", wsTabStop|0x20|0x80, 0)
	pSendMessageW.Call(uintptr(st.card), 0x00C5, 50, 0)
	pSendMessageW.Call(uintptr(st.card), 0x1501, 1, uintptr(unsafe.Pointer(utf16("卡密"))))
	// Keep internal handles for existing diagnostics/command routing, never show them.
	st.login = mk("BUTTON", "", wsTabStop|0x0B, studioLoginID)
	a.hLog = mk("EDIT", "", esMultiline|esAutoVScroll|esReadOnly|wsVScroll, 0)
	a.hBtn1 = mk("BUTTON", "打开雷达", wsTabStop|0x0B, idBtnOpen)
	a.hBtn2 = mk("BUTTON", "", wsTabStop|0x0B, idBtnStop)
	st.export = mk("BUTTON", "", wsTabStop|0x0B, studioExportID)
	for _, h := range []syscall.Handle{st.login, a.hLog, a.hBtn1, a.hBtn2, st.export} {
		studioShow(h, false)
	}
	a.studioLayout()
	pSetTimer.Call(uintptr(a.hwnd), studioAnimationTimer, 40, 0)
}
func (a *guiApp) studioLayout() {
	if a.hwnd == 0 {
		return
	}
	var r rectT
	pGetClientRect.Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&r)))
	w, h := int(r.Right), int(r.Bottom)
	x, y, cw, _ := studioCardRect(w, h)
	studioMove(a.studio.card, x+18, y+15, cw-36, 32)
	px, py, pw := studioDashboardRect(w, h)
	studioMove(a.hBtn1, px, py+153, pw, 56)
	studioShow(a.studio.card, a.studio.page == "login" && !a.studio.busy && a.studio.revealStart.IsZero())
	studioShow(a.hBtn1, a.studio.page == "runtime")
	for _, control := range []syscall.Handle{a.studio.login, a.hLog, a.hBtn2, a.studio.export} {
		studioShow(control, false)
	}
	studioInvalidate(a.hwnd)
}
func studioError(e error) string { return startupdiag.Format(e) }

func (a *guiApp) studioSubmit() {
	st := a.studio
	if st.busy || st.page != "login" || !st.revealStart.IsZero() {
		return
	}
	var buf [128]uint16
	n, _, _ := user32.NewProc("GetWindowTextW").Call(uintptr(st.card), uintptr(unsafe.Pointer(&buf[0])), 128)
	card := strings.TrimSpace(syscall.UTF16ToString(buf[:int(n)]))
	for i := range buf {
		buf[i] = 0
	}
	pSetWindowTextW.Call(uintptr(st.card), uintptr(unsafe.Pointer(utf16(""))))
	st.busy = true
	st.errText = ""
	studioShow(st.card, false)
	st.detail = "正在校验卡密、设备签名与短期数据资格…"
	user32.NewProc("EnableWindow").Call(uintptr(st.login), 0)
	studioInvalidate(a.hwnd)
	go func() {
		auth, e := authorizeCaptureWithCard(st.ctx, card)
		card = ""
		var session *captureSession
		if e == nil {
			if st.ctx.Err() != nil {
				auth.cancel()
				auth.remote.Close()
				return
			}
			session, e = startCaptureAuthorized(&emitter{}, auth)
		}
		if st.ctx.Err() != nil {
			if session != nil {
				session.Stop()
			}
			return
		}
		select {
		case st.events <- studioResult{session, e}:
			pPostMessageW.Call(uintptr(a.hwnd), studioEventMessage, 0, 0)
		default:
			if session != nil {
				session.Stop()
			}
		}
	}()
}
func (a *guiApp) studioEvent() {
	st := a.studio
	select {
	case r := <-st.events:
		st.busy = false
		user32.NewProc("EnableWindow").Call(uintptr(st.login), 1)
		if r.err != nil {
			st.detail = studioError(r.err)
			st.errText = st.detail
			studioShow(st.card, true)
			user32.NewProc("SetFocus").Call(uintptr(st.card))
			a.appendLog(st.detail)
			studioInvalidate(a.hwnd)
			return
		}
		a.sess = r.session
		st.page = "runtime"
		st.detail = "采集已启动；请在受控测试服务器重新建立连接，捕获完整握手。"
		studioShow(st.card, false)
		studioShow(st.login, false)
		studioShow(a.hLog, false)
		studioShow(a.hBtn1, true)
		studioShow(st.export, false)
		a.appendLog("授权完成，本机采集/密钥获取已启动；解析和像素投影在远端。")
		a.appendLog("已启用安全阶段诊断；自动写入 diagnostics。复现后点击“导出诊断包”，不含原始包或密钥。")
		a.studioLayout()
		a.openRadar()
		go func() {
			select {
			case <-st.ctx.Done():
				r.session.Stop()
			case <-r.session.doneCh:
			}
		}()
	default:
	}
	studioInvalidate(a.hwnd)
}
func (a *guiApp) studioRefresh() {
	if a.uiBeat != nil {
		a.uiBeat.Store(time.Now().UnixMilli())
	}
	a.flushLog()
	if a.studio.page != "runtime" || a.sess == nil {
		return
	}
	st := a.sess.Status()
	up := a.sess.sender.Stats()
	mapID, state, players, sounds := a.sess.ui.ViewState()
	a.studio.stats = [6]string{fmt.Sprint(st.Packets), studioKeyPhase(st.KeyPhase), fmt.Sprint(up["packets"]), mapID, fmt.Sprint(players), fmt.Sprint(sounds)}
	switch {
	case !st.Running:
		v := a.sess.diag.stopPacked.Load()
		a.studio.detail = fmt.Sprintf("已停止 [GS-STOP %d/%d/%d]；请导出诊断包。", uint8(v), uint8(v>>8), uint16(v>>16))
	case !a.sess.captureFilterAvailable():
		a.studio.detail = filterStatusText(uint8(a.sess.diag.filterState.Load()))
	case st.Packets == 0:
		a.studio.detail = "尚未收到数据：检查目标进程、网卡和管理员权限。"
	case a.sess.diag.ownedUDP.Load() == 0:
		a.studio.detail = "[GS-FLOW 1] 尚无目标本机端口命中；未知流量不会上行，请导出本轮诊断。"
	case !a.sess.keyReady.Load():
		a.studio.detail = "本机尚未获得密钥；请保留本轮诊断，不代表卡密验证失败。"
	case state == "map_required" || mapID == "":
		a.studio.detail = "已开始上行，地图尚未识别。等待服务端自动识别地图；不按声音猜图。"
	case state == "sounds_only":
		a.studio.detail = "地图已识别；服务端当前仅返回声音层，人物实体尚未同步。底图从本机 maps 加载。"
	case players == 0:
		a.studio.detail = "地图：" + mapID + "。尚无可信人物；等待完整同步或检查游戏构建兼容性。"
	default:
		a.studio.detail = "地图：" + mapID + " · 本地 PNG 底图 · 已授权像素视图"
	}
	studioInvalidate(a.hwnd)
}

type studioPaintStruct struct {
	DC              uintptr
	Erase           int32
	Rect            rectT
	Restore, Update int32
	Reserved        [32]byte
}

func (a *guiApp) studioPaintWindow() {
	var ps studioPaintStruct
	dc, _, _ := user32.NewProc("BeginPaint").Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&ps)))
	defer user32.NewProc("EndPaint").Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&ps)))
	var r rectT
	pGetClientRect.Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&r)))
	mem, _, _ := gdi32.NewProc("CreateCompatibleDC").Call(dc)
	bitmap, _, _ := gdi32.NewProc("CreateCompatibleBitmap").Call(dc, uintptr(r.Right), uintptr(r.Bottom))
	old, _, _ := gdi32.NewProc("SelectObject").Call(mem, bitmap)
	a.studioPaint(mem, int(r.Right), int(r.Bottom), float64(time.Now().UnixMilli())/1000)
	gdi32.NewProc("BitBlt").Call(dc, 0, 0, uintptr(r.Right), uintptr(r.Bottom), mem, 0, 0, 0x00CC0020)
	gdi32.NewProc("SelectObject").Call(mem, old)
	gdi32.NewProc("DeleteObject").Call(bitmap)
	gdi32.NewProc("DeleteDC").Call(mem)
}

type studioDrawItem struct {
	Kind, ID, Item, Action, State uint32
	Hwnd, DC                      uintptr
	Rect                          rectT
	Data                          uintptr
}

func (a *guiApp) studioDrawButton(ptr uintptr) uintptr {
	d := (*studioDrawItem)(unsafe.Pointer(ptr))
	w, h := int(d.Rect.Right), int(d.Rect.Bottom)
	studioButtonFill(d.DC, w, h)
	studioText(d.DC, "打开雷达", w/2-40, (h-24)/2, 100, 28, 16, studioRGB(42, 27, 46))
	return 1
}
func (a *guiApp) studioHit(lp uintptr) uintptr {
	// Default coordinates conversion supports dragging from the custom title area.
	point := [2]int32{int32(int16(lp & 0xffff)), int32(int16((lp >> 16) & 0xffff))}
	user32.NewProc("ScreenToClient").Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&point[0])))
	var r rectT
	pGetClientRect.Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&r)))
	if point[1] < 70 && point[0] < r.Right-100 {
		return 2
	}
	return 1
}

func studioKeyPhase(phase string) string {
	for _, v := range []string{"已就绪", "等待握手包", "冻结", "校验", "搜索", "反查", "失败", "已禁用"} {
		if strings.Contains(phase, v) {
			return v
		}
	}
	return "处理中"
}

func studioIntroAlpha(elapsed time.Duration) int {
	if elapsed <= 1050*time.Millisecond {
		return 255
	}
	if elapsed >= 1700*time.Millisecond {
		return 0
	}
	return int(255 * (1 - float64(elapsed-1050*time.Millisecond)/float64(650*time.Millisecond)))
}
