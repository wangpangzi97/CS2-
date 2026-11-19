// 窗口模式：CS2雷达.exe（-H=windowsgui 构建）双击进来。
//
// 全部用 Win32 API 直接实现，不引入任何第三方 GUI 库（项目零外部依赖）。
//
//	ShellExecuteExW("runas")   自己弹 UAC 提权（SIO_RCVALL 必须要管理员）
//	RegisterClassExW / CreateWindowExW / GetMessageW  原生窗口
//	STATIC + BUTTON + EDIT     状态行 / 按钮 / 日志框
//
// stderr 被重定向到管道，采集链路原有的所有 fmt.Fprintf(os.Stderr, ...)
// 都会流进日志框 —— 这样不用改动抓包代码就能把日志显示出来。
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	pRegisterClassExW  = user32.NewProc("RegisterClassExW")
	pCreateWindowExW   = user32.NewProc("CreateWindowExW")
	pDefWindowProcW    = user32.NewProc("DefWindowProcW")
	pDestroyWindow     = user32.NewProc("DestroyWindow")
	pPostQuitMessage   = user32.NewProc("PostQuitMessage")
	pGetMessageW       = user32.NewProc("GetMessageW")
	pTranslateMessage  = user32.NewProc("TranslateMessage")
	pDispatchMessageW  = user32.NewProc("DispatchMessageW")
	pSendMessageW      = user32.NewProc("SendMessageW")
	pPostMessageW      = user32.NewProc("PostMessageW")
	pSetWindowTextW    = user32.NewProc("SetWindowTextW")
	pGetClientRect     = user32.NewProc("GetClientRect")
	pSetTimer          = user32.NewProc("SetTimer")
	pKillTimer         = user32.NewProc("KillTimer")
	pMessageBoxW       = user32.NewProc("MessageBoxW")
	pGetStockObject    = gdi32.NewProc("GetStockObject")
	pCreateFontW       = gdi32.NewProc("CreateFontW")
	pSetDpiAwareness   = user32.NewProc("SetProcessDpiAwarenessContext")
	pSetProcessDpiAwar = user32.NewProc("SetProcessDPIAware")
	pShellExecuteExW   = shell32.NewProc("ShellExecuteExW")
	pGetModuleHandleW  = kernel32.NewProc("GetModuleHandleW")
	pMulDiv            = kernel32.NewProc("MulDiv")
)

// ---- Win32 常量 ----

const (
	wsOverlappedWindow = 0x00CF0000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsBorder           = 0x00800000
	wsVScroll          = 0x00200000
	wsTabStop          = 0x00010000
	bsPushButton       = 0x00000000
	esMultiline        = 0x0004
	esAutoVScroll      = 0x0040
	esReadOnly         = 0x0800
	ssLeft             = 0x00000000

	wmCreate       = 0x0001
	wmDestroy      = 0x0002
	wmSize         = 0x0005
	wmClose        = 0x0010
	wmSetFont      = 0x0030
	wmCommand      = 0x0111
	wmTimer        = 0x0113
	wmVScroll      = 0x0115
	emSetSel       = 0x00B1
	emScrollCaret  = 0x00B7
	emReplaceSel   = 0x00C2
	sbBottom       = 7
	swShow         = 5
	swShowNormal   = 1
	mbIconError    = 0x00000010
	mbOK           = 0x00000000
	defaultGUIFont = 17
	fwNormal       = 400
	defaultCharset = 1
	cleartypeQ     = 5
	cwUseDefault   = 0x80000000

	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00004000
	errCancelled          = 1223

	idBtnOpen = 1001
	idBtnStop = 1002
	idTimer   = 1
)

// 日志框容量上限。
//
// 这个窗口是**长期常驻**的（一局几十分钟），而 EDIT 控件的每次插入都是按
// 当前总长做一次重排。只追加不裁剪的话文本会无界增长，越跑越慢，最终整个
// 窗口无响应 —— 这就是「跑一段时间卡死」的成因。所以两处都要封顶：
//   - maxLogChars：控件里保留的最大字符数，超了从头部裁一批并整体重建；
//   - maxPendingLines：Go 侧待刷缓冲的行数上限（stderr 被瞬间灌爆时兜底）。
const (
	maxLogChars     = 100000
	maxPendingLines = 2000
)

// ---- Win32 结构体 ----

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

type rectT struct {
	Left, Top, Right, Bottom int32
}

type msgT struct {
	Hwnd     syscall.Handle
	Message  uint32
	_        uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	PtX      int32
	PtY      int32
	LPrivate uint32
}

type shellExecuteInfoW struct {
	CbSize       uint32
	FMask        uint32
	Hwnd         syscall.Handle
	LpVerb       *uint16
	LpFile       *uint16
	LpParameters *uint16
	LpDirectory  *uint16
	NShow        int32
	_            int32
	HInstApp     syscall.Handle
	LpIDList     uintptr
	LpClass      *uint16
	HkeyClass    syscall.Handle
	DwHotKey     uint32
	_            uint32
	HIcon        syscall.Handle
	HProcess     syscall.Handle
}

// ---- GUI 应用 ----

type guiApp struct {
	studio  *studioUI
	hwnd    syscall.Handle
	hStatus syscall.Handle
	hLog    syscall.Handle
	hBtn1   syscall.Handle
	hBtn2   syscall.Handle
	font    syscall.Handle

	sess     *captureSession
	radarURL string
	startErr string
	stopping bool

	logMu    sync.Mutex
	pending  []string // 待刷进控件的行
	logLines []string // 控件里当前已有的行（裁剪时按它算）
	logChars int      // logLines 的总字符数（含换行）

	// UI 心跳：refreshStatus 每次进来更新一次，看门狗据此判断 UI 线程是否被卡住。
	uiBeat *atomic.Int64
	// uiDone 在窗口开始销毁时置位，让看门狗别再误报"卡死"。
	uiDone atomic.Bool
	// exitGuard 保证兜底退出只启动一次。
	exitGuard atomic.Bool
	// closeConfirmed 记住用户已经在「私钥搜索还没跑完」的确认框里选了「仍要关闭」，
	// 避免第二次 WM_CLOSE 又弹一遍。
	closeConfirmed bool

	// 帧耗时诊断：lastFrameEnd 是上一帧刷新的结束时刻（UnixMilli），
	// lastWarnAt 是上一次告警时刻，用来给告警限流。
	// 有这两个值才能区分「UI 线程被卡住」和「WM_TIMER 根本没来」——
	// 前者是单帧耗时暴涨，后者是帧间隔暴涨但每帧都很快。
	lastFrameEnd atomic.Int64
	lastWarnAt   atomic.Int64
}

var gui *guiApp // 窗口过程需要，单例

// wndProcCallback 必须保持引用，否则会被 GC 回收导致崩溃。
var wndProcCallback uintptr

func init() {
	wndProcCallback = syscall.NewCallback(guiWndProc)
}

func utf16(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		p, _ = syscall.UTF16PtrFromString("")
	}
	return p
}

func messageBox(title, text string, flags uint32) {
	pMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(text))),
		uintptr(unsafe.Pointer(utf16(title))), uintptr(flags))
}

// messageBoxYesNo 弹一个「是/否」框，返回用户是否选了「是」。
//
// 关窗前的拦截用：私钥搜索跑到一半被关掉，等于这一局白打，
// 而日志上看起来只是「又没拿到私钥」—— 07:38 那局就是这么没的。
func messageBoxYesNo(title, text string) bool {
	const (
		mbYesNo         = 0x00000004
		mbIconWarning   = 0x00000030
		mbSetForeground = 0x00010000
		idYes           = 6
	)
	r, _, _ := pMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(text))),
		uintptr(unsafe.Pointer(utf16(title))), uintptr(mbYesNo|mbIconWarning|mbSetForeground))
	return r == idYes
}

// ---- 提权 ----

// isAdminFn 是 winapiIsAdmin 的间接层。
//
// 存在的唯一理由：`IsUserAnAdmin` 的结果取决于当前进程令牌，单元测试没法把自己
// 变成非管理员。留一个可替换的变量，就能把「已提权标记却仍非管理员 → 必须报错而
// 不是无限弹 UAC」这条分支纳入测试。生产路径上它恒等于 winapiIsAdmin。
var isAdminFn = winapiIsAdmin

// ensureElevated 保证当前进程是管理员。
//
// 返回 (true, nil) 表示已经重新拉起了一个提权实例，本进程应立即退出。
func ensureElevated() (bool, error) {
	if isAdminFn() {
		return false, nil
	}
	if *flagElevated {
		// 已经是被提权拉起的那一份，却仍然不是管理员 → 用户拒了 UAC 或策略禁止。
		return false, fmt.Errorf("没有拿到管理员权限。\n\n" +
			"SIO_RCVALL（原始套接字双向抓包）必须要管理员权限。\n" +
			"请在弹出的 UAC 窗口点「是」，或右键本程序选「以管理员身份运行」。")
	}

	exe, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("取自身路径失败: %v", err)
	}
	params := buildArgLine(os.Args[1:], "-elevated")

	var sei shellExecuteInfoW
	sei.CbSize = uint32(unsafe.Sizeof(sei))
	sei.FMask = seeMaskNoCloseProcess | seeMaskNoAsync
	sei.LpVerb = utf16("runas")
	sei.LpFile = utf16(exe)
	sei.LpParameters = utf16(params)
	sei.NShow = swShowNormal

	r, _, e := pShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		if errno, ok := e.(syscall.Errno); ok && uint32(errno) == errCancelled {
			return false, fmt.Errorf("已取消提权（UAC 被拒绝）。\n\n" +
				"程序需要管理员权限才能抓包。想继续请重新运行并同意 UAC。")
		}
		return false, fmt.Errorf("提权失败: %v", e)
	}
	return true, nil
}

// buildArgLine 重建命令行：保留原有参数，追加 extra。
func buildArgLine(args []string, extra string) string {
	out := make([]string, 0, len(args)+1)
	out = append(out, args...)
	out = append(out, extra)
	for i, a := range out {
		if strings.ContainsAny(a, " \t") {
			out[i] = `"` + a + `"`
		}
	}
	return strings.Join(out, " ")
}

func winapiIsAdmin() bool {
	r, _, _ := shell32.NewProc("IsUserAnAdmin").Call()
	return r != 0
}

// ---- 窗口 ----

const className = "CS2RadarWindowClass"

func (a *guiApp) create() error {
	hInst, _, _ := pGetModuleHandleW.Call(0)

	cursor, _, _ := user32.NewProc("LoadCursorW").Call(0, 32512) // IDC_ARROW
	hbr, _, _ := pGetStockObject.Call(16)                        // COLOR_BTNFACE + 1

	// 字体必须在建窗口之前就绪：WM_CREATE 是在 CreateWindowExW 内部派发的。
	a.font = makeFont()

	wc := wndClassExW{
		CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		Style:         0x0002 | 0x0001, // CS_HREDRAW | CS_VREDRAW
		LpfnWndProc:   wndProcCallback,
		HInstance:     syscall.Handle(hInst),
		HCursor:       syscall.Handle(cursor),
		HbrBackground: syscall.Handle(hbr),
		LpszClassName: utf16(className),
	}
	if r, _, e := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassExW 失败: %v", e)
	}

	exStyle := uintptr(0)
	if a.studio != nil {
		exStyle = 0x00080000
		a.studio.revealStart = time.Now()
	}
	hwnd, _, e := pCreateWindowExW.Call(
		exStyle,
		uintptr(unsafe.Pointer(utf16(className))),
		uintptr(unsafe.Pointer(utf16("gamesense"))),
		uintptr(0x80000000|0x00080000|0x00020000),
		studioCenter(1040, 0), studioCenter(700, 1), 1040, 700,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW 失败: %v", e)
	}
	a.hwnd = syscall.Handle(hwnd)
	if a.studio != nil {
		a.studioRevealWindow()
	}

	user32.NewProc("ShowWindow").Call(hwnd, swShow)
	user32.NewProc("UpdateWindow").Call(hwnd)
	return nil
}

// makeFont 造一个中文友好的字体，按系统 DPI 缩放。
func makeFont() syscall.Handle {
	dpi := uintptr(96)
	if err := user32.NewProc("GetDpiForSystem").Find(); err == nil {
		if d, _, _ := user32.NewProc("GetDpiForSystem").Call(); d != 0 {
			dpi = d
		}
	}
	h, _, _ := pMulDiv.Call(9, dpi, 72)
	f, _, _ := pCreateFontW.Call(
		uintptr(-int32(h)), 0, 0, 0, fwNormal,
		0, 0, 0, defaultCharset, 0, 0, cleartypeQ, 0,
		uintptr(unsafe.Pointer(utf16("Microsoft YaHei UI"))),
	)
	if f == 0 {
		f, _, _ = pGetStockObject.Call(defaultGUIFont)
	}
	return syscall.Handle(f)
}

// createControls 建控件。窗口过程收到 WM_CREATE 时调用。
//
// 子控件的 hMenu 参数就是控件 ID —— WM_COMMAND 的 LOWORD(wParam) 会带回来。
func (a *guiApp) createControls() {
	if a.studio != nil {
		a.studioCreate()
		return
	}
	hInst, _, _ := pGetModuleHandleW.Call(0)
	mk := func(class, text string, style uintptr, id uintptr) syscall.Handle {
		h, _, _ := pCreateWindowExW.Call(
			0,
			uintptr(unsafe.Pointer(utf16(class))),
			uintptr(unsafe.Pointer(utf16(text))),
			style|wsChild|wsVisible,
			0, 0, 10, 10,
			uintptr(a.hwnd), id, hInst, 0,
		)
		return syscall.Handle(h)
	}

	a.hStatus = mk("STATIC", "正在启动…", ssLeft, 0)
	a.hLog = mk("EDIT", "", wsBorder|wsVScroll|wsTabStop|
		uintptr(esMultiline|esAutoVScroll|esReadOnly), 0)
	a.hBtn1 = mk("BUTTON", "打开雷达页", uintptr(bsPushButton)|wsTabStop, idBtnOpen)
	a.hBtn2 = mk("BUTTON", "停止并退出", uintptr(bsPushButton)|wsTabStop, idBtnStop)

	for _, h := range []syscall.Handle{a.hStatus, a.hLog, a.hBtn1, a.hBtn2} {
		pSendMessageW.Call(uintptr(h), wmSetFont, uintptr(a.font), 1)
	}
	a.layout()
}

// layout 按客户区大小摆放控件。
func (a *guiApp) layout() {
	if a.studio != nil {
		a.studioLayout()
		return
	}
	if a.hwnd == 0 || a.hStatus == 0 {
		return
	}
	var rc rectT
	pGetClientRect.Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&rc)))
	w := int32(rc.Right - rc.Left)
	h := int32(rc.Bottom - rc.Top)
	const pad, btnH, btnW = int32(14), int32(34), int32(150)
	statusH := int32(64)

	move := func(hwnd syscall.Handle, x, y, cw, ch int32) {
		if cw < 10 {
			cw = 10
		}
		if ch < 10 {
			ch = 10
		}
		user32.NewProc("MoveWindow").Call(uintptr(hwnd), uintptr(x), uintptr(y),
			uintptr(cw), uintptr(ch), 1)
	}
	move(a.hStatus, pad, pad, w-2*pad, statusH)
	logY := pad + statusH + 8
	move(a.hLog, pad, logY, w-2*pad, h-logY-pad-btnH-10)
	by := h - pad - btnH
	move(a.hBtn1, pad, by, btnW, btnH)
	move(a.hBtn2, pad+btnW+10, by, btnW, btnH)
}

func (a *guiApp) setStatus(s string) {
	if a.hStatus != 0 {
		pSetWindowTextW.Call(uintptr(a.hStatus), uintptr(unsafe.Pointer(utf16(s))))
	}
}

func (a *guiApp) appendLog(line string) {
	// 带时间戳：用户报"卡死"时，光看内容分不清是「真的不动了」还是
	// 「本来就没新日志」。有时间戳一眼就能看出来。
	a.logMu.Lock()
	a.pending = append(a.pending, time.Now().Format("[15:04:05] ")+line)
	if len(a.pending) > maxPendingLines { // 防瞬间灌爆时 Go 侧内存先炸
		a.pending = a.pending[len(a.pending)-maxPendingLines/2:]
	}
	a.logMu.Unlock()
}

// exeDir 返回可执行文件所在目录；取不到就退到临时目录。
func exeDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return os.TempDir()
}

const (
	uiWatchdogTick = 2 * time.Second
	// 阈值不能太敏感：系统繁忙时 UI 线程偶发停顿几秒是正常的（实测见过
	// 6.3 秒的偶发停顿）。10 秒既不会把偶发停顿误判成卡死，
	// 又能在真卡死时及时取证。
	uiStallAfter = 10 * time.Second
	// 单帧耗时超过它 = UI 线程自己在某一步里卡住了（flushLog / Status / SetWindowText）。
	uiSlowFrame = 500 * time.Millisecond
	// 帧间隔超过它 = UI 线程没卡，是 WM_TIMER 没送到（消息队列被别的消息占住）。
	uiGapWarn = 1500 * time.Millisecond
	// 告警限流：连续异常时最多每 3 秒记一笔，别让诊断本身把日志灌爆。
	uiWarnEvery = 3 * time.Second
)

// startUIWatchdog 盯着 UI 线程的心跳，一旦发现它长时间不刷新就落一份取证。
//
// 为什么需要它：用户报"卡死"时，光看窗口没法区分「UI 线程被卡住」和
// 「数据本来就没在动」。refreshStatus 由 WM_TIMER 每 400ms 触发一次，每次更新
// uiBeat；UI 线程一旦卡住（不管卡在 flushLog、SendMessage 还是 Status()），
// 定时器就进不来，uiBeat 停住。
//
// 关键：这条路径**不经过 UI 线程**，所以 UI 卡了它照样能把**全部 goroutine
// 的调用栈**写到 exe 同目录 —— 栈里直接看得出卡在哪个函数哪一行。
func (a *guiApp) startUIWatchdog() {
	// A goroutine stack can expose process addresses and secret arguments.
	// Keep UI timing only; no runtime.Stack or automatic file export.
	a.uiBeat = &atomic.Int64{}
	a.uiBeat.Store(time.Now().UnixMilli())
}

// trimLogLines 从头部裁掉整行，直到保留部分的字符数（含每行 "\r\n"）不超过 target。
//
// 整行裁、不截断，避免日志里出现半行。返回裁剪后的切片与新的字符计数；
// 返回的切片是**独立副本**，否则裁剪后仍会引用整个旧底层数组，白占内存。
func trimLogLines(lines []string, target int) ([]string, int) {
	acc, keepFrom := 0, 0
	for i := len(lines) - 1; i >= 0; i-- {
		acc += len(lines[i]) + 2
		if acc > target {
			keepFrom = i + 1
			acc -= len(lines[i]) + 2 // 这一行要被裁掉，不能计进保留部分的字符数
			break
		}
	}
	if keepFrom >= len(lines) {
		return nil, 0 // 单行就超长：整条丢掉，也比把控件拖死强
	}
	kept := make([]string, len(lines)-keepFrom)
	copy(kept, lines[keepFrom:])
	return kept, acc
}

// flushLog 把待刷日志追加进 EDIT 框。
//
// 追加之外还要维护一个字符数上限：超过 maxLogChars 就从头部裁掉一批，
// 并整体重建一次控件文本。裁剪一次比追加贵，所以一次多裁一点
// （裁到目标的 3/4），避免每轮刷新都触发重建。
func (a *guiApp) flushLog() {
	a.logMu.Lock()
	if len(a.pending) == 0 {
		a.logMu.Unlock()
		return
	}
	batch := a.pending
	a.pending = nil

	a.logLines = append(a.logLines, batch...)
	for _, l := range batch {
		a.logChars += len(l) + 2 // +2 是 "\r\n"
	}

	rebuild := false
	var full string
	if a.logChars > maxLogChars {
		a.logLines, a.logChars = trimLogLines(a.logLines, maxLogChars-maxLogChars/4)
		full = strings.Join(a.logLines, "\r\n") + "\r\n"
		rebuild = true
	}
	a.logMu.Unlock()

	if rebuild {
		pSetWindowTextW.Call(uintptr(a.hLog), uintptr(unsafe.Pointer(utf16(full))))
	} else {
		text := strings.Join(batch, "\r\n") + "\r\n"
		pSendMessageW.Call(uintptr(a.hLog), emSetSel, ^uintptr(0), ^uintptr(0)) // 移到末尾
		pSendMessageW.Call(uintptr(a.hLog), emReplaceSel, 0,
			uintptr(unsafe.Pointer(utf16(text))))
	}
	// 强制滚到底。EM_SCROLLCARET 依赖插入符位置，控件没有焦点时不可靠
	// （实测视图会停在原地，看起来像"日志不刷了"）。
	pSendMessageW.Call(uintptr(a.hLog), wmVScroll, sbBottom, 0)
}

// refreshStatus 由定时器调用：刷新状态行 + 灌日志。
func (a *guiApp) refreshStatus() {
	if a.studio != nil {
		a.studioRefresh()
		return
	}
	t0 := time.Now()
	// 第一件事就是打心跳 —— 如果卡在下面的 flushLog 或 Status()，
	// 下一次定时器就进不来，看门狗据此判定 UI 卡死。
	if a.uiBeat != nil {
		a.uiBeat.Store(t0.UnixMilli())
	}
	// 用 defer 记账，这样下面每个 return 分支都不会漏统计。
	defer a.noteFrame(t0)

	// 排障开关：故意冻结 UI 线程，用来确认卡死取证这条路是通的。
	if n := *flagUIFreeze; n > 0 {
		*flagUIFreeze = 0 // 只冻结一次
		time.Sleep(time.Duration(n) * time.Second)
	}

	a.flushLog()

	if a.startErr != "" {
		a.setStatus("启动失败\r\n" + a.startErr)
		return
	}
	if a.sess == nil {
		a.setStatus("正在启动…（正在打开抓包口、启动雷达页）")
		return
	}
	st := a.sess.Status()
	var b strings.Builder
	if a.stopping || !st.Running {
		b.WriteString("状态：正在停止 / 已停止\r\n")
	} else {
		fmt.Fprintf(&b, "状态：运行中（%s）　收包 %d　过滤丢弃 %d\r\n",
			st.Elapsed.Truncate(1e9), st.Packets, st.Filtered)
	}
	fmt.Fprintf(&b, "密钥：%s", st.KeyPhase)
	if st.KeyTag != "" {
		fmt.Fprintf(&b, "（%s）", st.KeyTag)
	}
	if st.FilterOn {
		// 端口可能几十个，全铺在状态行上会把它撑成一条长带，
		// 每 400ms 重设一次也白费力气。只留头几个 + 总数。
		ps := st.FilterPorts
		if len(ps) > 6 {
			fmt.Fprintf(&b, "　　端口过滤：开（pid=%d，%d 个端口 %v…%d）",
				st.FilterPID, len(ps), ps[:4], ps[len(ps)-1])
		} else {
			fmt.Fprintf(&b, "　　端口过滤：开（pid=%d 端口=%v）", st.FilterPID, ps)
		}
	} else {
		b.WriteString("　　端口过滤：等目标进程（未过滤=收全部 UDP）")
	}
	a.setStatus(b.String())
}

// noteFrame 记录一帧刷新的耗时与间隔，异常时写一行日志。
//
// 存在的理由：用户报"卡死"时窗口看起来都一样，但成因完全不同 ——
//
//	cost 大（单帧耗时暴涨）→ UI 线程自己卡在某个 Win32 调用里；
//	gap 大而 cost 小        → UI 线程是空闲的，只是 WM_TIMER 没送到
//	                          （消息队列被大量其它消息占住，定时器被饿死）。
//
// 这两种的修法南辕北辙：前者要优化那一行调用，后者要治消息来源。
// 没有这行日志，光看窗口只能靠猜。
func (a *guiApp) noteFrame(t0 time.Time) {
	end := time.Now()
	cost := end.Sub(t0)

	prev := a.lastFrameEnd.Load()
	a.lastFrameEnd.Store(end.UnixMilli())
	if prev == 0 {
		return // 第一帧没有参照物
	}
	gapMs := end.UnixMilli() - prev

	slow := cost > uiSlowFrame
	lag := time.Duration(gapMs)*time.Millisecond > uiGapWarn
	if !slow && !lag {
		return
	}
	// 限流：连续异常时最多每 uiWarnEvery 记一笔，别让诊断自己把日志灌爆。
	nowMs := end.UnixMilli()
	if last := a.lastWarnAt.Load(); last != 0 &&
		time.Duration(nowMs-last)*time.Millisecond < uiWarnEvery {
		return
	}
	a.lastWarnAt.Store(nowMs)

	why := "UI 线程忙（单帧耗时过长）"
	if !slow {
		why = "WM_TIMER 未送达（UI 线程空闲）"
	}
	msg := fmt.Sprintf("⚠ UI 刷新异常：间隔 %dms　耗时 %dms　%s",
		gapMs, cost.Milliseconds(), why)
	a.appendLog(msg)
	// 同时写 stderr：-logfile 能把它落成文件，退出后可以直接看时间线。
	// 有 uiWarnEvery 限流兜着，不会把管道灌满。
	fmt.Fprintln(os.Stderr, msg)
}

// startCaptureAsync 在后台起抓包；失败时把错误写进状态行。
func (a *guiApp) startCaptureAsync() {
	em := &emitter{ipc: false}
	go func() {
		s, err := startCapture(em)
		if err != nil {
			a.startErr = fmt.Sprintf("启动失败：%v", err)
			a.appendLog("✗ 启动失败: " + err.Error())
			if _, denied := err.(*authorizationError); denied {
				a.appendLog("  请先运行 guyi-license.exe activate 激活；检查 license.json、HTTPS 证书和服务器时间。")
			} else {
				a.appendLog("  请检查网卡及管理员权限。")
			}
			return
		}
		a.sess = s
		a.radarURL = s.ViewURL()
		// 双击即用：抓包口和雷达页都起来了就自动开浏览器。
		// （-auto-exit 是冒烟测试模式，那时 flagOpenBrowser 已被置为 false。）
		if *flagOpenBrowser {
			a.openRadar()
		}
		s.Wait()
		traceStop("gui: s.Wait() 已返回（抓包侧收尾完毕）")
		if *flagAutoExit {
			pPostMessageW.Call(uintptr(a.hwnd), wmClose, 0, 0)
			a.armExitGuard()
		}
	}()
}

func (a *guiApp) openRadar() {
	a.radarURL = ""
	if a.sess != nil {
		a.radarURL = a.sess.ViewURL()
	}
	if a.radarURL == "" {
		a.appendLog("雷达页地址还没就绪，请稍等几秒再点。")
		return
	}
	openBrowser(a.radarURL)
}

// armExitGuard 启动一次性兜底退出：8 秒后无条件结束进程。
//
// 为什么不能只挂在 wmClose 里：wmClose 是由 UI 线程处理的，UI 线程一旦被
// 卡住，wmClose 自己也执行不了，兜底就成了死代码。所以**每一条能主动发起
// 退出的路径**都要各自武装一次 —— 按钮点击（UI 线程，能点说明它是活的）
// 和 -auto-exit（跑在后台 goroutine 上）。
func (a *guiApp) armExitGuard() {
	if !a.exitGuard.CompareAndSwap(false, true) {
		return
	}
	traceStop("gui: 武装 8 秒兜底退出")
	go func() {
		time.Sleep(8 * time.Second)
		traceStop("gui: 8 秒兜底到期，os.Exit(0) —— 说明正常退出路径没走通")
		os.Exit(0)
	}()
}

// stopAndQuit 请求关窗退出。
//
// 真正的停止 + 销毁在 WM_CLOSE 里做（DestroyWindow → 消息循环退出 →
// run() 再等抓包 goroutine 收尾），这里只负责请求。
func (a *guiApp) stopAndQuit() {
	if a.stopping {
		return
	}
	a.stopping = true
	pSetWindowTextW.Call(uintptr(a.hBtn2), uintptr(unsafe.Pointer(utf16("正在停止…"))))
	pPostMessageW.Call(uintptr(a.hwnd), wmClose, 0, 0)
	a.armExitGuard()
}

// run 进入消息循环（阻塞）。
func (a *guiApp) run() {
	// stderr → 管道 → 日志框
	restore := a.redirectStderr()
	defer restore()

	// GUI 模式下默认自动打开浏览器；-auto-exit 是冒烟测试模式，不弹浏览器。
	*flagOpenBrowser = !*flagAutoExit
	// Integrated native login is required before capture.
	if a.studio == nil {
		a.startCaptureAsync()
	}

	a.startUIWatchdog()
	pSetTimer.Call(uintptr(a.hwnd), idTimer, 400, 0)

	var msg msgT
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if a.studio != nil && msg.Message == 0x0100 && msg.WParam == 13 && a.studio.page == "login" {
			a.studioSubmit()
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	traceStop("gui: 消息循环已退出")
	pKillTimer.Call(uintptr(a.hwnd), idTimer)
	if a.sess != nil {
		a.sess.Stop()
		a.sess.Wait()
		traceStop("gui: run() 收尾完成，即将返回退出码")
	}
}

// redirectStderr 把 os.Stderr 换成管道，逐行送进日志框。
//
// 如果指定了 -logfile，同一份内容再落一份到文件 —— 窗口版没有控制台，
// 用户报"卡死"时截屏只能看到可见的那几行，有了文件才能把完整时间线发出来。
func (a *guiApp) redirectStderr() func() {
	r, w, err := os.Pipe()
	if err != nil {
		return func() {}
	}
	old := os.Stderr
	os.Stderr = w

	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			a.appendLog(line)
		}
	}()
	return func() {
		os.Stderr = old
		w.Close()
		r.Close()
	}
}

// guiWndProc 窗口过程。
func guiWndProc(hwnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case 0x000F:
		if gui != nil && gui.studio != nil {
			gui.studioPaintWindow()
			return 0
		}
	case 0x0014:
		if gui != nil && gui.studio != nil {
			return 1
		}
	case 0x0133, 0x0138:
		if gui != nil && gui.studio != nil {
			return studioControlColor(wParam)
		}
	case 0x002B:
		if gui != nil && gui.studio != nil {
			return gui.studioDrawButton(lParam)
		}
	case 0x0084:
		if gui != nil && gui.studio != nil {
			return gui.studioHit(lParam)
		}
	case studioEventMessage:
		if gui != nil && gui.studio != nil {
			gui.studioEvent()
			return 0
		}
	case wmCreate:
		if gui != nil {
			gui.hwnd = hwnd
			gui.createControls()
		}
		return 0
	case wmSize:
		if gui != nil {
			gui.layout()
		}
		return 0
	case wmTimer:
		if wParam == studioAnimationTimer && gui != nil && gui.studio != nil {
			gui.studioRevealWindow()
			studioInvalidate(gui.hwnd)
			return 0
		}
		if gui != nil {
			gui.refreshStatus()
		}
		return 0
	case wmCommand:
		id := wParam & 0xffff
		if gui != nil {
			switch id {
			case studioLoginID:
				if gui.studio != nil {
					gui.studioSubmit()
				}
			case idBtnOpen:
				gui.openRadar()
			case studioExportID:
				gui.exportSafeDiagnostics()
			case idBtnStop:
				gui.stopAndQuit()
			}
		}
		return 0
	case wmClose:
		// 关窗 = 停抓包 + 销毁窗口。抓包 goroutine 的收尾由 run() 里的
		// Stop()+Wait() 兜住，避免销毁后还有后台线程在写控件。
		traceStop("gui: WM_CLOSE 收到")
		if gui != nil {
			// 私钥搜索还在关键阶段时拦一下：关掉就等于这一局白打，
			// 而用户看到的现象只是「又没拿到私钥」，会以为功能坏了。
			if !gui.closeConfirmed && gui.sess != nil && gui.sess.keySearchBusy() {
				phase, _ := gui.sess.keyPhase.Load().(string)
				if !messageBoxYesNo("私钥搜索还没跑完",
					"现在正在："+phase+"。\n\n"+
						"这一局还没有客户端私钥 —— 关掉就等于白打：没有私钥解不出一帧，雷达也不会有任何目标。\n\n"+
						"如果刚开局没多久，建议等它跑完（通常十几秒到两分钟）。\n\n"+
						"确定要现在关闭吗？") {
					return 0 // 用户选了「否」：不关窗，搜索继续
				}
			}
			if gui.studio != nil {
				gui.studio.cancel()
			}
			gui.closeConfirmed = true
			gui.stopping = true
			gui.uiDone.Store(true) // 正常关闭：看门狗别再误报"UI 卡死"
			if gui.sess != nil {
				gui.sess.Stop()
			}
			// 覆盖"点窗口右上角 X"这条路：它也走 wmClose，但发起者不是按钮。
			gui.armExitGuard()
		}
		pKillTimer.Call(uintptr(hwnd), idTimer) // 先停定时器，别再往正在销毁的控件写
		pDestroyWindow.Call(uintptr(hwnd))
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

// runGUI 是 CS2雷达.exe 的入口。返回进程退出码。
func runGUI(cfgPath string) int {
	// Production does not auto-create logs or raw diagnostic reports.

	// DPI 感知（失败就算了，Windows 会自己缩放）
	if err := pSetDpiAwareness.Find(); err == nil {
		pSetDpiAwareness.Call(^uintptr(3)) // PER_MONITOR_AWARE_V2 = -4
	} else {
		pSetProcessDpiAwar.Call()
	}

	launched, err := ensureElevated()
	if err != nil {
		messageBox("CS2 雷达", err.Error(), mbIconError|mbOK)
		return 1
	}
	if launched {
		return 0 // 提权实例已拉起，本进程退出
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	showStudioIntro()
	app := &guiApp{studio: newStudioUI()}
	gui = app
	// 把这条 goroutine 钉死在当前 OS 线程上 —— **Win32 GUI 的硬性要求**。
	//
	// Windows 的消息队列是 per-OS-thread 的：窗口建在哪个线程，它的消息
	// （WM_TIMER / WM_CLOSE / WM_PAINT…）就只进哪个线程的队列。而 Go 的
	// goroutine 会在 OS 线程之间迁移，一旦消息循环被调度到别的线程上，
	// 原线程队列里的消息就永远没人取 —— 表现就是：
	//   跑一段时间后窗口"假死"、状态栏不再刷新、点关闭没反应（WM_CLOSE 收不到）。
	// 这类问题只在跑了若干秒后才出现，冒烟测试十几秒根本复现不了。
	// LockOSThread 之后这条 goroutine 不再迁移，消息循环始终是同一个线程。
	// UI thread already locked before the approved fragment intro.
	if err := app.create(); err != nil {
		messageBox("CS2 雷达", err.Error(), mbIconError|mbOK)
		return 1
	}
	if cfgPath != "" {
		app.appendLog("配置文件: " + cfgPath)
	}
	app.appendLog("gamesense：请在本窗口登录卡密，登录前不打开网卡、不读取游戏进程。")
	app.run()
	return 0
}
