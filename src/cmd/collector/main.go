// Production collector: remote-only; data-protocol migration candidate, not a release.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"local/cs2-radar/internal/capturefilter"
	"local/cs2-radar/internal/handshake"
	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
	"local/cs2-radar/internal/pcapdev"
	"local/cs2-radar/internal/runtimereport"
	"local/cs2-radar/internal/startupdiag"
	"local/cs2-radar/internal/transport"
	"local/cs2-radar/internal/uibridge"
	"local/cs2-radar/internal/uplink"
	"local/cs2-radar/internal/winapi"
)

var (
	flagIPC        = flag.Bool("ipc", false, "Stream packets and keys to the launcher's anonymous pipe")
	flagDuration   = flag.Duration("duration", 0, "Stop after this duration")
	flagNoKeys     = flag.Bool("no-keys", false, "Capture without accessing the game process bytes")
	flagNoFilter   = flag.Bool("no-filter", false, "关闭端口过滤（默认按目标进程占用的本机 UDP 端口过滤）")
	flagListDevice = flag.Bool("list-devices", false, "List capture interfaces then exit")
	flagSelfCheck  = flag.Bool("selfcheck", false, "抓包能力自检（SIO_RCVALL 是否可用）后退出")
	flagMemoryInfo = flag.Bool("memory-info", false, "Query memory region counts only; do not read memory or suspend the game")
	flagPID        = flag.Int("pid", 0, "Target process id (default: find cs2.exe)")
	flagProc       = flag.String("proc", "cs2.exe", "Target process name")
	flagScanBudget = flag.Uint64("scan-budget", 4_000_000, "Max X25519 candidates before giving up (reconstruction-only knob)")
	// 大范围扫描时的廉价预筛。关掉它就是"逐字节全量校验"，零漏检但极慢 ——
	// 只在"怀疑被预筛漏掉"时用。
	flagPrivFilter = flag.String("priv-filter", "auto", "大范围扫描预筛：auto=自动开 / off=关闭（逐字节全量校验，零漏检但慢得多）")
	// clamp 形态优先的两遍扫。默认开：X25519 标量乘是这条路的全部成本，
	// 先用 clamp 形态筛一遍能把 976 MB 从 2 分半压到十秒级，没命中再跑全量。
	flagClampFirst = flag.Bool("clamp-first", true, "私钥扫描先跑「clamp 形态」那一遍（快约 30 倍），没命中再跑全量；关掉则直接全量")
	flagKeyBudget  = flag.Int("key-budget", 1200, "私钥搜索总预算（秒）：超时即停，报告里写明覆盖了多少")
	// 冻结期间最多抓多少 MB 内存到本地副本。
	// 抓是 memcpy 级别（实测 64 MB 只占掉 978 ms 冻结里的一小部分），校验才是瓶颈，
	// 所以这里放开：抓得多，解冻后能校验的范围就大。校验本身受 -key-budget 约束。
	flagSnapMB = flag.Int("snap-mb", 1024,
		"冻结期间最多抓取多少 MB 内存。并行抓取实测 6.7 GB/s：512→77ms、1024→153ms、2048→306ms；4096 会撞 700ms 看门狗")
	// 冻结游戏进程：原版 v2.0.5 的做法。目的是把进程的时间停住，抢在客户端
	// 擦掉会话私钥之前把内存抄下来。
	//
	// ⚠ 2026-10-18 重要修正（推翻 10-17 的归因）：
	//
	// 10-17 21:01 那次运行之后账号被封，当时判断主因是 `NtSuspendProcess`。
	// 但用户实测**原版没有被检测到**，而反汇编 `memscan.(*Process).FreezeFast`
	// @0xe5a80 确认：原版就是一次 `NtSuspendProcess(p.Handle)` —— 和我们完全一样。
	// 所以**冻结动作本身不是封号主因**。
	//
	// 🔴 2026-10-19 再修正（推翻上一版的归因）：
	//
	// 上一版把真因归到「冻结着的时候读了多少」（原版读 32 字节，我们 21:01
	// 读了 512 MB + 6.6 GB）。逆向完美平台反作弊（报告
	// `2/report/20261019-完美平台反作弊分析.md`）后确认：**读量它根本看不到** ——
	// ReadProcessMemory 只在本机内核里发生，不经过任何网络或驱动上报。
	//
	// 真正异常的是 `NtSuspendProcess` 把**全部线程（含反作弊注入的心跳线程）
	// 挂起 1.979 秒**。心跳断流会被判成"进程被调试/挂起"。
	// 所以风险点是**冻结时长**，不是冻结动作，也不是读量：
	//
	//	原版 -freeze-hold 上限 : 700 ms（反汇编 0x18324d mov edi, 0x29b92700）
	//	我们 21:01 那次         : 1979 ms  ← 被封
	//	现在 short 实测         : 352 ms（42 枚举 + 92 定位 + 168 抓取）
	//
	// 🔴 2026-10-19 09:39 改回默认 short。
	//
	// 理由（用户判断正确）：私钥只活一次 RTT，不冻结根本拿不到 —— 09:39 那次
	// 跑的是默认 off，日志里就是 `[key] 冻结情况：未冻结` + `达到上限被截断`，
	// keyfind 找到公钥 4 处却始终没有私钥，派生卡在 has_key=false。
	//
	// 原版本身也冻结，这是从反汇编量出来的硬数据：
	//	原版 -freeze-hold 上限 : 700 ms（0x18324d mov edi, 0x29b92700）
	//	原版到点兜底解冻        : 0x183520 call time.AfterFunc
	//	我们 21:01 那次         : 1979 ms  ← 被封
	//	short 实测              : 352 ms   ← 比原版上限还短一半
	//
	// 也就是说封号那次不是「冻结」这件事，是**冻结了 1.979 秒**，把反作弊
	// 注入的心跳线程一起挂起了近 2 秒。现在 -freeze-hold 默认 700 且硬夹到
	// 700（超了自动退回），冻结时长永远 ≤ 原版上限。
	flagFreeze = flag.String("freeze", "short",
		"short=握手后立刻冻，枚举+定位+抓取都在冻结窗口内（实测约 350ms）—— **默认**，"+
			"这是唯一能拿到会话私钥的档位"+
			" / off=不冻（只抓包，拿不到私钥，也就不会有目标）"+
			" / full=同 short（保留旧名兼容）。"+
			"⚠ 冻结时长上限硬夹 700ms = 原版反汇编量出来的值（0x18324d）；"+
			"21:01 那次是 1979ms 才封号。"+
			"⚠ 真正的安全网是 acguard：检测到完美/5E/Faceit/EAC/BattlEye 在场时，"+
			"不管这个参数填什么都会拒绝碰进程（见 -allow-ac）。")

	// 反作弊在场时是否仍然碰游戏进程。
	//
	// 默认 false。理由见 acguard.go 的文件头：完美平台能直接看到谁打开了 cs2.exe，
	// 「冻得短」并不安全 —— 2026-10-19 现场一次冻结+读就封号了。
	flagAllowAC = flag.Bool("allow-ac", false,
		"在反作弊进程在场时仍然读写游戏进程内存。**默认禁止**。"+
			"默认行为：检测到完美/5E/Faceit/EAC/BattlEye/Vanguard 就退化成纯抓包，"+
			"一个字节都不碰游戏进程。明知风险自负才加这个参数")

	// 单次冻结的硬上限。默认 700 ms —— 从原版反汇编量出来的真值，不是估的：
	//
	//	原版 0x18324d  mov edi, 0x29b92700   ; 700,000,000 ns
	//	原版 0x183520  call time.AfterFunc   ; 到点兜底解冻
	//
	// 我们原来写的是 6 秒（比原版长 8.6 倍）。这个数字直接决定反作弊看到的
	// 「一次挂起有多长」，是当前最值得对齐的一个参数。
	flagFreezeHold = flag.Int("freeze-hold", 700,
		"单次冻结硬上限（毫秒），到点强制解冻。默认 700 = 原版实测值；"+
			"调大只是为了排查'700ms 内扫不完'，生产不要超过 1500")

	// 节流：原版每个服务器最多试 3 次、相邻两次至少隔 1 秒。
	// 反汇编依据见 throttle.go 顶部注释。
	flagKeyTries = flag.Int("key-tries", 3,
		"同一个服务器（按握手包源 IP）最多尝试几次密钥搜索，0=不限。默认 3 = 原版实测值")
	flagKeyGap = flag.Int("key-gap", 1000,
		"同一个服务器两次尝试之间的最小间隔（毫秒），0=不限制。默认 1000 = 原版实测值")

	// hint 表路径。快路径的全部意义在这里：原版 probeHint 只读 32 字节 × 条数，
	// 而全量扫描要读 7.5 GB —— 差 7 个数量级，这才是"原版不被检测、我们被检测"的原因。
	//
	// 空字符串 = 用 exe 同目录的 hints.json。设成 "off" 可禁用（强制每次全量扫描）。
	flagHints = flag.String("hints", "",
		"hint 表路径（默认 exe 同目录 hints.json）。有命中时只读 32 字节×条数，不冻结不扫描；off=禁用")

	// hint 第 2 轮（rebase）默认关掉。
	//
	// 03:27 现场实测：第 2 轮展开出 8 个候选、读 256 字节、**未命中**，
	// 却花掉 132~154 ms —— 时间几乎全花在 `RegionsWithError` 枚举 7948 个区域上。
	// 而这 130 ms 直接加在"握手→冻结延迟"上（那次延迟从 6 ms 涨到 305 ms），
	// 而私钥只活一个 RTT。**用 130 ms 的竞速时间去换 8 个几乎不可能命中的候选，
	// 是最差的交易。**
	//
	// 结论：region_off 跨进程不稳定，第 2 轮基本无效。保留代码但默认关闭，
	// 需要排查时用 -hint-rebase 打开。
	flagHintRebase = flag.Bool("hint-rebase", false,
		"hint 第 2 轮：按区域指纹展开候选再试（默认关。实测跨进程基本不命中，且要枚举全部区域、耗时 130ms+）")

	// hint 表诊断：不抓包、不读内存内容，只把 hint 记录的地址换算成各种相对偏移，
	// 并报告在当前进程里落不落得到可读区域。
	//
	// 这是"自己测出 hint 偏移"的工具：跑一次看 RVA，重开游戏再跑一次看 RVA 是否相同。
	flagHintsInfo = flag.Bool("hints-info", false,
		"打印 hint 表的地址/模块RVA/区域偏移，并检查在当前进程里是否可读（用于自己测偏移）")

	// 抓包诊断：跑完后写一份报告，说明「过滤前到底抓到了什么、为什么没握到手」。
	// 排障用，常态不写文件。
	flagDiagnose = flag.String("diagnose", "", "跑完后写抓包诊断报告到该路径（端口分布 / 握手检测）")

	// 内存里找**会话密钥**（锚点法 + 全内存暴力搜索）。默认关闭。
	//
	// 2026-10-19 定案：CS2 走 Valve GameNetworkingSockets 直连 UDP，
	// 会话密钥由握手材料经 HKDF-SHA256 派生，公式已经拿到（internal/cs2crypto/gns.go）。
	// 也就是说「在内存里翻密钥」这条路的**存在意义已经没有了**：
	// 它烧 10~20 分钟 CPU、把帧率和解码都拖慢，而且实测扫完 6.7 GB 一无所获
	// （密钥在 Go/Steam 网络栈里以扩展轮密钥形式存在，不是 32 字节明文）。
	//
	// 留着这个开关只为将来协议再变时做排障，常态不要开。
	flagMemSessionKey = flag.Bool("mem-session-key", false,
		"（排障）在 cs2 内存里搜 AES 会话密钥：锚点法 + 全内存暴力搜索，很慢，常态不需要")

	// 原始包落盘（JSONL，每行 {ts,dir,src,dst,data}）。排障用，文件可能很大。
	flagDump = flag.String("dump", "", "把**过滤前**的 UDP 包写成 JSONL（排障用，文件较大）")
	// 故意冻结 UI 线程，用来验证"UI 卡死取证"这套机制本身是活的。
	// 不验证的话，等真出卡死时可能拿到一份空文件，那就白改了。
	flagUIFreeze = flag.Int("ui-freeze", 0, "（排障）启动后让 UI 线程故意冻结 N 秒，验证卡死取证")
	// 把日志框里的内容同时落一份到文件。窗口版没有控制台，用户截屏只能看到
	// 可见的那几行；有了文件才能拿到完整时间线（尤其退出路径上的 [stop] 打点）。
	flagLogFile = flag.String("logfile", "", "（排障）把日志框内容同时写到该文件")

	// GUI 模式：由 CS2雷达.exe（-H=windowsgui 构建）自动置位，打开原生窗口。
	flagGUI = flag.Bool("gui", false, "窗口模式（CS2雷达.exe 用；自动提权 + 打开浏览器）")
	// 提权后重入的标记，防止无限弹 UAC。
	flagElevated = flag.Bool("elevated", false, "内部标记：已提权重入")
	// 抓包结束（-duration 到点或抓包出错）后自动关窗口，供冒烟测试用。
	flagAutoExit = flag.Bool("auto-exit", false, "窗口模式：抓包结束后自动退出")

	// Production is remote-only; no local decoder, replay or insecure flag.
	flagOpenBrowser = flag.Bool("open-browser", false, "授权启动后打开原生回环像素视图（不携带凭据）")
	flagUplink      = flag.String("uplink", "", "必需：HTTPS 服务端上行地址 /api/v1/ingest")
	flagSession     = new(string) // server-assigned only
	flagCACert      = flag.String("ca", "", "可选 PEM CA；仍严格验证证书及服务器身份")

	// 配置文件：让最终用户不用记一堆参数。
	// 不指定时自动读 exe 同目录的 capture.json。
	flagConfig = flag.String("config", "", "配置文件路径（默认：exe 同目录的 capture.json）")

	flagPrintRadar = flag.Bool("print-radar-url", false, "已停用：请用 -view-only 或运行中的原生客户端打开本机视图")
)

// defaultGUIMode 由构建参数注入。
//
// 同一份代码编出两个 exe：
//
//	capture.exe      控制台版：不注入 → "false"
//	CS2雷达.exe      窗口版：-ldflags "-X main.defaultGUIMode=true"
//
// 这样双击 CS2雷达.exe（不带任何参数）就直接进窗口模式。
var defaultGUIMode = "false"

// radarURL never exports a credential into a URL, browser history or logs.
func radarURL() (string, error) {
	if err := uplink.ValidateEndpoint(*flagUplink); err != nil {
		return "", err
	}
	return "", fmt.Errorf("视图地址仅在原生授权启动后创建；请使用 -view-only 或客户端的打开按钮")
}

// clientConfig 是 capture.json 的结构。字段与命令行参数一一对应。
//
// 优先级：命令行显式给出 > 配置文件 > 内置默认值。
// 实现方式是在 flag.Parse() 之前把配置值写进 flag 的默认值，
// 这样"命令行没给就用默认（=配置值）"这条规则自然成立。
type clientConfig struct {
	Listen     string `json:"listen"`      // 旧字段；非空即拒绝
	Uplink     string `json:"uplink"`      // （可选）服务器上行地址；留空 = 本机解码
	Session    string `json:"session"`     // 会话标识（同一房间用同一个）
	Token      string `json:"token"`       // 上行鉴权共享密钥
	CA         string `json:"ca"`          // 服务端证书（相对路径按配置文件所在目录解析）
	Insecure   bool   `json:"insecure"`    // 旧字段；true 即拒绝
	Proc       string `json:"proc"`        // 目标进程名
	PID        int    `json:"pid"`         // 目标进程号（0=按名字找）
	Duration   string `json:"duration"`    // 跑多久后停，如 "2h"（空=一直跑）
	NoKeys     bool   `json:"no_keys"`     // 只抓包不读内存
	NoFilter   bool   `json:"no_filter"`   // 关闭端口过滤
	ScanBudget uint64 `json:"scan_budget"` // 私钥搜索候选上限
}

// scanConfigPath 预扫描命令行，找出配置文件路径；没给就找 exe 同目录的 capture.json。
func scanConfigPath() string {
	args := os.Args[1:]
	for i, a := range args {
		if (a == "-config" || a == "--config") && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "-config=") {
			return strings.TrimPrefix(a, "-config=")
		}
		if strings.HasPrefix(a, "--config=") {
			return strings.TrimPrefix(a, "--config=")
		}
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "capture.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// loadConfig 读配置文件并把它写进各 flag 的默认值。返回实际使用的路径（可能为空）。
func loadConfig() string {
	path := scanConfigPath()
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		privateDiagnosticf("读配置文件失败 %s: %v\n", path, err)
		os.Exit(2)
	}
	var c clientConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		privateDiagnosticf("配置文件格式错误 %s: %v\n", path, err)
		os.Exit(2)
	}
	dir := filepath.Dir(path)

	if c.Listen != "" || c.Insecure {
		fmt.Fprintln(os.Stderr, "生产版禁止本地监听或跳过证书校验；请更新 capture.json")
		os.Exit(2)
	}
	if c.Uplink != "" {
		*flagUplink = c.Uplink
	}
	if c.Token != "" || (c.Session != "" && c.Session != "default") {
		fmt.Fprintln(os.Stderr, "旧静态 token/自选会话已停用；请迁移到设备绑定数据授权")
		os.Exit(2)
	}
	if c.CA != "" {
		// 相对路径按配置文件所在目录解析，这样整个目录可以随便挪位置
		if !filepath.IsAbs(c.CA) {
			c.CA = filepath.Join(dir, c.CA)
		}
		*flagCACert = c.CA
	}
	if c.Proc != "" {
		*flagProc = c.Proc
	}
	if c.PID != 0 {
		*flagPID = c.PID
	}
	if c.Duration != "" {
		d, err := time.ParseDuration(c.Duration)
		if err != nil {
			privateDiagnosticf("配置文件 duration 无效 %q: %v\n", c.Duration, err)
			os.Exit(2)
		}
		*flagDuration = d
	}
	if c.NoKeys {
		*flagNoKeys = true
	}
	if c.NoFilter {
		*flagNoFilter = true
	}
	if c.ScanBudget != 0 {
		*flagScanBudget = c.ScanBudget
	}
	return path
}

// describeConfig never prints a card, access token, key or URL credential.
func describeConfig(path string) {
	privateDiagnosticf("配置文件: %s\n", path)
	fmt.Fprintln(os.Stderr, "  解码位置: 仅远端（失败停止，无本地回退）")
	privateDiagnosticf("  上行地址: %s\n", *flagUplink)
	privateDiagnosticf("  服务端证书: %s\n", orDash(*flagCACert))
	fmt.Fprintln(os.Stderr, "  数据鉴权: Ed25519 设备证明 / 短期资格 / 服务端分配会话")
}

func orDash(s string) string {
	if s == "" {
		return "(未设置)"
	}
	return s
}

// emitter 把事件写成 NDJSON（-ipc 时走管道帧，否则走 stderr 便于人工观察）。
type emitter struct {
	ipc bool
	mu  sync.Mutex
}

func (e *emitter) emit(name string, data map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Event payloads used to contain private keys, raw peers and memory
	// addresses. Production exports fixed event names and numeric totals only.
	if name == "capture_stats" {
		packets, _ := data["packets"].(uint64)
		bytes, _ := data["bytes"].(uint64)
		fmt.Fprintf(os.Stderr, "[stats] packets=%d bytes=%d\n", packets, bytes)
		return
	}
	for _, c := range name {
		if c < 'a' || c > 'z' {
			if c != '_' {
				return
			}
		}
	}
	if len(name) == 0 || len(name) > 48 {
		return
	}
	fmt.Fprintln(os.Stderr, "[event]", name)
}

// statsSummary 把 capture_stats 压成一行人类可读摘要。
func statsSummary(d map[string]any) string {
	num := func(k string) any {
		if v, ok := d[k]; ok {
			return v
		}
		return 0
	}
	var b strings.Builder
	fmt.Fprintf(&b, "收 %v 包", num("packets"))
	if f, ok := d["filter"].(map[string]any); ok {
		fmt.Fprintf(&b, "｜过滤丢弃 %v", f["dropped"])
		// 单独把「像 GNS 的被丢包」写出来。混在总丢弃里看不出问题，
		// 而这个数非零就等价于「signon 正在被白名单丢掉」。
		if v, ok := f["drop_gns"]; ok {
			fmt.Fprintf(&b, "（其中像 GNS 的 %v）", v)
		}
		if ps, ok := f["ports"].([]uint16); ok {
			fmt.Fprintf(&b, "（白名单 %d 个端口）", len(ps))
		}
	} else if s, ok := d["filter"].(string); ok {
		fmt.Fprintf(&b, "｜%s", s)
	}
	fmt.Fprintf(&b, "｜c2s %v s2c %v", num("c2s"), num("s2c"))
	if tp, ok := d["top_ports"].([]string); ok && len(tp) > 0 {
		fmt.Fprintf(&b, "｜最忙端口 %s", strings.Join(tp, " "))
	}
	if f, ok := d["top_drop_flows"].([]string); ok && len(f) > 0 {
		fmt.Fprintf(&b, "｜被丢的GNS流 %s", strings.Join(f, " "))
	}
	if up, ok := d["uplink"].(map[string]any); ok {
		fmt.Fprintf(&b, "｜上行 %v 包/%v 批", up["packets"], up["batches"])
	}
	return b.String()
}

// runHintsInfo 打印 hint 表的地址与各种相对偏移，并检查它们**在当前进程里**
// 落不落得到可读区域。
//
// 这是「自己测出 hint 偏移」的工具，用法只有两步：
//
//  1. 跑一次正常采集，让它扫描成功（会写一条 hint 进 hints.json）
//  2. 退出游戏、重开、连服务器，再跑 `capture.exe -hints-info`
//     看「模块 RVA」这一行和上次是否相同
//
// 判定：
//
//	RVA 相同 + 可读=是   → 这个偏移跨会话稳定，可以写死复用
//	RVA 不同 + 可读=否   → 私钥在会移动的堆块里，hint 只能同局内用（跨会话靠第 2 轮 rebase）
//
// 注意：这个模式**不读任何内存内容**，只用 VirtualQueryEx 的区域表判断可达性。
// 它连 PROCESS_VM_READ 都不申请（OpenForQuery 用 0x400），足迹比采集时更小。
func runHintsInfo() int {
	path := hintPath()
	if path == "" {
		fmt.Fprintln(os.Stderr, "-hints off：没有 hint 表可看")
		return 2
	}
	hs := keyfind.LoadHints(path)
	fmt.Printf("hint 表：%s\n", path)
	fmt.Printf("条目数：%d\n\n", len(hs))
	if len(hs) == 0 {
		fmt.Println("（空表。先跑一次正常采集，让全量扫描成功并写入一条，再回来。")
		fmt.Println("  或者用 -hints 指定另一份表。）")
		return 0
	}

	pid, err := resolvePID()
	if err != nil {
		privateDiagnosticf("解析目标进程失败：%v\n（可以加 -pid 指定，或先启动游戏）\n", err)
		return 2
	}
	proc, err := memscan.OpenForQuery(pid)
	if err != nil {
		privateDiagnosticf("打开进程失败：%v\n", err)
		return 2
	}
	defer proc.Close()

	regions, rerr := proc.RegionsWithError(time.Now().Add(30*time.Second), 0)
	if rerr != nil && rerr != memscan.ErrRegionDeadline && rerr != memscan.ErrRegionLimit {
		privateDiagnosticf("枚举区域失败：%v\n", rerr)
		return 2
	}
	moduleBase := proc.ModuleBase()

	fmt.Printf("当前进程：pid=%d，可读区域 %d 个\n", pid, len(regions))
	if moduleBase != 0 {
		fmt.Printf("当前模块基址：%#x\n", moduleBase)
	} else {
		fmt.Printf("当前模块基址：取不到（没有 MEM_IMAGE 区域）\n")
	}
	fmt.Println()

	for i, h := range hs {
		fmt.Printf("【%d】学习时\n", i+1)
		fmt.Printf("  地址        %#x\n", h.Addr)
		if h.ModuleBase != 0 {
			fmt.Printf("  模块基址    %#x  → RVA %#x\n", h.ModuleBase, h.ModuleOff)
		} else {
			fmt.Printf("  模块基址    未记录\n")
		}
		if h.RegionSize != 0 {
			fmt.Printf("  区域        %#x + %#x  (size %s, protect %#x, type %#x)\n",
				h.RegionBase, h.RegionOff, humanSize(uintptr(h.RegionSize)),
				h.RegionProtect, h.RegionType)
		} else {
			fmt.Printf("  区域        未记录\n")
		}
		if h.LearnedAt != "" {
			fmt.Printf("  学到于      %s，累计命中 %d 次\n", h.LearnedAt, h.Hits)
		}
		fmt.Printf("  当时公钥    %s\n", orDash(h.Pub))

		fmt.Printf("  当前进程里：\n")
		_, asIsOK := memscan.RegionOf(regions, h.Addr)
		fmt.Printf("    as-is       %#x  可读=%s\n", h.Addr, yesNo(asIsOK))

		modOK := false
		if moduleBase != 0 && h.ModuleOff != 0 {
			addr := uintptr(int64(moduleBase) + h.ModuleOff)
			_, ok := memscan.RegionOf(regions, addr)
			modOK = ok
			fmt.Printf("    module+off  %#x  可读=%s  (RVA %#x)\n", addr, yesNo(ok), h.ModuleOff)
		} else {
			fmt.Printf("    module+off  不可算（没记模块偏移或拿不到当前模块基址）\n")
		}

		cands := keyfind.HintCandidates(h, moduleBase, regions)
		var regionAddrs []uintptr
		for _, c := range cands {
			if c.Source == "region+off" {
				regionAddrs = append(regionAddrs, c.Addr)
			}
		}
		if len(regionAddrs) > 0 {
			fmt.Printf("    region+off  同指纹区域 %d 个（每个都是候选）\n", len(regionAddrs))
			for _, a := range regionAddrs {
				fmt.Printf("                  %#x\n", a)
			}
		} else if h.RegionSize != 0 {
			fmt.Printf("    region+off  同指纹区域 0 个（区域布局变了）\n")
		}

		fmt.Printf("  结论：")
		switch {
		case asIsOK && modOK:
			fmt.Printf("原地址和模块相对**都**可用 → 这个 RVA 跨会话稳定，可以直接复用。\n")
		case modOK:
			fmt.Printf("原地址已失效（ASLR 移动），但**模块相对偏移可用** → 偏移 = RVA %#x。\n", h.ModuleOff)
		case len(regionAddrs) > 0:
			fmt.Printf("模块相对不可用，区域相对有 %d 个候选 → 下次会走第 2 轮 rebase 试它们。\n", len(regionAddrs))
		default:
			fmt.Printf("两种相对量都落不到可读区域 → 私钥在会移动的堆块里，hint 只能同局内用。\n")
			fmt.Printf("        跨会话只能靠每次重新扫描（这正是需要压小扫描面的场景）。\n")
		}
		fmt.Println()
	}
	return 0
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

// runListDevices 打印抓包方式与本机可抓包的网卡地址。
//
// 抓包只用 Windows 原始套接字（SIO_RCVALL），不依赖任何第三方驱动。
func runListDevices() {
	fmt.Println("抓包方式: Windows 原始套接字 socket(AF_INET, SOCK_RAW, IPPROTO_IP)")
	fmt.Println("          + WSAIoctl(fd, SIO_RCVALL=0x98000001) 双向抓包")
	fmt.Println("          + WSARecvFrom 逐包取回")
	fmt.Println("          + GetExtendedUdpTable 按目标进程 UDP 端口过滤")
	fmt.Println("          不依赖 Npcap / wpcap.dll，不需要任何驱动。")
	fmt.Println()

	if err := pcapdev.RawAvailable(); err == nil {
		fmt.Println("状态: ✓ 可用")
	} else {
		fmt.Printf("状态: ✗ 不可用（%v）\n", err)
		fmt.Println("      SIO_RCVALL 需要管理员权限。请「以管理员身份运行」，")
		fmt.Println("      或直接双击 CS2雷达.exe（它会自己弹 UAC 提权）。")
		return
	}

	devs := pcapdev.Devices()
	fmt.Println()
	if len(devs) == 0 {
		fmt.Println("未找到可抓包的 IPv4 地址。")
		return
	}
	fmt.Println("将在这几个网卡地址上开抓包口（每个地址一个 socket）：")
	for _, d := range devs {
		fmt.Printf("  %-16s %s\n", d.Name, d.Description)
	}
	fmt.Println()
	fmt.Println("说明：SIO_RCVALL 是「整机抓包」，不按网卡选择 —— 所有网卡的流量都会收到，")
	fmt.Println("      再由端口过滤只留下目标进程的 UDP。所以没有 -dev / -backend 参数。")
}

// runSelfCheck 做一次真实抓包能力自检：实际打开一次抓包句柄。
// 返回进程退出码（0 = 通过）。
func runSelfCheck() int {
	rawOK := pcapdev.RawAvailable() == nil
	fmt.Printf("自检：原始套接字(SIO_RCVALL) 可用=%v\n", rawOK)

	h, err := pcapdev.Open()
	if err != nil {
		privateDiagnosticf("✗ 抓包打开失败: %v\n", err)
		fmt.Fprintln(os.Stderr, "  提示：SIO_RCVALL 需要管理员权限 —— 请「以管理员身份运行」，")
		fmt.Fprintln(os.Stderr, "        或直接双击 CS2雷达.exe（自动提权）。")
		return 1
	}
	defer h.Close()
	fmt.Printf("✓ 抓包可用，模式 = %s，网卡 %d 个\n", h.RawCaptureMode(), h.InterfaceCount())
	fmt.Println("  端口过滤：按目标进程占用的本机 UDP 端口过滤。")
	fmt.Println("            发现不到端口时不过滤（宁可多收，不可漏收）；-no-filter 可关闭。")
	return 0
}

func main() {
	if defaultDeviceRepairMode == "true" {
		os.Exit(runDeviceRepairUI())
	}
	// 必须在 flag.Parse() 之前：把配置文件的值灌进 flag 默认值，
	// 这样命令行显式给出的参数仍能覆盖配置（优先级自然成立）。
	cfgPath := loadConfig()
	flag.Parse()
	if *flagDiagnosticSelftest {
		os.Exit(runDiagnosticSelftest())
	}
	if *flagDeviceCheck || *flagDeviceRepair {
		os.Exit(runDeviceCheck(os.Stdout, *flagDeviceRepair))
	}
	if *flagConnectionCheck {
		os.Exit(runConnectionCheck(os.Stdout))
	}
	if err := productionDiagnosticsPolicy(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *flagLicenseCheck {
		os.Exit(runLicenseCheck())
	}
	if *flagViewOnly {
		os.Exit(runViewOnly())
	}
	if err := uplink.ValidateEndpoint(*flagUplink); err != nil {
		if (*flagGUI || defaultGUIMode == "true") && !*flagPrintRadar {
			messageBox("gamesense 配置错误", err.Error(), mbIconError|mbOK)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// 私钥搜索预算：<=0 表示不限制（排障时可用 -key-budget 0 让兜底扫到底）。
	if *flagKeyBudget > 0 {
		keyScanBudget = time.Duration(*flagKeyBudget) * time.Second
	} else {
		keyScanBudget = 24 * time.Hour
	}
	switch strings.ToLower(strings.TrimSpace(*flagPrivFilter)) {
	case "off", "none", "no", "0", "false":
		privFilterDisabled = true
	}
	// -priv-filter off 是「零漏检」档，跟 clamp 优先的目的正好相反：
	// 那一档要的是逐字节全量，所以强制关掉快扫，避免多花一遍时间。
	clampFirstScan = *flagClampFirst && !privFilterDisabled
	if *flagSnapMB > 0 {
		snapshotCapBytes = uintptr(*flagSnapMB) << 20
	}

	// 冻结上限与节流：对齐原版 v2.0.5（数值来源见各 flag 的注释）。
	//
	// 夹取范围是为了防止手滑：-freeze-hold 0 会让冻结立刻超时（等于不冻，
	// 但走的是"冻结失败"分支，日志会误导）；上限 5000 ms 是安全红线，
	// 超过就退回原版的 700 ms —— 宁可这次搜不到，也不要让游戏停 6 秒。
	if *flagFreezeHold > 0 {
		hold := time.Duration(*flagFreezeHold) * time.Millisecond
		if hold > 5*time.Second {
			privateDiagnosticf(
				"⚠ -freeze-hold %d ms 超过安全上限，已退回 700 ms（原版实测值）\n", *flagFreezeHold)
			hold = 700 * time.Millisecond
		}
		freezeHoldLimit = hold
	}

	if *flagPrintRadar {
		link, err := radarURL()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println(link)
		return
	}

	if *flagHintsInfo {
		os.Exit(runHintsInfo())
	}

	if *flagListDevice {
		runListDevices()
		return
	}

	if *flagSelfCheck {
		os.Exit(runSelfCheck())
	}

	// 窗口模式：CS2雷达.exe（-H=windowsgui 构建）双击进来。
	// 自己负责提权、开窗口、跑采集、开浏览器。
	if *flagGUI || defaultGUIMode == "true" {
		os.Exit(runGUI(cfgPath))
	}

	// 除 -list-devices 外，都先把生效配置打出来，让用户确认在连哪台服务器。
	if cfgPath != "" {
		describeConfig(cfgPath)
	}

	if *flagMemoryInfo {
		runMemoryInfo()
		return
	}

	// 启动时就把 hint 表状态打出来。
	//
	// 为什么必须放在这里：hint 只影响「拿到握手之后」的路径，没有握手时
	// 一个字都不会提。03:16 那次就是这样 —— 用户想验证 hint 快路径，
	// 结果整场没抓到握手，日志里连"有没有加载 hints.json"都看不出来，
	// 白等 3 分钟。这一行让"表里到底有没有东西"在启动瞬间就可见。
	if p := hintPath(); p != "" {
		hs := keyfind.LoadHints(p)
		privateDiagnosticf("[key] hint 表：%s（%s）\n", keyfind.DescribeHints(hs), p)
		if len(hs) > 0 {
			privateDiagnosticf(
				"[key]   → 抓到握手后会先试这 %d 条（读 32 字节×条数，不冻结、不扫描）\n", len(hs))
		}
	}

	runCapture()
}

// ---- Production remote-only outlet ----

// openBrowser 用系统默认浏览器打开 URL。
//
// 用 rundll32 的 FileProtocolHandler：它按协议关联派发，比拼 cmd start 少一层
// 引号转义问题。失败也不影响采集，所以只忽略错误。
func openBrowser(u string) {
	if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start(); err != nil {
		privateDiagnosticf("（未能自动打开浏览器: %v；请手动访问上面的地址）\n", err)
	}
}

// newSender accepts only a native, enrolled device-bound session.
func newSender(auth *captureLicense) (uplink.Sink, error) {
	if err := uplink.ValidateEndpoint(*flagUplink); err != nil {
		return nil, err
	}
	if auth == nil || auth.remote == nil || auth.remote.SessionID() == "" {
		return nil, fmt.Errorf("设备绑定数据授权尚未建立")
	}
	*flagSession = auth.remote.SessionID()
	return uplink.NewAsyncAuthenticatedRemote(*flagUplink, *flagSession, *flagCACert, auth.send)
}

// ---- 内存区域元数据（-memory-info）----

func runMemoryInfo() {
	pid, err := resolvePID()
	if err != nil {
		privateDiagnosticf("resolve pid: %v\n", err)
		os.Exit(1)
	}
	proc, err := memscan.OpenForQuery(pid)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer proc.Close()

	regions, err := proc.RegionsWithError(time.Now().Add(5*time.Second), 0)
	if err != nil && err != memscan.ErrRegionDeadline {
		privateDiagnosticf("regions: %v\n", err)
	}
	var total, writable uint64
	for _, r := range regions {
		total += uint64(r.Size)
		if r.Protect&0x04 != 0 || r.Protect&0x40 != 0 {
			writable += uint64(r.Size)
		}
	}
	fmt.Printf("pid=%d readable_regions=%d readable_bytes=%d writable_bytes=%d\n",
		pid, len(regions), total, writable)

	// ── 区域大小分布 ──
	//
	// 这一节是为了回答一个具体问题：**能不能靠"只扫小区域"把 locatePub 压进 700 ms。**
	//
	// 2026-10-19 实测依据：公钥在 cs2.exe 里的 5 处命中，所在区域大小分别是
	// 0x10000 / 0x3000 / 0x3f000 / 0xe000 / 0x11000 —— 全部 ≤ 256 KB，
	// 而且 Type 全是 MEM_PRIVATE（0x20000，堆）。而 locatePub 现在要扫 8061 MB
	// 才找到它们，耗时 2.451 s（≈3.29 GB/s）。
	//
	// 只要「MEM_PRIVATE 且 ≤1 MB」这一档的总字节数 < 2.3 GB，700 ms 就装得下。
	// 这个数决定阶段 3 是先做"收窄范围"（改动小）还是必须重写定位算法（改动大）。
	type sizeBucket struct {
		name  string
		limit uintptr
		n     int
		bytes uint64
	}
	buckets := []sizeBucket{
		{"≤64KB", 64 << 10, 0, 0},
		{"≤256KB", 256 << 10, 0, 0},
		{"≤1MB", 1 << 20, 0, 0},
		{"≤16MB", 16 << 20, 0, 0},
		{">16MB", ^uintptr(0), 0, 0},
	}
	var privN int
	var privBytes, smallPriv uint64
	for _, r := range regions {
		if r.Type != winapi.MEM_PRIVATE {
			continue
		}
		privN++
		privBytes += uint64(r.Size)
		if r.Size <= 1<<20 {
			smallPriv += uint64(r.Size)
		}
		for i := range buckets {
			if r.Size <= buckets[i].limit {
				buckets[i].n++
				buckets[i].bytes += uint64(r.Size)
				break
			}
		}
	}
	fmt.Printf("\n区域大小分布（只统计 MEM_PRIVATE = 堆，公钥必然在这里）\n")
	fmt.Printf("  合计 %d 个区域 / %.1f MB\n", privN, float64(privBytes)/(1<<20))
	for _, b := range buckets {
		pct := 0.0
		if privBytes > 0 {
			pct = float64(b.bytes) * 100 / float64(privBytes)
		}
		fmt.Printf("  %-8s %6d 个 / %8.1f MB  (%4.1f%%)\n", b.name, b.n, float64(b.bytes)/(1<<20), pct)
	}
	// 这行是结论：按当前实测速度 3.29 GB/s，700 ms 只能扫 2.3 GB。
	fmt.Printf("  → 只扫 MEM_PRIVATE 且 ≤1MB：%.1f MB，按 3.29 GB/s 约需 %d ms（目标 <700 ms）\n",
		float64(smallPriv)/(1<<20), int(float64(smallPriv)/3.29e9*1000))
}

// resolvePID 是所有内存访问的唯一入口 —— 反作弊闸门就放在这里，
// 一处拦住就全拦住（枚举区域 / 定位公钥 / 抓快照 / 找会话密钥都从这里拿 PID）。
func resolvePID() (uint32, error) {
	if reason := acBlockReason(); reason != "" {
		warnACBlocked(reason)
		return 0, &targetResolveError{state: filterSafetyBlocked, cause: fmt.Errorf("反作弊安全策略阻止访问目标进程")}
	}
	if *flagPID > 0 {
		return uint32(*flagPID), nil
	}
	return lookupTargetPID(*flagProc, memscan.FindPid)
}

// ---- 抓包会话 ----
//
// 命令行版与 GUI 版共用同一个 captureSession：
//   · 命令行版：startCapture() 后等 Ctrl+C / -duration，然后 Stop + Wait。
//   · GUI 版：跑在 goroutine 里，用 Status() 定时刷界面，按钮调 Stop()。

// captureStatus 是一次抓包的实时快照。
type captureStatus struct {
	Running     bool
	Packets     uint64
	Bytes       uint64
	C2S         uint64
	S2C         uint64
	Filtered    uint64
	FilterOn    bool
	FilterPID   uint32
	FilterPorts []uint16
	TopPorts    []string
	KeyPhase    string // 等待握手包 / 正在搜索 / 已就绪 / 失败
	KeyTag      string
	KeyErr      string
	Elapsed     time.Duration
}

type captureSession struct {
	report     *runtimereport.Journal
	reportDone chan struct{}
	diag       safeObservationCounters
	ui         *uibridge.Bridge
	em         *emitter
	h          *pcapdev.Handle
	sender     uplink.Sink
	locals     map[string]bool
	start      time.Time

	stopCh   chan struct{}
	stopOnce sync.Once
	doneCh   chan struct{}

	cfilter            *capturefilter.Filter
	filterMu           sync.Mutex
	ownerRefreshStart  time.Time
	ownerRefreshBudget int
	noFilter           bool

	pkts, bytes    uint64
	dirC2S, dirS2C uint64
	filteredOut    uint64
	// filterDropGNS 是「被白名单丢掉、但载荷首字节像 GNS 加密帧（高位 1）」的包数。
	//
	// 单列这个计数的理由：`filteredOut` 把 DNS/HTTPS 这类无关包和**游戏包**混在一起，
	// 现场看到 200 个丢弃根本分不清是不是丢了 signon。而 signon 丢了和 signon 没收到
	// 是两条完全相反的排查路线 —— 前者是白名单漏端口，后者是抓包没起来。
	// 2026-10-19 13:59 那次就是被这个混合计数掩盖了约 20 个 1137 字节的 signon 包。
	filterDropGNS uint64
	portMu        sync.Mutex
	portCnt       map[uint16]int
	// dropFlow 记「被白名单丢掉的像 GNS 的包」的**完整五元组**计数。
	//
	// 🔴 2026-10-19 22:35 现场：`过滤丢弃 96598（其中像 GNS 的 75439）`，
	// 但日志只打了 `51596→47960` 两个端口号，**没有 IP** —— 于是「这条流到底
	// 是游戏主链路，还是本机两个进程之间的回环」完全判不出来，
	// 只能靠猜。加这个表之后，下一局一眼就能定性。
	dropFlow map[string]int

	keyMu    sync.Mutex
	keyReady atomic.Bool
	// keySearching 表示私钥搜索还在跑。用户关窗口时搜索可能正在兜底，
	// 报告要如实写"结果未定"而不是让用户以为"扫完了也没有"。
	keySearching atomic.Bool
	keyAttached  atomic.Bool
	foundKey     []byte
	foundTag     string
	foundAddr    uintptr
	keyErr       string
	keyPhase     atomic.Value // string

	targetPubCh chan []byte

	// hsMu/hsClient/hsServer 记住「这次握手是谁跟谁」。
	//
	// 用来给 ServerHello 配对：只有来自同一个对端、发回同一个本机端口的包，
	// 才允许把里面的服务器临时公钥配到这次的私钥上。
	// 没有这道闸门，换服务器/换图时会拿别家的公钥算共享密钥 —— 同样解不出来，
	// 而且错得很隐蔽（日志上一切正常）。
	hsMu     sync.Mutex
	hsClient string
	hsServer string

	// GNS 双向握手材料（2026-10-19 定案的主链路）。
	//
	// 0x22 = ConnectRequest（客户端），0x23 = ConnectOK（服务器）。
	// 会话密钥由这两份报文的 cert/crypt 原始字节 + 双方 nonce + 双方连接 ID
	// 经 HKDF-SHA256 派生，公式见 internal/cs2crypto/gns.go。
	// 材料齐了 + 私钥到手 → 直接解出，不需要冻结扫内存、不需要暴力搜索。
	gnsMu       sync.Mutex
	gnsClient   *handshake.GNSPeer
	gnsServer   *handshake.GNSPeer
	gnsClientID []byte
	gnsServerID []byte

	// GNS 真实数据帧环形缓冲（两个方向各留一批）。
	//
	// 用途只有一个：给「从内存读 IV + 反推密钥」当判据。GCM 认证标签是
	// 「这把密钥/这个 IV 对不对」的完美判据，所以只要有几帧真密文，
	// 就能把内存里找到的候选逐个判掉 —— 不需要知道 KDF。
	gnsFrameMu sync.Mutex
	gnsC2S     [][]byte
	gnsS2C     [][]byte
	gnsRecover atomic.Bool // 同一时刻只跑一个内存恢复线程

	// memPIDErrOnce 保证「解析目标进程失败」只打一次日志。
	//
	// 反作弊在场时 resolvePID 每次都被闸门拦下，而内存恢复线程每 2 秒开一次，
	// 原来会一直刷同一行，把「为什么这局没目标」的说明全冲掉。
	memPIDErrOnce atomic.Bool

	// filterOffWhy 记录「端口过滤为什么没生效」。
	//
	// 两种原因的处理方式完全不同：cs2.exe 还没起来 = 等一下就好；
	// resolvePID 被反作弊闸门拦住 = 这一局永远不会过滤、也不会解密。
	filterOffWhy atomic.Value // string

	// gnsDiag 是「收帧闸门」的一次性诊断。
	//
	// 09:27 现场：has_gns=true、store 侧 frames=1167，但采集端一条 [gnsmem]
	// 都没有 —— 说明帧在采集端就被闸门拒了，而闸门条件（flags ∈ 0x80..0x83）
	// 是照开源源码推的，很可能和线上 Valve 内部构建不一致。
	//
	// 光放宽闸门还不够：得知道真实 flags 长什么样，否则下一轮还是猜。
	// 所以这里统计前 400 个 GNS 候选包的 flags 直方图 + connID 命中数，
	// 打印一次就永久停（不刷屏、不占带宽）。
	gnsDiagMu sync.Mutex
	gnsDiag   gnsFrameDiag
	// gnsRecoverTries 限制重试次数。
	//
	// 为什么要限：每次尝试都要遍历一遍目标进程内存（几 GB，约十秒）。
	// 帧环形缓冲有 24 个位置，如果不限次数，失败一次就会在收满之前
	// 反复重来近 20 次 —— 那是几分钟的持续大内存读，而成功概率并不会
	// 因为"多扫几遍同样的内存"而提高。
	gnsRecoverTries atomic.Int32

	// gnsRecoverAt 记「上一次开跑时，两个方向里较少的那个有几帧」。
	//
	// 🔴 2026-10-19 15:08 现场暴露的问题：原来的闸门是
	// `len(c2s) < 6 && len(s2c) < 6` —— 只要**一边**凑到 6 帧就开跑，
	// 于是第一次恢复在 c2s=6 / s2c=3 时就启动了。而 gnsTryKey 要求 3 帧全过，
	// s2c 只有 3 帧等于「一帧不完整就判密钥错」，假阴性极难查。
	// 更糟的是 3 次重试预算在开局几秒内就烧完了，之后帧涨到 2000 也不再试。
	//
	// 现在改成：两边都够 + 帧数比上次多出一档才重试。
	gnsRecoverAt atomic.Int32

	// 服务器临时公钥 + 一小撮真实密文帧，供「直接找会话密钥」用。
	//
	// 为什么要留帧：AES-GCM 的认证标签是判断"这把密钥对不对"的完美判据。
	// KDF 未知时，与其继续猜 info 串，不如拿真实帧去内存里试 —— 试中即得。
	skMu        sync.Mutex
	skPub       []byte       // 服务器临时公钥（ECDH 对端，也是内存里的强锚点）
	skClientPub []byte       // 客户端临时公钥（内存里一定存着一份，另一个强锚点）
	skFrames    [][]byte     // 本连接最早的一批 0x82 加密帧
	skGen       atomic.Int64 // 握手「代」：换图/重连 +1，搜索线程据此换料重来
	skRunning   atomic.Bool  // 同一时刻只允许一个搜索线程

	// hintProc 缓存 hint 快路径用的进程句柄。
	//
	// 🔴 为什么必须缓存：probeHintsFast 每个候选都调一次，原来每次都
	// resolvePID()（CreateToolhelp32Snapshot + 遍历全部进程）+ OpenForRead，
	// 一次 5~15 ms。04:10 现场那条握手包里有两个候选 → 两次探测 → 38 ms 的
	// 「握手→搜索延迟」里大半是这两次 pid 解析，而这段时间私钥正在被擦。
	// 句柄缓存后每次探测只剩 32 字节读取，微秒级。
	hintProcMu sync.Mutex
	hintProc   *memscan.Process

	// 节流：复刻原版 v2.0.5 的「每个服务器最多 3 次、间隔 ≥1 秒」。
	// 键是握手包的**源 IP**（和原版一致）—— 用公钥当键等于没有节流，
	// 因为每次握手的公钥都不一样。
	thr *keyThrottle
	// curTarget 是最近一次被放行的目标，命中后用它 MarkFound，
	// 这样同一个服务器后续握手直接跳过。
	curTarget atomic.Value // string
	// throttledOut 是因节流被丢掉的握手数，进诊断报告。
	// 没有这个计数，现场看到「有握手但没动静」会误判成抓包坏了。
	throttledOut atomic.Uint64

	// pubSeenAt 是「第一次在 c2s 包里认出 32 字节公钥」的 Unix 纳秒时间戳。
	//
	// 为什么要记它：整条链路上唯一会输给时间的地方是「私钥被客户端擦除」。
	// Steam 数据报的会话私钥只需要活过一次 RTT —— 客户端发出 ClientHello 后，
	// 收完 ServerHello 就把它算成共享密钥并清零。几十毫秒就够。
	// 所以「握手包进来到开始冻结」这段延迟是决定性指标，必须实测而不是猜。
	pubSeenAt atomic.Int64

	// 抓包诊断（-diagnose）。只在开启时记账，常态零开销。
	diagOn     bool
	diagMu     sync.Mutex
	diagPort   map[uint16]*diagPortStat
	diagZ22    uint64   // c2s 包中「载荷首字节就是 0x22」的数量
	diagHit    uint64   // ParseHandshake 命中次数
	diagSamps  []string // 0x22 候选样本（最多 20 条）
	diagPubHex string   // ParseHandshake 提取出的 32 字节公钥（十六进制）

	// 原始包落盘（-dump）
	dumpMu sync.Mutex
	dumpF  *os.File
	dumpW  *bufio.Writer

	// 密钥搜索诊断。用户现场会出现"握手包抓到了、但私钥搜不到"，
	// 这时光看抓包侧的报告定不了性 —— 必须知道：用的是哪个 pid、
	// 枚举到多少可读区域、扫了多少候选、内存读有没有成片失败、
	// 以及**这 32 字节公钥在目标进程内存里到底存不存在**。
	// 最后一项是判定"公钥方向"的关键（见 probePubInMemory）。
	keyDiagMu      sync.Mutex
	keyDiagPID     uint32
	keyDiagProc    string
	keyDiagRegions int
	keyDiagRegionB uint64
	keyDiagErr     string
	keyDiagStats   map[string]uint64
	keyDiagPubHit  int
	keyDiagPubAddr []uintptr
	keyDiagPubScan uint64
	keyDiagDump    []string // 每处命中点前后各 64 字节的十六进制
	// 扫描覆盖情况：邻域搜索与全内存兜底各一份。
	// 没有这两个数，报告里只能说"没找到"，说不出"扫了多大范围、为什么不够"。
	keyDiagWire int // 有多少处命中看起来是报文副本（前置 protobuf 字段头）
	// keyDiagPubUsed 是**本次搜索实际使用的**那 32 字节（hex）。
	//
	// 为什么要和 diagPubHex 分开记：diagPubHex 是"第一次解析握手得到的公钥"，
	// 而一次运行里可能有多次握手（换服务器 / 重连 / 多投候选），每次的 pub 不同。
	// 报告里如果只写一个，就会出现"报告说搜的是 A，dump 出来的命中点却是 B"
	// —— 用户现场 17:27 那份报告正是这样，等于让人无法核对到底搜了什么。
	keyDiagPubUsed string
	keyDiagNear    string
	keyDiagPointer string // 指针反查（原版 chase）
	// 指针反查找到的槽位数，分「冻结副本」和「全部可写内存」两处记。
	// 报告结论要据此分流：活内存里也是 0 个 = 整个进程没有东西引用这段公钥，
	// 那它几乎肯定不是客户端自己算出来的公钥。
	keyDiagPtrSlotsSnap int
	keyDiagPtrSlotsLive int
	// keyDiagPtrDump 是"指向公钥的槽位"的地址与上下文 dump。
	// 没有它就只能看到"1 个槽位"这种数字，定不出结构体字段偏移。
	keyDiagPtrDump string
	keyDiagFull    string
	// 冻结情况：是否冻上、持有多久、是否超时被强解、解冻是否成功。
	// "解冻失败"是最高级别故障，必须在报告里一眼看到。
	keyDiagFreeze string
	// keyDiagLag 是「在 c2s 包里认出公钥」→「开始搜索（即将冻结）」的延迟。
	//
	// 这是整条链路上唯一会输给时间的地方：会话私钥只活一次 RTT，
	// 客户端算完共享密钥就清零。延迟越大，私钥越可能已经不在。
	// 19:46 现场这段是 1.5 s（一个白等的定时器），必须能实测出来。
	keyDiagLag string
	// keyDiagFreezeLag 是「认出公钥」→「NtSuspendProcess 真正返回」的延迟。
	//
	// 比 keyDiagLag 更接近真相：keyDiagLag 量到 searchKey 进门为止，
	// 那时进程还在跑。20:18 现场 keyDiagLag = 19 ms，而 12 ms 是等候选的
	// 静默窗口、~7 ms 是 FreezeFast 本身 —— 两段都在"没被保护"的状态里。
	// 这个数才是私钥到底还活着的真实余量。
	keyDiagFreezeLag string
	keyDiagPhase     string
}

// diagPortStat 是诊断用的单端口计数。端口取「本机那一侧」：
// c2s 取源端口，s2c 取目的端口。
type diagPortStat struct {
	c2s, s2c uint64
}

// startCapture 打开抓包句柄、起本机雷达页、启动各工作 goroutine。
// 返回后抓包已在后台运行；调用方用 Wait() 等它结束、Stop() 让它结束。
func startCapture(em *emitter) (*captureSession, error) {
	return startCaptureAuthorized(em, nil)
}

func startCaptureAuthorized(em *emitter, lease *captureLicense) (*captureSession, error) {
	if err := productionDiagnosticsPolicy(); err != nil {
		return nil, startupdiag.Wrap(startupdiag.Policy, err)
	}
	// The shared GUI/CLI boundary authorizes before any sender, socket or worker.
	var err error
	if lease == nil {
		lease, err = authorizeCapture()
	}
	if err != nil {
		return nil, err
	}
	attached := false
	defer func() {
		if !attached {
			lease.cancel()
			lease.remote.Close()
		}
	}()
	ui, err := uibridge.StartWithLocalMaps(lease.ctx, *flagUplink, lease.remote, filepath.Join(exeDir(), "maps"))
	if err != nil {
		return nil, &authorizationError{err}
	}
	defer func() {
		if !attached {
			ui.Close()
		}
	}()
	sender, err := newSender(lease)
	if err != nil {
		return nil, startupdiag.Wrap(startupdiag.Sender, err)
	}
	defer func() {
		if !attached {
			lease.cancel()
			if remote, ok := sender.(*uplink.Sender); ok {
				remote.Abort()
			}
		}
	}()

	h, err := pcapdev.Open()
	if err != nil {
		return nil, startupdiag.Wrap(startupdiag.Capture, err)
	}
	s := &captureSession{
		ui:       ui,
		em:       em,
		h:        h,
		sender:   sender,
		locals:   localIPv4Set(),
		start:    time.Now(),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		cfilter:  capturefilter.NewStrict(),
		noFilter: *flagNoFilter,
		portCnt:  map[uint16]int{},
		dropFlow: map[string]int{},
		// 节流：复刻原版「每个服务器最多 3 次、相邻两次至少隔 1 秒」。
		// 见 throttle.go —— 这个模块存在的唯一理由是别让一局游戏把
		// 同一个进程反复挂起十几次。
		thr: newKeyThrottle(time.Duration(*flagKeyGap)*time.Millisecond, *flagKeyTries),
		// 容量要放得下"主公钥 + 若干兜底候选"（见 run() 里的投递处），
		// 否则后面几个候选会被 default 分支静默丢掉。
		targetPubCh: make(chan []byte, 16),
		diagOn:      false,
		diagPort:    map[uint16]*diagPortStat{},
	}
	s.keyPhase.Store("等待握手包")
	s.startSafeDiagnostics()
	em.emit("capture_ready", map[string]any{
		"mode":   h.RawCaptureMode(),
		"ifaces": h.InterfaceCount(),
		"filter": !s.noFilter,
		"proc":   *flagProc,
	})
	s.startStatsLoop()
	s.startFilterLoop()
	s.startKeySearch()
	s.startStallHint()
	// -duration：跑够时长自动停（GUI 版也认这个参数）
	if *flagDuration > 0 {
		go func() { time.Sleep(*flagDuration); s.stopAs(6, nil) }()
	}
	go s.run()
	lease.watch(s)
	go func() { <-s.doneCh; ui.Close() }()
	attached = true
	return s, nil
}

// startStallHint 抓了 60 秒还停在「等待握手包」时，把最常见的三种成因写进日志。
//
// 状态栏只有"等待握手包"四个字，用户无从下手；而这三条覆盖了绝大多数现场
// （抓包时机、加速器、proc 配错），直接写出来比让他猜有效得多。
func (s *captureSession) startStallHint() {
	if *flagNoKeys {
		return
	}
	go func() {
		select {
		case <-time.After(60 * time.Second):
			if v, _ := s.keyPhase.Load().(string); v == "等待握手包" {
				fmt.Fprintln(os.Stderr, "[GS-WAIT] 60秒仍未识别到可用握手；收包量不代表目标流量或密钥就绪。")
				fmt.Fprintln(os.Stderr, "请保留本轮诊断包；本提示不是检测到加速器或操作顺序错误。")
				fmt.Fprintln(os.Stderr, "无需换卡、重建凭据或调大冻结参数；停止时请记录GS-STOP数字错误码。")
			}
		case <-s.stopCh:
		}
	}()
}

// Stop 请求停止（幂等）。
func (s *captureSession) Stop() {
	s.recordStop(1, 0, 0)
	s.stopOnce.Do(func() {
		if s.ui != nil {
			s.ui.Invalidate()
		}
		traceStop("Stop() 被调用，close(stopCh)")
		close(s.stopCh)
		// 顺手叫醒可能正阻塞在 Next() 上的主循环。不加这句的话，
		// 网卡安静时要等下一个包到达它才会回到循环顶部看到 stopCh，
		// 用户看到的就是"点了关闭窗口不动"。
		if s.h != nil {
			s.h.Interrupt()
		}
	})
}

// traceStop 在退出路径上打带毫秒的时间戳。
//
// 为什么需要：用户报"窗口关不掉"时，从 Stop() 到进程真正退出中间有好几步
// （抓包主循环退出 → 关句柄 → 关 uplink → 写诊断报告 → 通知 UI），
// 任何一步卡住都表现为"点关闭没反应"。没有时间戳只能靠猜是哪一步，
// 有了它一次就能看出卡在哪儿。输出量很小（一次退出不到 10 行）。
func traceStop(format string, args ...any) {
	privateDiagnosticf("[stop %s] %s\n",
		time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

// Wait 等抓包循环彻底退出。
func (s *captureSession) Wait() {
	<-s.doneCh
	if s.reportDone != nil {
		<-s.reportDone
	}
}

// Status 返回当前状态快照。
func (s *captureSession) Status() captureStatus {
	st := captureStatus{
		Packets:     atomic.LoadUint64(&s.pkts),
		Bytes:       atomic.LoadUint64(&s.bytes),
		C2S:         atomic.LoadUint64(&s.dirC2S),
		S2C:         atomic.LoadUint64(&s.dirS2C),
		Filtered:    atomic.LoadUint64(&s.filteredOut),
		FilterOn:    s.cfilter.Active(),
		FilterPID:   s.cfilter.PID(),
		FilterPorts: s.cfilter.Ports(),
		TopPorts:    s.topPorts(6),
		Elapsed:     time.Since(s.start),
	}
	s.keyMu.Lock()
	st.KeyTag, st.KeyErr = s.foundTag, s.keyErr
	s.keyMu.Unlock()
	st.Running = !s.stopped()
	if v, ok := s.keyPhase.Load().(string); ok {
		st.KeyPhase = v
	}
	return st
}

func (s *captureSession) stopped() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

// keySearchBusy 报告私钥搜索是否正处在「关掉就白打」的阶段。
//
// 只认几个**长任务**阶段：抓内存、指针反查、校验冻结副本、正在搜索私钥。
// 「等待握手包」「已就绪」这些不算 —— 那时候关窗没有损失。
//
// 🔴 存在的理由：07:38 那局搜索跑到 20% 时窗口被关，用户看到的结果是
// 「又没拿到私钥」，和「搜完了确实没有」完全无法区分。关窗前必须问一句。
func (s *captureSession) keySearchBusy() bool {
	if s == nil {
		return false
	}
	v, _ := s.keyPhase.Load().(string)
	switch {
	case strings.Contains(v, "校验冻结副本"),
		strings.Contains(v, "正在搜索私钥"),
		strings.Contains(v, "冻结期间抓取"),
		strings.Contains(v, "指针反查"):
		return true
	}
	return false
}

// topPorts 返回出现次数最多的端口（**过滤前**的全量直方图）。
//
// 用途是「判断到底有没有抓到游戏流量」—— CS2 对局服务端端口通常在
// 27015–27050。刻意统计过滤前的数据，不能被端口过滤污染。
func (s *captureSession) topPorts(n int) []string {
	s.portMu.Lock()
	defer s.portMu.Unlock()
	type pc struct {
		p uint16
		c int
	}
	list := make([]pc, 0, len(s.portCnt))
	for p, c := range s.portCnt {
		list = append(list, pc{p, c})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].c > list[j].c })
	out := []string{}
	for i := 0; i < len(list) && i < n; i++ {
		out = append(out, fmt.Sprintf("%d(%d)", list[i].p, list[i].c))
	}
	return out
}

// noteDropFlow 记一条「被白名单丢掉的像 GNS 的流」的完整五元组。
//
// 只记前 64 条不同的流，防止某个扫描器刷爆 map。
func (s *captureSession) noteDropFlow(udp *transport.UDPPacket) {
	key := fmt.Sprintf("%s:%d→%s:%d",
		net.IP(udp.SrcIP[:]), udp.SrcPort, net.IP(udp.DstIP[:]), udp.DstPort)
	s.portMu.Lock()
	if _, ok := s.dropFlow[key]; ok || len(s.dropFlow) < 64 {
		s.dropFlow[key]++
	}
	s.portMu.Unlock()
}

// topDropFlows 返回被丢最多的几条「像 GNS 的流」。
func (s *captureSession) topDropFlows(n int) []string {
	s.portMu.Lock()
	defer s.portMu.Unlock()
	type fc struct {
		k string
		c int
	}
	list := make([]fc, 0, len(s.dropFlow))
	for k, c := range s.dropFlow {
		list = append(list, fc{k, c})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].c > list[j].c })
	out := []string{}
	for i := 0; i < len(list) && i < n; i++ {
		out = append(out, fmt.Sprintf("%s×%d", list[i].k, list[i].c))
	}
	return out
}

// ---- 抓包诊断（-diagnose / -dump）----
//
// 存在的理由：当"雷达页一直空白"时，光看状态栏无法区分下面几种情况 ——
// 白名单把流量滤光了 / 抓到的包里根本没有握手 / 握手格式和逆向结论不符。
// 把过滤前的端口分布和握手候选落盘，才能用数据判断，而不是靠猜。

// diagRecord 记一个包（只在 -diagnose 下调用）。
func (s *captureSession) diagRecord(dir string, udp *transport.UDPPacket) {
	local := udp.SrcPort
	if dir != "c2s" {
		local = udp.DstPort
	}
	s.diagMu.Lock()
	st := s.diagPort[local]
	if st == nil {
		st = &diagPortStat{}
		s.diagPort[local] = st
	}
	if dir == "c2s" {
		st.c2s++
	} else {
		st.s2c++
	}
	// 握手包的载荷开头就是 0x22（field 4, wireType 2）。这里只做 O(1) 的首字节判定，
	// 命中数直接回答「握手包到底有没有进抓包范围」。
	if dir == "c2s" && len(udp.Data) > 0 && udp.Data[0] == 0x22 {
		s.diagZ22++
		if len(s.diagSamps) < 20 {
			// 打印足够长：这个包是 4 层嵌套的 protobuf，只给前 48 字节
			// 根本看不出字段路径对不对（实测 331 字节的包，48 字节才刚到
			// 第二层）。160 字节足够核对到公钥所在的 `12 20`。
			n := len(udp.Data)
			if n > 160 {
				n = 160
			}
			s.diagSamps = append(s.diagSamps, fmt.Sprintf("  c2s %s:%d → %s:%d  len=%d  % x",
				net.IP(udp.SrcIP[:]), udp.SrcPort,
				net.IP(udp.DstIP[:]), udp.DstPort,
				len(udp.Data), udp.Data[:n]))
		}
	}
	s.diagMu.Unlock()
}

// diagDump 把一个过滤前的包写进 JSONL（只在 -dump 下调用）。
// setHSPeers 记录本次握手的「本机 ↔ 对端」地址对。
func (s *captureSession) setHSPeers(client, server string) {
	s.hsMu.Lock()
	s.hsClient, s.hsServer = client, server
	s.hsMu.Unlock()
}

// hsPeers 读取本次握手的地址对（空表示还没见过 ClientHello）。
func (s *captureSession) hsPeers() (client, server string) {
	s.hsMu.Lock()
	defer s.hsMu.Unlock()
	return s.hsClient, s.hsServer
}

func (s *captureSession) diagDump(dir string, udp *transport.UDPPacket) {
	// Retired: no raw packet persistence, even for direct internal calls.
}

// closeDump 收尾 dump 文件。
func (s *captureSession) closeDump() {
	s.dumpMu.Lock()
	defer s.dumpMu.Unlock()
	if s.dumpW != nil {
		s.dumpW.Flush()
		s.dumpW = nil
	}
	if s.dumpF != nil {
		s.dumpF.Close()
		s.dumpF = nil
	}
}

// writeDiagnose 输出诊断报告。
func (s *captureSession) writeDiagnose(path string) error {
	return fmt.Errorf("sensitive diagnostics are unavailable in production")
}

// statsData 组装 capture_stats 事件体。
func (s *captureSession) statsData(final bool) map[string]any {
	data := map[string]any{
		"packets":   atomic.LoadUint64(&s.pkts),
		"bytes":     atomic.LoadUint64(&s.bytes),
		"c2s":       atomic.LoadUint64(&s.dirC2S),
		"s2c":       atomic.LoadUint64(&s.dirS2C),
		"top_ports": s.topPorts(6),
	}
	if s.h != nil {
		data["capture_queue"] = s.h.Stats()
	}

	// 把被丢的「像 GNS 的流」的完整五元组也带上 —— 没有 IP 就无法判断
	// 那是游戏主链路还是本机回环（见 dropFlow 字段注释）。
	if f := s.topDropFlows(4); len(f) > 0 {
		data["top_drop_flows"] = f
	}
	if s.cfilter.Active() {
		data["filter"] = map[string]any{
			"pid":      s.cfilter.PID(),
			"ports":    s.cfilter.Ports(),
			"dropped":  atomic.LoadUint64(&s.filteredOut),
			"drop_gns": atomic.LoadUint64(&s.filterDropGNS),
		}
	} else {
		why := s.filterOffWhy.Load()
		if why == nil || why.(string) == "" {
			why = "未发现目标进程端口"
		}
		data["filter"] = fmt.Sprintf("off(%s，不过滤)", why)
	}
	if final {
		data["filtered"] = atomic.LoadUint64(&s.filteredOut)
		data["final"] = true
	}
	return data
}

func (s *captureSession) startStatsLoop() {
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-t.C:
				data := s.statsData(false)
				data["uplink"] = s.sender.Stats()
				s.em.emit("capture_stats", data)
			}
		}
	}()
}

// startFilterLoop 定期重查目标进程占用的本机 UDP 端口。
//
// 目标进程可能重开（换 pid）或新开 UDP 端口，所以定期刷 GetExtendedUdpTable；
// 端口集合变化时发一次 capture_filter 事件。
//
// 🔴 启动后前 20 秒用 250ms 的快周期，之后退回 3 秒。
//
// 3 秒对「已经稳定跑着的进程」够用，但对**刚连上服务器的那几秒**远远不够：
// 游戏连接是在采集器启动之后才建立的，新端口要等下一轮刷新才进白名单，
// 这中间该连接上的包全被丢掉。13:59 现场就是这样丢了约 20 个 1137 字节的
// signon 包（s2c 首个解出的段声明位置 = 22809），sendtable 再也拿不到。
//
// 握手识别时已经会即时补端口（见 ParseHello 分支），这里是第二道保险：
// 握手包万一没解析出来（版本变动 / 换了链路），快周期还能在 250ms 内补上。
func (s *captureSession) startFilterLoop() {
	if s.noFilter {
		s.diag.filterState.Store(5)
		return
	}
	go func() {
		var lastKey string
		refresh := func() {
			if !s.refreshCaptureFilter(resolvePID, capturefilter.Discover) {
				lastKey = ""
				return
			}
			key := fmt.Sprintf("%d:%v", s.cfilter.PID(), s.cfilter.Ports())
			if key != lastKey {
				lastKey = key
				s.em.emit("capture_filter", map[string]any{"state": filterAvailable})
			}
		}
		refresh()
		// 快周期：覆盖「采集器刚起来、游戏刚连上」这段最脆弱的时间窗。
		fast := time.NewTicker(250 * time.Millisecond)
		defer fast.Stop()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-s.stopCh:
				return
			case <-fast.C:
				refresh()
			}
		}
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-t.C:
				refresh()
			}
		}
	}()
}

// keyBatchQuietGap 是「候选收集」的静默窗口：连续这么久没有新候选就收工。
//
// ⚠ 这个值**不是**随便定的超时，它是「私钥能不能被抢到」的直接开销。
// 候选是在同一个收包回调里连续投进来的（先投 info.PublicKey，紧接着
// `for _, c := range handshake.ByteFieldCandidates` 逐个投），两次投递相隔
// 几微秒；通道有 16 个缓冲，投递方从不阻塞。
//
// 原来这里是固定 1500 ms。19:46 现场实测：握手 → 冻结之间整整 1.5 秒
// 完全不受保护。而 Steam 数据报的会话私钥只活一次 RTT —— 客户端发出
// ClientHello 后，收完 ServerHello 就把它算成共享密钥并 SecureZeroMemory，
// 几十毫秒的事。1.5 秒的空窗足以让私钥在冻结之前就消失，
// 之后无论追击窗口放多宽都找不到。
//
// 20:18 现场把这条线量到底了：改完 12 ms 之后「握手→搜索」报 19 ms，
// 而同一份报告里 7 处命中点有 2 处是 `pub[32] + 32 字节全 0` ——
// 那是**冻结那一刻**的状态（locatePub / takeSnap 都在 FreezeFast 之后跑，
// 进程已经停住了，读到的不可能是"后来才被擦掉"的）。
// 也就是说：客户端在公钥上网之后的 19 ms 内就把私钥 SecureZeroMemory 了。
//
// 19 ms 的构成：12 ms 是这个静默窗口，剩下 ~7 ms 是 FreezeFast
// （NtSuspendProcess 要遍历全部线程）加调度开销。**这 12 ms 是纯死等**。
//
// 候选是在同一个收包回调里连续投进来的（`s.targetPubCh <- info.PublicKey`
// 紧接着 `for _, c := range ByteFieldCandidates`），两次投递相隔几微秒，
// 通道有 16 个缓冲、投递方从不阻塞。所以 1 ms 对微秒级间隔仍有 3 个
// 数量级余量，而空窗直接砍掉 11 ms —— 这是这条链路上唯一能白拿的收益。
//
// ⚠ 别再往上调。调大 1 ms 就是少 1 ms 的竞速余量，而这场竞速是以
// 毫秒计的（客户端 RTT 通常 10~30 ms，ServerHello 一到就擦）。
const keyBatchQuietGap = 1 * time.Millisecond

// collectBatch 收集一批候选：先阻塞等第一个，之后「连续 quietGap
// 没有新候选」就收工，返回收到的全部候选（原样，不去重）。
//
// 返回 nil 表示 stop 通道关闭（调用方应当直接退出）。
//
// 单独抽成函数是为了能被测试直接驱动 —— 这段逻辑的代价是「私钥还活不活着」，
// 不能只靠读代码保证。
func collectBatch(ch <-chan []byte, stop <-chan struct{}, quietGap time.Duration) [][]byte {
	var out [][]byte
	// 先阻塞等第一个
	select {
	case pub := <-ch:
		if pub == nil {
			return out
		}
		out = append(out, pub)
	case <-stop:
		return nil
	}
	if quietGap <= 0 {
		quietGap = keyBatchQuietGap
	}
	quiet := time.NewTimer(quietGap)
	defer quiet.Stop()
	for {
		select {
		case pub := <-ch:
			if pub != nil {
				out = append(out, pub)
			}
			// 收到新的就重置静默计时。
			// 先 Stop 再排空 C，避免"已经触发的 tick 被 Reset 之后又立刻返回"。
			if !quiet.Stop() {
				select {
				case <-quiet.C:
				default:
				}
			}
			quiet.Reset(quietGap)
		case <-quiet.C:
			return out
		case <-stop:
			return nil
		}
	}
}

// startKeySearch 等握手公钥 → 进 cs2.exe 挖私钥。
//
// 这是个**循环**，不是一次性的。单次搜索可能因为误命中、进程刚重启、
// 内存还没就绪而失败；一次失败就永久停在"失败"是不可接受的 ——
// 下一局/下一次重连的握手包必须还能被接住。
// ─────────────────────────── hint 快路径 ───────────────────────────
//
// 这一节对应原版的 probeHint @0x1799a0 和 rememberHint（被内联，无独立符号）。
//
// 为什么它是最重要的一段：原版和我们的冻结方式完全一样（都是一次
// NtSuspendProcess），差别只在冻结期间读了多少 —— 原版读 32 字节，我们读 7.5 GB。
// 有了 hint 表，"第二次以后"就永远不需要扫描。

// hintPath 解析 -hints 的值。返回空串表示禁用。
//
// 🔴 硬约束（用户 2026-10-20 08:58 明确要求）：
// **不得在原始位置以外新建存储位置**。所以这里只允许一个落点 ——
// exe 同目录的 hints.json（或 -hints 显式指定的那个）。
// 曾经试过再写一份到 `%LOCALAPPDATA%\cs2radar\`，已被要求撤掉：
// 生成的文件一律留在程序自己所在的目录，不往系统盘其它地方撒。
func hintPath() string {
	v := strings.TrimSpace(*flagHints)
	switch strings.ToLower(v) {
	case "off", "none", "no", "0", "false":
		return ""
	case "":
		return filepath.Join(exeDir(), "hints.json")
	}
	return v
}

// rememberHint 把一次成功的命中记进 hint 表，供后续会话直接 probe。
//
// 只记地址，不记私钥：会话私钥下次就失效，落盘纯属留痕。
// markKeyFound 通知节流器：当前目标已经取到密钥。
//
// 原版对应 map1（0x182f74 `cmp byte ptr [rax], 0`）：一旦某个服务器成功过，
// 后续来自它的握手直接跳过，不再冻结、不再扫描。
func (s *captureSession) markKeyFound() {
	if v, ok := s.curTarget.Load().(string); ok && v != "" {
		s.thr.MarkFound(v)
	}
}

func (s *captureSession) rememberHint(addr uintptr, pub []byte) {
	path := hintPath()
	if path == "" || addr == 0 {
		return
	}
	pid, err := resolvePID()
	if err != nil {
		privateDiagnosticf("[key] hint 未记录：解析 pid 失败：%v\n", err)
		return
	}
	proc, err := memscan.OpenForQuery(pid)
	if err != nil {
		privateDiagnosticf("[key] hint 未记录：打开进程失败：%v\n", err)
		return
	}
	defer proc.Close()

	regions, _ := proc.RegionsWithError(time.Now().Add(10*time.Second), 0)
	moduleBase := proc.ModuleBase()

	h := keyfind.MakeHint(addr, pub, *flagProc, moduleBase, regions)
	hs := keyfind.LoadHints(path)
	hs = keyfind.MergeHint(hs, h)
	if err := keyfind.SaveHints(path, hs); err != nil {
		privateDiagnosticf("[key] hint 写入失败（%s）：%v —— 下次仍需全量扫描\n", path, err)
		return
	}
	rva := "-"
	if moduleBase != 0 {
		rva = fmt.Sprintf("RVA %#x", int64(addr)-int64(moduleBase))
	}
	privateDiagnosticf(
		"[key] 已记住 hint：%#x（%s，区域偏移 %#x）｜表内 %d 条 → %s\n",
		addr, rva, h.RegionOff, len(hs), path)
}

// hintProcess 返回缓存的进程句柄（hint 快路径专用）。
//
// 为什么缓存：一次握手里可能有多个 32 字节候选，每个都要走一遍 hint 探测，
// 而 resolvePID()（Toolhelp 遍历全部进程）+ OpenForRead 单次就要 5~15 ms。
// 这段延迟全在「握手 → 冻结」的竞速窗口里，而私钥只活一次 RTT。
//
// 句柄失效（cs2 重启）时探测会读失败、自然 miss，不会崩；下次再取仍复用。
func (s *captureSession) hintProcess() *memscan.Process {
	s.hintProcMu.Lock()
	defer s.hintProcMu.Unlock()
	if s.hintProc != nil {
		return s.hintProc
	}
	pid, err := resolvePID()
	if err != nil {
		return nil
	}
	proc, err := memscan.OpenForRead(pid)
	if err != nil {
		return nil
	}
	s.hintProc = proc
	return proc
}

// probeHintsFast 走原版快路径：逐条读 32 字节，用 X25519 反算公钥验证。
//
// 分两轮，顺序很重要：
//
//	第 1 轮：只用记录下来的**原地址**。零枚举、零扫描，读 32 字节×条数。
//	         这一轮就是原版 probeHint 的形状。
//	第 2 轮：仅当第 1 轮全 miss 时，枚举一次区域，把模块相对 / 区域相对
//	         两种偏移展开成候选再试。读量仍是 32 字节×候选数。
//
// 返回 true 表示已拿到私钥（keyReady 已置位）。
func (s *captureSession) probeHintsFast(pub []byte) bool {
	path := hintPath()
	if path == "" {
		return false
	}
	hs := keyfind.LoadHints(path)
	if len(hs) == 0 {
		privateDiagnosticf("[key] hint 表为空（%s），本次走全量扫描\n", path)
		return false
	}
	privateDiagnosticf("[key] hint 表已加载：%s（%d 条）\n", path, len(hs))
	if len(pub) != 32 {
		return false
	}

	proc := s.hintProcess()
	if proc == nil {
		privateDiagnosticf("[key] hint 快路径跳过：打开 %s 失败\n", *flagProc)
		return false
	}

	begin := time.Now()
	kf := keyfind.New(proc, pub, time.Now().Add(10*time.Second))

	// ── 第 1 轮：原地址，零枚举 ──
	res := kf.ProbeHints(hs)
	line := fmt.Sprintf("hint 快路径[1/2 原地址]：试 %d/%d 条｜读 %d 字节｜%s",
		res.Tried, len(hs), res.Bytes, map[bool]string{true: "命中", false: "未命中"}[res.Hit])

	// ── 第 2 轮：rebase 候选（只在第 1 轮全 miss 时做，且默认关闭）──
	//
	// 为什么要关：这一轮必须先枚举全部区域（实测 7948 个），耗时 132~154 ms，
	// 而它直接加在「握手→冻结」这段竞速时间上。03:27 现场第 2 轮展开 8 个候选、
	// 读 256 字节、未命中 —— 用 130 ms 换 8 个几乎不可能命中的地址，是亏的。
	// 需要排查 hint 偏移时用 -hint-rebase 打开。
	if !res.Hit && !*flagHintRebase {
		line += "｜[2/2 rebase] 已跳过（默认关，-hint-rebase 可开）"
	}
	if !res.Hit && *flagHintRebase {
		regions, rerr := proc.RegionsWithError(time.Now().Add(10*time.Second), 0)
		if rerr == nil || rerr == memscan.ErrRegionDeadline || rerr == memscan.ErrRegionLimit {
			moduleBase := proc.ModuleBase()
			tried := map[uintptr]bool{}
			for _, h := range hs {
				tried[h.Addr] = true
			}
			var cands []keyfind.HintCand
			for _, h := range hs {
				for _, c := range keyfind.HintCandidates(h, moduleBase, regions) {
					if tried[c.Addr] {
						continue
					}
					cands = append(cands, c)
				}
			}
			if len(cands) > 0 {
				r2 := kf.ProbeAddrs(cands)
				line += fmt.Sprintf("｜[2/2 rebase] 候选 %d 个｜读 %d 字节｜%s",
					r2.Tried, r2.Bytes, map[bool]string{true: "命中", false: "未命中"}[r2.Hit])
				if r2.Hit {
					r2.Tried += res.Tried
					r2.Bytes += res.Bytes
					res = r2
				}
			} else {
				line += "｜[2/2 rebase] 无可用候选（区域指纹不匹配）"
			}
		}
	}

	elapsed := time.Since(begin).Truncate(time.Millisecond)
	line += "｜耗时 " + elapsed.String()

	// 🔴 hint 未命中时把**原因**打出来（2026-10-20 09:05 现场定案）。
	//
	// 原来只有一句「未命中」，看不出是「地址漂移（正常）」还是「hint 坏了（故障）」。
	// 09:05 那局读到了文件、试了 1 条、读 32 字节、未命中 —— 这是**预期行为**：
	// 私钥对象在堆上，跨进程重启地址就会变：
	//
	//	08:55  addr=0x183642fe180  region_off=0x6180
	//	09:05  addr=0x1837cdfebc0  region_off=0xebc0   （差约 396 MB）
	//
	// 所以要稳定命中，只能靠「模块静态指针链」（原版 probeHint 的完整形态），
	// 光靠绝对地址记一条 hint 是不够的。这句话必须写进日志，否则每次都要重查一遍。
	if !res.Hit && len(hs) > 0 {
		var ages []string
		for _, h := range hs {
			ages = append(ages, fmt.Sprintf("%#x(区偏 %#x)", h.Addr, h.RegionOff))
		}
		privateDiagnosticf(
			"[key] hint 未命中原因：私钥对象在堆上，跨进程地址会漂移"+
				"（08:55 是 0x183642fe180/区偏 0x6180，09:05 是 0x1837cdfebc0/区偏 0xebc0，差约 396 MB）"+
				"｜本次试过：%s｜这是**预期行为**，不是故障；全量扫描会照常拿到密钥\n",
			strings.Join(ages, "、"))
	}
	s.recordKeyDiag(func() {
		s.keyDiagPhase = line
	})
	privateDiagnosticf("[key] %s\n", line)

	if !res.Hit {
		return false
	}

	// 命中：写状态、累加 Hits、落盘。
	s.sender.SetHandshake(pub)
	s.keyMu.Lock()
	s.foundKey, s.foundTag, s.foundAddr = res.Priv, res.Tag, res.Addr
	s.keyMu.Unlock()
	s.markKeyFound()
	s.keyReady.Store(true)
	s.keyPhase.Store("已就绪")
	s.rememberHint(res.Addr, pub)
	s.recordKeyDiag(func() {
		s.keyDiagPubUsed = fmt.Sprintf("%x", pub)
		s.keyDiagPhase = fmt.Sprintf("已就绪（hint 快路径：%s 命中，读 %d 字节，未冻结未扫描）",
			res.Source, res.Bytes)
	})
	privateDiagnosticf(
		"Connection key verified and passed to parser (tag=%s addr=%#x in %s, hint/%s)\n",
		res.Tag, res.Addr, elapsed, res.Source)
	s.em.emit("key_ready", map[string]any{
		"tag":     res.Tag,
		"addr":    fmt.Sprintf("%#x", res.Addr),
		"elapsed": elapsed.String(),
		"stage":   "hint-fast",
		"source":  res.Source,
		"bytes":   res.Bytes,
	})
	return true
}

func (s *captureSession) startKeySearch() {
	if *flagNoKeys {
		s.keyPhase.Store("已禁用(-no-keys)")
		return
	}
	go func() {
		tried := map[string]bool{} // 同一个公钥不重复试（一次要跑满 20 分钟）

		// ── 先攒一批候选 ──
		//
		// 同一个握手包里的候选是一起投进来的：ParseHandshake 选一个主公钥，
		// 再由 ByteFieldCandidates 把包里**所有** 32 字节字段补投进来。
		// 用户现场那条包里有**两个** {key_type=1, key_data=32B} 的
		// SessionCryptInfo（08 01 12 20 …），一个 e3d3923c…、一个 1fb5af6d…。
		// 只试一个就等于抛硬币。
		var batch [][]byte
		for len(batch) == 0 {
			raw := collectBatch(s.targetPubCh, s.stopCh, keyBatchQuietGap)
			if raw == nil {
				return // stopCh 关闭
			}
			for _, pub := range raw {
				if k := string(pub); !tried[k] {
					tried[k] = true
					batch = append(batch, pub)
				}
			}
		}

		// ── ⓪ 快路径：hint 表里记着地址的话，读 32 字节就能拿到 ──
		//
		// 这一步必须在 freeze 和任何扫描之前：它的读量是 32 字节 × 条数（≤1 KB），
		// 不枚举区域、不扫描、不冻结。原版日常走的就是这条。
		for _, cand := range batch {
			if s.probeHintsFast(cand) {
				return
			}
		}

		// ── ① 先按第一个候选走完整流程（freeze 必须尽快发生，不能拖）──
		//
		// 把同包的其它候选一起传进去：searchKey 在冻结+快照**之后**会对它们
		// 各做一次「定位 + 指针反查」（每个约 5 秒），命中就立刻收工。
		//
		// ⚠ 预筛不能放在 freeze 之前：那会把冻结推迟 20 秒，
		// 私钥很可能在这期间被客户端擦掉。先冻结、先抄副本，再谈其它候选。
		s.searchKey(batch[0], batch[1:])

		// ── ② 之后新来的握手照常处理 ──
		for {
			select {
			case pub := <-s.targetPubCh:
				if s.keyReady.Load() {
					continue
				}
				k := string(pub)
				if tried[k] {
					continue
				}
				tried[k] = true
				if s.probeHintsFast(pub) {
					continue
				}
				s.searchKey(pub, nil)
			case <-s.stopCh:
				return
			}
		}
	}()
}

// quickPointerPass 对每个候选公钥只做「全内存定位 + 指针反查」，命中即返回。
//
// 背景（2026-10-17 18:47 现场）：那条握手包里有**两个** 32 字节的
// SessionCryptInfo.key_data，ParseHandshake 只能挑一个。挑错了，
// 后面 20 分钟的暴力校验全是白费 —— 因为那个公钥根本不是客户端自己算的，
// 内存里当然没有对应私钥。
//
// 而"它有没有被引用"这个判据极其便宜：一次全可读区 memmem（7.5 GB ≈ 1.7 s）
// 加一次指针反查（纯 8 字节比较）。3~4 个候选全试完约 20 秒。
//
// 返回 true 表示已经找到私钥（foundKey 已写好、keyReady 已置位）。
func (s *captureSession) quickPointerPass(cands [][]byte) bool {
	if len(cands) == 0 {
		return false
	}
	pid, err := resolvePID()
	if err != nil {
		privateDiagnosticf("[key] 预筛跳过：解析 pid 失败：%v\n", err)
		return false
	}
	proc, err := memscan.OpenForRead(pid)
	if err != nil {
		privateDiagnosticf("[key] 预筛跳过：打开进程失败：%v\n", err)
		return false
	}
	defer proc.Close()

	// 注意：这里不碰 s.keySearching —— 调用方（searchKey）已经置位了，
	// 在这里 defer 复位会让后面几个阶段被误判成"搜索已结束"。

	begin := time.Now()
	deadline := begin.Add(90 * time.Second)
	s.keyPhase.Store("指针反查（逐个候选）")

	regions, rerr := proc.RegionsWithError(deadline, 0)
	if rerr != nil && rerr != memscan.ErrRegionDeadline && rerr != memscan.ErrRegionLimit {
		privateDiagnosticf("[key] 预筛跳过：枚举区域失败：%v\n", rerr)
		return false
	}
	var regionBytes uint64
	for _, r := range regions {
		regionBytes += uint64(r.Size)
	}
	ordered := sortRegionsForScan(regions)
	s.recordKeyDiag(func() {
		s.keyDiagPID = pid
		s.keyDiagProc = *flagProc
		s.keyDiagRegions = len(regions)
		s.keyDiagRegionB = regionBytes
		s.keyDiagPhase = fmt.Sprintf("指针反查预筛：%d 个候选（枚举到 %d 个区域 / %.1f MB）",
			len(cands), len(regions), float64(regionBytes)/(1<<20))
	})
	privateDiagnosticf("[key] 指针反查预筛：%d 个候选，可读 %.1f MB / %d 区域\n",
		len(cands), float64(regionBytes)/(1<<20), len(regions))

	for i, cand := range cands {
		if time.Now().After(deadline) || s.keyReady.Load() {
			break
		}
		if len(cand) < 4 {
			continue
		}
		hits, scanned := scanPub(proc, ordered, cand, 16, deadline)
		tag := fmt.Sprintf("%x", cand[:4])
		privateDiagnosticf("[key]   候选 %d/%d %s…：命中 %d 处（扫 %.1f MB）\n",
			i+1, len(cands), tag, len(hits), float64(scanned)/(1<<20))

		// 命中情况只写进日志，**不覆盖报告的「公钥在内存」那几行** ——
		// 那几行描述的是"本次主搜索用的那个公钥"，被候选覆盖会自相矛盾。
		// 只有候选真的命中时，才在下面成功分支里把报告改成它。
		wire := 0
		addrs := make([]uintptr, 0, len(hits))
		dumps := make([]string, 0, len(hits))
		for _, h := range hits {
			addrs = append(addrs, h.Addr)
			dumps = append(dumps, formatPubDump(h))
			if h.Wire {
				wire++
			}
		}
		if len(hits) == 0 {
			continue
		}

		kf := keyfind.New(proc, cand, deadline)
		var priv []byte
		var ftag string
		var addr uintptr
		kf.OnFound = func(p []byte, t string, a uintptr) { priv, ftag, addr = p, t, a }

		st := new(scanStat)
		slots, chases := scanPointersToLive(kf, proc, ordered, hits, deadline, st)
		line := fmt.Sprintf("候选 %d/%d（%s…）：活内存 %d 个槽位｜跟踪校验 %d 次｜耗时 %s",
			i+1, len(cands), tag, slots, chases, st.elapsed.Round(time.Millisecond))
		privateDiagnosticf("[key]   指针反查：%s\n", line)
		var dumpB strings.Builder
		for j, a := range st.slotAddrs {
			if j >= 3 {
				fmt.Fprintf(&dumpB, "  …另有 %d 个槽位未列出\n", len(st.slotAddrs)-3)
				break
			}
			fmt.Fprintf(&dumpB, "\n  【指针槽位·候选 %d/%d（%s…）】\n", i+1, len(cands), tag)
			// 这一路（quickPointerPass）跑在冻结之前，没有副本可读，只能读活内存。
			dumpB.WriteString(formatSlotDump(proc, nil, a, 64, ordered))
		}
		s.recordKeyDiag(func() {
			s.keyDiagPointer = line
			s.keyDiagPtrSlotsLive = slots
			if dumpB.Len() > 0 {
				s.keyDiagPtrDump += dumpB.String()
			}
		})
		if !kf.Found() {
			continue
		}

		s.sender.SetHandshake(cand)
		s.keyMu.Lock()
		s.foundKey, s.foundTag, s.foundAddr = priv, ftag, addr
		s.keyMu.Unlock()
		s.markKeyFound()
		s.keyReady.Store(true)
		s.keyPhase.Store("已就绪")
		// 记下这个地址：下次（同局重连 / 下次运行）直接 probe 32 字节即可。
		s.rememberHint(addr, cand)
		// 命中的是候选，不是主公钥 —— 报告里的「本次搜索用 / 命中点」要改成它，
		// 否则报告会说一套、实际命中的是另一套。
		s.recordKeyDiag(func() {
			s.keyDiagPubHit = len(hits)
			s.keyDiagPubScan = scanned
			s.keyDiagPubAddr = addrs
			s.keyDiagDump = dumps
			s.keyDiagWire = wire
			s.keyDiagPubUsed = fmt.Sprintf("%x", cand)
			s.keyDiagPhase = "已就绪（同包候选命中：指针反查直接找到，未走暴力校验）"
		})
		privateDiagnosticf(
			"Connection key verified and passed to parser (tag=%s addr=%#x in %s, 指针反查)\n",
			ftag, addr, time.Since(begin).Truncate(time.Millisecond))
		s.em.emit("key_ready", map[string]any{
			"tag":     ftag,
			"addr":    fmt.Sprintf("%#x", addr),
			"elapsed": time.Since(begin).String(),
			"stage":   "pointer-quick",
		})
		return true
	}
	s.recordKeyDiag(func() {
		s.keyDiagPhase = "指针反查预筛未命中，转常规搜索"
	})
	privateDiagnosticf("[key] 指针反查预筛未命中（%s），转常规搜索\n",
		time.Since(begin).Truncate(time.Millisecond))
	return false
}

// searchKey 针对一个候选公钥跑完整流程。
//
// siblings 是同一个握手包里**其它** 32 字节字段（可能是真正的客户端公钥）。
// 它们不单独跑 20 分钟的完整搜索 —— 那样排在前面的候选会把预算吃光；
// 只在冻结+快照之后各做一次「定位 + 指针反查」（约 5 秒/个），命中即收工。
func (s *captureSession) searchKey(pub []byte, siblings [][]byte) {
	s.sender.SetHandshake(pub)
	s.keyPhase.Store("正在搜索私钥")
	s.keySearching.Store(true)
	defer s.keySearching.Store(false)

	pid, err := resolvePID()
	if err != nil {
		s.failKey(err)
		return
	}
	s.recordKeyDiag(func() {
		s.keyDiagPID = pid
		s.keyDiagProc = *flagProc
		s.keyDiagPhase = "解析 pid 完成"
	})
	proc, err := memscan.OpenForRead(pid) // 0xC10
	if err != nil {
		s.failKey(err)
		return
	}
	defer proc.Close()

	// 验证器要在冻结**之前**建好 —— 冻结窗口里要直接用它验证候选。
	kf := keyfind.New(proc, pub, time.Now().Add(10*time.Minute))
	kf.MaxCandidates = *flagScanBudget
	var (
		priv []byte
		tag  string
		addr uintptr
		hit  bool
	)
	kf.OnFound = func(p []byte, t string, a uintptr) {
		priv, tag, addr, hit = p, t, a, true
	}

	begin := time.Now()
	// 握手 → 开始搜索 的延迟。这是决定"私钥还在不在"的关键指标：
	// 会话私钥只活一次 RTT，客户端算完共享密钥就清零。
	// 打出来才能判断"没找到"到底是搜索方法不行，还是抢晚了。
	//
	// Swap(0) 取走而不是 Load：取走之后下一次握手会重新计时，
	// 这样"多次握手"的场景里每一轮都量的是自己那一次。
	// 这里**不能**只报「握手→搜索」：搜索一开始就 freeze，但真正保住私钥的是
	// FreezeFast 成功的那一刻。19 ms 里有 12 ms 是等候选的静默窗口，
	// 那时候进程还在跑，私钥照样在被擦。所以把 pubSeenNS 留着，
	// 冻结结束后再补一条「握手→冻结」，那才是这场竞速的真实余量。
	var pubSeenNS int64
	if ns := s.pubSeenAt.Swap(0); ns > 0 {
		pubSeenNS = ns
		lag := time.Since(time.Unix(0, ns)).Round(time.Millisecond)
		privateDiagnosticf(
			"[key] 握手→搜索延迟：%s（越短越好；私钥只活一次 RTT，几十毫秒量级）\n", lag)
		s.recordKeyDiag(func() { s.keyDiagLag = lag.String() })
	}
	// deadlineOverall 是整个私钥搜索（含冻结副本校验 + 分级搜索）的总截止时间。
	// 各阶段都从它切预算，避免"每一段都给自己一份完整预算"导致总时长翻几倍。
	deadlineOverall := begin.Add(keyScanBudget)
	var (
		regions    []memscan.Region
		ordered    []memscan.Region
		pubHits    []pubHit
		pubScanned uint64
		frozenNear = new(scanStat) // 冻结副本「邻域」部分的校验统计
		frozenRest = new(scanStat) // 冻结副本「其余可写区」部分的校验统计
	)

	// ── 冻结窗口内第 1 步：枚举可读区域 ──
	//
	// 🔴 用并行枚举（RegionsParallel）：VirtualQueryEx 是逐区域的往返调用，
	// cs2.exe 有 7500+ 个区域，串行要走 ~80~100 ms。这段原来整段卡在
	// 「握手 → 冻结」的黄金窗口里（04:10 现场：188 ms 里有约 100 ms 是它），
	// 而私钥只活一次 RTT —— 这一百毫秒直接决定私钥还在不在。
	// 并行后同样 7500 个区域只要 ~10 ms（分段独立走，见 memscan.RegionsParallel）。
	enumRegions := func() error {
		t0 := time.Now()
		var rerr error
		regions, rerr = proc.RegionsParallel(time.Now().Add(10*time.Second), numWorkers())
		if rerr != nil && rerr != memscan.ErrRegionDeadline && rerr != memscan.ErrRegionLimit {
			return rerr
		}
		if len(regions) == 0 {
			// 并行枚举一个都没拿到（极少见）：退回串行，宁可慢也不能空手。
			regions, rerr = proc.RegionsWithError(time.Now().Add(10*time.Second), 0)
			if rerr != nil && rerr != memscan.ErrRegionDeadline && rerr != memscan.ErrRegionLimit {
				return rerr
			}
		}
		var regionBytes uint64
		for _, r := range regions {
			regionBytes += uint64(r.Size)
		}
		el := time.Since(t0)
		// 这条必须打到 stderr：它是「握手→冻结」里最容易被忽视的一段，
		// 不单独量出来就会把整段延迟都算到"定位公钥"头上。
		privateDiagnosticf("[key] 区域列表：%d 个 / %.1f MB（并行枚举 %s）\n",
			len(regions), float64(regionBytes)/(1<<20), el.Round(time.Millisecond))
		s.recordKeyDiag(func() {
			s.keyDiagRegions = len(regions)
			s.keyDiagRegionB = regionBytes
			s.keyDiagPhase = fmt.Sprintf("枚举到 %d 个可读区域（%.1f MB，耗时 %s）",
				len(regions), float64(regionBytes)/(1<<20), el.Truncate(time.Millisecond))
		})
		s.em.emit("pub_check", map[string]any{
			"pub":     fmt.Sprintf("%x", pub),
			"regions": len(regions),
		})
		return nil
	}

	// ── 冻结窗口内第 2 步：全内存定位公钥 ──
	//
	// 同时回答两个问题：公钥在不在客户端内存里（方向对不对），以及它在哪
	// （私钥就在附近）。原来直接盲扫私钥 —— 7 GB 上 400 万候选只覆盖 0.6%。
	//
	// 🔴 2026-10-19 两级化（这一版最重要的性能改动）：
	//
	// 实测依据（cs2.exe pid 13328，`-memory-info`）：
	//
	//	MEM_PRIVATE 合计 5654 个 / 7576.7 MB
	//	  ≤64KB   1839 个 /   57.4 MB  ( 0.8%)
	//	  ≤256KB  2405 个 /  468.9 MB  ( 6.2%)
	//	  ≤1MB     907 个 /  342.5 MB  ( 4.5%)
	//	  ≤16MB    416 个 / 1695.3 MB  (22.4%)
	//	  >16MB     87 个 / 5012.6 MB  (66.2%)
	//
	// 而公钥在两次探测里的 6 处命中，所在区域大小分别是
	// 0x10000 / 0x3000 / 0x10000 / 0x3f000 / 0xe000 / 0x11000 —— **全部 ≤256 KB**。
	//
	// 按实测速度 3.29 GB/s：
	//   只扫「MEM_PRIVATE 且 ≤1MB」 → 868.8 MB → 约 276 ms  ← 700 ms 冻结装得下
	//   全量                        → 7576.7 MB → 约 2300 ms ← 装不下
	//
	// 所以第一级只扫小区域；第一级没命中、且**还有时间预算**时才退回全量。
	// 在 `-freeze full` 下预算就是冻结截止时间，第一级命中时自然不会再扫大块 ——
	// 省下来的 2 秒正好留给 takeSnap，这就是"快照从 0 MB 变成几百 MB"的来源。
	locatePub := func(dl time.Time) {
		ordered = sortRegionsForScan(regions)
		s.keyPhase.Store("定位公钥")
		t0 := time.Now()

		small, rest := splitPubScanRegions(ordered)
		pubHits, pubScanned = scanPub(proc, small, pub, 16, dl)
		stage := "小区域"
		// 第一级没命中才扫其余区域；已经超时就不扫了（在 full 档里这意味着
		// 把剩余时间让给 takeSnap —— 抓一份快照比多找一个公钥地址更值钱）。
		if len(pubHits) == 0 && len(rest) > 0 && time.Now().Before(dl) {
			s.keyPhase.Store("定位公钥（全量兜底）")
			more, n := scanPub(proc, rest, pub, 16, dl)
			pubHits = append(pubHits, more...)
			pubScanned += n
			stage = "小区域+全量"
		}
		privateDiagnosticf(
			"[key] 公钥定位分两级：小区域 %.1f MB / 其余 %.1f MB（本级=%s）\n",
			float64(totalMemBytes(small))/(1<<20),
			float64(totalMemBytes(rest))/(1<<20), stage)
		addrs := make([]uintptr, 0, len(pubHits))
		dumps := make([]string, 0, len(pubHits))
		for _, h := range pubHits {
			addrs = append(addrs, h.Addr)
			dumps = append(dumps, formatPubDump(h))
		}
		wire := 0
		for _, h := range pubHits {
			if h.Wire {
				wire++
			}
		}
		s.recordKeyDiag(func() {
			s.keyDiagPubHit = len(pubHits)
			s.keyDiagPubAddr = addrs
			s.keyDiagPubScan = pubScanned
			s.keyDiagDump = dumps
			s.keyDiagWire = wire
			// 把**这次真的拿去搜的**那 32 字节记下来。它可能和报告里
			// 「提取到的公钥」不同（多次握手 / 多投候选），不记就会互相矛盾。
			s.keyDiagPubUsed = fmt.Sprintf("%x", pub)
		})
		privateDiagnosticf("[key] 公钥定位：扫 %.1f MB，命中 %d 处（%s）\n",
			float64(pubScanned)/(1<<20), len(pubHits),
			time.Since(t0).Truncate(time.Millisecond))

		// 诊断：把每处公钥命中的绝对地址和两种相对偏移打出来。
		//
		// 为什么要打这一行：hints.json 存的是**相对偏移**（ModuleOff / RegionOff），
		// 它的全部前提是「下次运行还在同一个相对位置」。这个前提从来没有验证过 ——
		// 如果公钥在堆上、每次分配位置都不同，那 hints 机制对公钥定位就是无效的，
		// 「拿 hints.json」这条路根本走不通。
		//
		// 验证方法：跑两次，比同一个序号命中的 ModuleOff。
		//   相同 → hints 可行，值得投入；
		//   不同 → hints 对公钥无效，只能把 locatePub 压进 700 ms。
		mb := proc.ModuleBase()
		for i, h := range pubHits {
			moff := int64(0)
			if mb != 0 {
				moff = int64(h.Addr) - int64(mb)
			}
			privateDiagnosticf(
				"[key] 公钥命中 %d/%d：addr=%#x ModuleOff=%#x RegionOff=%#x RegionSize=%#x Protect=%#x Type=%#x\n",
				i+1, len(pubHits), h.Addr, moff,
				int64(h.Addr)-int64(h.Region.Base),
				h.Region.Size, h.Region.Protect, h.Region.Type)
		}
	}

	// ── 冻结窗口内第 3 步：把命中点附近的内存**复制到本地** ──
	//
	// 这一步是第七轮的核心改动。原来冻结窗口里跑的是"读 + X25519 校验"，
	// 用户现场实测：只读了 0.44 MB，却花了 4.294 秒（43 万次校验 × 10 µs），
	// 把 6 秒冻结预算吃光还被截断。**校验根本不需要游戏冻着。**
	//
	// 现在冻结期间只做"读"（memcpy 级别），解冻后再在本地副本上慢慢校验。
	// 于是冻结时长从 6 秒降到 1 秒以内，能读的范围反而从 0.44 MB 扩到几十 MB。
	//
	// 第八轮再加一条：抓取范围不再只限"命中点 ±8 MB"，而是在抓完邻域之后
	// **继续按区域评分顺序往下抓**，直到 -snap-mb 上限。理由是读取几乎免费
	// （实测 64 MB 只占冻结时长的一小部分），而"抓得越多、解冻后能校验的越多"。
	// 用户现场 6 处命中 ±8 MB 只有 64 MB，占可写区的 0.9% —— 太少了。
	var snap *memSnapshot
	// snapFrozen 记「这次快照是不是在冻结窗口内抄的」。
	//
	// 🔴 2026-10-19 15:08 现场：`-freeze off` 时日志同时打了
	//   「快照耗时：201ms —— 全程在冻结窗口内」
	//   「冻结情况：未冻结｜抓取 908664 KB」
	// 两行自相矛盾。off 分支（下面 default 之前的 case）根本不调 freezeRun，
	// 快照是在**进程照常运行**时抄的，说"冻结窗口内"是错的，而且这句话
	// 正是用户判断"这局到底有没有碰进程"的依据 —— 不能含糊。
	var snapFrozen bool

	takeSnap := func(dl time.Time) {
		if len(pubHits) == 0 {
			return
		}
		s.keyPhase.Store("冻结期间抓取内存")
		primary := nearRangesIn(pubHits, snapshotWindow, "snap-near", regions)
		// 邻域之外的可写区**按优先级**补上（已扣掉邻域，不会重复读）。
		//
		// 🔴 这里原来是 `subtractRanges(writableRanges(ordered), primary)`，
		// 而 writableRanges 内部走 mergeRanges —— 会按**地址**重排。
		// 于是 takeSnapshot 按地址顺序抄，撞到 512 MB 上限就停，
		// 抄到的全是低地址的大堆。02:52 现场就是这样：453.8 MB 全花在
		// 5 GB 级大堆上，而 7 处公钥命中全在 20~192 KB 的小区域里。
		rest := snapRanges(regions, primary)
		if c := snapTierBytes(regions, rest); len(c) > 0 {
			privateDiagnosticf("[key] 快照计划：邻域 %.1f MB｜%s｜预算 %d MB\n",
				float64(totalRangeBytes(primary))/(1<<20), strings.Join(c, "｜"),
				snapshotCapBytes>>20)
			// 把「每档实际能拿到多少」也打出来。只打计划量是不够的：
			// 07:29 那局计划写着「私有大堆 6253.4 MB」，实抓只有 71.8 MB，
			// 两个数字差 87 倍，但日志里看不出是配额问题还是读取失败。
			var q strings.Builder
			for i, name := range snapTierNames {
				fmt.Fprintf(&q, " %s=%dMB", name, uintptr(float64(snapshotCapBytes)*snapTierQuota[i])>>20)
			}
			privateDiagnosticf("[key] 快照配额（每档保底，用不完让给后面的档）：%s\n", q.String())
		}
		// 单独计时：这几步全都在**冻结窗口内**，冻结时长直接等于反作弊风险。
		// 03:43 现场「冻结 474ms / 抓 1024 MB」= 2.2 GB/s，而基准能到 6.7 GB/s，
		// 差 3 倍的来源必须能拆开看 —— 是 RPM 本身慢，还是计划/对账这些 CPU 步骤
		// 也在冻着的时候跑。
		t0 := time.Now()
		snap = takeSnapshot(proc, append(primary, rest...), len(primary), snapshotCapBytes, dl)
		take := time.Since(t0)
		// 实际抓到的分档构成 —— 计划的和抓到的必须能对上账，
		// 否则"预算花在哪一档"又变成靠猜（02:52 那次就是靠猜才错了一轮）。
		if snap != nil && snap.bytes > 0 {
			if c := snapCapturedTiers(regions, snap); len(c) > 0 {
				privateDiagnosticf("[key] 快照实抓：%s\n", strings.Join(c, "｜"))
			}
			frozenNote := "—— **未冻结**，进程照常运行，这是活内存快照"
			if snapFrozen {
				frozenNote = "—— 全程在冻结窗口内"
			}
			privateDiagnosticf(
				"[key] 快照耗时：%s（%.2f GB/s｜%d 段｜短读 %d）%s\n",
				take.Round(time.Millisecond),
				float64(snap.bytes)/float64(1<<30)/take.Seconds(), snap.regions, snap.shortRead,
				frozenNote)
		}
	}

	// thawReserve 是留给解冻本身的余量（NtResumeProcess + 重试）。
	//
	// 🔴 必须随冻结上限缩放。原来是写死的 700 ms —— 冻结上限也是 6 秒时没问题，
	// 但上限对齐原版改成 700 ms 之后，`hold - 700ms` 就等于"现在"，
	// takeSnap 会拿到一个已经过期的截止时间，一字节都抄不到。
	// 取 hold 的 1/5，夹在 [30 ms, 200 ms]。
	thawReserve := freezeHoldLimit / 5
	if thawReserve > 200*time.Millisecond {
		thawReserve = 200 * time.Millisecond
	}
	if thawReserve < 30*time.Millisecond {
		thawReserve = 30 * time.Millisecond
	}

	mode := strings.ToLower(strings.TrimSpace(*flagFreeze))
	// 冻结前提示一次，但把数字说清楚 —— 恐慌来自"冻结"这个词，
	// 真正决定反作弊观感的是**冻结了多久**。
	if mode != "off" && mode != "none" && mode != "no" && mode != "0" && mode != "false" {
		privateDiagnosticf(
			"⚠ 握手时会冻结 %s 一次：NtSuspendProcess 挂起全部线程，\n"+
				"  本次上限 %s（原版反汇编量出来的上限是 700ms，short 实测约 352ms）。\n"+
				"  封号那次是 1979ms —— 时长才是风险点，不是冻结动作本身。\n",
			*flagProc, freezeHoldLimit)
	} else {
		// 🔴 off 必须**明说后果**，不能只说"最安全"。
		//
		// 2026-10-19 15:20 现场：用户跑了一整局 `-freeze off`，
		// 日志只有 `[key] 快照耗时…**未冻结**` 和反复的
		// `还没有客户端私钥（需要 -freeze short）`，最后 0 目标。
		// 他的原话是「之前冻结不是已经可以拿到密钥了么？怎么现在又在做重复的
		// 事情获取不到密钥」—— 说明"off=最安全"这个说法把代价藏起来了。
		privateDiagnosticf(
			"⚠ -freeze off：**不会冻结 %s，也拿不到会话私钥**，\n"+
				"  因此解不开包、雷达不会有任何目标。\n"+
				"  这一档只用于纯抓包排障。要出目标请用默认的 -freeze short。\n",
			*flagProc)
	}
	var fo freezeOutcome
	switch mode {
	case "off", "none", "no", "0", "false":
		// 不冻结：最安全（完全不动游戏），但可能错过"抢在擦除前"的窗口。
		if err := enumRegions(); err != nil {
			s.failKey(err)
			return
		}
		locatePub(time.Now().Add(4 * time.Minute))
		takeSnap(time.Now().Add(60 * time.Second))
	default:
		// short / full：**握手后立刻冻结**，枚举 + 定位 + 抓取全在冻结窗口内。
		//
		// 🔴 2026-10-19 04:10 改语义（这一版最重要的改动）：
		//
		// short 原来是「先枚举 + 先定位（实测 188 ms）→ 再冻结」。而私钥只活
		// 一次 RTT —— 客户端收完 ServerHello 就把会话私钥 SecureZeroMemory。
		// 04:10 那次邻域 33.4 MB 全扫完、指针链追了 521 次校验，依然 0 命中，
		// 不是方法不对，是**字节已经不存在了**。
		//
		// 两次成功都是"先冻结再定位"：03:05 是 6 ms、03:43 是 21 ms。
		// 所以 short 和 full 现在走同一条路径，区别只在预算：
		//   short → 冻结窗口内可用 hold - thawReserve
		//   full  → 同上（保留这个名字只为兼容旧命令行）
		//
		// 冻结时长 ≈ 并行枚举 10 ms + 定位 50 ms + 抓取 210 ms ≈ 270 ms，
		// 远低于 21:01 那次被封的 1.979 s。
		s.keyPhase.Store("冻结游戏后定位公钥")
		var ferr error
		freezeDL := time.Now().Add(freezeHoldLimit - thawReserve)

		// 给抓取留出预算：定位是"尽力而为"，抓取才是必须完成的。
		// 不加这道闸，公钥若不在小区域、locatePub 去扫 5 GB 其余区，
		// 会把整个冻结窗口吃光，takeSnap 拿到过期 deadline → 抓 0 MB，
		// 于是又回到"冻了 700 ms 却什么都没抄到"的老毛病。
		locateDL := freezeDL
		if left := time.Until(freezeDL); left > 0 {
			if cap := time.Now().Add(left * 3 / 5); cap.Before(locateDL) {
				locateDL = cap
			}
		}

		fo = freezeRun(proc, freezeHoldLimit, func() {
			snapFrozen = true
			if ferr = enumRegions(); ferr != nil {
				return
			}
			locatePub(locateDL)
			takeSnap(freezeDL)
		})
		if ferr != nil {
			s.failKey(ferr)
			return
		}
	}

	// ── 冻结结束，先把冻结结果落进报告 ──
	//
	// ⚠ 顺序很重要：这几行原来写在校验完之后。18:47 现场用户在第 2 分钟
	// 关窗口，那时"其余副本"还在校验，于是整份报告连"冻结了多久、抄了多少"
	// 都没有 —— 最贵的证据被后置的记录点吞掉了。
	// 原则：**每一级一跑完就写诊断，不要攒到最后**。
	// 冻结真正发生的时刻 —— 这才是这场竞速的计分点。
	//
	// 只有真的冻上了才有意义：没冻上（FreezeErr）时进程一直在跑，
	// 这个数再小也保不住私钥，所以那种情况不报，免得给出虚假的乐观。
	if fo.Froze && pubSeenNS > 0 && !fo.FreezeAt.IsZero() {
		fl := fo.FreezeAt.Sub(time.Unix(0, pubSeenNS)).Round(time.Millisecond)
		privateDiagnosticf(
			"[key] 握手→冻结延迟：%s（真正的计分点；其中挂进程本身占 %s）\n",
			fl, fo.FreezeCost.Round(100*time.Microsecond))
		s.recordKeyDiag(func() {
			s.keyDiagFreezeLag = fmt.Sprintf("%s（挂进程占 %s）",
				fl, fo.FreezeCost.Round(100*time.Microsecond))
		})
	}

	freezeSummary := fo.String()
	if snap != nil && snap.bytes > 0 {
		freezeSummary += "｜抓取 " + snap.summary()
	}
	s.recordKeyDiag(func() { s.keyDiagFreeze = freezeSummary })
	privateDiagnosticf("[key] 冻结情况：%s\n", freezeSummary)

	// 解冻失败是最高级别故障：游戏会一直卡着，用户只能手动结束进程。
	// 必须显式告知，不能只写日志。
	if fo.ThawErr != nil {
		fmt.Fprintln(os.Stderr, "⚠ 恢复目标进程失败，请手动结束游戏后重新启动；生产版不导出底层诊断详情。")
		s.em.emit("freeze_thaw_failed", map[string]any{"error": fo.ThawErr.Error()})
	}

	// ── ① 指针反查（原版 chase）── 放在所有暴力校验之前
	//
	// 18:47 现场定性：这一级原来埋在 runKeySearch 里，而 runKeySearch 排在
	// 「其余副本」的 465 MB 暴力校验之后。用户 2 分钟关窗口，那一级一次都没跑过。
	// 这是纯排序错误 —— 指针反查是整个流程里**性价比最高**的一步：
	// 只有 8 字节比较、不需要 X25519，几百毫秒到几秒，却能直接跨过
	// "公钥和私钥地址无关"这道墙。必须第一个跑。
	//
	// 两遍：
	//   副本版 —— 冻结那一刻的字节，私钥若在冻结期间被擦除也只有这一份；
	//   活内存版 —— 覆盖副本没抄到的那 94%，避免"槽位 0 个"的假结论。
	var ptrLine string
	if len(pubHits) > 0 && !kf.Found() {
		var (
			snapSlots, snapChases int
			liveSlots, liveChases int
			snapBytes, liveBytes  uint64
			ptrElapsed            time.Duration
		)
		var slotAddrs []uintptr
		if snap != nil && snap.bytes > 0 {
			s.keyPhase.Store("指针反查（冻结副本）")
			st := new(scanStat)
			withProgress("指针反查·副本", st, snap.bytes, 10*time.Second, func() {
				snapSlots, snapChases = scanPointersTo(kf, proc, snap, pubHits,
					time.Now().Add(30*time.Second), st)
			})
			snapBytes = st.bytes.Load()
			ptrElapsed += st.elapsed
			slotAddrs = append(slotAddrs, st.slotAddrs...)
		}
		if !kf.Found() {
			s.keyPhase.Store("指针反查（全部可写内存）")
			st := new(scanStat)
			withProgress("指针反查·活内存", st, uint64(totalRangeBytes(writableRanges(ordered))),
				10*time.Second, func() {
					liveSlots, liveChases = scanPointersToLive(kf, proc, ordered, pubHits,
						time.Now().Add(90*time.Second), st)
				})
			liveBytes = st.bytes.Load()
			ptrElapsed += st.elapsed
			slotAddrs = append(slotAddrs, st.slotAddrs...)
		}
		ptrLine = fmt.Sprintf(
			"指向公钥的槽位：冻结副本 %d 个（扫 %.1f MB）、全部可写内存 %d 个（扫 %.1f MB）｜"+
				"跟踪校验 %d 次｜耗时 %s",
			snapSlots, float64(snapBytes)/(1<<20),
			liveSlots, float64(liveBytes)/(1<<20),
			snapChases+liveChases, ptrElapsed.Round(time.Millisecond))

		// 槽位本身和它周围的结构体 dump 出来。
		//
		// 光有"几个槽位"这个数字判断不了任何事：19:10 现场找到 1 个槽位、
		// 顺着它追却没命中，只能靠 dump 才能看出私钥指针到底在哪个偏移。
		var dumpB strings.Builder
		const maxSlotDump = 6
		if len(slotAddrs) > 0 {
			dumpB.WriteString("\n  【指针槽位】谁指向公钥、它周围长什么样：\n")
			dumpB.WriteString("  ▶ 只标**那 8 字节的指针值**（不是 32 字节）。最后一行「槽位值」\n")
			dumpB.WriteString("  就是它指向的地址 —— 应该等于上面某个公钥命中点。\n")
		}
		for i, a := range slotAddrs {
			if i >= maxSlotDump {
				fmt.Fprintf(&dumpB, "  …另有 %d 个槽位未列出\n", len(slotAddrs)-maxSlotDump)
				break
			}
			dumpB.WriteString(formatSlotDump(proc, snap, a, 64, ordered))
		}
		slotDump := dumpB.String()

		// 立刻落报告 —— 后面无论用户什么时候关窗口，这一级的结果都不会丢。
		s.recordKeyDiag(func() {
			s.keyDiagPointer = ptrLine
			s.keyDiagPtrSlotsSnap = snapSlots
			s.keyDiagPtrSlotsLive = liveSlots
			s.keyDiagPtrDump = slotDump
		})
		privateDiagnosticf("[key] 指针反查：%s\n", ptrLine)
		if len(slotAddrs) > 0 {
			// 📌 槽位与私钥的**相对偏移不是常数**（2026-10-20 两局样本，别当定论用）：
			//
			//	09:05  槽位 0x1837cdfeb20  私钥 0x1837cdfebc0  ⇒ 私钥 = 槽位 + 0xA0
			//	09:13  槽位 0x183970f2ca0  私钥 0x183970f2ae0  ⇒ 私钥 = 槽位 - 0x1C0
			//
			// 两次都在同一个 PRIVATE 区域里（相距几百字节），但方向和大小都变了
			// ⇒ 槽位只是「某个指向公钥副本的指针」，不是「私钥结构体的固定字段」。
			// 所以**不能**用「槽位 + 常数」去推私钥 —— 早先只凭一局得出的 0xA0 已作废。
			//
			// 另一个槽位（09:13 的 0x1835bd08878）干脆不在私钥所在区域，
			// 说明这类指针有好几处，扫到哪一个不固定。
			privateDiagnosticf("[key] 指针槽位：%#x\n", slotAddrs[0])
		}

		// 槽位上下文**直接打到 stderr**，不要只留在诊断报告里。
		//
		// 20:36 现场最贵的一条证据就这么丢了：那次没加 -diagnose，
		// 于是 formatSlotDump 的内容一个字都没落盘，只剩下「指针槽位：0x2a083bd2ed8」
		// 这一行地址。而"槽位周围长什么样、有没有 32 字节被清零、附近还有哪些指针"
		// 恰恰是判断"私钥是被擦除了还是压根没扫到"的唯一依据。
		// 打两处就够（一屏以内），多了反而淹掉别的日志。
		if slotDump != "" {
			lines := strings.Split(strings.TrimRight(slotDump, "\n"), "\n")
			limit := len(lines)
			if limit > 40 {
				limit = 40
			}
			privateDiagnosticf("%s\n", strings.Join(lines[:limit], "\n"))
		}

		// ── ①a 锚点内联窗口：槽位 / 命中点 ±512 字节，1 字节步长、不走预筛 ──
		//
		// 20:36 现场的结构化线索只有一条：槽位 0x2a083bd2ed8 与公钥命中 4/7
		// 0x2a083bd30e0 在同一块 64 KB 区域、相距 520 字节。
		// 指针追了 3006 次没命中，但"私钥内联在结构体里"这个形态 chaseAt
		// 根本碰不到（它只跟指针，不校验锚点周围的裸字节）。
		//
		// ⚠ 不要求 len(slotAddrs)>0：指针反查一个槽位都没找到时，
		// 公钥命中点本身仍然是最好的锚点（私钥可能就内联在公钥所在的
		// C++ 结构体里）。这一级每个锚点只有 1025 次校验，永远值得跑。
		if !kf.Found() && len(pubHits) > 0 {
			anchors := append([]uintptr(nil), slotAddrs...)
			for _, h := range pubHits {
				if h.Addr != 0 {
					anchors = append(anchors, h.Addr)
				}
			}
			s.keyPhase.Store("锚点内联窗口")
			st := new(scanStat)
			var n int
			withProgress("锚点内联窗口", st, uint64(len(anchors)*inlineProbeRadius*2), 10*time.Second, func() {
				n = probeInlineWindows(kf, ptrReader{snap: snap, proc: proc}, anchors, st)
			})
			privateDiagnosticf(
				"[key] 锚点内联窗口：%d 个锚点 × ±%d 字节（1 字节步长、不走预筛）｜校验 %d 次｜耗时 %s\n",
				len(anchors), inlineProbeRadius, n, st.elapsed.Truncate(time.Millisecond))
		}
	}

	// ── ①b 同包其它候选：各做一次「定位 + 指针反查」──
	//
	// 一条握手包里常有两个 {key_type=1, key_data=32B} 的 SessionCryptInfo
	// （`08 01 12 20 …`）。ParseHandshake 只能挑一个，挑错了后面 20 分钟全白费。
	// 每个候选只要一次 memmem（7.5 GB ≈ 1.7 s）+ 一次指针反查，
	// 而"有没有结构体引用它"这个判据本身就足以判断挑没挑错。
	//
	// 放在冻结之后：冻结已经把那一刻的字节抄下来了，这里慢一点不影响私钥存活。
	if !kf.Found() && len(siblings) > 0 {
		if s.quickPointerPass(siblings) {
			return
		}
	}

	// ── ② 校验冻结副本：先邻域、后其余 ──
	//
	// 想跑多久跑多久，游戏已经在跑了，不受影响。
	//
	// 邻域 = 命中点 ±8 MB，约 60 MB，几秒级；其余 = 按区域评分补进来的可写区，
	// 几百 MB、几分钟。先跑邻域的意义是"私钥到底在不在公钥旁边"这个判断
	// 在几十秒内就有答案，后面的大范围校验即使被关窗口打断，结论也不受影响。
	if snap != nil && snap.bytes > 0 && !kf.Found() {
		s.keyPhase.Store("校验冻结副本（邻域）")
		withProgress("校验冻结副本·邻域", frozenNear, snap.primaryBytes(), 10*time.Second, func() {
			snap.verifyNear(kf, time.Now().Add(nearVerifyBudget), frozenNear)
		})
		line := "邻域副本：" + frozenNear.summary()
		s.recordKeyDiag(func() { s.keyDiagNear = line })
		privateDiagnosticf("[key] %s\n", line)
	}
	if snap != nil && !kf.Found() && snap.primary < len(snap.chunks) {
		left := time.Until(deadlineOverall)
		if left > 5*time.Second {
			// 🔴 这段提示不是客套话，是 07:38 那局的直接教训。
			//
			// 现场：`已读 195.6 / 976.1 MB（20%）｜预计还需 2m0s`，然后 07:39:55
			// 窗口被关掉 —— 搜索停在 20%，私钥当然没出来，而日志上看起来
			// 就是「又没拿到」，和「搜索跑了但没找到」完全是两件事。
			//
			// 所以必须把「还要多久」和「关掉就白打」写在最显眼的位置。
			restMB := float64(snap.bytes-snap.primaryBytes()) / (1 << 20)
			if clampFirstScan {
				privateDiagnosticf(
					"[key] ⚠ 下面要校验「其余可写区」%.0f MB —— **这一步没跑完就等于这一局白打**（没有私钥就解不出一帧）。\n"+
						"[key]   第一遍只测 clamp 形态的窗口（约 %.0f 秒，命中就是它）；没命中再跑全量（约 %.0f 秒）。\n"+
						"[key]   07:38 那局就是在 20%% 时被关掉的，不是「找不到」，是「没跑完」。\n",
					restMB, restMB/90, restMB/6.5)
			} else {
				privateDiagnosticf(
					"[key] ⚠ 下面要校验「其余可写区」%.0f MB，约 %.0f 秒 —— **没跑完就等于这一局白打**，请不要关闭窗口。\n",
					restMB, restMB/6.5)
			}
			s.keyPhase.Store("校验冻结副本（其余可写区）")
			withProgress("校验冻结副本·其余", frozenRest, snap.bytes-snap.primaryBytes(), 15*time.Second, func() {
				snap.verifyRest(kf, deadlineOverall, frozenRest)
			})
		}
	}

	// ② 剩下的级别交给 runKeySearch。
	//
	// 冻结期间抓的是 ±8 MB 窗口（与区域求交），已经覆盖了原分级策略的
	// 第 1~3 级（±64 KB / ±1 MB / ±8 MB），所以正常情况下直接跳到第 4 级
	// （公钥所在整块区域）—— 不再把同一片内存扫三遍。
	// 只有抓取被截断（上限/超时）时才退回从第 1 级重新走。
	// 前三级（±64 KB / ±1 MB / ±8 MB）在冻结副本的「邻域」部分里已经逐字节校验过了，
	// 所以正常情况下直接从第 4 级（公钥所在整块区域）往下走。
	//
	// ⚠ 第八轮这里有个实打实的浪费：判据原来是 `snap.truncated`，而快照只要
	// 撞到 -snap-mb 上限就会置 truncated（用户现场 512 MB 正好撞上）。于是
	// startStage 被拉回 0，把邻域 50.7 MB / 880 万次校验**又扫了一遍**，白花 1 分 8 秒。
	//
	// ⚠ 第九轮改成 `snap.primary > 0` 又埋了个反方向的坑：primary > 0 只说明
	// 「遍历到了邻域段」，不代表每段都读全（短读 / 尾部不足 32 字节都会留洞）。
	// 一旦有洞，前三级邻域会被**静默跳过** —— 不报错、不提示，只是永远找不到。
	// 所以现在逐段核对：每个命中点的 ±snapshotWindow 与可读区求交后，
	// 必须被邻域副本**完整覆盖**才允许跳过。
	coveredNear := false
	var coveredBytes uintptr
	if snap != nil && snap.primary > 0 && !frozenNear.deadline && frozenNear.bytes.Load() > 0 {
		if prim := snap.primaryRanges(); len(prim) > 0 {
			coveredNear = true
			for _, h := range pubHits {
				for _, w := range nearRangesIn([]pubHit{h}, snapshotWindow, "chk-near", regions) {
					if !coversRange(prim, w.lo, w.hi) {
						coveredNear = false
						privateDiagnosticf(
							"[key] 邻域副本没盖住 %#x-%#x（%.1f MB），不跳过前三级\n",
							w.lo, w.hi, float64(w.hi-w.lo)/(1<<20))
						break
					}
				}
				if !coveredNear {
					break
				}
			}
			if coveredNear {
				coveredBytes = totalRangeBytes(prim)
			}
		}
	}
	startStage := len(nearStages)
	if !coveredNear {
		startStage = 0
	}
	// 19:10 现场留下过一个疑点：报告里冻结副本明明写着「达到上限被截断」，
	// 紧接着却打「邻域搜索：已在冻结副本里覆盖（跳过重复扫描）」。
	// 光看这两行会以为是第九轮那个「截断却判已覆盖」的坑又回来了。
	//
	// 核查结论：**不是 bug**。截断发生在「按区域评分补的那些块」上，
	// 而邻域块是 ranges 的前 primaryCount 段、**最先抓**，永远不会被截断
	// 影响到（takeSnapshot 是按 ranges 顺序抓的，截断只会砍尾部）。
	// 19:10 那三个命中点所在区域只有 56 KB / 172 KB / 108 KB，
	// ±8 MB 窗口与可读区求交后一共才 19.2 MB —— 全在最先抓的那一段里。
	//
	// 但这套推理在报告里没有任何数字能自证，所以这里把决策依据打出来：
	// 下次再看到「已覆盖」，可以直接对账 primary 到底盖了多少 MB。
	if coveredNear {
		privateDiagnosticf(
			"[key] 邻域副本已完整覆盖 %d 处命中点的 ±%.0f MB 窗口（共 %.1f MB），跳过前三级重复扫描\n",
			len(pubHits), float64(snapshotWindow)/(1<<20), float64(coveredBytes)/(1<<20))
	}
	// 冻结副本已经把邻域校验过了，分级搜索就从"区域"这一级往下走。
	// 剩余预算按总截止时间算，别让每一段都重新领一份完整预算。
	left := time.Until(deadlineOverall)
	if left < 30*time.Second {
		left = 30 * time.Second
	}
	var preDone []scanRange
	if snap != nil {
		preDone = snap.coveredRanges()
	}
	hit, rep := runKeySearch(kf, proc, ordered, pubHits,
		func(phase string) { s.keyPhase.Store(phase) }, left, startStage, preDone, snap)
	nearSummary, fullSummary := rep.Near, rep.Full
	if rep.Pointer != "" {
		s.recordKeyDiag(func() { s.keyDiagPointer = rep.Pointer })
	}

	if !hit {
		switch {
		case len(pubHits) > 0:
			err = fmt.Errorf("公钥在内存中（%d 处），但邻域/所在区域/全可写区都没找到匹配私钥", len(pubHits))
		default:
			err = fmt.Errorf("公钥不在目标进程内存中（已扫 %.1f MB，0 命中）—— 这 32 字节多半不是客户端公钥",
				float64(pubScanned)/(1<<20))
		}
	}
	if !hit {
		stats := kf.Stats()
		s.em.emit("key_error", map[string]any{"error": err.Error(), "stats": stats})
		s.recordKeyDiag(func() {
			s.keyDiagErr = err.Error()
			s.keyDiagStats = stats
			s.keyDiagNear = nearSummary
			s.keyDiagFull = fullSummary
			s.keyDiagPhase = "私钥搜索失败（耗时 " +
				time.Since(begin).Truncate(time.Millisecond).String() + "）"
		})
		s.setKeyErr(err.Error())
		return
	}
	s.recordKeyDiag(func() {
		s.keyDiagNear = nearSummary
		s.keyDiagFull = fullSummary
	})
	s.keyMu.Lock()
	s.foundKey, s.foundTag, s.foundAddr = priv, tag, addr
	s.keyMu.Unlock()
	s.markKeyFound()
	s.keyReady.Store(true)
	s.keyPhase.Store("已就绪")
	// 全量扫描拿到地址后必须记下来 —— 这是把"每次 7.5 GB"变成"以后 32 字节"的唯一入口。
	s.rememberHint(addr, pub)
	// 原文日志：Connection key verified and passed to parser
	privateDiagnosticf("Connection key verified and passed to parser (tag=%s addr=%#x in %s)\n",
		tag, addr, time.Since(begin))
	s.em.emit("key_ready", map[string]any{
		"tag":     tag,
		"addr":    fmt.Sprintf("%#x", addr),
		"elapsed": time.Since(begin).String(),
		"stats":   kf.Stats(),
	})
}

func (s *captureSession) setKeyErr(msg string) {
	s.keyMu.Lock()
	s.keyErr = msg
	s.keyMu.Unlock()
	s.keyPhase.Store("失败")
}

// recordKeyDiag 在锁内改密钥诊断字段（写的是搜索 goroutine，读的是收尾线程）。
func (s *captureSession) recordKeyDiag(fn func()) {
	s.keyDiagMu.Lock()
	fn()
	s.keyDiagMu.Unlock()
}

// sortRegionsForScan 把区域按「可能藏密钥的程度」排序。
//
// 为什么必须排：用户机器上 cs2.exe 有 **7096 MB 可读内存、6292 个区域**。
// 按地址顺序扫的话，预算全被低地址的小区域吃掉 —— 实测 400 万候选只覆盖
// 41.6 MB（占全量 0.6%），真正的大堆根本没轮到，所以必然搜不到。
//
// 排序依据：
//  1. MEM_PRIVATE（堆/栈）优先 —— 密钥是运行时生成的，只可能在私有内存里；
//  2. 同类里大的优先 —— 大块更可能是主堆；
//  3. MEM_IMAGE 排最后 —— 那是 PE 映像（代码 + 只读常量），私钥不可能在里面。
//
// pubScanSmallMax 是公钥定位第一级的区域大小上限。
//
// 1 MB 这个值不是拍的：2026-10-19 用 `-memory-info` 实测 cs2.exe 的堆分布，
// 「MEM_PRIVATE 且 ≤1MB」共 868.8 MB（占堆总量 11.5%），按 3.29 GB/s 约 276 ms；
// 而公钥的 6 处实际命中，所在区域全部 ≤256 KB。1 MB 是给版本变化留的余量。
var pubScanSmallMax = uintptr(1 << 20)

// splitPubScanRegions 把区域分成「小区域（第一级）」和「其余（兜底）」。
//
// 小区域的判据是 **MEM_PRIVATE 且 size ≤ pubScanSmallMax**。限定 MEM_PRIVATE
// 是因为两次实测里公钥的 6 处命中 Type 全是 0x20000（堆），PE 映像里不可能有
// 运行时下发的会话公钥。其余区域（大的堆 + MAPPED + IMAGE）留给兜底级。
func splitPubScanRegions(all []memscan.Region) (small, rest []memscan.Region) {
	small = make([]memscan.Region, 0, len(all)/2)
	rest = make([]memscan.Region, 0, len(all)/2)
	for _, r := range all {
		if r.Type == winapi.MEM_PRIVATE && r.Size <= pubScanSmallMax {
			small = append(small, r)
		} else {
			rest = append(rest, r)
		}
	}
	return small, rest
}

// totalMemBytes 是 []memscan.Region 的总字节数（诊断用）。
func totalMemBytes(rs []memscan.Region) uint64 {
	var n uint64
	for _, r := range rs {
		n += uint64(r.Size)
	}
	return n
}

func sortRegionsForScan(regions []memscan.Region) []memscan.Region {
	out := append([]memscan.Region(nil), regions...)
	rank := func(t uint32) int {
		switch t {
		case winapi.MEM_PRIVATE:
			return 0
		case winapi.MEM_MAPPED:
			return 1
		default: // MEM_IMAGE 及其它
			return 2
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank(out[i].Type), rank(out[j].Type)
		if ri != rj {
			return ri < rj
		}
		return out[i].Size > out[j].Size
	})
	return out
}

// snapSmallMax 是"抓快照时最优先抄"的区域大小上限。
//
// 数据依据（2026-10-19 02:52 现场，7 处公钥命中的 RegionSize）：
//
//	0x5000 / 0x8000 / 0x8000 / 0x10000 / 0x15000 / 0x15000 / 0x30000
//	= 20 KB / 32 KB / 32 KB / 64 KB / 84 KB / 84 KB / 192 KB
//
// **七处全在 ≤192 KB 的小区域里，没有一处落在大堆。** 这直接说明握手/会话
// 那些小对象住在小区域；私钥作为同量级的对象，极可能也在同类区域。
// 而原来的排序按 size 降序，512 MB 预算全被 5 GB 的大堆吃掉。
const snapSmallMax = 256 << 10

// snapTier 给区域分优先级档（数字越小越先抄）。
func snapTier(r memscan.Region) int {
	switch {
	case r.Type == winapi.MEM_PRIVATE && r.Size <= snapSmallMax:
		return 0
	case r.Type == winapi.MEM_PRIVATE && r.Size <= 1<<20:
		return 1
	case r.Type == winapi.MEM_PRIVATE:
		return 2
	case r.Type == winapi.MEM_MAPPED:
		return 3
	default:
		return 4
	}
}

var snapTierNames = [...]string{"小区域≤256KB", "中区域≤1MB", "私有大堆", "映射区", "映像/其它"}

// snapTierQuota 是每一档**保底拿到的预算比例**。
//
// 🔴 2026-10-20 07:29 现场暴露的问题：原来是「按档位严格排序、先到先得」，
// 于是预算按 0→1→2→… 一路吃下去：
//
//	快照计划：邻域 53.6 MB｜小区域≤256KB 551.8 MB｜中区域≤1MB 412.9 MB
//	         ｜私有大堆 6253.4 MB｜映射区 305.8 MB｜映像/其它 84.9 MB｜预算 1024 MB
//	快照实抓：小区域≤256KB 551.3 MB｜中区域≤1MB 400.9 MB｜私有大堆 **71.8 MB**
//	冻结情况：冻结 267ms｜已恢复｜抓取 1048576 KB｜**达到上限被截断**
//
// 小区域 + 中区域就吃掉 952 MB，**私有大堆只拿到自己 1.1% 的字节**，
// 而新分配的 32 字节密钥对象正是住在私有大堆里的。结果就是
// `[room1] GNS 握手材料已齐，但没有客户端私钥` —— 找了半天，但根本没读到那一段。
//
// 改成配额制：每档保底，谁先抄完就把剩下的让给后面的档。
// 小区域仍然排第一（公钥确实在 20~192 KB 的区域里，硬规则依据见 snapSmallMax），
// 但不再能独吞整个预算。
var snapTierQuota = [...]float64{0.30, 0.15, 0.45, 0.07, 0.03}

// snapRanges 产出"冻结期间按优先级抄写"的区间列表。
//
// 与 writableRanges 的唯一差别是**顺序**：这里按优先级，不是按地址。
// takeSnapshot 严格按顺序抄，撞到 -snap-mb 上限就停 —— 顺序直接决定
// "512 MB 预算花在哪"，所以不能交给 mergeRanges 按地址重排。
func snapRanges(regions []memscan.Region, primary []scanRange) []scanRange {
	rest := subtractRanges(writableRanges(regions), primary)
	if len(rest) == 0 {
		return nil
	}
	// 把每个 rest 区间的起点映射回它所属的区域，才能拿到类型/大小。
	idx := make([]memscan.Region, 0, len(regions))
	for _, r := range regions {
		if r.Size >= 32 {
			idx = append(idx, r)
		}
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i].Base < idx[j].Base })
	tierOf := func(addr uintptr) int {
		k := sort.Search(len(idx), func(i int) bool { return idx[i].Base > addr }) - 1
		if k < 0 || addr >= idx[k].Base+idx[k].Size {
			return 2 // 找不到就当中间档，别把区间丢掉
		}
		return snapTier(idx[k])
	}
	// 按档位分桶，桶内仍按「小/中区域先抄小的、大区域先抄大的」排序。
	buckets := make([][]scanRange, len(snapTierNames))
	for _, r := range rest {
		t := tierOf(r.lo)
		buckets[t] = append(buckets[t], r)
	}
	for t := range buckets {
		b := buckets[t]
		if t <= 1 {
			// 小/中区域：小的先抄。预算一旦截断，这样覆盖到的**块数**最多，
			// 而"私钥在不在里面"取决于块数，不取决于字节数。
			sort.SliceStable(b, func(i, j int) bool { return (b[i].hi - b[i].lo) < (b[j].hi - b[j].lo) })
		} else {
			sort.SliceStable(b, func(i, j int) bool { return (b[i].hi - b[i].lo) > (b[j].hi - b[j].lo) })
		}
	}

	// 第一轮：每档按配额取，取到配额就停（剩下的留到第二轮）。
	//
	// 配额是"保底"不是"上限"：某档实际字节数小于配额时，它会在第一轮就抄完，
	// 后面几档自然多拿 —— 不会浪费预算。
	out := make([]scanRange, 0, len(rest))
	taken := make([]int, len(buckets))
	for t, b := range buckets {
		quota := uintptr(float64(snapshotCapBytes) * snapTierQuota[t])
		var used uintptr
		for taken[t] < len(b) {
			r := b[taken[t]]
			n := r.hi - r.lo
			// used == 0 时无条件收下，否则一个大区间永远进不来（配额比它小）。
			if used > 0 && used+n > quota {
				break
			}
			out = append(out, r)
			used += n
			taken[t]++
		}
	}
	// 第二轮：把各档剩下的补在后面。只有预算没被配额吃满时才轮得到，
	// 撞到 -snap-mb 上限时它们本来也读不到 —— 但顺序仍然是确定的。
	for t, b := range buckets {
		out = append(out, b[taken[t]:]...)
	}
	return out
}

// snapTierBytes 汇总每个档位的字节数，用于日志自证"预算花在哪一档"。
func snapTierBytes(regions []memscan.Region, rs []scanRange) []string {
	if len(rs) == 0 {
		return nil
	}
	idx := make([]memscan.Region, 0, len(regions))
	for _, r := range regions {
		if r.Size >= 32 {
			idx = append(idx, r)
		}
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i].Base < idx[j].Base })
	var sum [len(snapTierNames)]uintptr
	for _, r := range rs {
		t := 2
		if k := sort.Search(len(idx), func(i int) bool { return idx[i].Base > r.lo }) - 1; k >= 0 &&
			r.lo < idx[k].Base+idx[k].Size {
			t = snapTier(idx[k])
		}
		sum[t] += r.hi - r.lo
	}
	out := make([]string, 0, len(snapTierNames))
	for i, n := range snapTierNames {
		if sum[i] == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s %.1f MB", n, float64(sum[i])/(1<<20)))
	}
	return out
}

// snapCapturedTiers 统计**实际抄到**的字节按档位分布。
//
// 和 snapTierBytes（计划值）分开是刻意的：计划与实际对不上时，说明
// takeSnapshot 在某一档里提前撞了上限或超时，这是必须看见的信号。
func snapCapturedTiers(regions []memscan.Region, snap *memSnapshot) []string {
	if snap == nil || len(snap.chunks) == 0 {
		return nil
	}
	idx := make([]memscan.Region, 0, len(regions))
	for _, r := range regions {
		if r.Size >= 32 {
			idx = append(idx, r)
		}
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i].Base < idx[j].Base })
	var sum [len(snapTierNames)]uintptr
	for _, c := range snap.chunks {
		t := 2
		if k := sort.Search(len(idx), func(i int) bool { return idx[i].Base > c.addr }) - 1; k >= 0 &&
			c.addr < idx[k].Base+idx[k].Size {
			t = snapTier(idx[k])
		}
		sum[t] += uintptr(len(c.data))
	}
	out := make([]string, 0, len(snapTierNames))
	for i, n := range snapTierNames {
		if sum[i] == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s %.1f MB", n, float64(sum[i])/(1<<20)))
	}
	return out
}

// pubHit 是一处公钥命中。
type pubHit struct {
	Addr   uintptr
	Region memscan.Region
	// Dump 是命中点前后各 64 字节的原始内容，DumpAt 是公钥在这段里的偏移。
	// 用途：如果私钥与公钥是成对存储的（绝大多数实现的布局），它必然落在
	// 这 128 字节里 —— 报告里直接把字节打出来，一眼就能看出布局对不对，
	// 不用再靠"搜索窗口开多大"去猜。
	Dump   []byte
	DumpAt int
	// MarkLen 是 dump 里要用 ▶ 标出来的长度（0 = 32，即"公钥那 32 字节"）。
	//
	// 指针槽位是**8 字节**的值，不是 32 字节的公钥。原来复用这个渲染函数时
	// 一律标 32 字节，报告里 ▶ 指向 `30 32 ef 6d 18 02 00 00 44 00 3a 00 ...`，
	// 后半截其实是邻居字段 —— 看图的人会以为槽位是 32 字节。
	MarkLen int
	// Judge 表示这是**公钥命中点**，渲染时要附一句「旁边那 32 字节是不是私钥」
	// 的结论（见 judgeNeighborhood）。指针槽位不设这一位。
	Judge bool
	// Wire 表示"这处命中看起来是抓到的报文在内存里的副本"，判据是公钥前面
	// 紧挨着 protobuf 字段头（`12 20` 或 `08 01 12 20`）。
	//
	// 为什么这个判据有用（2026-10-17 用户现场实测）：6 处命中全部满足这个
	// 特征，说明客户端内存里那些公钥都是**报文缓冲/解析后的消息对象**，
	// 不是密钥材料。报文副本旁边永远不会有私钥 —— 在这附近放大窗口是白费。
	Wire bool
}

// wireLike 判断命中点前面是不是 protobuf 字段头。
//
// 用户现场的握手消息结构是：
//
//	0a 31 | 08 01 | 12 20 <32 字节公钥> | 19 <8 字节> | 20 0d | 28 02
//	        版本   字段2 长度32                         字段4   字段5
//
// 其中 `12 20`（字段 2、长度 32）就是公钥的字段头。解析后的消息对象在堆里
// 通常也会保留同样的内联布局，所以这个判据对"原始缓冲"和"解析后的对象"都成立。
func wireLike(buf []byte, pos int) bool {
	if pos >= 4 && buf[pos-4] == 0x08 && buf[pos-3] == 0x01 &&
		buf[pos-2] == 0x12 && buf[pos-1] == 0x20 {
		return true
	}
	return pos >= 2 && buf[pos-2] == 0x12 && buf[pos-1] == 0x20
}

// regionTypeName 把 MEMORY_BASIC_INFORMATION.Type 翻成可读名字。
func regionTypeName(t uint32) string {
	switch t {
	case winapi.MEM_PRIVATE:
		return "PRIVATE"
	case winapi.MEM_MAPPED:
		return "MAPPED"
	case winapi.MEM_IMAGE:
		return "IMAGE"
	default:
		return fmt.Sprintf("TYPE_%#x", t)
	}
}

// formatPubDump 把公钥命中点前后各 64 字节排成可读的十六进制。
//
// 这是判断"私钥是否与公钥成对存储"最直接的证据。上一版报告只给了统计数字
// （"附近 512 KB 内没有匹配的私钥"），完全没法区分两种完全不同的情况：
//
//	a) 布局不同 —— 私钥在，但不在公钥旁边（该继续放大窗口 / 换锚点）；
//	b) 根本不是密钥对 —— 这 32 字节只是碰巧相同的常量或缓存副本（该换候选）。
//
// 把字节打出来，一眼就能看出来。行首的 ▶ 标记覆盖公钥本身，前后偏移是相对
// 公钥起点的字节数；如果某个 -32 或 +32 偏移处有一块看着像随机数的 32 字节，
// 那就是候选私钥，可以直接人工核对。
// formatSlotDump 把「指向公钥的槽位」前后各 span 字节 dump 出来。
//
// 为什么必须看这个：19:10 现场在活内存里找到 1 个槽位指向公钥，
// 但顺着它追没命中。光知道"有 1 个"什么都判断不了 —— 必须看到槽位
// 周围的结构体长什么样，才能知道私钥指针在哪个偏移上。
//
// 读不到前半段就退回只读后半段（槽位可能正好在区域开头）。
//
// regions 用来查这个槽位到底落在哪个内存区域里。**不要像原来那样
// 用 `memscan.Region{Base: addr &^ 0xFFF}` 糊一个假的** —— 那会打出
// `TYPE_0x0　区域 0x21840afe000 + 0 B` 这种头部（19:46 报告里全是这样），
// 看的人会以为那块区域是 0 字节，或者以为是新类型的内存。
// formatSlotDump 渲染一个「指向公钥的槽位」及其周围 64 字节。
//
// ⚠ 必须优先读**冻结副本**，不能只读活内存。
//
// 20:18 现场就栽在这上面：报告里
//
//	0x20ced9d0d68　PRIVATE　区域 0x20ced9c5000 + 128 KB
//	▶     +0  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
//	    槽位值 = 0x0（非用户态地址（不像指针））
//
// 一个「值等于公钥地址」的槽位，值怎么可能是 0？看起来像反查逻辑错了。
// 其实没错：**槽位是在冻结那一刻的副本里反查出来的，而 dump 读的是解冻后
// 一分钟的活内存** —— 那个对象早被释放/复用了。两个数据源不同时间，
// 结论自然对不上，却白白让人怀疑反查算法。
//
// 现在：副本覆盖该地址就从副本读（那是权威的冻结状态），
// 同时把活内存的值附在后面。两者不一致时明说是"冻结后被改写"，
// 而不是让它看起来像 bug。
func formatSlotDump(proc *memscan.Process, snap *memSnapshot, addr uintptr, span int,
	regions []memscan.Region) string {
	want := span + 32
	lo := addr
	if addr >= uintptr(span) {
		lo = addr - uintptr(span)
	}

	var buf []byte
	var got int
	frozen := false
	if s := snapRead(snap, lo, int(addr-lo)+want); s != nil {
		buf, got, frozen = s, len(s), true
	} else if proc != nil {
		buf = make([]byte, int(addr-lo)+want)
		got, _ = proc.ReadAt(lo, buf)
		if got < int(addr-lo)+32 {
			// 前半段不可读：只读槽位往后
			lo = addr
			buf = make([]byte, want)
			got, _ = proc.ReadAt(lo, buf)
		}
	}
	if got < 8 {
		return fmt.Sprintf("  %#x（读不到上下文）\n", addr)
	}

	reg := regionOf(regions, addr)
	h := pubHit{
		Addr:    addr,
		Dump:    buf[:got],
		DumpAt:  int(addr - lo),
		Region:  reg,
		MarkLen: 8, // 槽位是 8 字节的指针，不是 32 字节的公钥
	}
	out := formatPubDump(h)

	// 把槽位里那 8 字节**直接解成地址打出来**。
	// 这是这一段最核心的信息：槽位指向哪儿？是不是公钥命中点之一？
	if h.DumpAt >= 0 && h.DumpAt+8 <= len(h.Dump) {
		var v uintptr
		for i := 0; i < 8; i++ {
			v |= uintptr(h.Dump[h.DumpAt+i]) << (8 * i)
		}
		kind := "非用户态地址（不像指针）"
		if isUserPtr(v) {
			kind = "用户态地址"
			if r := regionOf(regions, v); r.Size > 0 {
				kind = fmt.Sprintf("→ %s 区域 %#x + %s", regionTypeName(r.Type), r.Base, humanSize(r.Size))
			}
		}
		src := "活内存"
		if frozen {
			src = "冻结副本"
		}
		out += fmt.Sprintf("    槽位值 = %#x（%s）｜取自%s\n", v, kind, src)

		// 冻结副本和活内存不一致 → 明说，别让人以为反查算错了。
		if frozen && proc != nil {
			var live [8]byte
			if n, _ := proc.ReadAt(addr, live[:]); n == 8 {
				var lv uintptr
				for i := 0; i < 8; i++ {
					lv |= uintptr(live[i]) << (8 * i)
				}
				if lv != v {
					out += fmt.Sprintf("    ⚠ 现在活内存里这 8 字节已经是 %#x —— 冻结之后对象被释放/改写了。\n", lv)
					out += "      反查没错：它指的是**冻结那一刻**的状态。别按当前值判读。\n"
				}
			}
		}
	}
	return out
}

// regionOf 找出 addr 落在哪个区域；找不到返回零值。
func regionOf(regions []memscan.Region, addr uintptr) memscan.Region {
	for _, r := range regions {
		if r.Size > 0 && addr >= r.Base && addr < r.Base+r.Size {
			return r
		}
	}
	return memscan.Region{}
}

func formatPubDump(h pubHit) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %#x　%s　区域 %#x + %s\n",
		h.Addr, regionTypeName(h.Region.Type), h.Region.Base, humanSize(h.Region.Size))
	if len(h.Dump) == 0 {
		b.WriteString("    （未采集到上下文）\n")
		return b.String()
	}
	const perLine = 16
	markLen := h.MarkLen
	if markLen <= 0 {
		markLen = 32
	}
	for i := 0; i < len(h.Dump); i += perLine {
		end := i + perLine
		if end > len(h.Dump) {
			end = len(h.Dump)
		}
		mark := "  "
		if i < h.DumpAt+markLen && end > h.DumpAt {
			mark = "▶ "
		}
		fmt.Fprintf(&b, "    %s%+6d  ", mark, i-h.DumpAt)
		for j := i; j < end; j++ {
			fmt.Fprintf(&b, "%02x ", h.Dump[j])
		}
		for j := end; j < i+perLine; j++ {
			b.WriteString("   ")
		}
		b.WriteString(" ")
		for j := i; j < end; j++ {
			if c := h.Dump[j]; c >= 0x20 && c < 0x7f {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("\n")
	}
	if h.Judge {
		b.WriteString(judgeNeighborhood(h))
	}
	return b.String()
}

// looksLikePriv 判断 32 字节是否"像一把私钥"。
//
// 判据和全内存扫描的预筛一致（`privFilter` 的默认值 {MinDistinct:24, MaxZeros:2}）：
// 20000 个真 X25519 私钥实测漏检 1 个（0.005%），足够做"肉眼结论"的自动化。
// 这里只是给报告加一行判断，不参与真正的搜索，所以宁可宽松一点。
func looksLikePriv(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	var seen [256]bool
	distinct, zeros := 0, 0
	for _, c := range b {
		if c == 0 {
			zeros++
		}
		if !seen[c] {
			seen[c] = true
			distinct++
		}
	}
	return distinct >= 24 && zeros <= 2
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// judgeNeighborhood 把「公钥旁边那几十个字节」直接翻译成一句结论。
//
// ── 为什么值得单独做这件事（2026-10-17 19:46 现场）──────────────────
//
// 报告里原本只有十六进制。19:10 和 19:46 两次的命中点 dump 长得一模一样：
//
//	 0  PUBKEY（32 字节）
//	32  00 00 00 ...（32 字节全 0）
//
// 那个位置、那个长度，正好是一个 X25519 私钥。两次不同公钥、不同地址、
// 同样的形状 —— 这是「pub[32] + priv[32] 布局里私钥已被 SecureZeroMemory」
// 的典型特征。但这份证据要靠人盯着十六进制自己看出来，等于没有。
//
// 所以这里做三件事：
//  1. 紧跟公钥的 32 字节全 0  → 直接说"像被擦除的私钥槽"；
//  2. 紧跟公钥的 32 字节高熵  → 直接说"疑似私钥，先看这里"；
//  3. 否则在 ±256 字节里扫一遍，指出有没有别的像私钥的块。
//
// 这条结论直接决定下一步往哪走：形状 1 说明"抢晚了"（要继续压前冻结时机），
// 形状 2 说明"就在这儿"（该去查为什么 X25519 校验没通过）。
func judgeNeighborhood(h pubHit) string {
	var b strings.Builder
	const klen = 32
	// Judge 只对"公钥命中点"为真。指针槽位（MarkLen=8）走同一个渲染函数，
	// 但绝不能套用这套判读 —— 槽位后面那 32 字节是邻居字段，不是密钥槽。
	if !h.Judge {
		return ""
	}
	if h.DumpAt < 0 || h.DumpAt+klen > len(h.Dump) {
		return ""
	}

	// 报文副本不做"这里是私钥"的判读 —— 21:01 现场的假阳性。
	//
	// 那次的第 1 处命中 `0xb8e97ee23c` 前面是 `3a 75 0a 31 08 01 12 20`
	// （protobuf 字段头），后面紧跟的 32 字节被判成"高熵 → 疑似私钥"。
	// 其实那是**这条握手包在内存里的副本**，公钥后面当然是整段密文载荷，
	// 熵自然高。把它报成"疑似私钥"会把人引向错误的偏移。
	//
	// `h.Wire` 就是现成的判据（公钥前面紧挨着 `08 01 12 20` / `12 20`）。
	if h.Wire {
		b.WriteString("    └ 判读：这处是**抓到的报文在内存里的副本**（公钥前面紧挨着\n")
		b.WriteString("      protobuf 字段头 `08 01 12 20`）。后面那 32 字节是报文后续\n")
		b.WriteString("      载荷（密文），熵高是必然的，**不是私钥** —— 别按这个偏移去找。\n")
		return b.String()
	}

	// ① 紧跟其后的 32 字节（最常见的内联布局）
	if h.DumpAt+2*klen <= len(h.Dump) {
		blk := h.Dump[h.DumpAt+klen : h.DumpAt+2*klen]
		switch {
		case allZero(blk):
			// ⚠ 这段措辞在 2026-10-17 21:01 之后改过，别再改回去。
			//
			// 原来的结论是「极可能是私钥已被客户端擦除 → 对策是让冻结更早」。
			// 21:01 现场把冻结压到了 **6 ms**（ClientHello 刚上网、客户端还没
			// 收到 ServerHello），这个位置**仍然**全 0 —— 时间上不可能是擦除。
			// 而且同一份报告里两处不同命中点的 `+32` 是同一串字节
			// （`19 1d 97 91 79 84 e1 d7 3e 20 0d 28 02`），
			// 随机私钥撞不出一样的前 14 字节。
			//
			// 所以真相是：**这个结构体本来就不放私钥**，那 32 字节是保留字段。
			// 「贴公钥扫」这条路已经走到头，不是窗口不够宽、也不是冻结不够早。
			b.WriteString("    └ 判读：**+32 处 32 字节全为 0**。\n")
			b.WriteString("      以前这里写的是「私钥已被擦除 → 让冻结更早」，**那个结论已废弃**：\n")
			b.WriteString("      21:01 把冻结压到 6ms（ClientHello 刚上网、还没收到 ServerHello）\n")
			b.WriteString("      时这里仍然全 0 —— 时间上不可能是擦除。\n")
			b.WriteString("      结论：**这个结构体本来就不放私钥**，那 32 字节是保留字段。\n")
			b.WriteString("      → 别再加大冻结/窗口，那条路已经走到头了（见报告第 20 节）。\n")
		case looksLikePriv(blk):
			b.WriteString("    └ 判读：**+32 处 32 字节高熵** —— 疑似私钥就在这个偏移。\n")
			b.WriteString("      → 若仍没通过 X25519 校验，说明它不属于这处公钥（是邻居字段），\n")
			b.WriteString("        把这段字节发出来核对。\n")
		default:
			b.WriteString("    └ 判读：+32 处既不是全 0 也不像私钥（多半是别的字段）。\n")
		}
	}

	// ② 在可见窗口里扫别的 32 字节块（跳过公钥本身和已判读的 +32）
	var found []int
	for off := 0; off+klen <= len(h.Dump); off += 8 {
		rel := off - h.DumpAt
		if rel >= 0 && rel < klen {
			continue // 公钥本身
		}
		if rel == klen {
			continue // 上面已经判过
		}
		if looksLikePriv(h.Dump[off : off+klen]) {
			found = append(found, rel)
		}
	}
	if len(found) == 0 {
		if h.DumpAt+2*klen > len(h.Dump) {
			b.WriteString("    └ 判读：可见窗口里没有像私钥的 32 字节块。\n")
		}
		return b.String()
	}
	b.WriteString("    └ 判读：窗口内另有像私钥的 32 字节块，偏移：")
	for i, rel := range found {
		if i > 0 {
			b.WriteString(" / ")
		}
		fmt.Fprintf(&b, "%+d", rel)
	}
	b.WriteString("\n")
	return b.String()
}

// humanSize 把字节数写成 MB / KB（区域大小动辄几百 MB，原始字节数不好读）。
func humanSize(n uintptr) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// scanPub 全内存搜这 32 字节公钥（按 sortRegionsForScan 的顺序），返回命中处。
//
// 这是本轮的关键改动。原来的做法是**盲扫私钥**：把内存里每个 8 字节对齐位置
// 当成候选私钥，推公钥去比对。候选量随内存大小线性爆炸（7 GB / 8 ≈ 9 亿），
// 预算 400 万只够扫 0.6%，等于没扫。
//
// 换个方向：**公钥是已知的 32 字节**，直接 memmem 就能定位，代价只有内存拷贝
// 的量级。找到公钥之后，私钥几乎总在同一结构体或相邻对象里（两个值通常缓存在
// 一起），在命中点附近试私钥，代价可以忽略。
//
// 这是把"大海捞针"换成"先找到装针的盒子"。
func scanPub(proc *memscan.Process, regions []memscan.Region, pub []byte, limit int, deadline time.Time) ([]pubHit, uint64) {
	if len(pub) != 32 || limit <= 0 {
		return nil, 0
	}
	const block = 1 << 20

	// 并行扫：这一步在冻结窗口里跑，单线程 2.2 秒 = 游戏白冻 2.2 秒。
	// 按区域分发（大区域会被拆成多块），命中用 mutex 汇总。
	// 用户现场实测：7.6 GB 单线程 2.23 s，并行后降到亚秒级。
	ch := make(chan memscan.Region, 64)
	var (
		mu      sync.Mutex
		hits    []pubHit
		scanned uint64
		stop    atomic.Bool
	)
	go func() {
		defer close(ch)
		for _, r := range regions {
			// 大区域切成 8 MB 一块，避免一个 worker 独占几百 MB
			for off := uintptr(0); off < r.Size; off += 8 << 20 {
				size := r.Size - off
				if size > 8<<20 {
					size = 8 << 20
				}
				// worker 永远会消费（命中后是 continue 而不是 return），
				// 所以这里的阻塞发送不会卡死；stop 只用来提前收工。
				ch <- memscan.Region{Base: r.Base + off, Size: size, Protect: r.Protect, Type: r.Type}
				if stop.Load() {
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, block)
			var local []pubHit
			var localScanned uint64
			for r := range ch {
				if stop.Load() || (!deadline.IsZero() && time.Now().After(deadline)) {
					continue
				}
				for off := uintptr(0); off < r.Size; off += block {
					if stop.Load() || (!deadline.IsZero() && time.Now().After(deadline)) {
						break
					}
					want := block
					if rem := r.Size - off; rem < uintptr(block) {
						want = int(rem)
					}
					if want < len(pub) {
						break
					}
					n, err := proc.ReadAt(r.Base+off, buf[:want])
					if err != nil || n < len(pub) {
						continue
					}
					localScanned += uint64(n)
					for i := 0; i+len(pub) <= n; {
						j := bytes.Index(buf[i:n], pub)
						if j < 0 {
							break
						}
						pos := i + j
						// 顺手把命中点前后各 64 字节抄下来（buf 每块会被覆盖，必须拷贝）。
						dlo, dhi := pos-64, pos+len(pub)+64
						if dlo < 0 {
							dlo = 0
						}
						if dhi > n {
							dhi = n
						}
						local = append(local, pubHit{
							Addr:   r.Base + off + uintptr(pos),
							Region: r,
							Dump:   append([]byte(nil), buf[dlo:dhi]...),
							DumpAt: pos - dlo,
							Wire:   wireLike(buf, pos),
							Judge:  true, // 这是公钥命中点 → 让报告给"旁边是不是私钥"下结论
						})
						i = pos + 1
					}
					mu.Lock()
					if len(hits)+len(local) >= limit {
						mu.Unlock()
						stop.Store(true)
						break
					}
					mu.Unlock()
				}
			}
			mu.Lock()
			hits = append(hits, local...)
			scanned += localScanned
			mu.Unlock()
		}()
	}
	wg.Wait()

	// 按地址排序，报告里的命中点顺序稳定（并行扫描的到达顺序不确定）。
	sort.Slice(hits, func(i, j int) bool { return hits[i].Addr < hits[j].Addr })
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits, scanned
}

// keySearchReport 记录分级搜索每一级的覆盖情况（进诊断报告）。
type keySearchReport struct {
	Near    string // 邻域搜索（±8 KB / 64 KB / 1 MB / 8 MB）
	Pointer string // 指针反查（原版 chase，tag="pointer"）
	Full    string // 兜底（公钥所在区域 / 全可写区）
}

// runKeySearch 是"已知公钥 → 找私钥"的分级策略本体。
//
// 抽成独立函数（而不是写在 searchKey 里）是为了能被测试直接调用：把一对
// 真实密钥埋进本进程内存、把公钥和私钥故意放远，就能验证"邻域搜不到时
// 兜底真的会跑、并且真能搜到"。只测各个零件而没测编排，等于没测。
//
// 分级思路：
//
//	第 1~3 级：离公钥命中点 ±64 KB / 1 MB / 8 MB 逐级放大（合并重叠区间）；
//	第 4 级：公钥命中所在地的**整块内存区域**；
//	第 5 级：所有可写区域（PRIVATE 优先）。
//
// 全部阶段共享一个总预算 budget，超时就停 —— 不按 clamp 形态过滤后 7.3 GB
// 全量要 90 分钟量级，不可能扫完，所以必须限时并如实报告覆盖情况。
// nearStages 是"离公钥多远"的分级窗口。
//
// 阶梯和原版 v2.0.5 对齐（反汇编 `main.findPrivWithHints` 里的
// `{0x2000, 0x10000, 0x100000}` 字面量 = 8 KB / 64 KB / 1 MB），
// 我们多留一级 ±8 MB（第八轮实测私钥不在 ±8 MB 内，但多一级只多几秒）。
var nearStages = []struct {
	w    uintptr
	desc string
}{
	{8 << 10, "8 KB"},
	{64 << 10, "64 KB"},
	{1 << 20, "1 MB"},
	{8 << 20, "8 MB"},
}

// runKeySearch 从第 startStage 级开始做分级搜索。
//
// startStage 的用途：searchKey 会在**冻结窗口内**先把第 0 级（±64 KB）做掉
// （抢在客户端擦除临时私钥之前），然后解冻，再调本函数从第 1 级继续。
// 传 0 表示不跳过（不冻结、或冻结窗口里没做）。
// preDone 是"调用方已经扫过/校验过"的区间（冻结副本覆盖到的那些）。
//
// 不传它的话，兜底会把副本里已经逐字节校验过的几百 MB 再扫一遍 ——
// 用户现场 17:27 就这样白花了 2 分 38 秒，而那两分半正好是最后差的那一点预算。
//
// snap 是冻结期间抓下来的内存副本。只有"指针反查"这一级需要它：
// 反查"谁指向公钥字节"必须遍历副本，而且用副本还能省掉再冻结一次。
// 传 nil 表示没有副本，那一级会被跳过（其余级别不受影响）。
func runKeySearch(kf *keyfind.Search, proc *memscan.Process, regions []memscan.Region,
	pubHits []pubHit, phase func(string), budget time.Duration, startStage int,
	preDone []scanRange, snap *memSnapshot) (bool, keySearchReport) {
	var rep keySearchReport
	if phase == nil {
		phase = func(string) {}
	}
	if startStage < 0 {
		startStage = 0
	}
	deadline := time.Now().Add(budget)
	hard := time.Now().Add(10 * time.Minute) // 外层硬上限，防止 budget 传成天文数字
	dl := func() time.Time { return earliest(hard, deadline) }

	nearSt := new(scanStat)
	// 已扫过的区间，供后面的兜底去重。初始值来自冻结副本的覆盖范围。
	done := mergeRanges(append([]scanRange(nil), preDone...))
	for i := startStage; i < len(nearStages); i++ {
		w := nearStages[i]
		if kf.Found() || len(pubHits) == 0 || time.Now().After(deadline) {
			break
		}
		phase("附近搜索私钥 " + w.desc)
		// 扣掉 done：走到这里说明邻域副本没盖全（比如段内短读留了洞），
		// 但盖到的部分不该再扫一遍 —— 否则就退化成第八轮那种"邻域扫两次"。
		rs := subtractRanges(nearRangesIn(pubHits, w.w, "near-pub", regions), done)
		if len(rs) == 0 {
			continue
		}
		scanRangesStat(kf, proc, rs, dl(), nearSt)
		done = mergeRanges(append(done, rs...))
	}
	rep.Near = nearSt.summary()
	// 冻结副本已经把前几级覆盖掉了，这时 nearSt 一定是空的 ——
	// 再打一行"读 0.0 MB｜校验 0 次"只会让人误以为"邻域搜了但什么都没有"。
	if startStage < len(nearStages) {
		privateDiagnosticf("[key] 邻域搜索：%s\n", rep.Near)
	} else if len(pubHits) > 0 {
		privateDiagnosticf("[key] 邻域搜索：已在冻结副本里覆盖（跳过重复扫描）\n")
	}
	if kf.Found() {
		return true, rep
	}

	// ② 指针反查**不在这里做**了。
	//
	// 18:47 现场定性：这一级原来就插在这个位置，而 runKeySearch 要等
	// 「其余副本」465 MB 暴力校验跑完才被调用。用户 2 分钟关窗口 →
	// 这一级一次都没跑过，报告里连那一行都没有。
	//
	// 现在它被提到 freeze 之后、verifyNear 之前（见 keySearch 主流程的 ① 段），
	// 并且跑两遍：冻结副本 + 全部可写活内存。那里才是它该待的地方：
	// 它是整个流程里唯一不花 X25519 就能跨过"公钥私钥地址无关"这道墙的机制。

	// ③ 公钥所在整块区域
	if len(pubHits) > 0 && time.Now().Before(deadline) {
		// ⚠ 必须扣掉 done（尤其是冻结副本已经校验过的那几百 MB）。
		// 用户现场 17:27：其余副本读 450.8 MB / 校验 22118142 次 / 2m38s，
		// 紧接着"全可写区兜底"又把这几百 MB 从头扫了一遍 —— 2 分半白花。
		// 这里漏掉 subtractRanges 就是那 2 分半的直接来源。
		all := fullRegionRanges(pubHits, "full-region")
		rr := subtractRanges(all, done)
		skipped := totalRangeBytes(all) - totalRangeBytes(rr)
		if len(rr) == 0 {
			// 同样把依据打出来：命中点所在的**整块区域**（不是 ±8 MB 窗口）
			// 如果小到被副本完整盖住，这一级确实没东西可扫。
			// 19:10 那三块区域分别只有 56 / 172 / 108 KB。
			privateDiagnosticf(
				"[key] 公钥所在整块区域：%d 处命中点的所在区域共 %.1f MB，已被冻结副本完整覆盖（跳过重复扫描）\n",
				len(pubHits), float64(totalRangeBytes(all))/(1<<20))
			rep.Full = "公钥所在区域｜已在冻结副本里覆盖（跳过重复扫描）"
		} else {
			privateDiagnosticf("[key] 邻域没找到，改扫公钥所在整块区域：%d 块，共 %.1f MB（已扣掉扫过的 %.1f MB）\n",
				len(rr), float64(totalRangeBytes(rr))/(1<<20), float64(skipped)/(1<<20))
			phase(fmt.Sprintf("扫描公钥所在区域（共 %.0f MB）", float64(totalRangeBytes(rr))/(1<<20)))
			st := new(scanStat)
			scanRangesStat(kf, proc, rr, dl(), st)
			done = mergeRanges(append(done, rr...))
			rep.Full = "公钥所在区域｜" + st.summary()
			privateDiagnosticf("[key] 区域扫描：%s\n", st.summary())
		}
		if kf.Found() {
			return true, rep
		}
	}

	if time.Now().Before(deadline) {
		// 扣掉前几级已经扫过的区间，别把预算浪费在重复扫描上。
		wr := subtractRanges(writableRanges(regions), done)
		privateDiagnosticf("[key] 转入全内存可写区兜底：%d 块，共 %.1f MB（已扣掉扫过的 %.1f MB）\n",
			len(wr), float64(totalRangeBytes(wr))/(1<<20),
			float64(totalRangeBytes(done))/(1<<20))
		// 先算清楚这一级到底扫不扫得完，再决定要不要让用户干等。
		//
		// 20:18 现场报的是「预计还需 49m4s → 1h5m15s」，而搜索总预算只有
		// keyScanBudget（20 分钟）—— 用户 1 分半就关窗口了，那一级永远跑不完。
		// 更糟的是那个 ETA 是**按字节数线性外推**的，而这个阶段根本不是 IO
		// 受限：2026-10-17 实测（16 核，Go 1.24.4，crypto/ecdh X25519）
		//   单核单次 37.987 µs = 25,778 次/s；16 核 190,537 次/s（只 7.4 倍）
		// 现场同一份日志里 32 MB 跑了 2,586,587 次校验 / 15 s = 172,439 次/s，
		// 已经吃到峰值的 90%。**加线程、加缓冲、改块大小都没用，是纯算力墙。**
		// 已经算清楚这一级扫不扫得完；跑不完就别开跑（见下面 skipFallback 的说明）。
		var skipFallback bool
		var needStr, leftStr string
		if mb := float64(totalRangeBytes(wr)) / (1 << 20); mb > 0 {
			need := time.Duration(mb * (1 << 20) * x25519PassRate / float64(x25519ChecksPerSec) * float64(time.Second))
			left := time.Until(deadline)
			needStr = need.Round(time.Minute).String()
			leftStr = left.Round(time.Second).String()
			if need > left {
				privateDiagnosticf(
					"[key] ⚠ 这一级按实测算力（%.0f 万次 X25519/s，预筛通过率 %.1f%%）需 %s，"+
						"而预算只剩 %s —— **本次扫不完**，最多覆盖 %.0f%%。\n",
					float64(x25519ChecksPerSec)/1e4, x25519PassRate*100,
					need.Round(time.Minute), left.Round(time.Second),
					float64(left)/float64(need)*100)
				privateDiagnosticf(
					"[key]   → 结论：兜底这一级救不了场。私钥若真在这 %.0f MB 里，也早被解冻后的"+
						"客户端擦掉了（它扫的是活内存，不是冻结那一刻的副本）。\n", mb)
				// 🔴 算出来跑不完就**别跑**。
				//
				// 20:36 现场：这里已经打出「需 51m0s，预算只剩 16m48s，最多覆盖 33%」，
				// 然后照样开跑 —— 白烧 1 分 20 秒、白读 1.7 GB 活内存，
				// 还把用户仅剩的窗口时间用掉了，最后仍然 0 命中。
				// 明知 33% 覆盖率的暴力扫描，期望值就是 0；把这段时间让给
				// 指针追逐/内联窗口的多轮尝试才有意义。
				skipFallback = true
			} else {
				privateDiagnosticf(
					"[key] 这一级按实测算力估算需 %s，预算 %s —— 来得及跑完。\n",
					need.Round(time.Second), left.Round(time.Second))
			}
		}
		if skipFallback {
			rep.Full += "全可写区｜**预算不足，已跳过**（按实测算力需 "
			rep.Full += needStr
			rep.Full += "，剩余 "
			rep.Full += leftStr
			rep.Full += "）"
		} else {
			phase(fmt.Sprintf("全内存可写区兜底（共 %.0f MB，预算内扫描）",
				float64(totalRangeBytes(wr))/(1<<20)))
			st := new(scanStat)
			// 全可写区兜底动辄几分钟。每隔 15 秒报一次进度，
			// 否则用户只看到一行"搜索仍在进行"，分不清是卡死还是在推进。
			withProgress("全可写区兜底", st, uint64(totalRangeBytes(wr)), 15*time.Second, func() {
				scanRangesStat(kf, proc, wr, dl(), st)
			})
			if rep.Full != "" {
				rep.Full += "｜全可写区｜"
			} else {
				rep.Full = "全可写区｜"
			}
			rep.Full += st.summary()
			privateDiagnosticf("[key] 全可写区兜底：%s\n", st.summary())
		}
	}
	return kf.Found(), rep
}

// ⚠ 关于"clamp 形态过滤"的重要结论（2026-10-17 实测推翻）
//
// X25519 在**运算时**会对标量做 clamp：b[0] &= 248、b[31] &= 127、b[31] |= 64。
// 一开始我据此加了一层过滤 —— 认为私钥"存储时就已经 clamp"，可以用
// b[0]&7==0 && b[31]&0xC0==0x40 筛掉 31/32 的候选。
//
// 实测证明这是错的：绝大多数实现（libsodium 的 crypto_box_keypair、OpenSSL 的
// X25519_public_from_private、Go 的 crypto/ecdh）都是**保存原始随机 32 字节，
// 在每次运算时对副本 clamp**。本机实测 Go 生成的私钥里只有 3.4%（≈1/32）
// 满足 clamp 形态。
//
// 后果很严重：如果拿 clamp 形态当硬过滤，真正的私钥有 31/32 的概率被静默丢弃，
// 报告上只会显示"没找到"，根本看不出是被自己过滤掉的。所以**现在任何一级
// 扫描都不再按 clamp 形态过滤**，代价是 X25519 校验次数涨 32 倍，靠"分级放大
// 范围 + 多核并行 + 硬时限"来控制总耗时。

// scanBlock 是扫描的单次读取块大小。1 MB 是实测吞吐（约 4000 MB/s）与
// 单次系统调用开销之间的平衡点。
const scanBlock = 1 << 20

// scanRange 是一段待扫的地址区间（已按内存区域边界裁剪过）。
type scanRange struct {
	lo, hi uintptr
	tag    string // 进 keyfind 的命中标签，便于事后区分是哪一级搜到的
}

// scanStat 汇总一次扫描的覆盖情况，写进诊断报告。
//
// 这些数字是判断"搜不到到底是范围不够还是方法不对"的唯一依据 ——
// 上一版报告只有 checks 一个数，完全看不出扫了多少内存、覆盖了多大比例。
type scanStat struct {
	bytes   atomic.Uint64 // 实际读到的字节数
	cand    atomic.Uint64 // 真正做了 X25519 校验的候选数
	regions atomic.Uint64 // 覆盖的区域数
	shortRd atomic.Uint64 // 读失败 / 短读的次数
	strided atomic.Uint64 // 因高熵被降级成 8 字节步长的块数
	// clampHit 是「clamp 形态那一遍就命中」的块数。
	// 它等于 1 说明私钥是带 clamp 存下来的 —— 下一轮可以直接只跑快扫。
	clampHit atomic.Uint64
	elapsed  time.Duration
	deadline bool       // 是否因超时提前结束
	filter   privFilter // 本次扫描用的预筛（零值 = 没开）
	filtered bool       // 是否真的启用了预筛

	// slotAddrs 是指针反查找到的"指向公钥的槽位"地址。
	//
	// 为什么要记：19:10 现场找到了 1 个槽位，但顺着它追没命中 ——
	// 光有"1 个"这个数字什么都判断不了，必须知道**那个槽位在哪**、
	// 周围长什么样，才能定出真实结构体的字段偏移。
	slotAddrs []uintptr
}

func (s *scanStat) summary() string {
	if s == nil {
		return ""
	}
	cut := ""
	if s.deadline {
		cut = "｜**超时截断（未扫完）**"
	}
	mode := ""
	if s.filtered {
		mode = "｜预筛 " + s.filter.String()
	}
	// 降级块数必须报出来：它意味着这些块有 7/8 的偏移没看，
	// 藏着"其实扫过但漏了"的可能，不能让人以为覆盖是完整的。
	if n := s.strided.Load(); n > 0 {
		mode += "｜高熵降级 " + utoa(n) + " 块（8 字节步长）"
	}
	if s.clampHit.Load() > 0 {
		mode += "｜clamp 形态那一遍就命中"
	}
	return fmt.Sprintf("读 %.1f MB｜区域 %d 个｜校验 %d 次｜短读 %d｜耗时 %s%s%s",
		float64(s.bytes.Load())/(1<<20), s.regions.Load(),
		s.cand.Load(), s.shortRd.Load(),
		s.elapsed.Truncate(time.Millisecond), mode, cut)
}

// keyScanBudget 是私钥搜索的总时间预算。
//
// 为什么需要一个"预算"而不是"扫完为止"：不按 clamp 形态过滤后，7.3 GB 内存
// 要 9.2 亿次 X25519 校验，实测 38.6 µs/次（本机 16 线程）→ 全量要几十小时。
// 用户不可能等这么久，而"卡在半路且什么都不知道"是最糟的体验。
//
// 第八轮把默认从 180 秒提到 600 秒，原因是数据：真实堆内存的预筛通过率约 0.3%
// （用户现场 62.9 MB 只做了 21.5 万次校验、耗时 1.97 秒），按这个速率
// 7 GB 大约 220 秒能扫完 —— 180 秒差一点点，600 秒留足余量。
// 真正拖慢的是高熵块，那些块现在会被降级成 8 字节步长（见 scanBufferStat）。
var keyScanBudget = 1200 * time.Second

// ============================================================
// 冻结游戏进程（原版 v2.0.5 的做法）
// ============================================================
//
// 为什么冻结：客户端拿到握手包、算出会话密钥之后，很多实现会用
// SecureZeroMemory 之类的**安全擦除**把临时私钥抹掉（这是密码学库的标准做法）。
// 一旦被抹掉，再怎么搜内存也搜不到 —— 这不是搜索算法的问题。
//
// 冻结进程（NtSuspendProcess）会把所有线程的时间停住，擦除线程根本没机会运行，
// 于是私钥会一直留在内存里，我们可以在冻结状态下从容搜完再解冻。
// 这才是原版"能拿到密钥"的关键机制，而不是"读得干净"。
//
// ⚠ 这不是反检测手段，恰恰相反：挂起游戏进程是内核级反作弊最容易注意到的动作。
// 原版二进制里专门留了一句「游戏恢复调用未成功，请立即停止工具」，说明作者
// 很清楚这件事的严重性。
//
// ⚠⚠ 最危险的事实：NtSuspendProcess 的挂起计数**不绑定句柄**。挂起之后即使
// 我们的进程崩溃、被杀，游戏进程仍然保持挂起 —— 用户只能手动结束游戏。
// 所以下面的 freezeRun 必须做到"无论发生什么都要解冻"，这是安全底线。

// freezer 是"冻结/恢复目标进程"的最小接口（memscan.Process 已实现）。
//
// 抽成接口的唯一目的是让"保证解冻"这段安全逻辑能脱离真实进程做单元测试 ——
// 这段逻辑一旦有漏洞就是"用户的游戏永久卡死"，必须有测试盯着。
type freezer interface {
	FreezeFast() error
	ThawFast() error
}

// freezeHoldLimit 是单次冻结的硬上限。
//
// 安全第一：超过这个时长，看门狗**强制解冻**，哪怕搜索还没做完。
// 宁可这次搜不到（可以再跑一次），也不能让用户的游戏一直停着 ——
// 游戏卡死比搜不到密钥严重得多。
//
// 🔴 2026-10-19 对齐原版（这次是从原版反汇编里量出来的，不是估的）：
//
//	原版 capture.exe  main.main.func6.3
//	  0x18324d  mov  edi, 0x29b92700     ; 700,000,000 ns = 700 ms
//	  0x183252  call time.Time.Add       ; deadline = now + 700ms
//	  0x183520  call time.AfterFunc      ; Until(deadline) 到点兜底解冻
//
// 也就是说原版的冻结上限是 **700 ms**，不是 6 秒。我们之前那个 6 秒是拍的，
// 比原版长 8.6 倍；21:01 那次实测冻了 1.979 s，已经是原版的 2.8 倍。
//
// 反作弊（完美平台 `ObRegisterCallbacks` + 线程回调）能看到的差别就在这里：
// 同样是 NtSuspendProcess，冻 700 ms 和冻 6 秒是两个量级的事。
//
// 代价必须说清楚：`locatePub` 在本机实测约 2.2 s，700 ms 内跑不完，
// 所以无 hints.json 时全量定位基本必然被截断 —— **这正是原版的行为**，
// 原版也是「700 ms 内扫不到就这一轮放弃」。要改回长冻结用 `-freeze-hold`。
var freezeHoldLimit = 700 * time.Millisecond

// freezeOutcome 记录一次冻结的实际情况，进诊断报告。
type freezeOutcome struct {
	Froze     bool          // 是否真的冻上了
	FreezeErr error         // 冻结失败原因（冻不上就照常搜，只是没有抢时间的保护）
	Hold      time.Duration // 实际持有时长
	Forced    bool          // 是否由看门狗强制解冻（说明 fn 超时了）
	ThawErr   error         // 解冻失败原因 —— 最高级别故障
	Panicked  bool          // fn 是否 panic（panic 也不能导致永久冻结）
	Completed bool          // fn 是否正常跑完
	// FreezeAt 是 NtSuspendProcess 返回成功的那一刻。
	//
	// 为什么需要它：「握手→搜索」量的是 searchKey 进门的时间，而真正决定
	// 私钥还在不在的是**进程停住**的时刻。中间还夹着 FreezeFast 自己
	// （遍历全部线程）和调度开销，实测约 7 ms —— 在这条以毫秒计的竞速里
	// 它占三分之一，必须单独量出来，否则永远不知道该优化哪一段。
	FreezeAt time.Time
	// FreezeCost 是 FreezeFast 单次调用的耗时（NtSuspendProcess 往返）。
	//
	// 和 FreezeAt 分开记：FreezeAt 回答「多晚才停住」，FreezeCost 回答
	// 「挂进程这个动作本身有多贵」。如果它就有 5 ms，那再怎么砍前面的
	// 等待也到不了 2 ms，得换挂进程的方式（按线程 SuspendThread 并行挂）。
	FreezeCost time.Duration
}

func (o freezeOutcome) String() string {
	if !o.Froze {
		if o.FreezeErr != nil {
			return "未冻结（" + o.FreezeErr.Error() + "）"
		}
		return "未冻结"
	}
	s := fmt.Sprintf("冻结 %s", o.Hold.Truncate(time.Millisecond))
	if o.Forced {
		s += "｜**超时被强制解冻**"
	}
	if o.Panicked {
		s += "｜fn panic"
	}
	if !o.Completed && !o.Panicked && !o.Forced {
		s += "｜未正常结束"
	}
	if o.ThawErr != nil {
		s += "｜⚠ 解冻失败：" + o.ThawErr.Error()
	} else {
		s += "｜已恢复"
	}
	return s
}

// freezeRun 在冻结状态下执行 fn，并**保证无论发生什么都会解冻**。
//
// 四层保证（缺一不可，少一层就可能是"游戏永久卡死"）：
//
//  1. **defer 解冻** —— fn 正常返回、提前 return 都会走到；
//  2. **panic 兜底** —— fn panic 时 recover 后照样解冻；
//  3. **看门狗强制解冻** —— fn 卡在某个系统调用里时，到点由独立 goroutine 解冻；
//  4. **解冻重试** —— NtResumeProcess 偶发失败是可能的，重试 3 次，绝不放弃。
//
// 解冻彻底失败时把错误带回去，由调用方在 UI/日志/诊断报告里高亮 ——
// 这种情况下用户必须手动结束游戏进程，程序要明确告诉他这一点。
func freezeRun(fz freezer, hold time.Duration, fn func()) freezeOutcome {
	var out freezeOutcome
	if fn == nil {
		return out
	}
	if fz == nil {
		fn()
		out.Completed = true
		return out
	}
	if hold <= 0 {
		hold = freezeHoldLimit
	}

	fzBegin := time.Now()
	if err := fz.FreezeFast(); err != nil {
		// 冻不上不是错误（进程可能刚退出），照常搜索，只是失去抢时间的保护。
		out.FreezeErr = err
		func() {
			defer func() {
				if r := recover(); r != nil {
					out.Panicked = true
				}
			}()
			fn()
			out.Completed = true
		}()
		return out
	}
	out.Froze = true
	out.FreezeAt = time.Now()
	out.FreezeCost = out.FreezeAt.Sub(fzBegin)
	begin := time.Now()

	var (
		mu     sync.Mutex
		thawed bool
	)
	thaw := func(forced bool) {
		mu.Lock()
		defer mu.Unlock()
		if thawed {
			return
		}
		thawed = true
		out.Hold = time.Since(begin)
		out.Forced = forced
		// 重试 3 次：一次失败绝不能把游戏丢在那儿冻着。
		for i := 0; i < 3; i++ {
			err := fz.ThawFast()
			out.ThawErr = err
			if err == nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	var wg sync.WaitGroup
	doneCh := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTimer(hold)
		defer t.Stop()
		select {
		case <-t.C:
			thaw(true) // 超时强解：安全优先，宁可不搜
		case <-doneCh:
		}
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				out.Panicked = true
			}
		}()
		defer close(doneCh)
		defer thaw(false)
		fn()
		out.Completed = true
	}()

	// 等看门狗真正退出再返回，避免它在返回后还去动 fz。
	wg.Wait()
	thaw(false) // 幂等：如果看门狗已经解过，这里直接返回
	return out
}

// subtractRanges 从 all 里扣掉 done 已覆盖的部分，返回还没扫过的区间。
//
// 为什么要扣：第 4 级扫的是"公钥所在整块区域"，第 5 级扫的是"所有可写区域"，
// 后者天然包含前者。不扣就会把同一段内存再扫一遍 —— 在 3 分钟的总预算下，
// 这等于白白浪费掉大部分预算，直接降低找到私钥的概率。
//
// 要求 all 与 done 各自已排序且内部不重叠（mergeRanges 的输出满足）。
func subtractRanges(all, done []scanRange) []scanRange {
	if len(done) == 0 {
		return all
	}
	var out []scanRange
	j := 0
	for _, r := range all {
		lo := r.lo
		for j < len(done) && done[j].hi <= lo {
			j++
		}
		k := j
		for k < len(done) && done[k].lo < r.hi {
			d := done[k]
			if d.lo > lo {
				out = append(out, scanRange{lo: lo, hi: d.lo, tag: r.tag})
			}
			if d.hi > lo {
				lo = d.hi
			}
			if lo >= r.hi {
				break
			}
			k++
		}
		if lo < r.hi {
			out = append(out, scanRange{lo: lo, hi: r.hi, tag: r.tag})
		}
	}
	return out
}

// scanChunk 是任务切分的粒度。
//
// 为什么必须切：任务是按区间分发的，如果只给 6 个大区间，就只有 6 个 worker
// 在干活，其余空闲 —— 本机实测 15K 次校验本该 40 ms 却花了 601 ms，正是
// "1 个区间 = 1 个 worker"造成的。切到 1 MB 一块（正好等于单次读取量）后，
// 任意大小的区间都能把所有核吃满。
const scanChunk = 1 << 20

// splitRanges 把大区间切成 scanChunk 大小的任务块。
func splitRanges(rs []scanRange) []scanRange {
	// 分段大小要自适应，不能写死 1 MB。
	//
	// 03:27 现场：`邻域搜索：读 0.3 MB｜区域 2 个｜校验 323522 次｜耗时 8.985s`
	// —— 0.3 MB 走了逐字节全量校验（小范围不开预筛，这是对的），
	// 32 万次 X25519 串行下来 12 秒。但按 1 MB 切只切出 **1~2 段**，
	// 16 个核里只有 1~2 个在干活，于是真的跑了 9 秒。
	//
	// 修法：按总量/核数算目标段长，夹在 [32 KB, 1 MB]。
	//   - 大扫描（7 GB）→ 仍是 1 MB，行为不变；
	//   - 小扫描（0.3 MB）→ 32 KB 一段，切出 10 段，多核都用得上。
	chunk := uintptr(scanChunk)
	if w := numWorkers(); w > 1 {
		if want := totalRangeBytes(rs) / uintptr(w); want < chunk {
			chunk = want
		}
	}
	if chunk < 32<<10 {
		chunk = 32 << 10
	}
	if chunk > scanChunk {
		chunk = scanChunk
	}

	var out []scanRange
	for _, r := range rs {
		for lo := r.lo; lo < r.hi; lo += chunk {
			hi := lo + chunk
			if hi > r.hi {
				hi = r.hi
			}
			if hi-lo < 32 {
				break
			}
			out = append(out, scanRange{lo: lo, hi: hi, tag: r.tag})
		}
	}
	return out
}

// scanRangesStat 在若干区间里并行找私钥，统计累加进 st。
//
// 三个关键点：
//
//  1. **块读**而不是逐 8 字节 ReadProcessMemory。跨进程读本身有开销，1 MB 的
//     窗口按 32 字节逐个读要 3 万次系统调用，块读只要 1 次。用户现场那版逐
//     字节实现，512 KB 窗口只跑了 12.9 万次检查就结束 —— 大量位置因为窗口被
//     区域边界裁剪根本没试到。
//  2. **并行**。X25519 校验是整条链路的瓶颈（本机单线程 38.8 µs、16 线程
//     等效 5.0 µs），而校验之间完全独立；keyfind.Search.Check 内部用原子量 +
//     sync.Once，天然并发安全。
//  3. **不按 clamp 形态过滤**（原因见上面的长注释）。代价是校验次数涨 32 倍，
//     靠分级放大范围 + 硬时限来控制。
//
// numWorkers 返回并行扫描的 worker 数。
//
// X25519 是纯 CPU 活，用满逻辑核；上限 32 防止在超大机器上把游戏卡住
// （冻结期间我们读内存，核越多对游戏调度影响越大）。
func numWorkers() int {
	n := runtime.NumCPU()
	if n > 32 {
		n = 32
	}
	if n < 1 {
		n = 1
	}
	return n
}

// exhaustiveLimit 是"逐字节全量校验"的规模上限。
//
// 24 MB ≈ 2400 万次 X25519 校验 ≈ 实测 6.1 µs/次 → 约 145 秒，还在预算内。
// 超过这个规模就必须开预筛，否则一定超时。
const exhaustiveLimit = 24 << 20

// x25519ChecksPerSec 是本机 16 核实测的 X25519 校验吞吐（2026-10-17 实测）。
//
//	单核单次 37.987 µs = 25,778 次/s
//	16 核 190,537 次/s —— 只有 7.4 倍，不是 16 倍（超线程 + 内存带宽）
//
// 现场交叉验证：20:18 日志里 32 MB 跑出 2,586,587 次校验 / 15 s
// = 172,439 次/s，即峰值的 90%。说明兜底阶段**已经贴着算力墙跑**，
// 再优化线程数/缓冲/块大小都不会有收益。用它来算 ETA 才有意义。
const x25519ChecksPerSec = 190_000

// x25519PassRate 是预筛（DefaultPrivFilter：不同字节≥24 且 零字节≤2）
// 对普通内存字节的通过率。实测：20:18 现场 32 MB → 2,586,587 次校验，
// 32 MB / 32 = 1,048,576 个 32 字节窗口，但逐字节扫有 33,554,432 个起点，
// 2586587 / 33554432 = 7.7%。
const x25519PassRate = 0.077

// scanRangesStat 扫一批区间，返回是否命中。
//
// ── 两个必须记住的点（都是 2026-10-17 第五轮踩出来的）──
//
//  1. **逐字节，不是 8 字节一跳。** 旧实现 `off += 8` 只检查 8 字节对齐的窗口，
//     等于 7/8 的偏移从来没被看过。当时的测试之所以能过，是因为它在 Go 的
//     `ecdh.PrivateKey` 结构体里命中了另一个**对齐**的内部副本，埋进去的未对齐
//     副本一次都没被检查 —— 测试给了一个虚假的安全感。现在由
//     `TestScanRangesUnalignedKey` 用"只存在未对齐副本"的场景钉死。
//
//  2. **大范围必须预筛。** 逐字节扫 7.5 GB 是 75 亿个窗口，按 6.1 µs/次要 12 小时。
//     预筛（`privFilter`）把明显不是随机数据的窗口跳过，代价约 3 ns/偏移。
//     小范围（≤ 24 MB）不开预筛，保持"零漏检"。
//
// ── 高熵块的自适应步长（2026-10-17 第八轮）──
//
// 用户现场（17:02 那份日志）：
//
//	区域扫描：读 0.5 MB｜区域 6 个｜校验 507749 次｜耗时 11.537s
//
// 0.5 MB 里做了 50 万次校验 —— 预筛几乎没筛掉任何东西（通过率 96.8%）。
// 原因是预筛的判据是"像不像随机数据"，而**真正的高熵块全是随机数据**，
// 通过率天然接近 100%。X25519 实测 38.6 µs/次（本机 16 线程），
// 这种块按 1 字节步长扫，1 MB 就要 38 秒 —— 一块就能把整个预算吃光。
//
// 对策：先花几十微秒探一下这个块的通过率，通过率过半就改用 8 字节步长。
// 8 字节对齐不是拍脑袋：Go/C++/Rust 的堆分配器给对象至少 8 字节对齐，
// 加密库的密钥缓冲（32 字节）实际都在 8 或 16 字节边界上。
// 代价是漏掉 7/8 的偏移，所以**只在预筛已经失效的高熵块上这么做**，
// 并且把"有多少块被降级"写进报告，不隐瞒。
const (
	entropySegLen     = 64 << 10 // 分段长度：每段单独判断是否高熵
	entropyProbes     = 4        // 每段分散取几个 4 KB 窗口做探测
	entropyPassCut    = 10       // 通过率 > 1/10 视为高熵
	highEntropyStride = 8        // 高熵段改用的步长
)

// scanBufferStat 在一段**已经读进本地**的字节上跑私钥校验。
//
// 抽出来是因为有两个调用方（目标进程内存、冻结副本），行为必须完全一致 ——
// 否则"冻结副本里没找到、直读找到了"这种差异会让人误判成冻结有问题。
//
// 分段判高熵而不是整块一刀切：一个 1 MB 块里只要有一小段随机数据
// （压缩包、纹理、已加密的缓冲），整块降级就会漏掉其余部分里非对齐的私钥。
func scanBufferStat(kf *keyfind.Search, buf []byte, base uintptr, tag string,
	pf privFilter, st *scanStat) bool {
	if len(buf) < 32 {
		return false
	}
	if !pf.Enabled() || len(buf) < entropySegLen {
		return filterScan(buf, pf, func(off int) bool {
			st.cand.Add(1)
			return kf.Check(buf[off:off+32], tag, base+uintptr(off))
		})
	}
	for start := 0; start < len(buf); start += entropySegLen {
		end := start + entropySegLen
		if end > len(buf) {
			end = len(buf)
		}
		seg := buf[start:end]
		if len(seg) < 32 {
			break
		}
		// ① 探一下这段的预筛通过率。真随机数据通过率≈97%，真实堆内存≈0.3%，
		//    两者差三个数量级，1/10 的门槛怎么选都不会误判。
		//
		// ⚠ 必须**分散取样**，不能只看开头 16 KB。用户现场 17:27 的"区域扫描"
		// 0.6 MB 做了 58.9 万次校验（通过率 94%），却一个块都没被判成高熵 ——
		// 因为那些区域是"头部结构化、后面全是随机数据"，只看头部就被骗过去了。
		// 现在在段的 0/1/4/1/2/3/4 处各取 4 KB，四段合计 16 KB。
		const probeWin = 4 << 10
		passes, seen := 0, 0
		for k := 0; k < entropyProbes; k++ {
			at := 0
			if len(seg) > probeWin {
				at = k * (len(seg) - probeWin) / (entropyProbes - 1)
			}
			w := seg[at:]
			if len(w) > probeWin {
				w = w[:probeWin]
			}
			if len(w) < 32 {
				continue
			}
			seen += len(w) - 31
			filterScan(w, pf, func(int) bool {
				passes++
				return false
			})
		}
		stride := 1
		if seen > 0 && passes*entropyPassCut > seen {
			stride = highEntropyStride
			st.strided.Add(1)
		}
		// ② 扫这一段。视图向后多看 31 字节，保证段边界上的窗口不漏。
		hi := end + 31
		if hi > len(buf) {
			hi = len(buf)
		}
		view := buf[start:hi]
		if stride == 1 {
			if filterScan(view, pf, func(off int) bool {
				if start+off >= end {
					return false // 已归下一段处理
				}
				st.cand.Add(1)
				return kf.Check(view[off:off+32], tag, base+uintptr(start+off))
			}) {
				return true
			}
			continue
		}
		for off := 0; start+off < end && off+32 <= len(view); off += stride {
			st.cand.Add(1)
			if kf.Check(view[off:off+32], tag, base+uintptr(start+off)) {
				return true
			}
		}
	}
	return false
}

// clampFirstScan 控制「clamp 形态优先」的两遍扫（-clamp-first，默认开）。
//
// 🔴 存在的理由（2026-10-20 07:38 现场）：
//
//	[key] 校验冻结副本·其余 进行中：已读 195.6 / 976.1 MB（20%）… 预计还需 2m0s
//
// 而用户在 07:39:55 就把窗口关了 —— 这一局**根本没有得出「找不到私钥」的结论**，
// 它只是没跑完。慢在哪：`verifyPriv` 对每个候选都要做一次 X25519 标量乘
// （实测约 5 µs），976 MB 逐字节 × 预筛通过率 3.1% ≈ 3000 万个候选 ≈ 2 分半。
//
// 而 X25519 私钥有一半概率是**带 clamp 形态**存下来的（OpenSSL 在存盘前就
// clamp），那种情况下 2 次字节比较就能筛掉 31/32，把标量乘次数降一个数量级。
// 所以先用 clamp 形态扫一遍（十秒级），没命中再跑完整预筛 —— 覆盖率不变。
var clampFirstScan = true

// scanBufferStatClampFirst 是 scanBufferStat 的「先 clamp 后全量」版本。
//
// 两遍都在同一段字节上跑，`st.bytes` 由调用方只记一次，所以进度条不会跳。
func scanBufferStatClampFirst(kf *keyfind.Search, buf []byte, base uintptr, tag string,
	pf privFilter, st *scanStat) bool {
	if len(buf) < 32 {
		return false
	}
	if clampFirstScan {
		pfClamp := pf
		pfClamp.RequireClamp = true
		if scanBufferStat(kf, buf, base, tag, pfClamp, st) {
			st.clampHit.Add(1)
			return true
		}
		if kf.Found() {
			return true
		}
	}
	return scanBufferStat(kf, buf, base, tag, pf, st)
}

func scanRangesStat(kf *keyfind.Search, proc *memscan.Process, ranges []scanRange,
	deadline time.Time, st *scanStat) bool {
	if len(ranges) == 0 {
		return false
	}
	pf := privFilter{MinDistinct: 0, MaxZeros: -1}
	if totalRangeBytes(ranges) > exhaustiveLimit && !privFilterDisabled {
		pf = DefaultPrivFilter
	}
	st.filter = pf
	st.filtered = pf.Enabled()

	begin := time.Now()
	defer func() {
		st.elapsed += time.Since(begin)
		if !deadline.IsZero() && time.Now().After(deadline) {
			st.deadline = true
		}
	}()

	workers := numWorkers()
	// 生产者单独跑，用 stop 保证 worker 全部提前退出时它不会永久阻塞在
	// `ch <- r` 上（否则每轮搜索都漏一个 goroutine）。
	ch := make(chan scanRange, 64)
	stop := make(chan struct{})
	go func() {
		defer close(ch)
		for _, r := range splitRanges(ranges) {
			select {
			case ch <- r:
			case <-stop:
				return
			}
			if kf.Found() || (!deadline.IsZero() && time.Now().After(deadline)) {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, scanBlock)
			for r := range ch {
				if kf.Found() || (!deadline.IsZero() && time.Now().After(deadline)) {
					return
				}
				st.regions.Add(1)
				for a := r.lo; a < r.hi; a += scanBlock {
					if kf.Found() || (!deadline.IsZero() && time.Now().After(deadline)) {
						return
					}
					want := scanBlock
					if rem := r.hi - a; rem < uintptr(scanBlock) {
						want = int(rem)
					}
					if want < 32 {
						break
					}
					n, err := proc.ReadAt(a, buf[:want])
					if err != nil || n < 32 {
						st.shortRd.Add(1)
						continue
					}
					st.bytes.Add(uint64(n))
					// 逐字节滑动（旧版是 off += 8，漏掉 7/8 的偏移）。
					// 小范围不开预筛 → 朴素逐字节循环；
					// 大范围开预筛 → 只对"像随机数据"的窗口做 X25519；
					// 高熵块 → 自动降级成 8 字节步长（见 scanBufferStat）。
					if scanBufferStatClampFirst(kf, buf[:n], a, r.tag, pf, st) {
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	return kf.Found()
}

// nearVerifyBudget 是"命中点邻域"副本的校验预算。
//
// 用户现场邻域只有 63 MB，实测 2 秒级就能校验完；给 60 秒是为了兜住
// "命中点多 + 邻域被大区域撑满"的情况（6 处命中 × ±8 MB 求交后可能上百 MB）。
// 之所以要单独限一个预算：邻域之后还有几百 MB 的其余可写区要校验，
// 不能让邻域把总预算吃光。
const nearVerifyBudget = 60 * time.Second

// withProgress 在 fn 跑的过程中定期把已读字节数/校验次数打到日志里。
//
// 之所以需要：全量兜底动辄几分钟，用户在这期间只看到一行"搜索仍在进行"，
// 无法判断是卡死了还是在推进。每隔十几秒报一次数，至少能看出数字在涨。
func withProgress(label string, st *scanStat, total uint64, interval time.Duration, fn func()) {
	if st == nil || interval <= 0 || fn == nil {
		if fn != nil {
			fn()
		}
		return
	}
	start := time.Now()
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				read := st.bytes.Load()
				el := time.Since(start)
				// 报进度时必须带 ETA。用户现场就是这样关的窗口：只看到"已读 3.3 GB"
				// 却不知道还要多久，以为是卡住了。有了"还剩 X 分钟"才会等。
				eta := ""
				if total > read && read > 0 {
					perMB := el.Seconds() / (float64(read) / (1 << 20))
					leftMB := float64(total-read) / (1 << 20)
					eta = fmt.Sprintf("｜剩余 %.0f MB｜预计还需 %s",
						leftMB, (time.Duration(perMB*leftMB) * time.Second).Truncate(time.Second))
				} else if total > 0 {
					eta = "｜剩余 0 MB"
				}
				pct := ""
				if total > 0 {
					pct = fmt.Sprintf("（%.0f%%）", 100*float64(read)/float64(total))
				}
				privateDiagnosticf(
					"[key] %s 进行中：已读 %.1f / %.1f MB%s｜区域 %d 个｜校验 %d 次｜已耗时 %s%s\n",
					label, float64(read)/(1<<20), float64(total)/(1<<20), pct,
					st.regions.Load(), st.cand.Load(), el.Truncate(time.Second), eta)
			}
		}
	}()
	defer close(done)
	fn()
}

// mergeRanges 按地址排序并合并重叠/相邻区间。
//
// 必要性：6 个公钥命中点可能落在同一块大区域里，各自的 ±8 MB 窗口高度重叠，
// 不合并就会把同一段内存扫 6 遍 —— 白白多花 5 倍时间。
func mergeRanges(in []scanRange) []scanRange {
	if len(in) <= 1 {
		return in
	}
	out := append([]scanRange(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].lo < out[j].lo })
	merged := out[:1]
	for _, r := range out[1:] {
		last := &merged[len(merged)-1]
		if r.lo <= last.hi { // 重叠或相邻
			if r.hi > last.hi {
				last.hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

// nearRanges 把"公钥命中点 ± window"换算成待扫区间（按区域边界裁剪 + 合并）。
func nearRanges(hits []pubHit, window uintptr, tag string) []scanRange {
	return nearRangesIn(hits, window, tag, nil)
}

// nearRangesIn 把"公钥命中点 ± window"换算成待扫区间，**与全部可读区域求交**。
//
// ── 为什么必须有 regions 参数（2026-10-17 第五轮的关键修复）──
//
// 旧实现把窗口裁剪到"命中点自己所在的那一块区域"里：
//
//	lo = max(addr-window, hit.Region.Base)
//	hi = min(addr+window+32, hit.Region.Base+hit.Region.Size)
//
// 用户现场的 6 个公钥命中点全都落在 16 KB ~ 216 KB 的**小区域**里，于是
// ±64 KB / ±1 MB / ±8 MB 三级窗口全部被裁成"就这一小块"，三级加起来只扫了
// 0.6 MB —— 等于没放大窗口，直接跳到全内存兜底。
//
// 正确做法是把窗口当成**地址空间里的一个区间**，去和所有可读区域求交：
// 命中点所在的 16 KB 小区块外面紧挨着的大堆区、线程栈、其他分配区都会被覆盖到。
// 这才是"放大窗口"应有的语义。
func nearRangesIn(hits []pubHit, window uintptr, tag string, regions []memscan.Region) []scanRange {
	if len(regions) == 0 {
		// 兼容旧调用：没有区域列表时只能按命中点自身区域裁剪。
		out := make([]scanRange, 0, len(hits))
		for _, h := range hits {
			lo := h.Region.Base
			if h.Addr > window {
				if v := h.Addr - window; v > lo {
					lo = v
				}
			}
			hi := h.Addr + window + 32
			if end := h.Region.Base + h.Region.Size; hi > end {
				hi = end
			}
			if hi <= lo+32 {
				continue
			}
			out = append(out, scanRange{lo: lo, hi: hi, tag: tag})
		}
		return mergeRanges(out)
	}

	// 区域按基址排序，用二分找到第一个可能与窗口相交的区域，再顺序往后走。
	sorted := append([]memscan.Region(nil), regions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Base < sorted[j].Base })

	out := make([]scanRange, 0, len(hits)*2)
	for _, h := range hits {
		var lo uintptr
		if h.Addr > window {
			lo = h.Addr - window
		}
		hi := h.Addr + window + 32

		// 第一个"结束地址 > lo"的区域。
		idx := sort.Search(len(sorted), func(i int) bool {
			return sorted[i].Base+sorted[i].Size > lo
		})
		for i := idx; i < len(sorted); i++ {
			r := sorted[i]
			if r.Base >= hi {
				break
			}
			a, b := r.Base, r.Base+r.Size
			if a < lo {
				a = lo
			}
			if b > hi {
				b = hi
			}
			if b > a+32 {
				out = append(out, scanRange{lo: a, hi: b, tag: tag})
			}
		}
	}
	return mergeRanges(out)
}

// fullRegionRanges 取"公钥命中点所在的整块内存区域"作为扫描区间。
//
// 这是最后一级：前几级都是按固定距离放大窗口，而这一级直接扫完公钥所在的
// 整块区域 —— 只要密钥对和公钥副本在同一个分配区里，就一定能覆盖到。
// 比"全进程 7 GB 盲扫"精准得多，也比继续放大固定窗口更不容易漏。
func fullRegionRanges(hits []pubHit, tag string) []scanRange {
	seen := make(map[uintptr]bool, len(hits))
	out := make([]scanRange, 0, len(hits))
	for _, h := range hits {
		if seen[h.Region.Base] || h.Region.Size < 32 {
			continue
		}
		seen[h.Region.Base] = true
		out = append(out, scanRange{lo: h.Region.Base, hi: h.Region.Base + h.Region.Size, tag: tag})
	}
	return mergeRanges(out)
}

// writableRanges 把可写内存区域转成扫描区间（PRIVATE 优先）。
//
// 为什么只扫可写页：会话密钥是运行时写进去的，只可能落在可写页。PE 映像的
// 代码段和只读常量段占可读内存的相当一部分，跳过它们能省掉大量无意义的
// X25519 校验，而不会漏掉任何可能的私钥位置。
func writableRanges(regions []memscan.Region) []scanRange {
	out := make([]scanRange, 0, len(regions))
	for _, r := range regions {
		if !winapi.WritableProtect(r.Protect) || r.Size < 32 {
			continue
		}
		out = append(out, scanRange{lo: r.Base, hi: r.Base + r.Size, tag: "full-scan"})
	}
	return mergeRanges(out)
}

// totalRangeBytes 统计区间总字节数（诊断报告要用它说清"扫了多大范围"）。
func totalRangeBytes(rs []scanRange) uintptr {
	var n uintptr
	for _, r := range rs {
		n += r.hi - r.lo
	}
	return n
}

// earliest 取两个截止时间里更早的那个（零值表示不限，直接取另一个）。
func earliest(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

func (s *captureSession) failKey(err error) {
	s.em.emit("key_error", map[string]any{"error": err.Error()})
	fmt.Fprintln(os.Stderr, err)
	s.setKeyErr(err.Error())
}

// run 是抓包主循环。
func (s *captureSession) run() {
	defer func() {
		traceStop("run(): close(doneCh)，抓包循环彻底结束")
		close(s.doneCh)
	}()
	defer func() {
		traceStop("run(): 开始关抓包句柄")
		s.h.Close()
		traceStop("run(): 抓包句柄已关")
	}()

	for {
		if s.stopped() {
			traceStop("run(): 进入退出分支")
			_ = s.sender.Close()
			traceStop("run(): uplink 已关")
			data := s.statsData(true)
			data["uplink"] = s.sender.Stats()
			s.em.emit("capture_stats", data)
			s.closeDump()
			if *flagDiagnose != "" {
				if err := s.writeDiagnose(*flagDiagnose); err != nil {
					privateDiagnosticf("写诊断报告失败: %v\n", err)
				} else {
					privateDiagnosticf("诊断报告已写入 %s\n", *flagDiagnose)
				}
			}
			traceStop("run(): 收尾完成，准备 return")
			return
		}

		raw, err := s.h.Next()
		if err != nil {
			if s.stopped() {
				continue
			}
			s.em.emit("capture_error", map[string]any{"error": err.Error()})
			continue
		}
		if raw == nil {
			continue
		}
		atomic.AddUint64(&s.pkts, 1)
		atomic.AddUint64(&s.bytes, uint64(len(raw)))

		udp, err := transport.ParseIPv4UDP(raw)
		if err != nil {
			continue
		}

		dir := direction(s.locals, udp)
		localPort := udp.SrcPort
		if dir == "s2c" {
			localPort = udp.DstPort
		}
		if dir == "unknown" {
			localPort = 0
		}
		s.observeSafeFlow(localPort)

		// 方向与端口记账（诊断用，统计的是**过滤前**的全量）
		if dir == "c2s" {
			atomic.AddUint64(&s.dirC2S, 1)
		} else if dir == "s2c" {
			atomic.AddUint64(&s.dirS2C, 1)
		}
		if dir == "unknown" {
			s.diag.directionUnknown.Add(1)
			atomic.AddUint64(&s.filteredOut, 1)
			continue
		}
		// Fail closed BEFORE handshake parsing, key search, auto-admission or uplink.
		if !s.captureFilterAvailable() {
			atomic.AddUint64(&s.filteredOut, 1)
			continue
		}
		if !s.admitOwnedTargetUDP(udp, dir, s.refreshOwnedTargetForHandshake) {
			s.diag.ownershipRejected.Add(1)
			atomic.AddUint64(&s.filteredOut, 1)
			continue
		}
		s.portMu.Lock()
		s.portCnt[udp.SrcPort]++
		s.portCnt[udp.DstPort]++
		s.portMu.Unlock()

		if s.diagOn {
			s.diagRecord(dir, udp)
		}
		if s.dumpW != nil {
			s.diagDump(dir, udp)
		}

		// 尝试从 UDP 载荷里解析握手公钥。
		//
		// ⚠ 位置很关键：放在**端口过滤之前**，且只对 c2s（客户端发出）方向做。
		// 握手包就是客户端发出去的那一个，方向确定、包量小。如果等过滤之后再做，
		// 一旦白名单没覆盖到握手用的端口（换了进程、换了端口、流量走了别的链路），
		// 就会**静默地**永远收不到握手 —— 表现就是状态栏一直停在"等待握手包"。
		// 宁可多扫几个包（有 tried 去重 + 失败后重试兜底），也不能漏掉唯一的握手。
		if dir == "c2s" {
			// GNS 主链路：先把 ConnectRequest 的完整材料（cert/crypt/nonce/connID）
			// 留下来。首字节不是 0x22/0x23 时这个调用只是一次字节比较。
			gp, gpErr := handshake.ParseGNSHandshake(udp.Data)
			s.observeSafeGNS(len(udp.Data) > 0 && handshake.IsGNSType(udp.Data[0]), gpErr == nil)
			if gpErr == nil &&
				gp.Type == handshake.TypeGNSConnectRequest {
				s.noteGNSPeer(gp)
			}
			s.diag.helloAttempts.Add(1)
			if info, err := handshake.ParseHello(udp.Data); err == nil && len(info.PublicKey) == 32 {
				s.diag.helloParsed.Add(1)
				// Direction and discovered local ownership were verified before parsing.
				// ── 节流闸门：原版 v2.0.5 在 parseHandshake 之后、冻结之前做同一件事 ──
				//
				// 反汇编位置 0x182f48–0x1831b3，三重判定见 throttle.go 顶部。
				// 闸门放在这里而不是放进 searchKey，是因为这里才有**源 IP**；
				// 放到 searchKey 就只剩公钥，而公钥每次都变，节流会失效。
				target := net.IP(udp.SrcIP[:]).String()
				allowed := true
				if v := s.thr.Allow(target); v != throttleAllow && v != throttleNoTarget {
					allowed = false
					n := s.throttledOut.Add(1)
					// 只在头一次和每 50 次打一行，避免刷屏。
					if n == 1 || n%50 == 0 {
						privateDiagnosticf(
							"[key] 握手被节流丢弃（%s）：%s｜累计 %d 次｜%s\n",
							target, v, n, s.thr.Summary())
					}
				}
				s.curTarget.Store(target)
				if s.diagOn {
					s.diagMu.Lock()
					s.diagHit++
					// 记下提取到的公钥。报告里没有它，就没法核对
					// "内存里搜的"和"握手包里提取的"是不是同一个东西。
					if s.diagPubHex == "" {
						s.diagPubHex = fmt.Sprintf("%x", info.PublicKey)
					}
					s.diagMu.Unlock()
				}
				// 先投主公钥，再投**包里其它 32 字节字段**作为兜底候选。
				//
				// 为什么需要兜底：字段路径是从 v2.0.5 逆向来的，一旦版本变动或
				// 当初认错一层，主公钥就不是客户端公钥，在内存里怎么搜都搜不到
				// （用户现场正是这种情况）。此时把包里所有 32 字节字段都试一遍，
				// 每个只要一次全内存 memmem（约 1.6 秒/7 GB），比让用户再抓一次
				// 包快得多。startKeySearch 有 tried 去重，成功后会立刻停止，
				// 所以多投没有副作用。
				// 记下「这一次认出公钥」的时刻。用 Store（每次握手都覆盖）而不是
				// 只在第一次写：一次运行可能抓到多次握手（换图/重连/换服务器），
				// 卡住第一次会让后面每次的延迟都算成几分钟，指标直接失效。
				// searchKey 进来时用 Swap(0) 取走，所以下一次握手会重新计时。
				// 节流命中时只跳过「投递候选」，不跳过整包 ——
				// 这个包本身还是要交给解码出口（否则雷达页会少一帧）。
				if allowed {
					s.pubSeenAt.Store(time.Now().UnixNano())
					// 记住这次握手的两端，供 ServerHello 配对。
					s.setHSPeers(
						fmt.Sprintf("%s:%d", net.IP(udp.SrcIP[:]), udp.SrcPort),
						fmt.Sprintf("%s:%d", net.IP(udp.DstIP[:]), udp.DstPort))
					// 客户端临时公钥也留一份：它一定被存在客户端的握手状态
					// 结构体里，而会话密钥就在同一个结构体附近，是最可靠的锚点。
					// 换图/重连会带来新公钥，这里顺手把旧料清掉并推进「代」。
					s.resetSessionKeyMaterial(info.PublicKey)
					select {
					case s.targetPubCh <- info.PublicKey:
						s.em.emit("handshake_found", map[string]any{
							"src_port": udp.SrcPort, "dst_port": udp.DstPort,
							"len": len(udp.Data), "off": info.ProtoOff,
							"pub": fmt.Sprintf("%x", info.PublicKey),
						})
					default:
					}
					for _, c := range handshake.ByteFieldCandidates(udp.Data, 32) {
						if string(c) == string(info.PublicKey) {
							continue
						}
						select {
						case s.targetPubCh <- c:
						default: // 队列满就跳过，绝不在抓包线程上阻塞
						}
					}
				}
			}
		}

		// 服务器临时公钥：来自 ServerHello（首字节 0x23，和 ClientHello 的 0x22 是
		// 同一套 netchan 消息类型，不是 protobuf 字段）。
		//
		// 🔴 这一段是 2026-10-19 补的，缺它的后果是「密钥挖到了但一条消息都解不出」：
		// 共享密钥 = ECDH(客户端私钥, **服务器**公钥)。以前只解析 c2s 的 ClientHello，
		// 拿到的其实是客户端自己的公钥，于是算出来的是 ECDH(私钥, 自己公钥) ——
		// 数学上必然错，而且日志里看起来一切正常（key_ready、包也在流）。
		//
		// 五元组必须卡死：握手是 c2s，回包必须来自同一个对端、发回同一个本机端口。
		// 换服务器/换图时否则会把别家的公钥配到这次的私钥上，错得更隐蔽。
		if dir == "s2c" {
			// GNS 主链路：ConnectOK（0x23）。五元组必须和本次 ConnectRequest 对上，
			// 否则换服务器/换图时会把别家的服务器材料配到这次的客户端材料上。
			gp, gpErr := handshake.ParseGNSHandshake(udp.Data)
			s.observeSafeGNS(len(udp.Data) > 0 && handshake.IsGNSType(udp.Data[0]), gpErr == nil)
			if gpErr == nil &&
				gp.Type == handshake.TypeGNSConnectOK {
				cs, ss := s.hsPeers()
				src := fmt.Sprintf("%s:%d", net.IP(udp.SrcIP[:]), udp.SrcPort)
				dst := fmt.Sprintf("%s:%d", net.IP(udp.DstIP[:]), udp.DstPort)
				if cs != "" && ss != "" && src == ss && dst == cs {
					s.noteGNSPeer(gp)
				}
			}
			s.diag.helloAttempts.Add(1)
			if info, err := handshake.ParseHello(udp.Data); err == nil && len(info.PublicKey) == 32 {
				s.diag.helloParsed.Add(1)
				cs, ss := s.hsPeers()
				src := fmt.Sprintf("%s:%d", net.IP(udp.SrcIP[:]), udp.SrcPort)
				dst := fmt.Sprintf("%s:%d", net.IP(udp.DstIP[:]), udp.DstPort)
				if cs != "" && ss != "" && src == ss && dst == cs {
					s.sender.SetServerPub(info.PublicKey)
					s.skMu.Lock()
					s.skPub = append([]byte(nil), info.PublicKey...)
					s.skMu.Unlock()
					privateDiagnosticf(
						"[key] 服务器临时公钥：%x（ServerHello｜%s → %s｜off=%d）\n",
						info.PublicKey, ss, cs, info.ProtoOff)
					s.em.emit("server_hello", map[string]any{
						"pub": fmt.Sprintf("%x", info.PublicKey),
						"src": ss, "dst": cs,
					})
					// 有了私钥 + 服务器公钥之后，就可以去内存里直接找会话密钥了。
					s.startSessionKeySearch()
				}
			}
		}

		// Recheck ownership after parsing: a concurrent refresh may invalidate it.
		if !s.captureFilterAvailable() || !s.cfilter.MatchOwnedLocal(localPort) {
			s.diag.ownershipRejected.Add(1)
			atomic.AddUint64(&s.filteredOut, 1)
			continue
		}

		// 留几帧真实密文：AES-GCM 的认证标签是"这把密钥对不对"的完美判据，
		// 后面去内存里找会话密钥时靠它验证。只留本连接的 0x82 加密帧。
		if dir == "s2c" && len(udp.Data) > 40 && udp.Data[0] == 0x82 {
			cs, ss := s.hsPeers()
			if cs != "" && ss == fmt.Sprintf("%s:%d", net.IP(udp.SrcIP[:]), udp.SrcPort) {
				s.keepFrame(udp.Data)
			}
		}

		// 本连接的 GNS 数据帧（两个方向分开留），给「内存读 IV + 反推密钥」当判据。
		// 只在真的收下了一帧时才去检查是否够料启动 —— 每包都加锁不值当。
		if s.keepGNSFrame(dir, udp.Data) {
			s.maybeRecoverGNS()
		}

		// 投递：原始包交给解码出口（本机 → 进程内解码器；远端 → 上行）
		s.sender.Push(uplink.Packet{
			TsMs: time.Now().UnixMilli(),
			Dir:  dir,
			Src:  fmt.Sprintf("%s:%d", net.IP(udp.SrcIP[:]), udp.SrcPort),
			Dst:  fmt.Sprintf("%s:%d", net.IP(udp.DstIP[:]), udp.DstPort),
			Data: base64.StdEncoding.EncodeToString(udp.Data),
		})

		// 密钥就绪后，把私钥也上行（服务器靠它算共享密钥）
		if s.keyReady.Load() && s.keyAttached.CompareAndSwap(false, true) {
			s.keyMu.Lock()
			privCopy := append([]byte(nil), s.foundKey...)
			tag, addr := s.foundTag, s.foundAddr
			s.keyMu.Unlock()
			s.em.emit("key_attached", map[string]any{
				"tag": tag, "addr": fmt.Sprintf("%#x", addr),
			})
			s.sender.SetKey(privCopy)
			_ = s.sender.Flush(false)
		}
	}
}

// runCapture 是命令行版的入口：起抓包 → 等信号 / -duration → 退出。
func runCapture() {
	em := &emitter{ipc: *flagIPC}

	// 最常见的失败原因就是没提权。提前说清楚，别让用户对着一个
	// 语焉不详的错误信息猜。
	if !winapi.IsAdmin() {
		fmt.Fprintln(os.Stderr, "──────────────────────────────────────────────")
		fmt.Fprintln(os.Stderr, "⚠  当前不是管理员权限")
		fmt.Fprintln(os.Stderr, "   读取游戏进程内存、开原始套接字（SIO_RCVALL）都需要管理员。")
		fmt.Fprintln(os.Stderr, "   请关闭本窗口，右键「以管理员身份运行」后重试；")
		fmt.Fprintln(os.Stderr, "   或者直接双击 CS2雷达.exe —— 它会自己弹 UAC 提权。")
		fmt.Fprintln(os.Stderr, "──────────────────────────────────────────────")
		if !*flagNoKeys {
			os.Exit(1)
		}
	}

	s, err := startCapture(em)
	if err != nil {
		em.emit("capture_error", map[string]any{"error": err.Error()})
		privateDiagnosticf("采集未能启动: %v\n", err)
		fmt.Fprintln(os.Stderr, "排查建议：")
		fmt.Fprintln(os.Stderr, "  1) 确认已「以管理员身份运行」（SIO_RCVALL 必须要）")
		fmt.Fprintln(os.Stderr, "  2) 跑 -selfcheck 做一次真实抓包自检")
		fmt.Fprintln(os.Stderr, "  3) 跑 -list-devices 看本机有哪些可抓包的网卡地址")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "本机受保护视图：", s.ViewURL())
	if *flagOpenBrowser {
		openBrowser(s.ViewURL())
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; s.Stop() }()
	if *flagDuration > 0 {
		go func() { time.Sleep(*flagDuration); s.stopAs(6, nil) }()
	}
	s.Wait()
}

// direction 判断包方向：源 IP 是本机 → c2s，否则 s2c。
func direction(locals map[string]bool, u *transport.UDPPacket) string {
	srcLocal, dstLocal := locals[net.IP(u.SrcIP[:]).String()], locals[net.IP(u.DstIP[:]).String()]
	if srcLocal == dstLocal {
		return "unknown"
	}
	if srcLocal {
		return "c2s"
	}
	return "s2c"
}

func localIPv4Set() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v4 := ipn.IP.To4(); v4 != nil {
				out[v4.String()] = true
			}
		}
	}
	return out
}
