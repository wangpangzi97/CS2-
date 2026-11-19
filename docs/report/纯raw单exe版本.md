# 纯 raw socket 单 exe 版本

日期：2026-10-16
起因：用户要求「去除 npcap 版本，只保存 raw socket … 此版本，然后集成一个 exe 打开可以直接使用，不再使用 cmd 命令运行」

---

## 0 结果速览

| 项 | 内容 |
| --- | --- |
| 抓包 | **只有一条路**：`socket(AF_INET,SOCK_RAW,IPPROTO_IP)` → `bind(网卡)` → `WSAIoctl(SIO_RCVALL=0x98000001)` → `WSARecvFrom` → `GetExtendedUdpTable` 端口过滤 |
| 第三方依赖 | **零**（没有 Npcap / wpcap.dll，没有 GUI 库，没有驱动） |
| 分发形态 | 解压 → **双击 `CS2雷达.exe`** → UAC 点「是」→ 出窗口 + 自动开雷达页。**不用 cmd，不用 .bat** |
| 分发包 | 4 个文件：`CS2雷达.exe` / `capture.exe` / `capture.json` / `使用说明.txt` |
| 哈希 | `CS2雷达.exe` `734d6f0e…354771`；`capture.exe` `ca8f103a…4eca84`；zip `eb50df9f…2bad2` |

---

## 1 删除 Npcap：`internal/pcapdev` 重写

### 删掉的

| 符号 / 参数 | 说明 |
| --- | --- |
| `wpcap` LazyDLL 及全部 `pcap_*` 调用 | `pcap_findalldevs` / `pcap_open_live` / `pcap_next_ex` / `pcap_setbuff` / `pcap_setmintocopy` / `pcap_compile` / `pcap_setfilter` / `pcap_close` |
| `Backend` / `BackendNpcap` / `ParseBackend` | `-backend` 参数一并删除 |
| `NpcapAvailable()` / `NpcapPath` | 不再探测 wpcap.dll |
| `ListDevices()` | 改为 `Devices()`，列本机非回环 IPv4（每地址开一个 RCVALL socket） |
| `SetBuffer` / `SetMinToCopy` / `SetFilter` / `SetLocalUDPFilter` | 都是 wpcap-only 旋钮，全删 |
| `-dev` 参数 | SIO_RCVALL 是整机抓包，没有「选网卡」这回事 |
| **`ip4:udp` 降级路** | 只收「发往本机」方向，拿不到客户端握手 → 留着只会让人误以为在正常工作 |

### 留下的（唯一路径）

```go
socket(AF_INET, SOCK_RAW, IPPROTO_IP)
  → bind(fd, 本机非回环 IPv4)            每个地址一个 socket
  → WSAIoctl(fd, SIO_RCVALL=0x98000001, ON)
  → WSARecvFrom(fd, ...)                 逐包取回（200ms 收超时，便于优雅退出）
  → 只留 IPv4 + UDP（buf[0]>>4==4 && buf[9]==17）→ channel
  → Handle.Next()
```

对外 API 收敛成：

```go
func Open() (*Handle, error)
func RawAvailable() error
func Devices() []Device
const ModeName = "raw-SIO_RCVALL(双向)"
func (h *Handle) Next() ([]byte, error)
func (h *Handle) Close()
func (h *Handle) RawCaptureMode() string
func (h *Handle) InterfaceCount() int
```

`internal/capturefilter`（`GetExtendedUdpTable`）保持不变，仍是端口过滤的唯一实现。

---

## 2 单 exe 窗口版：`CS2雷达.exe`

### 2.1 一份代码两个 exe

```bash
# 控制台版（排障用，保留 -selfcheck / -list-devices / -replay）
go build -trimpath -ldflags="-s -w" -o dist/capture.exe ./cmd/collector

# 窗口版（双击即用）
go build -trimpath -ldflags="-s -w -H=windowsgui -X main.defaultGUIMode=true" \
  -o "dist/CS2雷达.exe" ./cmd/collector
```

`-X main.defaultGUIMode=true` 让双击（不带参数）直接进窗口模式；
`-H=windowsgui` 把 PE 子系统设成 2 —— **不弹控制台窗口**。

实测 PE 头：

```
capture.exe      PE32+=True  subsystem=3  WINDOWS_CUI（控制台）
CS2雷达.exe      PE32+=True  subsystem=2  WINDOWS_GUI（无控制台窗口）
```

### 2.2 提权

`ShellExecuteExW(lpVerb="runas", lpFile=自身, lpParameters=原参数+" -elevated")`。

- 已经是管理员 → 直接跑。
- 不是管理员 → 拉起提权实例，本进程退出。
- 带了 `-elevated` 却仍不是管理员 → 说明用户拒了 UAC，弹错误框退出
  （`-elevated` 这个标记就是用来**防止无限弹 UAC** 的）。
- 错误码 1223（`ERROR_CANCELLED`）单独处理，给一句人话提示。

### 2.3 窗口

全部用 Win32 API 直接实现，没有引入任何 GUI 库：

```
RegisterClassExW / CreateWindowExW / GetMessageW / DispatchMessageW
STATIC（状态行） + EDIT（日志框，只读+多行+垂直滚动） + 2 个 BUTTON
SetTimer(400ms) 刷新状态行并追加日志
```

- 字体：`Microsoft YaHei UI`，按 `GetDpiForSystem` 缩放（`CreateFontW`，
  `-MulDiv(9, dpi, 72)`）；拿不到就退回 `DEFAULT_GUI_FONT`。
- DPI 感知：`SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)`，失败退回
  `SetProcessDPIAware()`。
- 控件 ID 通过 `CreateWindowExW` 的 `hMenu` 参数传（子窗口的 hMenu 就是 ID），
  `WM_COMMAND` 的 `LOWORD(wParam)` 带回来。
- `WM_SIZE` 重排布局；尺寸过小会 clamp，不会算出负宽高。

### 2.4 日志怎么进窗口的

**没有改一行抓包代码**：把 `os.Stderr` 换成 `os.Pipe()`，
后台 goroutine 逐行读出来追加到 EDIT 框。
采集链路里原有的所有 `fmt.Fprintf(os.Stderr, ...)` 自动就显示了。

### 2.5 踩到的真 bug

第一版**窗口关不掉**：`WM_CLOSE` 分支只调了 `stopAndQuit()` 却没 `DestroyWindow`，
点「停止并退出」和 `-duration` 到点自动退出都无效，进程一直挂着。

修法：
- `WM_CLOSE` → `KillTimer` + `sess.Stop()` + `DestroyWindow`；
- 真正的收尾（`sess.Wait()`）交给消息循环退出后的 `run()`；
- `stopAndQuit()` 退化成「发一条 WM_CLOSE」。

---

## 3 采集端重构：`captureSession`

原来 `runCapture(backend)` 是个 300 行的大函数，状态全在局部变量里，
GUI 既读不到状态也停不了它。这次抽成会话对象：

```go
type captureSession struct { ... }
func startCapture(em *emitter) (*captureSession, error)  // 打开句柄 + 起后台 goroutine
func (s *captureSession) Stop()                          // 幂等
func (s *captureSession) Wait()
func (s *captureSession) Status() captureStatus          // GUI 定时读
```

- 命令行版：`startCapture` → 等 Ctrl+C / `-duration` → `Stop` + `Wait`。
- GUI 版：跑在 goroutine 里，400ms 定时器读 `Status()`，按钮调 `Stop()`。
- `-duration` 现在**两个版本都认**（GUI 也能「跑 2 小时自动停」）。
- `startLocalRadar()` / `newSender()` 改成返回 `error` —— 原来监听失败直接
  `os.Exit(1)`，窗口版没有控制台，会静默消失。

新增/变更的事件字段：

```
[event] capture_ready  map[filter:true ifaces:3 mode:raw-SIO_RCVALL(双向) proc:cs2.exe]
[event] capture_filter map[pid:24068 ports:[51981 51982]]
[event] capture_stats  map[... filter:map[dropped:1006 ...] ...]
```

（`backend` / `dev` 字段已删除。）

---

## 4 新增回归测试

`cmd/collector/gui_test.go::TestWin32ProcsResolve`

逐个 `Find()` 23 个 Win32 导出（user32 / gdi32 / shell32 / kernel32），
把「导出名写错 → 调用时才 panic」提前到单元测试。

> 为什么专门加这条：本项目已经因为 `ws2_32` 的 `WSARecvFrom`（大写 F）
> 踩过一次 —— 写成 `WSARecvfrom` 直接 "Failed to find procedure"。
> `syscall.NewLazyDLL` 是**调用时**才解析导出名的。

`internal/pcapdev/raw_test.go` 同步更新：`Open()` 无参、去掉
`TestListDevicesNeverPanics`、`TestDevicesNeverPanics` 顶替。

### 4.1 提权分支回归测试（补测）

提权逻辑原来**一条测试都没有**，原因是 `IsUserAnAdmin` 的结果由当前进程令牌决定，
测试进程没法把自己变成非管理员。为此在 `gui.go` 里加了一个间接层：

```go
// 生产路径上恒等于 winapiIsAdmin；存在的唯一理由是让测试能替换它。
var isAdminFn = winapiIsAdmin
```

`ensureElevated()` 改调 `isAdminFn()`，于是三条分支里两条可以离线覆盖：

| 测试 | 覆盖分支 | 断言 |
| --- | --- | --- |
| `TestEnsureElevatedAlreadyAdmin` | 已是管理员 | 返回 `(false, nil)` —— 不得重入（重入 = 死循环） |
| `TestEnsureElevatedStopsLoopWhenStillNotAdmin` | 带 `-elevated` 重入却仍非管理员 | **必须报错**，且报错信息含「管理员权限」 |
| `TestBuildArgLine` | 重入命令行重建 | 保留原参数、追加 `-elevated`、带空格参数加引号 |

> 第二条是最危险的一条：用户点了 UAC「否」，进程却再 `ShellExecuteExW("runas")`
> 一次 —— 那就是无限弹 UAC 的死循环。测试刻意只走 `flagElevated=true` 分支，
> `flagElevated=false` 的那条会真的弹 UAC 对话框，不能在单元测试里碰。
>
> 仍未覆盖：`ShellExecuteExW` 真正弹出 UAC 并拿到管理员令牌这一步（需要交互点击）。

---

## 5 验证

完整证据：`logs/raw_single_exe_verify_2026-10-16.txt`。摘要：

| 检查 | 结果 |
| --- | --- |
| `capture.exe -selfcheck` | ✓ 可用，模式 `raw-SIO_RCVALL(双向)`，网卡 3 个 |
| `capture.exe -list-devices` | 列出 3 个本机 IPv4（以太网 + 2 个 VMware） |
| 端口过滤（真实进程 + 真实 UDP） | `capture_filter ports:[51981 51982]` 与探针端口**完全一致**；`dropped 1210/1270`；`uplink packets 60`（目标流量未被误杀） |
| 窗口版实跑 | 窗口标题「CS2 雷达」建出（`Get-Process` 可见 `MainWindowTitle`）；雷达页 `HTTP 200` + 合法 JSON；`-duration` 到点后自动退出、端口释放 |
| PE 子系统 | 窗口版 = 2（GUI），控制台版 = 3（CUI） |
| Win32 导出解析 | 23/23 PASS |
| 提权分支 | `TestEnsureElevatedAlreadyAdmin` / `TestEnsureElevatedStopsLoopWhenStillNotAdmin` / `TestBuildArgLine` 全 PASS |
| 分发包编码 | PASS（`.txt` UTF-8 BOM + CRLF / `.json` UTF-8 无 BOM） |
| 干净目录解压 | `cli -replay` exit 0（60/60 帧、180 条消息、3 个目标）；`gui -duration 8s -auto-exit` exit 0 |
| `gofmt -l` / `go vet` / `go test ./...` | 全绿 |

---

## 6 仍未验证

1. **UAC 弹窗本身没在非管理员会话下实测** —— 当前 shell 本身就是管理员，
   `ensureElevated()` 直接走了「已是管理员」分支。现已用 `isAdminFn` 间接层把
   **「已提权标记却仍非管理员必须报错」**这条防死循环分支纳入单元测试；
   剩下没覆盖的只有「`ShellExecuteExW("runas")` 真的弹出 UAC、点『是』后拿到
   管理员令牌」这一步 —— 它需要交互点击，无法自动化。
   实测方法：用普通用户登录后双击 `CS2雷达.exe`，应当弹 UAC。
2. 真实对局下的全链路（本机无 CS2）。
3. 窗口在高 DPI 下的观感（DPI 感知 + 雅黑字体已就位，未肉眼确认）。
4. 窗口版没有图标（PE 无 `RT_ICON` 资源）—— 加图标需要生成 `.syso`
   资源对象，会引入构建工具，本轮没做。

