# 原版无 Npcap 时的取密钥机制 + 端口过滤对齐

日期：2026-10-16
对象：`CS2radar-v2.0.5.exe` / `capture.exe`（原版）
起因：用户提问「原版没有 npcap 是如何获取密钥的？参考他来做」

---

## 0 一句话结论

**原版从来不依赖 Npcap 取密钥。** 无 Npcap 时它走的是：

```
raw socket（AF_INET / SOCK_RAW / IPPROTO_IP）
  → WSAIoctl(fd, SIO_RCVALL = 0x98000001)   # 把网卡切成混杂模式，双向收包
  → WSARecvFrom(...)                        # 逐包取回
  → GetExtendedUdpTable(...)                # 按「目标进程占用的本机 UDP 端口」过滤
```

而**取密钥的关键不是 Npcap，是「双向抓包」**：靶子公钥 = 客户端自己的 X25519 公钥，
由客户端**发出去**（发送方向）。只收「发往本机」方向永远拿不到握手。
我此前的 raw 实现只收接收方向，这才是「没有效果」的根因（已修，见
`raw方向问题与SIO_RCVALL修复.md`）。

所以「集成 Npcap 到一个 exe」既非必要、也不可行（见第 4 节）。

---

## 1 静态证据：原版 capture.exe 根本没有 Npcap 依赖

| 检查项 | 结果 |
| --- | --- |
| 启动器 `CS2radar-v2.0.5.exe` 字符串 | 无任何 `npcap` / `wpcap` 字样 |
| `capture.exe` 中的 Npcap 字样 | 只有**使用串**：`C:\Windows\System32\Npcap\wpcap.dll`、`Npcap capture library is unavailable` |
| 全归档 `*.dll` / `*.sys` 安装产物 | **不存在** |
| `capture.exe` 导入表 | **只有 `kernel32.dll`**（含 `LoadLibraryExW` / `GetProcAddress`） |

导入表只有 kernel32 ⇒ `ws2_32.dll`、`iphlpapi.dll` 全部是**运行期动态加载**，
加载失败也只是降级，不是致命错误。这正是「无 Npcap 也能跑」的结构性原因。

---

## 2 静态证据：无 Npcap 时的实际路径就是 SIO_RCVALL

在 `capture.exe` 中定位到的相关导入/字符串：

```
SIO_RCVALL     0x98000001
WSAIoctl
socket / bind
WSARecvFrom
GetExtendedUdpTable      (iphlpapi.dll)
GetAdaptersAddresses     (iphlpapi.dll)
```

反汇编命中点：

```
0x177128:  bb 01 00 00 98        mov ebx, 0x98000001      ; SIO_RCVALL
           ...                   call WSAIoctl
```

即：**原版在没有 Npcap 时，就是把 raw socket 用 `SIO_RCVALL` 切成混杂模式双向抓包。**

---

## 3 与本次重构实现的对照

| 能力 | 原版 | 重构（修复前） | 重构（现在） |
| --- | --- | --- | --- |
| 无 Npcap 抓包 | raw socket | raw socket | raw socket |
| 抓发送方向 | ✅ `SIO_RCVALL` | ❌ `net.ListenPacket("ip4:udp")` 只收接收方向 | ✅ `SIO_RCVALL`（`internal/pcapdev`） |
| 收包 API | `WSARecvFrom` | `syscall.Recvfrom`（Windows 上**空实现**，返回 `not supported by windows`） | `ws2_32!WSARecvFrom` + 手写 `WSABUF` |
| 端口过滤 | `GetExtendedUdpTable` | 无 | ✅ `internal/capturefilter` |
| 有 Npcap 时 | 走 Npcap（可选加速） | 走 Npcap | 走 Npcap（不变） |

对齐后，**无 Npcap 的路径与原版在机制上完全一致**。

---

## 4 关于「集成 Npcap 成一个 exe」

结论：**原版没做，也不该做。**

- 原版**并未集成** Npcap：无安装逻辑、无驱动释放、无服务注册，只有一行「用不到就降级」的使用串。
- Npcap 免费版许可原文：`may be used (but not externally redistributed)`
  —— **不允许再分发**。把它塞进分发包属于再分发，不合规。
- **静默安装是 OEM 版功能**（需另购 OEM 授权）；免费版安装必须走交互式安装器（会弹窗、可能要重启）。
- 因此「一个 exe 里静默装好 Npcap」在免费版下做不出来；就算做出来也解决不了问题
  —— 因为**取密钥不需要 Npcap**。

> 顺带说明：本次已把 `npcap-1.89.exe`（1,325,224 字节，
> sha256 `8aed85e900d783d1308506e919587d3e540451947af8a82f2d04f819e44305cc`）
> 放在 `rebuild/cs2radar/tools/npcap/`，仅作为**可选**安装包来源，**不进分发包**。

如果确实想要 Npcap 的额外能力（指定网卡、高流量更稳），给最终用户的指引仍然是：
自行从 https://npcap.com/#download 下载安装，勾选 WinPcap 兼容模式。

---

## 5 本次新增：`internal/capturefilter`

### 5.1 为什么需要

`SIO_RCVALL` 打开后收到的是**该网卡上全部 UDP**（含其它程序）。
不过滤会有两个后果：

1. 浪费带宽与缓冲；
2. **无关包可能在 `handshake.ParseHandshake` 上误命中**（它扫每个包前 64 字节找 `0x22` 头）。
   一旦误命中，靶子公钥就是错的 —— 密钥搜索会带着错误靶子一路跑到超时。

### 5.2 实现

`rebuild/cs2radar/internal/capturefilter/filter.go`：

```go
func Discover(pid uint32) ([]uint16, error)          // iphlpapi!GetExtendedUdpTable
func New() *Filter
func (f *Filter) Set(pid uint32, ports []uint16)
func (f *Filter) Clear()
func (f *Filter) Active() bool
func (f *Filter) PID() uint32
func (f *Filter) Match(srcPort, dstPort uint16) bool  // 源或目的命中即保留
func (f *Filter) Ports() []uint16
```

- `UDP_TABLE_OWNER_PID`（=1）+ `MIB_UDPROW_OWNER_PID`（12 字节）；
- 两次调用 `GetExtendedUdpTable`：先拿 size，再拿数据；
- 端口在低 16 位、网络字节序，用 `ntohs` 转换；
- **保守兜底：端口集合为空时 `Match` 恒返回 `true`** —— 宁可多收，不可漏收。
  这是刻意设计的：过滤条件写错导致「静默抓不到包」是我们反复踩过的坑。

### 5.3 接入采集端（`cmd/collector/main.go`）

- `runCapture` 起一个 3 秒定时器，反复 `resolvePID()` + `Discover(pid)`；
- 端口集合变化时发一次 `capture_filter` 事件；
- 收包主循环里，在**握手解析之前**做 `cfilter.Match(udp.SrcPort, udp.DstPort)`，
  未命中则计入 `filteredOut` 并 `continue`；
- 新增逃生口 `-no-filter`（配置项 `no_filter`）。

新增事件/字段：

```
[event] capture_filter map[pid:24124 ports:[52972 52973]]
[event] capture_stats  map[... filter:map[dropped:1136 pid:24124 ports:[52972 52973]] ...]
[event] capture_stats  map[... filtered:1774 final:true ...]
```

`capture_stats` 里的 `top_ports` **仍然是过滤前的全量直方图** —— 它的用途是
「判断到底有没有抓到游戏流量」，不能被过滤污染，这一点是刻意的。

### 5.4 实测（真实进程 + 真实 UDP 流量）

完整证据见 `logs/capturefilter_verify_2026-10-16.txt`。摘要（最终 strip 版 exe）：

| 检查 | 结果 |
| --- | --- |
| `capture_filter` 报出的端口 | `[51218 51219]`，与探针实际端口**完全一致** |
| 过滤丢弃 | `dropped:1289 / packets:1339`（5s 时点） |
| 目标流量是否被误杀 | 否 —— `uplink packets:50` 且 `top_ports` 中 51218/51219 计数在涨 |
| `-no-filter` | 无 `capture_filter` 事件，`filtered:0`，回到收全部 UDP |
| 单元测试 | 3/3 PASS（含 `Discover` 真机发现本进程 UDP 端口 55528） |
| 回放回归 | 3 目标坐标逐位一致（`-794.2207/913.3321/72.0000` 等） |

> 该验证做了两轮：一轮用未 strip 的构建，一轮用最终 `-trimpath -ldflags="-s -w"` 构建，
> 结论一致（端口发现、丢弃计数、目标流量未被误杀）。

---

## 6 产物

| 文件 | sha256 |
| --- | --- |
| `dist/capture.exe`（6,895,616 字节） | `ab4bd8a6e4fc1335de8264c0caccd2f32c3bc14ab2722560bf5cdf2a8786cade` |
| `dist/cs2radar-client.zip`（2,881,292 字节） | `5eb9cff3278aae1e2562e3d0a5ef095844344f3995d800cd99d41e37e735c9e2` |

构建参数必须是 `-trimpath -ldflags="-s -w"`（见 `agents/E-build-deploy.md`）。
漏掉会得到 ~10 MB 的未 strip 版本 —— 体积翻倍，且**符号名会暴露在二进制里**，是检测足迹上的倒退。

分发包 7 个文件；编码校验 PASS（`.bat` GBK 无 BOM / `.txt` UTF-8 BOM / `.json` UTF-8 无 BOM）；
干净临时目录解压后回放 exit=0、60/60 帧可解、180 条消息。

---

## 7 仍未解决 / 边界

1. **端口过滤依赖目标进程确实持有游戏 UDP socket。** 若某版本 CS2 把游戏流量交给
   别的进程（如 Steam 辅助进程）持有，过滤会误杀 → 此时用 `-no-filter` 兜底，
   或把 `-proc` 指到实际持有 socket 的进程。
2. `Discover` 只覆盖 IPv4 UDP（`AF_INET`）；IPv6 未处理。CS2 对局走 IPv4，暂不影响。
3. 过滤是**每 3 秒刷新**，进程刚起、端口刚建时可能有最多 3 秒的窗口期收全量 UDP
   —— 这不影响正确性（多收不丢），只是短暂多一点无关包。
