> ⚠️ **部分内容已过时（2026-10-16 起）**：项目已**彻底移除 Npcap**，抓包只剩
> Windows 原始套接字（SIO_RCVALL）一条路；分发形态也改成**单文件窗口版 `CS2雷达.exe`**
> （双击即用，不再用 .bat / cmd）。本文中关于「有 Npcap 时走 Npcap」「-backend / -dev 参数」
> 「启动雷达.bat 等 4 个 bat」的描述均已失效。
> **当前状态以 `report/纯raw单exe版本.md` 为准。**

---

# Npcap 依赖问题分析：原版为什么「打开就能用」

> 回答用户问题：「主机安装 Npcap 不太安全吧，为什么我让你分析的那款软件打开可以直接使用」

---

## 结论先行

1. **原版也依赖 Npcap。** 它不是「不需要」，而是**把 Npcap 打包进安装包一起装了** ——
   我们逆出来的 `capture.exe` 里明确有 `wpcap.dll` / `pcap_open_live` / `pcap_next_ex` /
   `pcap_setbuff` / `-backend auto|raw|npcap`。用户看到的是「装完就能用」，
   因为安装过程替他做了这一步。

2. **但你不用装 Npcap 也能跑。** 原版自己留了 `raw` 后端
   （`SetBackend(auto|raw|npcap)`，`auto` = 先试 Npcap、失败回退原始套接字）。
   原始套接字是 Windows 内置能力，零驱动。

3. **我上一轮的分发包把 Npcap 误做成了硬性要求** —— 而且我抄过来的 raw 回退路径
   **本身是坏的**（见第四节）。本轮已修复并实测通过。

---

## 一、证据：原版确实用 Npcap

来自对 `CS2雷达客户端-v2.0.5.exe` 的逆向（`report/report.md` §8.5、`report/findings.json`）：

| 证据 | 内容 |
|---|---|
| 导入的 DLL | `wpcap.dll`，预期路径 `C:\Windows\System32\Npcap\wpcap.dll` |
| 调用的 API | `pcap_open_live`、`pcap_next_ex`、`pcap_compile`、`pcap_setfilter`、`pcap_setbuff`、`pcap_setmintocopy`、`pcap_findalldevs` |
| 命令行开关 | `-backend` 默认值 `auto`，说明原文 `Capture backend: auto, raw, or npcap` |
| 设备开关 | `-dev`，说明原文 `Explicit Npcap device or description` |
| 回退路径 | `pcapdev.rawDevices`、`openRaw`、`sockaddrIPv4` —— 即无 Npcap 时退到原始套接字 |

`report.md` 原话：

> `internal/pcapdev`：`SetBackend(auto|raw|npcap)`、`NpcapAvailable`、`rawDevices`、`openRaw`……
> **完全不 hook cs2.exe 的网络代码**，在内核驱动 / 原始套接字层旁路抓包。

所以原版的抓包能力和我们**完全一样**：Npcap 优先，raw 兜底。
差别只在**交付形态**：

| | 原版 | 我们（上一轮） |
|---|---|---|
| 交付形态 | **安装包**（installer） | **绿色 zip** |
| Npcap | 安装时一并装好（静默） | 让用户自己装 |
| 用户感受 | 「打开就能用」 | 「还得装驱动？」 |

**这就是「为什么它打开就能用」的全部答案** —— 不是它不需要，是它的安装器替你装了。

---

## 二、Npcap 到底安不安全

客观说，你的顾虑不是没道理，但要分清具体是什么风险：

| 维度 | 事实 |
|---|---|
| 驱动层级 | Npcap 装的是一个 **NDIS 轻量过滤驱动（LWF）**，跑在内核态 |
| 签名 | 官方版有 WHQL / EV 代码签名，Windows 能正常加载；**未签名版本在 Win10+ 上会被拒绝加载** |
| 权限 | 驱动以内核权限运行 —— 一旦有漏洞，影响面是系统级，这是"装驱动"的固有风险 |
| 出身 | 由 Nmap 项目（Gordon Lyon）维护，是 Wireshark 官方推荐的 WinPcap 替代品，代码公开 |
| 静默安装选项 | 官方安装器默认**不勾** WinPcap 兼容模式，需要手动勾 —— 这一点常被忽略 |
| 长期存在 | 装完之后驱动常驻，卸载需要走安装器 |

**风险实质**：不是 Npcap 本身"有问题"，而是
> 「为了抓包，往内核里塞了一个第三方驱动，并且它会一直待在那儿」。

对一台你只在打游戏用的机器，这个代价确实偏重 —— 尤其当你只是想要雷达画面时。

---

## 三、不装 Npcap 的方案：raw socket

Windows 从 XP 起就内置**原始套接字**（`SOCK_RAW` + `IPPROTO_UDP`），
不需要任何第三方驱动。原版就把它作为 `auto` 的兜底路径。

### 能力对比（实测 + 原理）

| | Npcap | raw socket |
|---|---|---|
| 需要装东西 | 是（内核驱动） | **否**（系统内置） |
| 需要管理员 | 是 | 是 |
| 抓接收方向（服务器→本机） | ✅ | ✅ |
| 抓发送方向（本机→服务器） | ✅ | ✅（SIO_RCVALL，见下） |
| 按网卡过滤 / 枚举网卡 | ✅ | ❌ `-dev` 无效 |
| 高流量下稳定性 | 好（内核缓冲可调） | 一般 |
| 内核态足迹 | 有常驻驱动 | **无** |

### raw 有两条路，能力天差地别（实测）

| 路径 | 发送方向 | 接收方向 | 说明 |
|---|---|---|---|
| `net.ListenPacket("ip4:udp","0.0.0.0")` | **0 个** | 15 个 | 只收「发往本机」 |
| `socket(AF_INET, SOCK_RAW, IPPROTO_IP)` + `bind(网卡地址)` + `WSAIoctl(SIO_RCVALL)` | **702 个** | 177 个 | **双向** |

实测命令与证据见 `tools/rawdir`（同时向 8.8.8.8/1.1.1.1/9.9.9.9:53 发 DNS 查询，
统计收到的包是「源=本机」还是「目的=本机」）。

### 关键问题：只收接收方向够不够？

**不够。** 位置数据确实走 s2c，但**握手包不是**。

密钥搜索的靶子公钥来自握手，而「靶子的对应私钥在 cs2.exe 内存里」
（`keyfind.verifyPriv`：`X25519(候选).PublicKey() == 靶子`，候选从游戏进程读）
→ 靶子 = **客户端自己的公钥** → 客户端把它**发出去** → **发送方向**。

所以只收接收方向时：握手永远抓不到 → `keyfind` 不启动 →
没有私钥 → 解不了密 → **雷达页永远空白**。用户看到的现象就是「没有效果」。

> 早先这里写的是「够用」，依据只是 `session.jsonl` 100% 是 s2c。
> 但那是 `mksession` 生成的**合成会话** —— 它把 `server_pub`/`key` 直接写在
> JSON 顶层，**完全绕过了握手解析**。也就是说回放链路从来没验证过
> 「从真实包里解析握手」这一步，这正是实机失败的地方。

**修复**：raw 后端默认改走 SIO_RCVALL（`internal/pcapdev/pcap.go`），
SIO_RCVALL 不可用（非管理员/被安全软件禁用）时才退回只收方向，
并在自检与 `capture_ready` 里明确标注。

```
[event] capture_ready map[backend:raw dev: mode:raw-双向(SIO_RCVALL)]
```

---

## 四、我修掉的 bug：raw 回退其实是坏的

这是本轮最重要的发现。

### 现象

`internal/pcapdev/pcap.go` 里 raw 后端的读取写的是：

```go
n, _, err := h.rawConn.ReadFrom(buf)   // ❌
return buf[:n], nil
```

而 `rawConn` 来自 `net.ListenPacket("ip4:udp", "0.0.0.0")`，动态类型是 `*net.IPConn`。

### 根因

Go 的 `(*net.IPConn).ReadFrom` **会剥离 IPv4 头**：

```go
// tools/go/src/net/iprawsock_posix.go:45  （构建标签含 windows）
func (c *IPConn) readFrom(b []byte) (int, *IPAddr, error) {
	n, sa, err := c.fd.readFrom(b)
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		addr = &IPAddr{IP: sa.Addr[0:]}
		n = stripIPv4Header(n, b)      // ← 把 IP 头 copy 掉了
	...
}
```

但采集器紧接着调 `transport.ParseIPv4UDP(raw)`，第一件事就是检查 `raw[0]>>4 != 4`：

```go
if pkt[0]>>4 != 4 {
    return nil, fmt.Errorf("not IPv4 (version %d)", pkt[0]>>4)
}
```

**于是 raw 后端的每一个包都被丢弃 → 静默失效 → 表现为「没装 Npcap 就完全抓不到包」。**

### 实测证据（`tools/rawtest`，管理员运行）

保存于 `logs/rawtest_evidence.txt`：

```
=== ReadFrom ===
  长度: 33
  前 48 字节: e433270f0021541152415750524f42452d30313233343536373839616263646566
  首字节 0xe4 → IP 版本字段 = 14  → **无 IPv4 头**（ParseIPv4UDP 会丢弃此包）
      （0xe433 = UDP 源端口 58419，紧跟 0x270f = 目的端口 9999）

=== ReadMsgIP ===
  长度: 53
  前 48 字节: 45000035606d0000801100007f0000017f000001e433270f0021541152...
  首字节 0x45 → IP 版本字段 = 4  → **带 IPv4 头**（ParseIPv4UDP 可用）
      （45 00 00 35 = IPv4/IHL=5/总长53；11 = IPPROTO_UDP；7f000001→7f000001 = 127.0.0.1→127.0.0.1）
```

### 修法

改用 `(*net.IPConn).ReadMsgIP` —— 它走 `recvmsg`，Go **不做头剥离**
（对比 `iprawsock_posix.go:75` 的 `readMsg`，里面没有 `stripIPv4Header` 调用）：

```go
if ipc, ok := h.rawConn.(*net.IPConn); ok {
    n, _, _, _, err := ipc.ReadMsgIP(buf, nil)
    ...
}
```

### 修复后实测（`tools/rawcap`，端到端）

```
raw 后端已打开，实际后端 = raw
  解析成功 #1: 127.0.0.1:55246 -> 127.0.0.1:9999  payload=25 字节
  解析成功 #2: ...
  解析成功 #3: ...

收到包数        : 201
带 IPv4 头      : 201
ParseIPv4UDP 成功: 201

结论：raw 后端可用，无需 Npcap。
```

回归测试：`internal/pcapdev/raw_test.go::TestRawBackendKeepsIPHeader`
（真实 raw socket + 真实流量；无管理员权限时自动 skip）。

---

## 五、本轮其他改动

| 改动 | 文件 | 说明 |
|---|---|---|
| raw 读取改用 `ReadMsgIP` | `internal/pcapdev/pcap.go` | 修掉上面那个 bug |
| 新增 `NpcapAvailable()` / `RawAvailable()` | `internal/pcapdev/pcap.go` | 后端可用性探测 |
| 新增 `SetReadDeadline()` | `internal/pcapdev/pcap.go` | raw 的 `Next()` 是阻塞 recvmsg，没超时退不出循环 |
| 新增 `-selfcheck` | `cmd/collector/main.go` | **真实打开一次抓包句柄**做能力自检，比 `-list-devices` 可靠 |
| `-list-devices` 优雅降级 | `cmd/collector/main.go` | Npcap 缺失**不再算错误**，改为报告两个后端可用性；退出码恒为 0 |
| bat 预检改用 `-selfcheck` | `tools/build_client_package.py` | 不再把 Npcap 当硬依赖 |
| 新增「启动雷达-免Npcap.bat」 | 分发包 | 强制 `-backend raw` |
| 新增「自检.bat」 | 分发包 | 一次跑完两个后端自检 + 设备枚举 |
| `使用说明.txt` 加第零节 | 分发包 | 开篇就讲「要不要装 Npcap」 |
| **架构改回本机** | `internal/radarsrv` + `cmd/collector` | 解码与雷达页移到本机 `127.0.0.1:8766`，不再上行公网（与原版一致）；`-uplink` 留作可选项。详见 `report/主机端分发与使用流程.md` §0 |
| raw 改走 `SIO_RCVALL` 双向抓包 | `internal/pcapdev/pcap.go` | 修「只收接收方向 → 拿不到握手公钥」。详见 `report/raw方向问题与SIO_RCVALL修复.md` |
| 新增端口过滤 | `internal/capturefilter/` + `cmd/collector/main.go` | 对齐原版 `GetExtendedUdpTable`；新增 `-no-filter` 逃生口。详见 `report/原版无Npcap机制与端口过滤对齐.md` |

分发包 `capture.exe` 当前 sha256：
`ab4bd8a6e4fc1335de8264c0caccd2f32c3bc14ab2722560bf5cdf2a8786cade`

> 原版**无 Npcap 时的取密钥机制**已查明：`WSAIoctl(fd, SIO_RCVALL=0x98000001)` +
> `WSARecvFrom` 双向抓包 + `GetExtendedUdpTable` 端口过滤。原版**不集成 Npcap**
> （免费版许可不允许再分发，静默安装是 OEM 版功能），取密钥也不需要它。
> 完整证据见 `report/原版无Npcap机制与端口过滤对齐.md`。

---

## 六、给你的建议

| 你的情况 | 建议 |
|---|---|
| 不想往系统里装内核驱动 | **双击「启动雷达.bat」就行**，什么都不用装。`backend: auto` 会自动走 raw |
| 装了 Npcap 但想强制不用 | 双击「启动雷达-免Npcap.bat」，或把 `capture.json` 的 `backend` 改成 `"raw"` |
| 抓不到包 / 想确认哪个后端能用 | 双击「自检.bat」，它会分别试 Npcap 和 raw 并说明原因 |
| 想双向抓包 / 多网卡环境 / 高流量 | 装 Npcap（勾 WinPcap 兼容模式），`auto` 会自动优先用它 |

---

## 七、遗留

1. **实机验证未做**：本机没装 Npcap、也没跑 CS2。
   raw 后端已用真实 raw socket + 真实本机 UDP 流量验证**能收包、能解析**
   （201/201），但「真实 CS2 流量下解出坐标」这一步仍需一台装了 CS2 的机器。
2. **s2c 单方向是否足够 —— 已结论：不够**。
   靶子公钥（= 客户端自己的 X25519 公钥，由 `keyfind.verifyPriv` 的语义推出）
   是客户端**发出去**的，属发送方向。只收接收方向永远拿不到握手 ⇒ 密钥搜索
   永不启动 ⇒ 雷达页空白。这是「没有效果」的根因，已改用 `SIO_RCVALL` 双向抓包修复。
3. **raw 后端不枚举网卡**：多网卡环境下无法指定，只能收全部网卡的入站流量
   （对雷达无害，只是多一点噪声）。
