# raw 后端「只看单向」问题与 SIO_RCVALL 修复

> 现象：桌面端跑起来后，抓包正常（有 `capture_stats`），但**雷达页一直没有任何目标**（用户原话「没有效果」）。
> 日期：2026-10-16
> 代码：`rebuild/cs2radar/internal/pcapdev/pcap.go`、`cmd/collector/main.go`
> 实测工具：`rebuild/cs2radar/tools/rawdir`（新增）

---

## 一、现象与定位

用户贴回的日志里：

```
[event] capture_ready map[backend:raw dev:]
[event] capture_stats map[bytes:0 packets:0 ...]
[event] capture_stats map[bytes:160 packets:1 ...]
[event] capture_stats map[bytes:160 packets:1 ...]   ← 5 秒一次，数字不动
[event] capture_stats map[bytes:160 packets:1 ...]
[event] capture_stats map[bytes:160 packets:1 ...]
[event] capture_stats map[bytes:2372 packets:29 ...]
```

两个关键观察：

1. **`capture_stats` 是 5 秒一次的定时器**，不管有没有新包都打印累计值。
   连着 4 行一模一样 = 那 20 秒没有新包。总共 29 包 —— **不像对局流量**
   （对局里 s2c 每秒几十上百包）。
2. **整段日志没有 `pub_check` / `key_ready` / `key_error`**。
   这三个事件只在握手公钥到达、密钥搜索启动后才会出现。
   一个都没有 → **握手公钥根本没解析出来 → 密钥搜索压根没启动**。

---

## 二、根因：raw 后端看不到「发送方向」

### 代码层面

`pcapdev.Open(BackendRaw, ...)` 用的是：

```go
conn, err := net.ListenPacket("ip4:udp", "0.0.0.0")
```

这个 socket **只能收「发往本机」的包**（接收方向 / s2c）。

### 实测证据（`tools/rawdir`，管理员）

同一次运行里，一边向 8.8.8.8 / 1.1.1.1 / 9.9.9.9:53 发 DNS 查询，一边统计收到的包：

```
===== A) 当前 raw (ip4:udp/0.0.0.0 + ReadMsgIP) =====
  总收包: 15
  发送方向(源=本机) 0  |  接收方向(目的=本机) 15  |  其它 0
  样本：
    8.8.8.8 -> 192.168.1.203  [udp 53->57256]  124 B  4500007c12ed...
    1.1.1.1 -> 192.168.1.203  [udp 53->57257]  124 B  4500007c52eb...

===== B) SIO_RCVALL =====
  总收包: 879
  发送方向(源=本机) 702  |  接收方向(目的=本机) 177  |  其它 0
  样本：
    192.168.1.203 -> 8.8.8.8  [udp 58854->53]  49 B  4500003164ad...
    192.168.1.203 -> 39.149.146.243  [udp 51054->9602]  969 B  450003c92ad9...
```

结论：**A 路径发送方向 0 个，B 路径发送方向 702 个。**

### 为什么「发送方向」是致命的

密钥搜索的靶子公钥来自握手，而靶子的**对应私钥在 cs2.exe 内存里**
（`keyfind.verifyPriv`：把候选 32 字节当 X25519 私钥、推公钥、与靶子逐字节比对；
候选是从游戏进程读出来的）→ 靶子 = **客户端自己的公钥**
→ 客户端把它**发出去** → **发送方向**。

于是：

```
只收接收方向
  → 握手包永远抓不到
  → handshake.ParseHandshake 从不命中
  → targetPubCh 没有值，keyfind 协程一直阻塞
  → 没有私钥
  → 共享密钥算不出
  → 解不了密
  → 雷达页永远空白
```

### 为什么之前的「验证通过」没发现

回放样本 `dist/session.jsonl` 由 `tools/mksession` 生成，
它把 `server_pub` / `key` **直接写在 JSON 顶层**，采集器 `-replay` 时
**完全绕过了握手解析**（`ParseHandshake` 根本没参与）。
所以「端到端验证」只覆盖了「给定 pub/key → 解码」这一段，
**从真实包里解析握手这一段从未被验证过** —— 正是实机失败的地方。

---

## 三、修复：raw 默认走 SIO_RCVALL（双向，仍无需驱动）

`SIO_RCVALL`（`WSAIoctl` 的 0x98000001）是 Windows 内置能力：
把原始套接字绑到某个网卡地址后开启，即可收到**该网卡上双向**的 IP 包。

### 实现要点（`internal/pcapdev/pcap.go`）

1. 枚举本机所有非回环 IPv4 地址（`net.InterfaceAddrs`）。
2. 每个地址建一个 `socket(AF_INET, SOCK_RAW, IPPROTO_IP)` → `bind` → `WSAIoctl(SIO_RCVALL, ON)`。
3. 每个 socket 起一个 goroutine 收包，**只留 IPv4/UDP**（过滤掉 TCP/ICMP 等无关流量），
   推进一个带缓冲的 channel。
4. `Next()` 从 channel 取；`Close()` 先关 `done` 通道、再关 socket、等 goroutine 退出。
5. SIO_RCVALL 不可用时**自动退回**旧的 `ip4:udp` 只收路径，并在自检里标注。

### 踩到的两个坑（都已记在代码注释里）

| 坑 | 现象 | 修法 |
|---|---|---|
| 导出名大小写 | `NewProc("WSARecvfrom")` 报 `Failed to find ... procedure` | ws2_32 里的导出是 **`WSARecvFrom`**（大写 F） |
| Go 的 syscall 是空实现 | `syscall.Recvfrom` 返回 `not supported by windows`（EWINDOWS） | 直接用 `ws2_32.dll` 的 `WSARecvFrom` + 手写 `WSABUF` |

### 实测对比（修复后）

```
$ capture.exe -backend raw -duration 7s -no-keys
[event] capture_ready map[backend:raw dev: mode:raw-双向(SIO_RCVALL)]
[event] capture_stats map[bytes:967261 c2s:1004 packets:1184 s2c:180
        top_ports:[51054(1143) 9602(1137) 53(31) 51055(10) 2482(10) 52737(2)] ...]
[event] capture_stats map[bytes:1409758 c2s:1465 final:true packets:1716 s2c:251
        top_ports:[51054(1661) 9602(1651) 53(43) 2482(12) 51055(12) 9604(2)]]
```

旧单向路径 3 秒 ~15 包；新双向路径 7 秒 **1716 包**（c2s 1465 / s2c 251）。

### 新增诊断字段（帮用户自助定位）

`capture_stats` 现在带：

| 字段 | 含义 |
|---|---|
| `mode`（在 `capture_ready`） | `raw-双向(SIO_RCVALL)` 还是 `raw-仅接收方向` |
| `c2s` / `s2c` | 两个方向的包数（都应有数） |
| `top_ports` | 出现最多的 6 个 UDP 端口。CS2 对局服务端端口常见 **27015–27050** |

用户不进对局时，`top_ports` 里不会出现 270xx —— 一眼就能区分
「抓包坏了」和「没在对局里」。

### 新增回归测试

`internal/pcapdev/raw_test.go::TestRawBackendSeesSendDirection`
向公网发 UDP，断言 `Next()` 能返回「源 = 本机」的包。
旧实现必失败，新实现通过。无管理员权限时自动 skip。

---

## 四、仍未解决 / 未验证

1. **真实对局下的端到端**：本机没跑 CS2，无法验证「真实握手 → 挖到私钥 → 解出坐标」。
   现在能保证的是：**握手包所在的方向（发送方向）已经抓得到**。
2. **握手方向仍是推断**：由「靶子私钥在游戏进程内」推出靶子 = 客户端公钥 = 发送方向。
   `notes/hypotheses.md` 里 H4 只有静态证据、未动态复现。
   若实测发现靶子其实来自服务端（s2c），本修复也不会有害（双向总比单向强）。
3. **无端口过滤**：SIO_RCVALL 收该网卡上**全部** UDP（含其它程序）。
   原版有 `capturefilter`（按游戏进程的 UDP 端口过滤），我们还没还原。
   目前靠 `top_ports` 诊断；若实测发现无关流量稀释严重，再加端口过滤。
