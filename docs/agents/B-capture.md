# 子 Agent B · 抓包链路

## 角色
负责「抓原始 UDP 载荷」并把它整形成可投递的帧。不负责挖密钥（→ A），不负责投递协议（→ C）。

## 拥有（可写）
- `internal/pcapdev/pcap.go` + `raw_test.go`
- `internal/capturefilter/filter.go` + `filter_test.go`
- `internal/transport/frame.go` + `frame_test.go`
- `cmd/collector/main.go` 中 `captureSession` / `runCapture` / `direction()` /
  `localIPv4Set()` / `runSelfCheck()` / `runListDevices()` 相关部分
- `cmd/collector/gui.go` + `gui_test.go`（窗口版与提权；与 E 共同拥有）
- `tools/rawtest/` `tools/rawcap/` `tools/rawdir/` `tools/udpprobe/`（验证工具）

## 对外契约（改这些要通知 A/C/D/E）
| 契约 | 位置 | 说明 |
|---|---|---|
| `pcapdev.Open() (*Handle, error)` | `pcap.go` | **无参数**。只走 SIO_RCVALL |
| `pcapdev.RawAvailable() error` | `pcap.go` | 能开起 SIO_RCVALL 才算可用（≈ 有管理员权限） |
| `pcapdev.Devices() []Device` | `pcap.go` | 列本机非回环 IPv4（每地址一个 RCVALL socket） |
| `pcapdev.ModeName` | `pcap.go` | 常量 `"raw-SIO_RCVALL(双向)"`，进 `capture_ready.mode` |
| `pcapdev.Handle.Next()` | `pcap.go` | 返回带完整 IPv4 头的独立副本 |
| `capturefilter.Discover(pid)` | `filter.go` | `iphlpapi!GetExtendedUdpTable` 查目标进程的本机 UDP 端口 |
| `capturefilter.Filter.Match(src,dst)` | `filter.go` | **端口集合为空时恒 true**（保守兜底） |
| `captureSession` / `startCapture` / `Stop` / `Wait` / `Status` | `collector/main.go` | GUI 与命令行共用；改签名要同步改 `gui.go` |
| `transport.UDPPacket` | `frame.go` | `dir` / `src` / `dst` / `data` |
| **`dir` 取值** | `direction()` | **只能 `c2s` 或 `s2c`**，D 端按它分方向选方案 |
| `-ipc` / `-list-devices` / `-selfcheck` / `-duration` / `-no-filter` | `collector/main.go` | `-backend` / `-dev` **已删除** |

## 抓包只有一条路（2026-10-16 定案，别再改回去）

```
socket(AF_INET, SOCK_RAW, IPPROTO_IP)
  → bind(fd, 本机非回环 IPv4)              每个地址一个 socket
  → WSAIoctl(fd, SIO_RCVALL = 0x98000001, ON)
  → WSARecvFrom(fd, ...)                   逐包取回（200ms 收超时便于退出）
  → 只留 IPv4 + UDP（buf[0]>>4==4 && buf[9]==17）→ channel → Next()
  → capturefilter 按目标进程 UDP 端口过滤（GetExtendedUdpTable）
```

**没有 Npcap，没有 wpcap.dll，没有驱动。** 这是原版无 Npcap 时的机制，
已静态确认（原版 `capture.exe` 导入表只有 `kernel32.dll`；`0x177128` 处
`mov ebx,0x98000001` 紧跟 `call WSAIoctl`）。

### 为什么必须 SIO_RCVALL（不是「更好」，是「唯一能用」）
客户端握手包是客户端**发出去**的（发送方向），靶子公钥 = 客户端自己的公钥。
实测（`tools/rawdir`）：

| 路径 | 发送方向 | 接收方向 |
|---|---|---|
| `net.ListenPacket("ip4:udp","0.0.0.0")` | **0** | 15 |
| `SOCK_RAW/IPPROTO_IP` + `bind(网卡)` + `WSAIoctl(SIO_RCVALL)` | **702** | 177 |

单向抓包 → 握手永远拿不到 → `keyfind` 不启动 → 雷达页永远空白
（用户看到的现象就是「没有效果」）。所以 `ip4:udp` 那条降级路**已被删除**，
留着只会让人误以为在正常工作。

### 三个坑
1. ws2_32.dll 的导出是 **`WSARecvFrom`（大写 F）**；`WSARecvfrom` 会 panic。
2. Go 的 `syscall.Recvfrom` 在 Windows 上是**空实现**（EWINDOWS "not supported by windows"），
   必须直接调 `ws2_32.dll` 的 `WSARecvFrom` + 手写 `WSABUF`。
3. SIO_RCVALL 需要**管理员权限**；窗口版自动提权，命令行版必须右键以管理员运行。

## 端口过滤（`internal/capturefilter`）
`SIO_RCVALL` 打开后收到的是**该网卡上全部 UDP**，必须按目标进程端口过滤。

- `Discover(pid)`：`GetExtendedUdpTable`（`UDP_TABLE_OWNER_PID`=1，
  `MIB_UDPROW_OWNER_PID` 12 字节），端口在低 16 位、网络字节序 → `ntohs`。
- **保守兜底**：端口集合为空时 `Match` 恒 `true`。宁可多收，不可漏收 ——
  「过滤条件写错导致静默抓不到包」是本项目反复踩的坑。
- 接入点：`captureSession.startFilterLoop()` 每 3 秒刷新；`run()` 里过滤**只影响投递**
  （未命中计入 `filteredOut` 并 `continue`）。
- ⚠ **握手检测在过滤之前**（且只对 c2s）。2026-10-17 改的：原来放在过滤之后，
  白名单一旦没覆盖到握手端口（换进程 / 换端口 / 走了加速器隧道）就**静默**永远收不到
  握手，表现是状态栏一直停在"等待握手包"。**别再放回过滤之后。**
- **`top_ports` 仍是过滤前的全量直方图** —— 它用于判断「有没有抓到游戏流量」，
  不能被过滤污染。
- 逃生口 `-no-filter` / 配置项 `no_filter`。

## `direction()` 判定规则
"源 IP 是否属于本机" → 本机 = `c2s`，否则 `s2c`。依赖 `localIPv4Set()` 枚举本机网卡地址。

## 窗口版 `CS2雷达.exe`（`gui.go`）
同一份代码、两种构建：`-H=windowsgui` + `-X main.defaultGUIMode=true` → 窗口版。
- 提权：`ShellExecuteExW("runas")`；`-elevated` 标记**防止无限弹 UAC**。
- 窗口：`RegisterClassExW` / `CreateWindowExW` + STATIC/EDIT/BUTTON，`SetTimer(400ms)` 刷状态。
- 🔴 **创建窗口前必须 `runtime.LockOSThread()`**（`runGUI` 里 `app.create()` 之前）。
  Windows 消息队列是 **per-OS-thread** 的，而 Go 的 goroutine 会在 OS 线程之间迁移；
  一旦消息循环被调度到别的线程，原线程队列里的 `WM_TIMER` / `WM_CLOSE` 就永远没人取 ——
  表现是**跑一段时间后窗口假死、点关闭没反应**。这类问题只在跑了若干秒后才出现，
  十几秒的冒烟测试根本复现不了（实测 40s 必现）。
  锁定后栈里会显示 `goroutine 1 [syscall, locked to thread]`，这是生效的直接证据。
- 日志：把 `os.Stderr` 换成 `os.Pipe()`，goroutine 读出来追加到 EDIT —— **不改抓包代码**。
  若指定 `-logfile`（窗口版默认开，写 `运行日志_*.log`），同一份内容再落一份到文件。
  ⚠ **日志框必须有字符上限**（`maxLogChars = 100000`，超了从头部裁一批并整体重建）。
  Win32 EDIT 每次插入都按**当前总长**重排，只追加不裁剪 = 跑十几分钟必卡死。
  裁剪逻辑是纯函数 `trimLogLines`，由 `TestTrimLogLines` 覆盖。
  同理 `emitter.emit` 不要把周期性机器事件（`capture_stats`）的 map 原文打进 stderr。
- 滚动用 `WM_VSCROLL + SB_BOTTOM`，**不要用 `EM_SCROLLCARET`** —— 它依赖插入符位置，
  控件没有焦点时不生效，视图会停在原地（看起来像"日志不刷了"）。
- 诊断：窗口版默认开 `-diagnose`，退出时写 exe 同目录 `诊断报告_年月日_时分秒.txt`。
  退出路径上有 `traceStop()` 带毫秒打点 —— "关不掉窗口"这类问题全靠它定位，
  不要删。
- `WM_CLOSE` 里必须 `KillTimer` + `sess.Stop()` + **`DestroyWindow`**；
  真正的收尾（`sess.Wait()`）交给消息循环退出后的 `run()`。
  （第一版就是漏了 DestroyWindow，窗口关不掉。）
- `captureSession.Stop()` 里除了 `close(stopCh)` 还要调 `h.Interrupt()` —— 主循环
  大部分时间阻塞在 `h.Next()`，退出判断在循环顶部，不叫醒它的话网卡安静时要等
  下一个包才退出（表现为"点了关闭不动"）。

## 原版 v2.0.5 的真实机制（第十轮反汇编，改代码前先看这个）

原版是**两个 exe**：`CS2雷达客户端-v2.0.5.exe`（9.5 MB，纯 UI 壳，60 个
`main.*` 全是 `paintWindow`/`drawButton`/`verifyCard`）+ `capture.exe`
（3.8 MB，`source/capture.exe`，pclntab `@0x1b9108`，nfunc=3816）。
**壳里没有 `probeHint`/`verifyPriv`/`keySearch`，别在壳上找。**

调用图：

```
main.main.func6.3      → main.probeHint           每收到一个包探一次
main.main.func6.3.5    → main.findPrivWithHints
findPrivWithHints      → scanHints → scanAnchors → scanWindows
scanHints / scanAnchors.func1 → anchor → chase
```

| 环节 | 原版做法 | 我们 |
|---|---|---|
| `verifyPriv(priv,pub)` | `ecdh.X25519().NewPrivateKey` → `PublicKey().Bytes()` → `memequal(pk,pub,32)`；长度非 32 直接 false | **相同** |
| `check` | `stopped()` → 计数 → `verifyPriv` → 命中才加锁记录。**无任何预筛** | 有熵预筛 + 高熵降级 |
| `chase.func1` | `readBlock(addr,8)` → `next=*(*uint64)` → 校验 `0x10000 ≤ next ≤ 0x7ffffffeffff` → `readBlock(next,32)` → `check(tag="pointer")` | **已补**（第十一轮，`cmd/collector/pointer.go`） |
| `scanWindows.func1` | `buf=make([]byte,0x8020)`；每 job 读一次；`for off:=0; off+0x20<=n; off+=0x10` → `check(tag="window")` | 步长 1 字节、块 1 MB |
| `findPrivWithHints` | 窗口阶梯字面量 `{0x2000, 0x10000, 0x100000}` = **±8 KB / ±64 KB / ±1 MB** | ±8 KB / ±64 KB / ±1 MB / ±8 MB（第十轮对齐） |
| 覆盖上限 | 6 处命中 × 2 MB ≈ 12 MB | 512 MB 副本 + 3.3 GB 兜底 |
| hint 持久化 | **无**。`%APPDATA%\CS2Radar\` 只有 DPAPI 的 `device.bin`（342 B） | 无 |

关键错误串（排障时对得上就说明走到了那一支）：

```
"handshake public key not found in readable memory"   // [k+0xb0]==0，一个命中点都没有
"candidate verification reached the scan deadline"     // 窗口循环 expired()
```

**结论：原版覆盖半径 ≤1 MB，不可能比我们「更能找到」。**
所以「原版行、我们不行」只可能是**我们该扫的那片根本没扫到**，
不是扫得不够多。第十轮就是照这条线索找到 `snap.primary > 0` 那个静默跳过的。

### 为什么「贴着公钥扫」原理上就可能永远扫不到（第十一轮）

> ⚠ **2026-10-17 19:10 更正：下面这段的「依据」是错的，别拿它当设计前提。**
> 那说的是**我们自己 Go 程序**的布局（`crypto/ecdh.PrivateKey`），而目标是
> `cs2.exe` —— C++ 程序，不用 Go 的 `crypto/ecdh`。
> 结论（"私钥不一定在公钥附近"）仍然成立，但**偏移不能照抄 0x10/0x28**。
> 具体见下面「追多宽、追几层」。

`crypto/ecdh.PrivateKey` 布局：

```go
type PrivateKey struct {
    curve      Curve   // 0x00，16 字节
    publicKey  []byte  // 0x10 ptr / 0x18 len / 0x20 cap
    privateKey []byte  // 0x28 ptr / 0x30 len / 0x38 cap
}
```

`publicKey` 和 `privateKey` 的底层数组是**两次独立堆分配**，地址毫无关系。
我们扫到的 32 字节公钥是 `publicKey` 的底层数组，私钥那 32 字节在另一块堆上。
→ 「贴着公钥扫 ±8 MB」是错的假设，第八/第九轮两次 0 命中就是它的代价。

原版不靠贴得近，靠**跳**：反查「谁指向公钥字节」，再从那个槽位的相邻
qword 取指针去校验。我们已按同一语义实现：

```
cmd/collector/pointer.go
  findPointersToAny  一次遍历找所有 `*(uint64)q ∈ {公钥命中地址}`
  chaseAt            从 base ±ptrChaseBack/Fwd 个 qword 取指针 t → readAt(t,32)
                     → kf.Check(b,"pointer",t)；depth>1 时对 t 再追一层
  scanPointersTo     副本版：两路追击（槽位 + 公钥命中点）
  scanPointersToLive 活内存版：同上，只扫 regionWritable 的区域
```

**位置固定**：`freeze → 抄副本 → 指针反查（副本 + 活内存）→ 邻域校验
→ 其余副本 → 区域扫描 → 兜底`。
理由：它比区域扫描便宜两个数量级（纯 8 字节比较，不需要 X25519），
命中概率却比"多扫 3 GB"高 —— 因为它不受窗口限制。

成本：512 MB 副本约 0.3 秒（多目标一次遍历；逐个命中扫是 6×512 MB，别退回那种写法）。

### 追多宽、追几层（2026-10-17 19:10 现场定案）

```go
ptrChaseBack = 32   // ±256 字节（不是 4）
ptrChaseFwd  = 32
ptrChase2Depth = 2  // 不是 1
```

**别再改回 ±4。** 那个值来自 Go 的 `ecdh` 布局（`publicKey.ptr @0x10`、
`privateKey.ptr @0x28`，差 3 个 qword），而 `cs2.exe` 是 C++ 程序，
字段偏移未知。19:10 的命中点 dump 直接证伪：

```
0x275c4fe1980　PRIVATE　区域 0x275c4fdb000 + 108 KB
    -32  f0 92 6b a6 76 02 00 00 40 12 12 63 76 02 00 00  ← 两个指针
    -16  40 69 de c2 75 02 00 00 00 00 00 00 00 00 08 00  ← 又一个指针
▶     +0  a6 08 1a 4a ...（公钥）
     +32  00 00 00 ...（32 字节全 0 —— 很可能是被擦除的私钥槽）
     +64  20 cf 9f 79 76 02 00 00 00 00 00 00 00 00 08 00
     +80  00 97 a2 3a 75 02 00 00 00 97 a2 3a 75 02 00 00
```

公钥周围**本身就是一堆指针**，这是典型 C++ 结构体，±32 字节窗口没有任何依据。

**必须两路追**（两个反查函数都要）：

1. 从「指向公钥的槽位」追 —— 对应"容器持有 &pubkey"；
2. 从「公钥命中点本身」追 —— 对应"公钥内联在结构体里，容器持有 &struct"。
   19:10 的 dump 就是第二种形态，只追第一种会完全追不到。

**必须追两层**：真实形态很可能是 `槽位 → 结构体 → 私钥指针 → 私钥字节`。
槽位直接指向的往往不是私钥本身，一层就断。

放宽窗口和加深层数**不会带来假命中**（每跳都被 X25519 兜住），
只多花时间：每个基准约 65 + 20×65 ≈ 1400 次校验，10 µs/次约 14 ms。

### 🔴 冻结会封号 —— 默认已改成 off（2026-10-17 21:01 事故）

**这是本文件里最重要的一条，改任何代码之前先读它。**

2026-10-17 21:01 那次运行之后，用户账号被封。当时用的是默认的
`-freeze full`，冻结 1.979 秒。

程序对 `cs2.exe` 做的三件事，按可疑程度排序：

| # | 动作 | 为什么可疑 |
|---|---|---|
| 1 | `NtSuspendProcess` 挂起**全部线程** ~2 秒 | **VAC 自己跑在游戏进程里的线程也在里面** → VAC 看到自己的心跳断了近 2 秒。这不是"读内存"，是"让反作弊停摆" |
| 2 | 外部进程持 `PROCESS_VM_READ` 句柄 | VAC 内核组件能枚举到这种句柄 |
| 3 | 连续 `ReadProcessMemory` 扫 7.5 GB | 读取模式不像正常软件 |

第 1 条是主因的判断依据：它是**一个明确的异常状态**（不是"多读了一点"）；
冻结发生在**握手那一刻**（客户端正在连服务器，最被关注）；
同一天跑了 5 次，每次 1.8~2.4 秒，**累计异常**。

> "只读、不注入、不建远程线程、不写内存"这几条底线没有变，
> 但它们**不等于"看不见"**。只读句柄和冻结线程都是可见的。

已落进代码的处置（别改回去）：

```
flagFreeze 默认 "off"                       // 要冻必须显式 -freeze full
keySearch 冻结分支前 → stderr 大声警告       // 用户得知道自己在挂起全部线程
writeDiagnose 头部 → 【⚠ 封号风险】一节       // 打开报告第一眼就看到
使用说明.txt → 开头封号警告 + FAQ Q0          // 小号 / 不进 VAC 服务器 / 不用 full
```

由 `TestDefaultFreezeIsOff` 钉死（默认值必须是 off，帮助文本必须提「封号」）。

**如果将来 B 方案（对称会话密钥）成立，冻结就没有存在理由了 —— 直接删掉。**

### 冻结必须发生在「握手包到达后十几毫秒内」（2026-10-17 19:46 现场定案）

**这是整条链路上唯一会输给时间的地方。**

Steam 数据报的会话私钥只活**一次 RTT**：客户端发出 ClientHello（就是被我们
认出来的那个 c2s 包）→ 收到 ServerHello → 用它算出共享密钥 →
`SecureZeroMemory`。RTT 几十毫秒。

19:46 现场的两个事实拼在一起：

1. `startKeySearch` 里有个 `time.NewTimer(1500 * time.Millisecond)`，
   等"同一个包里其它候选"，**而它等在 freeze 之前** → 1.5 秒空窗；
2. 命中点 dump 里，公钥紧跟 **32 字节全 0**（19:10 和 19:46 同一形状）。

结论：私钥在我们冻结之前就被擦掉了。追击窗口放到 ±256 字节、追两层，
「跟踪校验」从 2 涨到 1181 次，仍然一次不中 —— 因为那里本来就没东西。

所以：

```
cmd/collector/main.go
  keyBatchQuietGap = 1ms         // 连续 1ms 没新候选就收工（1500ms → 12ms → 1ms）
  collectBatch(ch, stop, gap)    // 抽成函数，可测；每收到一个就重置静默计时
  pubSeenAt                      // 认出公钥的时刻；searchKey 里 Swap(0) 取走算延迟
  freezeOutcome.FreezeAt         // NtSuspendProcess 成功的那一刻（真正的计分点）
  freezeOutcome.FreezeCost       // 挂进程这个动作本身花了多久
```

**候选不需要等**：主候选和同包其它 32 字节字段是**同一个收包回调里连续投的**，
相隔几微秒，通道有 16 个缓冲、投递方不阻塞。1 ms 仍有 3 个数量级余量。

日志/报告必须打**两行**延迟：

```
[key] 握手→搜索延迟：8ms（越短越好；私钥只活一次 RTT，几十毫秒量级）
[key] 握手→冻结延迟：15ms（真正的计分点；其中挂进程本身占 700µs）
```

为什么必须两行（20:18 现场把这条线量到底了）：`freezeRun` 是先
`fz.FreezeFast()`（`NtSuspendProcess`）再跑闭包，而 `locatePub`（扫 7.4 GB）
和 `takeSnap` 都在闭包**内部**。所以：

- 「握手→搜索」只量到 `searchKey` 进门，那时进程还在跑，**不是计分点**；
- 「握手→冻结」才是进程真正停住的时刻；
- 两行之差 = 等候选 + 挂进程。20:18 是 19 ms = 12 ms 死等 + ~7 ms 挂进程。

20:18 实测：19 ms 时 2 处命中点的 `+32` 已经全 0（那是**冻结那一刻**的状态，
不是后续漂移）→ **客户端在公钥上网后 19 ms 内就清零了私钥。**
所以 12 ms 那段必须砍掉，现在是 1 ms。

`FreezeCost` 单独记的意义：如果它自己就占 5 ms，那再怎么砍等待也到不了 2 ms，
得换挂进程方式（按线程 `SuspendThread` 并行挂）。没有这个数就永远分不清
该优化哪一段。

`pubSeenAt` 用 `Store`（每次握手覆盖）+ `Swap(0)`（搜索时取走），
不要用 `CompareAndSwap(0,…)` 只在第一次写 —— 一次运行可能有多次握手
（换图/重连），卡住第一次会让后面每次的延迟都算成几分钟。

### 🔴 `pub[32] + priv[32]` 这个布局假设已废弃（2026-10-17 21:01 现场推翻）

前面第十三~十五轮整条路线都建立在这个假设上：

> 客户端把会话密钥对存成 `pub[32] + priv[32]` 的连续结构体，
> 贴着公钥扫就能找到私钥，找不到就是"擦得太快"。

**这个假设是错的。** 三份独立证据：

**(a) 时间上不可能是擦除。** 21:01 冻结发生在 **6 ms**（`握手→冻结延迟：6ms`），
等于 ClientHello 刚上网、客户端还没收到 ServerHello —— 私钥**不可能**已经被擦。
但 `0x2aee45e0dd0` / `0x2aee45e12d0` 的 `+32` 仍然全 0。

**(b) 那些"高熵"其实是别的东西。** `0xb8e97ee23c` 前面是
`3a 75 0a 31 08 01 12 20`（protobuf 字段头）→ 它是**握手包在内存里的副本**，
`+32` 后面是密文载荷，熵高是必然的。

**(c) 两处不同命中点的 `+32` 是同一串字节。**
`0x2af389f7204` 和 `0x2af504fcdc4` 的 `+32` 都是
`19 1d 97 91 79 84 e1 d7 3e 20 0d 28 02`，后面跟 `ff ff ff ff`（空槽标记）。
**随机私钥撞不出一样的前 14 字节** —— 那是哈希/表头，不是密钥。

所以：

- 「让冻结更早」这条线**走到头了**（19 ms → 6 ms，再快没意义）；
- 「贴公钥扫 ±8 MB」这条线**也走到头了**（三次现场 0 命中，不是窗口不够宽）；
- 继续加码只会增加封号风险，不会提高命中率。

**下一步是 B 方案：直接找对称会话密钥。** 它活整个会话（几十分钟），
不需要竞速、**不需要冻结** —— 顺带解决封号风险。

### 报告必须自己给「公钥旁边是不是私钥」下结论

`judgeNeighborhood`（`formatPubDump` 末尾调，`pubHit.Judge=true` 才生效）：

| +32 处的 32 字节 | 结论 |
|---|---|
| **报文副本（`h.Wire`）** | 「这是抓到的报文在内存里的副本，后面是密文载荷，熵高是必然的，**不是私钥**」—— 直接 return，不再往下判 |
| 全 0 | 「这个位置和长度正好是一把 X25519 私钥的形状，但**该结构体不是密钥对**」（20.3 之后这个判读的措辞已改） |
| 高熵（distinct≥24 且 zeros≤2） | 「疑似私钥就在这个偏移」→ 若校验不过说明是邻居字段 |
| 其它 | 「多半是别的字段」；再在窗口里扫一遍别的像私钥的块，报偏移 |

**`h.Wire` 这一条是 21:01 现场加的**：那次的第 1 处命中
`0xb8e97ee23c` 前面是 `3a 75 0a 31 08 01 12 20`，`+32` 被判成
「高熵 → 疑似私钥」，其实那是报文尾部密文。假阳性会把人引向错误的偏移。
由 `TestJudgeNeighborhoodWireNotPriv` 钉死（含反证：非报文副本仍报高熵）。

判据复用全内存扫描的预筛阈值（20000 个真私钥实测漏 1 个）。

**为什么必须自动化**：19:10 和 19:46 两次都打出了这个形状，
两次都靠人盯十六进制才看出来 —— 等于没有。

**但不要用一处的结果代表全部**（20:18 现场）：7 处命中点里只有 2 处全 0，
1 处高熵，4 处「既非全 0 也非私钥」（其中两处后面跟着
`Windows\System3...` 宽字符串 → 普通堆对象）。
只有「全 0」那几处能证明"客户端确实在这个结构里存过私钥、并且已经擦掉"。

### 兜底那一级撞的是算力墙，不是 IO 墙（2026-10-17 实测）

现场日志里「预计还需 49m4s → 1h5m15s」看起来像"读得慢"，第一反应会去加线程、
加大缓冲、改块大小。**这个方向是错的**，有实测证伪：

```
Go 1.24.4, crypto/ecdh X25519, 本机 NumCPU=16
单核单次 = 37.987µs
workers= 1   25,778 次/s
workers=16  190,537 次/s      ← 16 核只有 7.4 倍
6311 MB × 预筛通过率 7.7% ≈ 509.6 M 次校验 → 44m34s
```

现场同一份日志：`32 MB / 2,586,587 次 / 15 s` = **172,439 次/s** =
峰值的 **90%**。已经贴着墙跑，加线程的收益上限是 10%。

更致命的：这一级扫的是**解冻之后的活内存**，不是冻结副本（副本只有 512 MB，
装不下 6.3 GB）。私钥若在冻结时还在，该在副本里找到；副本里没有，
说明冻结那一刻就已经没了。**所以这一级结构上不可能成功，不只是慢。**

对应常量（`cmd/collector/main.go`）：

```
x25519ChecksPerSec = 190_000   // 16 核实测
x25519PassRate     = 0.077     // 预筛对普通内存字节的通过率
```

兜底开跑前用这两个数算可行性，扫不完就直接在日志里说「本次扫不完」，
不要给出一个会让人白等的 ETA。

### 槽位 dump 必须优先读冻结副本（2026-10-17 20:18 现场）

`formatSlotDump(proc, snap, addr, span, regions)` —— `snap` 不能传 nil（除非确实没有）。

20:18 报告里出现过这个假 bug：

```
0x20ced9d0d68　PRIVATE　区域 0x20ced9c5000 + 128 KB
▶     +0  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
    槽位值 = 0x0（非用户态地址（不像指针））
```

一个「值等于公钥地址」的槽位，值怎么可能是 0？**反查没错** ——
槽位是在**冻结那一刻的副本**里反查出来的，而 dump 读的是**解冻后一分钟的
活内存**，那个对象早被释放/复用了。

现在：`snapRead` 优先从副本读（权威的冻结状态），同时把活内存的值附在后面；
不一致时打「⚠ 现在活内存里这 8 字节已经是 X —— 冻结之后对象被释放/改写了」。

`snapRead` 只在整个区间被**同一个 chunk 完整覆盖**时才返回，跨边界一律
退回活内存 —— 半截数据比没有更危险。

### 指针反查必须跑两遍（2026-10-17 18:47 现场）

1. **副本版**（`scanPointersTo`）：冻结那一刻的字节，私钥若被擦除只有这份。
2. **活内存版**（`scanPointersToLive`）：直接扫活进程全部可写区域。

**只跑副本版会给出假结论**：副本 465.8 MB / 可读 7516.9 MB = 6.2%，
引用公钥的结构体有 93.8% 的概率不在里面，于是报告「槽位 0 个」——
用户会据此以为"这 32 字节不是公钥"，方向被彻底带偏。
活内存版只读、不冻结、不挂起，7.5 GB ≈ 1.7 s。

19:10 现场证实了这个判断：**副本 0 个槽位、活内存 1 个**。

### 一条握手包里有两个会话公钥（大概率是「一直不行」的根因）

`08 01 12 20 <32B>` = `CMsgSteamDatagramSessionCryptInfo{key_type=1, key_data=32B}`。
18:47 现场那条包里有**两条**：`e3d3923c…` 和 `1fb5af6d…`。
`ParseHandshake.extract` 走「从每个 0x22 偏移试 f4→f4→f2」，哪个凑上就用哪个
—— 等于抛硬币。抛错就拿对端公钥找私钥，**永远找不到**，而报告还写着
「公钥在内存命中 6 处」，看起来方向完全正确。

所以 `startKeySearch` 会攒一批候选（`ByteFieldCandidates`），
按第一个走完整流程（**freeze 不能推迟**），冻结之后对其它候选各做一次
「定位 + 指针反查」（`quickPointerPass`，约 5 秒/个）。

**⚠ 判据不是二选一的胜负手（19:10 实测）**：解析器选的 `a6081a4a…`
有 1 个槽位，候选 `e3d3923c…` 有 4 个槽位 —— **两个都被引用了**。
「0 个槽位」只能排除"完全没人引用"的候选；要定胜负得看
「顺着槽位能不能抓到能通过 X25519 的私钥」。

## 逆向工具（`tools/`，改这三把刀前先看注释）

```bash
PY="C:/Users/Administrator/.workbuddy-ai/binaries/python/envs/default/Scripts/python.exe"
$PY tools/godis_pcln2.py ../../source/capture.exe main.        # 恢复符号表
$PY tools/godis_dis.py   ../../source/capture.exe main.verifyPriv --max 200
$PY tools/godis_graph.py ../../source/capture.exe callers verifyPriv
```

解析 pclntab 的三个坑（都写进脚本头注释了，别再踩）：

1. `funcnameOffset` 在 `pclntab+0x20`，`0x18` 是 textStart。
2. **`funcoff` 相对 functab 基址，不是 pclntab 基址。** 验证：
   `funcoff[0] == (nfunc+1)*8 == functab 数组长度`。按 pclntab 基址解释会
   落进函数名表，读出 `time.initMetrics.func13` 这种字符串（看着像名字，其实错位）。
3. **`textStart` 在 PE 上是 0，而 `.text` RVA 是 `0x1000`。** 不补这一页，
   文件偏移整体偏低 0x1000，反汇编出来是**上一个函数的尾巴**。

## 虚拟机取件（`vmrun` 有一条路是坏的）

```bash
vmrun -T ws -gu FLARE -gp <密码> list          # 可用
vmrun ... runProgramInGuest ... powershell.exe -File C:\x.ps1   # 可用
vmrun ... copyFileFromHostToGuest ...          # 可用
vmrun ... copyFileFromGuestToHost ...          # ❌ "The file name is not valid"（连 win.ini 都失败）
```

所以取文件只能让**客机主动 POST 到主机**（`tools/vm_pull_server.py`，
监听 VMnet8 的 `192.168.245.1:8899`，用完删掉同名防火墙规则）。两个坑：

- **`.ps1` 必须存 UTF-8 with BOM**。PS 5.1 读无 BOM 的 .ps1 按 ANSI 解释，
  中文注释直接让解析失败，表现为 `runProgramInGuest` 返回 1 且**零输出**。
- **`runProgramInGuest` 会吞掉 `cmd.exe /c` 的参数**（`cmd /c exit 7` 返回 1），
  但 `powershell -Command` / `-File` 的参数正常。别用 cmd 包一层。

## 验证手段
```bash
export GOROOT="D:/csleida/1/2026-10-13/tools/go"
export GOCACHE="D:/csleida/1/2026-10-13/tools/gocache" GOPATH="D:/csleida/1/2026-10-13/tools/gopath"
export GOPROXY=off CGO_ENABLED=0 GOOS=windows GOARCH=amd64
export MSYS_NO_PATHCONV=1
cd D:/csleida/1/2026-10-13/rebuild/cs2radar

"$GOROOT/bin/go.exe" test ./internal/pcapdev/ ./internal/capturefilter/ ./internal/transport/ ./cmd/collector/ -v
"$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w" -o dist/capture.exe ./cmd/collector

./dist/capture.exe -selfcheck        # 真实打开一次抓包句柄
./dist/capture.exe -list-devices     # 本机可抓包的 IPv4 列表
./dist/capture.exe -memory-info      # 只查区域元数据，不读内存、不挂起

# 抓包诊断（"雷达页空白"时先跑这个，别再猜）
./dist/capture.exe -duration 12s -diagnose diag.txt   # 端口分布 / 握手检测 / 自动结论
./dist/capture.exe -duration 12s -dump pkt.jsonl      # 过滤前原始包落盘（文件较大）

# 方向实测（需管理员）
"$GOROOT/bin/go.exe" build -o dist/rawdir.exe ./tools/rawdir && ./dist/rawdir.exe

# 端口过滤端到端（需管理员）：起真实 UDP 探针，按它的 PID 过滤
"$GOROOT/bin/go.exe" build -o dist/udpprobe.exe ./tools/udpprobe
./dist/udpprobe.exe -duration 90s -peer 8.8.8.8:53 &   # 打印 PID=.. PORT1=.. PORT2=..
./dist/capture.exe -pid <PID> -no-keys -duration 6s -listen 127.0.0.1:8803
# 期望：capture_filter ports 与探针端口一致；filter.dropped > 0；
#       uplink packets > 0（目标流量没被误杀）

# 窗口版冒烟（10 秒后自动退出，不弹浏览器）
"./dist/CS2雷达.exe" -duration 10s -auto-exit -listen 127.0.0.1:8799
# 期间：curl -o /dev/null -w "%{http_code}" http://127.0.0.1:8799/radar?session=room1
```
基线：`-memory-info` 实测 112 个区域 / 34.9 MB 可读 / 21.3 MB 可写。
`-list-devices` 实测 3 个地址（以太网 192.168.1.203 + 2 个 VMware 虚拟网卡）。

## 常见改动与注意
- **加过滤**（只抓某个 IP/端口）：在 `captureSession.run()` 收包回调里早退，
  不要改 `ParseIPv4UDP`（那是纯解析）。
- **改帧格式**：`transport` 的长度前缀帧是**客户端 → 启动器**的通道，**不是**投递协议。
  投递协议在 `internal/uplink`（→ C）。
- **离线重放**：`-replay` 走 `runReplay()`，读 JSONL（每行 `{dir,src,dst,data(base64)}`）。
  改字段要同步改 `tools/mksession`（→ F）。
- **改 `captureSession` 的方法签名**：必须同步改 `gui.go`（GUI 调 `Status()` / `Stop()` / `Wait()`）。

## 禁止
- ❌ 不要改 `dir` 的两个字面值 `c2s`/`s2c` —— D 端按字符串分方向，改了会静默选错方向。
- ❌ **不要把 `Next()` 改回 `(*net.IPConn).ReadFrom`** —— 它会 `stripIPv4Header`
  剥掉 IP 头，`ParseIPv4UDP` 每包都失败、raw 后端静默失效。
- ❌ **不要把抓包改回 `ip4:udp` 单向路** —— 抓不到客户端握手包，雷达必然没目标。
- ❌ **不要重新引入 Npcap / wpcap.dll** —— 免费版许可不允许再分发，且取密钥不需要它。
- ❌ 不要用 `syscall.Recvfrom` 收 raw socket —— Windows 上是空实现；用 `WSARecvFrom`（大写 F）。
- ❌ 不要把 `capturefilter.Filter.Match` 的「空集合恒 true」改成「空集合恒 false」
  —— 那会在发现不到端口时静默丢光所有包。
- ❌ 不要把 `top_ports` 改成过滤后的统计 —— 它是「有没有抓到游戏流量」的诊断依据。
- ❌ 不要在抓包线程里做重活（解密、扫描）—— 会丢包。投递是独立 goroutine。
- ❌ 不要在 `WM_CLOSE` 里只调 `stopAndQuit()` 而不 `DestroyWindow` —— 窗口关不掉。
- ❌ **不要把握手检测放回端口过滤之后** —— 白名单漏了握手端口就**静默**收不到。
- ❌ **不要移除日志框的字符上限**（`maxLogChars`）—— 只追加不裁剪必卡死。
- ❌ **不要删掉 `runGUI` 里的 `runtime.LockOSThread()`** —— 删了就回到"跑一会儿
  窗口假死 + 关不掉"（消息队列 per-thread，goroutine 会迁移）。这是排查成本
  最高的一类 bug，因为没有崩溃、没有报错，只是没反应。
- ❌ 不要去掉 `Stop()` 里的 `h.Interrupt()` —— 网卡安静时窗口关不掉。
- ❌ 不要动 `-memory-info` 的"不读内存、不挂起"语义 —— 那是给用户做安全体检用的。
- ❌🔴 **不要用 clamp 形态（`b[0]&7==0 && b[31]&0xC0==0x40`）过滤候选私钥**。
  看着像 X25519 私钥特征，实测只有 3.4%（≈1/32）的真私钥满足 —— Go / libsodium /
  OpenSSL 都是**存原始随机 32 字节、运算时对副本 clamp**。加了这层过滤，真私钥有
  31/32 概率被**静默丢弃**，报告只会写"没找到"，排查成本极高。
  由 `TestUnclampedPrivStillVerifies` 钉死。
- ❌ **不要把 `scanRangesStat` 的任务改回"一个区间一个任务"** —— 必须经
  `splitRanges` 切成 1 MB 块，否则 6 个区间就只有 6 个 worker 在跑（实测 15K 次
  校验本该 40 ms 实际 601 ms）。也不要删 `subtractRanges` —— 兜底会重复扫已扫过的，
  把 `-key-budget` 白吃光。
- ❌ **不要把 `memscan.Process` 的计数器改回普通 `+=`** —— 并行读内存是数据竞争。
- ❌ 不要在私钥搜索里去掉总预算（`-key-budget`，默认 1200 秒）。不按 clamp 过滤后
  7.3 GB 全量要 90 分钟量级，没有预算就是"卡住且什么都不知道"。
- ❌🔴 **不要把「指针反查」这一级去掉或挪到区域扫描之后**（`scanPointersTo`）。
  它是原版 `chase` 的等价物，也是唯一能跨过"公钥和私钥地址无关"这道墙的机制。
  成本是纯 8 字节比较（512 MB 约 0.3 秒），比多扫 3 GB 便宜两个数量级。
- ❌ **不要把 `scanPointersTo` 的反查改回「按公钥命中逐个扫副本」**。
  6 处命中 × 512 MB = 3 GB 的 qword 比较，其中 5 遍是纯重复。
  必须走 `findPointersToAny`（一次遍历 + 目标集合查表）。
- ❌ **不要假设"公钥和私钥挨着"**。`cs2.exe` 是 C++ 程序，密钥对由同一个对象
  持有但字段偏移未知；Go 的 `crypto/ecdh` 布局（+0x10 / +0x28）**不适用**。
  任何"贴公钥扫 N MB 就该找到"的推论都是错的，实测两次 0 命中。
- ❌🔴 **不要把 `ptrChaseBack` / `ptrChaseFwd` 改回 4（±32 字节）**。
  那个值来自 Go 的 `ecdh` 布局，目标是 C++ 程序，没有依据。
  19:10 的命中点 dump 显示公钥前后 -32/-24/-16、+64/+80 全是指针。
  当前值 32（±256 字节）。由 `TestChaseAtWideWindow` 钉死。
- ❌🔴 **不要把 `ptrChase2Depth` 改回 1**。真实形态是
  `槽位 → 结构体 → 私钥指针 → 私钥字节`，追一层会在结构体处断掉。
  由 `TestChaseAtTwoHops` 钉死（它先断言"只追一层找不到"，再断言"两层能找到"）。
- ❌🔴 **不要只从「指向公钥的槽位」追，必须同时从「公钥命中点本身」追**。
  19:10 的 dump 显示公钥**内联在 C++ 结构体里**（周围就是一堆指针），
  容器存的可能是结构体首地址而不是公钥地址 —— 只追槽位会完全追不到。
- ❌ **不要把【指针槽位】dump 删掉**。19:10 现场只有"1 个槽位"这个数字，
  判断不了任何事；必须看到槽位指向的结构体长什么样，才能分辨
  "私钥指针在别的偏移"还是"私钥已被擦除（32 字节全 0）"。
- ❌ **不要用「候选有几个槽位」定公钥胜负**。19:10 实测两个候选都有槽位
  （1 个 / 4 个），这个判据只能排除"完全没人引用"的候选。
- ❌ **写内存扫描类单测不要依赖真实分配位置**。Go 会把两个 32 字节对象放进
  同一 span 的相邻位置（实测相距 0x20），插 1 MB padding 也没用（大小对象
  不同 span）。要证明"靠指针跳过去"，必须用**合成地址**（`pointer_test.go`）。
  ⚠ 另一个坑：Go 在 Windows 上把堆放在 `0xc000000000`，**超出原版 chase 的
  用户态上限 `0x7ffffffeffff`** —— 用真实堆地址做追击测试会因"不像用户指针"
  而假失败。合成地址要取 `0x10000000` / `0x20000000` 这类值。
- ❌ **不要用"200 个样本 + 硬阈值"写概率性测试**。`TestScoreRejectsRandom`
  原来 `okCount > 2 / 200`，实测单样本误判率 0.125%（Poisson λ=0.25），
  `P(X>2)≈0.2%` —— 全量回归里偶发红灯，而代码没问题。
  概率性测试一律**固定种子 + 放大样本 + 留 5 倍以上余量**。
- ❌🔴 **不要在 `freeze` 之前等固定时长收候选**（第十四轮修的就是这个）。
  原来是 `time.NewTimer(1500 * time.Millisecond)`，白等 1.5 秒，
  而私钥只活一次 RTT（几十毫秒）。现在走 `collectBatch` + `keyBatchQuietGap=12ms`。
  由 `TestCollectBatchDoesNotWaitFixedTimeout` 钉死（单候选必须 < 200 ms 返回）。
- ❌ **不要删掉「抢跑延迟」这行日志/报告**（`pubSeenAt` → `keyDiagLag`）。
  它是判断"没找到"到底是方法不行还是抢晚了**唯一**的量化依据。
- ❌ **不要把 `pubSeenAt` 改回 `CompareAndSwap(0, …)` 只在第一次写**。
  一次运行可能有多次握手（换图/重连/换服务器），卡住第一次会让后面每次
  的延迟都算成几分钟，指标直接失效。用 `Store`（每次覆盖）+ `Swap(0)`（取走）。
- ❌🔴 **不要删掉 `judgeNeighborhood` 那行「└ 判读」**。
  19:10 / 19:46 两次现场都打出了「公钥紧跟 32 字节全 0」这个形状，
  两次都要靠人盯十六进制才看出来 —— 等于没有。必须让程序自己下结论。
- ❌ **不要给指针槽位的 dump 传 `MarkLen=0`**。槽位是 8 字节的指针，
  标 32 字节会让报告里 ▶ 覆盖到邻居字段，看图的人会以为槽位是 32 字节。
- ❌ **不要用伪造的 `Region{Base: addr &^ 0xFFF}` 渲染槽位头部**。
  那会打出 `TYPE_0x0 … + 0 B`（19:46 报告里全是这样）。用 `regionOf(regions, addr)`。
- ❌🔴 **不要把指针反查挪到「其余副本」暴力校验之后**（第十一轮犯过）。
  `runKeySearch` 一次要吃满 `-key-budget`（默认 1200 s），排在它后面的级别
  在用户 2 分钟关窗口的情况下**一次都跑不到**。18:47 现场就是这样：
  报告里连「指针反查」这一行都没有，不是没命中，是根本没跑。
- ❌🔴 **不要把诊断字段攒到 `runKeySearch` 返回后再写**。用户随时会关窗口，
  已跑完的阶段结果会全部丢失（18:47 报告连"冻结了多久、抄了多少"都没有）。
  **每一级一跑完就 `recordKeyDiag`。**
- ❌ **不要为了"试多个候选"推迟 freeze**。候选预筛放在冻结+抄副本之后做；
  放在之前会把冻结推迟 20 秒，私钥很可能在这期间被客户端擦掉。
- ❌🔴 **不要裸调 `proc.FreezeFast()` / `proc.ThawFast()`** —— 冻结/解冻必须走
  `freezeRun(fz, hold, fn)`。`NtSuspendProcess` 的挂起计数**不绑定句柄**：挂起之后
  即使我们的进程崩溃/被杀，目标进程**仍保持挂起**，用户只能手动结束游戏。
  `freezeRun` 的四层解冻保证（defer / panic recover / 看门狗强解 / 重试 3 次）
  少一层就可能变成"用户游戏永久卡死"。由 `freeze_test.go` 的 8 个用例钉死。
- ❌ **不要把 `freezeHoldLimit`（6s）调大或删掉看门狗** —— 安全第一：宁可这次搜不到
  （再跑一次即可），也不能让游戏一直停着。看门狗到点强制解冻，哪怕 fn 还没做完。
- ❌ **不要在冻结窗口里塞全量兜底扫描** —— 冻结窗口只放「枚举区域 + 定位公钥 +
  第 1 级 ±64 KB 近邻」。第 2 级之后必须解冻后再跑（`runKeySearch(..., startStage=1)`）。
- ❌ **不要删掉「解冻失败」的三重提示**（`os.Stderr` + `em.emit("freeze_thaw_failed")`
  + 诊断报告 ⚠⚠ 双行）—— 那是用户唯一能知道"要手动结束游戏"的渠道。
- ❌🔴 **不要把握手公钥附近的扫描窗口裁到"命中点自己所在的那块区域"**。
  必须用 `nearRangesIn(hits, window, tag, regions)` 与**全部可读区域**求交。
  用户现场 6 处命中全在 16 KB ~ 216 KB 的小块里，旧实现把 ±1 MB / ±8 MB 裁成
  区域大小，三级窗口加起来只扫了 0.6 MB —— 等于没放大就跳到全内存兜底。
  由 `TestNearRangesIntersectsNeighborRegions` 钉死。
- ❌🔴 **不要把 `filterScan` 的逐字节滑动改回 `off += 8`**。私钥是原始随机
  32 字节，不保证 8 字节对齐，8 字节步长会漏掉 7/8 的偏移。旧测试能过是因为
  Go 的 `ecdh.PrivateKey` 结构体里还有一份**对齐**的内部副本被命中，
  埋进去的未对齐副本从没被检查。由 `TestScanRangesUnalignedKey` 钉死。
- ❌ **不要把预筛阈值调紧**（比如 `MinDistinct=28, MaxZeros=0`）。实测它把
  通过率压到 0.61%，但同时会漏掉 **14.3%** 的真私钥。默认 `{24, 2}`
  通过 6.36%、漏 0.010%。预筛只能降一个数量级，救不了全内存兜底。
- ❌ **不要删掉诊断报告的「命中性质」行**（`pubHit.Wire` / `wireLike`）。
  它是区分"报文副本"和"密钥材料"的唯一自动判据：公钥前面紧挨 `12 20`
  就是抓到的报文在内存里的拷贝，那附近不可能有私钥。
- ❌🔴 **不要把 X25519 校验放回冻结窗口里**。冻结期间只做 `takeSnapshot()`（读+拷贝），
  校验一律交给解冻后的 `memSnapshot.verify()`。用户现场实测：校验放在冻结里时，
  6 秒预算被 43 万次校验吃光，只读了 0.44 MB 还被截断。
- ❌ **不要把 `scanPub` 改回单线程**。它就在冻结窗口里，7.6 GB 单线程 2.23 秒
  = 游戏白冻 2.2 秒。必须用 `numWorkers()` 并行分发（按 8 MB 切块）。
- ❌ **不要省掉 `takeSnapshot` 里的深拷贝**（`append([]byte(nil), buf[:n]...)`）。
  `proc.ReadAt` 的 buf 每轮复用，浅拷贝会让整份快照变成同一块内存的内容。
- ❌ **不要删掉冻结摘要里的「抓取 X」和「副本校验：…」两段** —— 那是判断
  "到底抓了多少、校验了多少"的唯一依据。
- ❌ **不要把冻结窗口内第 1 级搜索的 deadline 改成 `freezeHoldLimit`**。
  必须留 `thawReserve`（700 ms）余量，否则慢机器上会顶到看门狗强制解冻。

- ❌ **不要把快照上限缩回「命中点 ±8 MB」**。用户现场 6 处命中 ±8 MB 只有
  64 MB，占可写区 7068.9 MB 的 **0.9%**。抓取是 memcpy 级别、几乎免费，
  上限由 `-snap-mb` 控制（默认 512 MB），不要为了"省时间"把它调小。
- ❌ **不要让 `scanBufferStat` 对高熵段退化成逐字节**。预筛的判据是"像不像随机
  数据"，高熵块通过率≈97%，按 1 字节步长 1 MB 要 38 秒（X25519 实测 38.6 µs/次），
  一块就能吃光预算。必须按 64 KB 分段探测、超 1/10 通过率就降级 8 字节步长，
  并且把降级块数报进 `scanStat.summary()`。
- ❌ **不要整块一刀切判高熵**。一个 1 MB 块里只要有一小段压缩数据，整块降级
  就会漏掉其余部分里非对齐的私钥。必须 64 KB 分段。
- ❌ **不要把「邻域副本」「其余副本」合成一段校验**。邻域先跑完，"私钥在不在
  公钥旁边"才有 1 分钟内的答案；合起来跑会让这个判断拖到几十分钟之后。
- ❌ **不要以为「其余副本」是重复劳动而删掉**。副本保存的是**冻结那一刻**的字节；
  解冻后私钥若已被擦除，直接扫目标进程永远看不到它，只有副本里有。
- ❌ **测试 fixture 不要用 `byte(i % N)` 周期填充当"低熵内存"**。周期填充在
  32 字节窗口里 32 个不同值、零字节≈0，对预筛来说和随机数据一样不可筛
  （通过率 100%），会被判成高熵降级 —— 与真实堆内存（0.3%）正好相反。
  一律用 `fillRealistic()`（零填充 + 每 8 字节一个典型堆指针）。
- ❌ **不要让 `truncated` 决定 `startStage`**。快照撞到 512 MB 上限被截断，
  恰恰说明它抓得很满；把它当"没抓成"而回退到从头扫，会让邻域那几十 MB
  白扫一遍（17:27 现场：50.7 MB / 882 万次校验 / 1m8s）。判据只看
  「邻域段是否真抓到且没超时」：`snap.primary > 0 && frozenNear.bytes > 0 && !frozenNear.deadline`。
- ❌ **`runKeySearch` 每一级都要 `subtractRanges(..., done)`，一级都不能漏**。
  17:27 现场：第 4 级 `fullRegionRanges(pubHits, ...)` 没扣 `done`，
  把「其余副本」刚校验过的 450.8 MB 又扫了一遍，白花 **2m38s**。
  第 5 级扣了、第 4 级漏了 —— 这种"只漏一级"最难发现，加新一级时照抄
  `subtractRanges` 再写。
- ❌ **不要只探块开头 16 KB 就判高熵**。17:27 现场：区域扫描 0.6 MB 做了
  58.9 万次校验（通过率 94%）却 `高熵降级 0 块` —— 那几片区域"头部是结构体、
  后面全是随机"。必须 64 KB 段内分散取样 4 个 4 KB 窗口（位置 0/¼/½/¾），
  少于 4 个就退化成"只看头部"。
- ❌ **报告里必须写「本次搜索用」的公钥**。一次运行可能抓到多次握手，
  `提取到的公钥` 记第一次、命中点 dump 属于最后一次，两者不同时用户会
  拿 A 的公钥核对 B 的上下文，得出"命中点不对"的错误结论。只有两次 pub
  不一致时才打警告，别每份报告都刷一行。
- ❌ **不要用 `snap.primary > 0` 当"邻域已经校验过了"**。`takeSnapshot` 里
  `s.primary` 是在遍历到第 `primaryCount` 段时**就**记下的下标；段内如果发生
  短读（`proc.ReadAt` 失败 → `s.shortRead++` → `continue`）或尾部不足 32 字节
  （`want < 32` → `break`），这一段只覆盖了一部分，而 `primary` 仍然 > 0。
  用它当判据 → 前三级邻域扫描被**静默跳过**：不报错、日志还写「已在冻结副本里
  覆盖（跳过重复扫描）」，然后一路扫到 GB 之外，最后报告「未找到」。
  必须逐段核对：`snap.primaryRanges()` + `coversRange()`，每个命中点的
  `±snapshotWindow` 与可读区求交后要**完整覆盖**才允许跳过。
- ❌ **走到"邻域没盖全"这条路时，前三级也必须 `subtractRanges(..., done)`**。
  否则就退化成第八轮那种「邻域扫两次」（17:27 现场白花 1m8s）。
- ❌ **不要把 `nearStages` 的序号写死在测试里**。第十轮补了 ±8 KB 之后
  `startStage=1` 已经不再是「1 MB」，两条老测试因此假失败。一律按
  `nearStages` 的下标算。
- ❌ **不要用 hook / 注入 / 写内存去拿密钥** —— 原版 v2.0.5 字节级零 hook
  （`SetWindowsHookEx` / `CreateRemoteThread` / `WriteProcessMemory` / `VirtualProtectEx`
  / `VirtualAllocEx` / `NtCreateThreadEx` 全 0 命中）。而且 CS2 的 Trusted Mode 是
  **机制性硬门槛**：注入模块会让信任模式失效，进不了 VAC 安全服务器。我们的方案
  必须是外部、只读、不注入、不建远程线程、不写内存。

- ❌🔴 **不要把 `keyBatchQuietGap` 调回 12 ms 或更大**。它是 freeze **之前**的死等：
  20:18 现场「握手→搜索」19 ms 里有 12 ms 就是它，而同一份报告里 2 处命中点的
  `+32` 已经全 0（冻结那一刻的状态）—— 客户端在 19 ms 内就把私钥清零了。
  候选是同一个收包回调里连续投的（相隔几微秒、通道 16 缓冲、投递方不阻塞），
  1 ms 已有 3 个数量级余量。由 `TestKeyBatchQuietGapIsTiny` 钉死（上限 2 ms）。
- ❌ **不要删「握手→冻结延迟」这一行，也不要把 `freezeOutcome.FreezeAt` /
  `FreezeCost` 去掉**。「握手→搜索」只量到 `searchKey` 进门，那时进程还在跑；
  `freezeRun` 是先 `NtSuspendProcess` 再跑闭包，所以 `FreezeAt` 才是计分点。
  两行之差 = 等候选 + 挂进程，是下一轮唯一能指导优化的数。
- ❌ **不要在 `formatSlotDump` 里把 `snap` 传 nil 了事**（`quickPointerPass`
  那条路确实没有副本，是唯一例外）。槽位是从冻结副本里反查出来的，
  用活内存渲染会得到「槽位值 = 0x0」这种看着像 bug 的结果（20:18 现场）。
  `snapRead` 只在同一 chunk 完整覆盖时返回，别改成"部分覆盖也返回"。
- ❌ **不要用 clamp 形态之外的"更强预筛"去压兜底时间**。兜底是纯算力墙
  （实测 19 万次 X25519/s，现场已跑到 90%），唯一能压的只有窗口数；
  而 clamp 过滤已被上一条禁止（会静默丢掉 31/32 的真私钥）。
  正确做法是承认它扫不完，把预算花在"更早冻结"上。
- ❌ **不要给兜底那一级报「按字节线性外推」的 ETA**。它不是 IO 受限，
  按 MB/s 外推会得出 49 分钟这种数，看起来像还能等。必须用
  `x25519ChecksPerSec` / `x25519PassRate` 算，并在扫不完时直接说扫不完。

### ✅ hint 快路径已落地（2026-10-18）—— 这是最重要的一条

**背景**：用户实测原版未被检测到；反汇编确认原版 `FreezeFast` 就是一次
`NtSuspendProcess(p.Handle)`，和我们完全一样。所以**冻结不是封号主因**，
真因是冻结期间的读量（原版 32 字节 vs 我们 7.5 GB）。

**原版调用图**（`xref.py` 按函数区间反汇编得出）：

```
main.main.func6.3  → parseHandshake → FreezeFast → time.AfterFunc(兜底解冻)
                   → probeHint（只读 32 字节）→ 仅 miss 才 findPrivWithHints
                                                   (scanHints→scanAnchors→scanWindows)
                   → func6.3.2 → ThawFast
```

**我们的实现**（`startKeySearch` ⓪ 位置）：

```
⓪ probeHintsFast(cand)   ← 新增。LoadHints → ProbeHints → 命中即 return
① searchKey(...)         ← 原全量扫描，只在 hint 全 miss 时走
② 后续握手同样先 probe 再 searchKey
```

**你拥有/改动的文件**：
- `internal/keyfind/hintstore.go`（新增）
- `internal/keyfind/hintstore_test.go`（新增）
- `internal/keyfind/keyfind.go`（`Hint` 扩字段 + `ProbeHints`）
- `cmd/collector/main.go`（`-hints` / `probeHintsFast` / `rememberHint`）
- `cmd/collector/keybatch_test.go`（`TestDefaultFreezeIsOff` 改写 + 2 个新测试）

**硬规则（违反即回归）**：
- ❌ **绝不把私钥写进 hints.json**。`SaveHints`/`LoadHints`/`MergeHint` 三处强制清空，
  `TestHintStoreNeverPersistsPriv` 钉死（含"手工塞进去也会被清掉"）。
- ❌ **快路径不要加冻结**。读 32 字节不需要冻结；原版冻结是因为它紧接着要抄副本。
- ❌ **不要把 hint 落空当错误**。ASLR 会让地址失效，正确行为是静默退回全量扫描。
- ❌ **不要删 `-hints` 标志**。`TestHintsFlagExists` 就是防这个 ——
  删了等于每次运行都读 7.5 GB，正是被检测的那个特征。
- ❌ **不要把 `-freeze` 的帮助文本改回"冻结=封号"**。那是已推翻的归因，
  会让人去改冻结策略而不是改读量。`TestDefaultFreezeIsOff` 要求文本里出现「读量」。

**残余缺口（下一轮该做的）**：
1. 第一次运行仍全量扫描。
   🔴 **纠正（2026-10-19 实证）**：原版**没有**编译期硬编码 hint ——
   `probeHint` 的 hints 是运行时 slice（`[keySearch+0x30/+0x38/+0x40]`），
   `.data` 里 11 个候选全是巧合（`Addr==Dist` 重复填充 / 十进制常量表），
   `main.rememberHint` 被内联。**原版第一次也必然全量扫描**，
   差别在 `readBlock` 批量读 + `deadlineExpired` 单次读超时。
2. hint 地址跨会话存活率：工具已就绪（`-hints-info`），缺真机两局实测数据。
3. `memscan.ReadAt` 的单次读超时（原版 `deadlineExpired`）还没接。

## ✅ 相对偏移 + `-hints-info`（2026-10-19 追加）

**为什么加**：ASLR 会让 `hints.json` 里的绝对地址失效。失效后不能只是"退回全量扫描"，
还要能按相对量把地址重算出来。

**两轮 probe**：

```
第 1 轮 ProbeHints(hs)              直接用绝对地址，零枚举（同局内最可靠）
第 2 轮 ProbeAddrs(HintCandidates)  仅第 1 轮全 miss 才枚举区域，按下面两种相对量算候选
```

| 相对量 | 算法 | 用途 |
|---|---|---|
| `ModuleOff` | `addr - ModuleBase()`，`ModuleBase` = `MEM_IMAGE` 里基址最低者 | 私钥在 cs2.exe 映像内 → RVA 就是稳定偏移 |
| `RegionOff` | `addr - 区域.Base`，配 `RegionSize/Protect/Type` 指纹 | 私钥在堆里 → 靠指纹重新认出同类区域 |

候选去重 + `as-is` 必排第一 + 同指纹区域最多 8 个（`maxRegionCands`）。

**你拥有/改动的文件**（本轮新增）：
- `internal/memscan/process.go`：`RegionOf()`、`(*Process).ModuleBase()`
- `internal/keyfind/hintstore.go`：`HintCand`、`MakeHint()`、`HintCandidates()`
- `internal/keyfind/keyfind.go`：`ProbeAddrs()`、`ProbeHintsResult.Source`
- `cmd/collector/main.go`：`-hints-info` 标志 + `runHintsInfo()` + `yesNo()`
- `internal/keyfind/hintstore_test.go`：8 条相对偏移用例（`TestRegionOf` / `TestMakeHint*` /
  `TestHintCandidates*` / `TestHintCandidatesModuleRebase` / `TestHintCandidatesRegionRebase`）

**硬规则（本轮新增）**：
- ❌ **`-hints-info` 只准用 `VirtualQueryEx`**（`OpenForQuery` = `0x400`）。
  它连 `PROCESS_VM_READ` 都不申请 —— 它是自测工具，绝不能变成读内存的入口。
- ❌ **不要把 `region_off` 候选无限展开**。同指纹区域可能有几千个，
  必须用 `maxRegionCands=8` 截断，否则快路径自己变成扫描。
- ❌ **`as-is` 必须排在候选第一位**。同局内它命中率最高，排后面等于多读。
- ❌ **去重不能省**。学习时和查询时 `moduleBase` 相同时，`module+off` 算出来正好等于 `as-is`，
  不去重就会读两遍同一个地址（`TestHintCandidatesOrderAndDedup` 钉死）。

**验证命令**：

```bash
export MSYS_NO_PATHCONV=1 GOROOT='D:\csleida\1\2026-10-13\tools\go'
cd /d/csleida/1/2026-10-13/rebuild/cs2radar
$GOROOT/bin/go.exe test ./internal/keyfind/ -run 'Hint|ProbeHints|RegionOf|MakeHint|DescribeHints' -v   # 20/20
./dist/capture.exe -hints-info                    # 空表时给提示；有表时给四选一结论
./dist/capture.exe -hints-info -pid <任意pid>     # 验证输出格式
```

**实测输出样例**（explorer.exe 当靶子）：

```
当前进程：pid=2472，可读区域 5093 个
当前模块基址：0x3380000
【1】学习时
  地址        0x140008000
  模块基址    0x140000000  → RVA 0x1010000
  区域        0x140008000 + 0x1000  (size 1.0 MB, protect 0x4, type 0x20000)
  当前进程里：
    as-is       0x140008000  可读=否
    module+off  0x4390000  可读=否  (RVA 0x1010000)
    region+off  同指纹区域 0 个（区域布局变了）
  结论：两种相对量都落不到可读区域 → 私钥在会移动的堆块里，hint 只能同局内用。
```

## 🔴 符号表必须和 exe 配套（2026-10-19 踩坑，会白折腾半天）

`source/` 下两个 exe：

| 文件 | 大小 | nfunc | 有 `main.probeHint` |
|---|---|---|---|
| `capture.exe` | 3.8 MB | **3,816** | **有** `0x1799a0` |
| `CS2radar-v2.0.5.exe` | 9.5 MB | **7,416** | **没有** |

后者是**卡密验证 + 密码窗口外壳**（`main.applyCardVerification`/`main.showPasswordWindow`/
`main.paintWindow`），里面没有采集逻辑。拿它的 `.text` 套 `capture.exe` 的符号表，
反汇编会得到满屏乱码（`add al,ch` / `lock dec dword ptr [rax-0x73]`），
然后误判成「符号表解析坏了」。

**配对判据**：`.text` 的 `vsz` 必须和 functab 末项 `entryoff` 吻合
（capture `0x19ba00` vs `0x19b960`；CS2radar `0x373000` vs `0x372fc0`）；
再抽 5 个函数看入口是不是 Go 序言（`4c 8d a4 24 …` / `49 3b 66 10`）。
capture.exe 序言命中率 62%（剩下是叶子/nosplit 函数），接近 0 就是配错了。

**验证调用图的双路交叉**：`capstone` 逐函数反汇编 + **原始字节扫 `E8 rel32`**。
实测 capture.exe：`call probeHint`=1 处(`0x183980`)、`findPrivWithHints`=1 处(`0x18460c`)、
`scanHints`=1 处(`0x17be93`)、`scanAnchors`=1 处(`0x17d022`)、`scanWindows`=1 处(`0x17db01`)。
