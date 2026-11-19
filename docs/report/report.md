# CS2雷达客户端 v2.0.5 逆向分析报告

**目标**：`C:\Users\flare\Desktop\csleida\CS2雷达客户端-v2.0.5.exe`（FLARE-Win10 虚拟机内）
**问题**：① 软件如何获取"进程密钥"；② 卡密验证机制
**日期**：2026-10-13　**案例目录**：`D:\csleida\1\2026-10-13\`

---

## 0. 大白话结论

**① 进程密钥（连接密钥）怎么拿**

软件不是"读某个配置/注册表拿到密钥"，而是**用暴力搜索从 `cs2.exe` 进程内存里挖出一个 32 字节的 X25519 私钥**：

1. 先从游戏握手里解析出 **32 字节 X25519 公钥**（手写 protobuf 解析器 `parsePB` + `parseHandshake`，靶子）；
2. 枚举 `cs2.exe` 的所有可读内存区域；
3. 用三条路径产生 32 字节候选：
   - **hint 路径**（快）：上次成功地址的缓存（`addr`/`dist`）直接探测；
   - **anchor 路径**：按已知字节锚点定位，再按分数排序；
   - **window 路径**：滑动窗口全量扫；
4. 每个候选跑 `verifyPriv`：**用候选私钥做 X25519 标量乘推导出公钥，和目标公钥逐字节比对**，相等即命中；
5. 命中后 `check` 提交结果 → 触发一次性回调 → 日志 `Connection key verified and passed to parser` → 事件 `key_ready`。

搜索期间会**短暂冻结/解冻游戏线程**（`SuspendThread`/`NtResumeProcess`，`FreezeFast`/`ThawFast`），失败时打印 `游戏恢复调用未成功，请立即停止工具`。

**② 卡密验证**

不是"把卡密明文发给服务器比对"，而是**设备密钥签名 + 卡密哈希 + 一次性挑战**：

1. 首次运行生成**按设备唯一的 Ed25519 密钥对**（`crypto/ed25519.GenerateKey`），用 **Windows DPAPI** 加密存到 `%AppData%\CS2Radar\device.bin`（本次实测已解密，见 §3.1）；
2. 校验时先 `POST /api/client/challenge` 取回 **32 字节随机 challenge**；
3. 把 challenge、**`sha256(upper(trim(卡密)))`**、设备 ID、设备公钥等拼成字符串：
   `radar-login-v1\n<challenge hex>\n<s1>\n<s2>\n<s3>\n<flag>\n<i1>\n<i2>`
4. 用**设备私钥 Ed25519 签名**，base64 后放进请求头 `X-Radar-Signature`；
5. `POST /api/client/check`（登录时是 `/api/client/login`）→ 服务器据此同时判定"卡密有效性"和"设备绑定"，返回 `ok/status/expiresAt/afterRebind/rebind/rebindDays/...`；
6. 需要换绑时弹窗（`确认换绑`/`换绑将扣除 %d 天`/`原电脑将停止服务`）。

服务器：`https://154.12.82.177`；本地雷达页：`http://127.0.0.1:8766`。

---

## 1. 目标与产物

| 产物 | 路径 | 大小 | SHA-256 |
|---|---|---|---|
| 原始客户端 | `source/CS2radar-v2.0.5.exe` | 9,525,152 | `4d47fdc79fc7fe047166ed5ef8d4daf8bba32d14482ea51007a88ba07feadee3` |
| 内嵌采集器（覆盖层解出） | `source/capture.exe` | 3,802,624 | `fcc23d3cab1ddc0bc9b48d9fe7518791b9049b7c7cc36438f51310252ea3ebf0` |
| 设备凭据文件 | `source/device.bin` | 342 | `6b60097a19fbdfed6b1702428a4dd2ac444e35de05664876c83fc391f9f8fd2b` |

分析工具链（本案例目录内）：`source/godis2.py`（通用 Go 反汇编标注器，PE 节表自动解析）、`source/findrefs2.py`（字符串引用反查）、`source/dpapi_probe.py`（VM 内 DPAPI 解密）、`source/verify_devkey.py`。

符号表：`logs/gosyms.json`（启动器 7,384 函数）、`logs/gosyms_capture.json`（采集器 3,816 函数）。均通过**手写 pclntab 解析器**获得（GoReSym 对 go1.27 报 `no valid pclntab found`）。

---

## 2. 软件结构

单一 Go 1.27.0 PE32+ x64，模块路径 `local/cs2-radar`，可执行名 `radar-launcher`。启动器**不是** WebView 壳，而是**纯 Win32 原生 GUI**（`createWindowAt`/`paintWindow`/`buttonProcedure`/`editProcedure`/`drawButton`/`utf16`）。

文件尾部 `0x778000` 起是 1,693,600 字节覆盖层，`0x778007` 处为 gzip 流，`zlib.decompressobj(31)` 解出 **3,802,624 字节的内嵌采集器**（MZ 头）。运行期由 `clientbundle.Prepare` 释放到
`%LOCALAPPDATA%\cs2-radar-runtime-<随机串>\capture.exe`（目录用 SDDL `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;...)` 收紧 ACL）。

### 包分工（非标准库符号统计）

| 二进制 | 项目包 |
|---|---|
| **启动器** | `agent`(30) `authwire`(5) `buildconfig`(1) `clientbundle`(8) `clientupdate`(7) `device`(12) `product`(2) `transport`(3) + `main`(58) + 第三方 `github.com/coder/websocket` |
| **采集器** | `capturefilter`(3) `memscan`(17) `pcapdev`(20) `transport`(3) + `main`(71) |

即：**采集器管"内存扫描 + 抓包 + 密钥搜索"，启动器管"授权 + UI + 内嵌件管理 + 管道读取"**。

### 采集器 ↔ 启动器 通道

- 采集器从 **stdin** 读命令（`bufio.(*Scanner).Scan`），往 **stdout 匿名管道**写事件；
  字符串自述：`Start this collector through CS2 Radar Launcher; a pipe is required.`
- 事件 = NDJSON：`main.event` 用 `encoding/json/v2.Marshal` / `(*Encoder).Encode` 组装，经 `transport.Write` 写出（帧协议见 §4.3）。
- 原始 UDP 包经 `transport.PackUDP` 一并写入。
- 事件字段：`event key pub dev ipc pid gbe raw priv auto udp4 scan addr dist conn_id captured_at regionBytes pcapDropped suspended message backend`；
  事件名：`key_ready` `pub_check` `key_error` `capture_ready` `capture_stats` `capture_error` `game_error` `network_delay` `stopped` `resumed`。
- 采集器自述：`Stream packets and keys to the launcher's anonymous pipe`。

---

## 3. 进程密钥（问题 ①）

### 3.1 判定函数 `main.verifyPriv`（0x179ea0）

```go
// 反汇编还原（crypto/ecdh.(*x25519Curve).NewPrivateKey @0x179f00）
func verifyPriv(priv []byte, targetPub []byte) bool {
    if len(priv) != 32 || len(targetPub) != 32 {   // cmp rbx,0x20 / cmp rsi,0x20
        return false
    }
    k, err := ecdh.X25519().NewPrivateKey(priv)     // 32 字节私钥
    if err != nil {
        return false                                 // test rbx,rbx -> jne fail
    }
    pub := k.PublicKey().Bytes()                     // 32 字节公钥
    return len(pub) == 32 && bytes.Equal(pub, targetPub)  // runtime.memequal
}
```

这是整个"进程密钥"判定的**唯一真值来源**：私钥→公钥推导 + 32 字节比对。

### 3.2 靶子公钥来源 `main.parsePB` / `main.parseHandshake`

`parsePB`（0x178e20）是**手写 protobuf 解析器**：varint 解 tag → `fieldNum = tag>>3`（拒绝 0 与 >0x7d0=2000），wireType 0/1/2/5；输出条目数组，**每条固定 48 字节**：

| 偏移 | 含义 |
|---|---|
| +0x00 | fieldNum |
| +0x08 | wireType |
| +0x10/+0x18/+0x20 | value 切片（ptr/len/cap，wireType=2 时）|
| +0x28 | 原始值（wireType=0/1/5）|

`parseHandshake`（0x179440）要求 `data[0] == 0x22`（field 4 + LEN），然后逐层导航，返回结构 `hsInfo`：

| 偏移 | 内容 |
|---|---|
| +0x00 | field 4 子消息原始字节（E1[f4]）|
| +0x18 | field 7 子消息原始字节（E1[f7]）|
| **+0x30** | **32 字节 X25519 公钥**（路径 `root.f4→f4→f2` 与 `root.f7→f1→f2`，长度必须恰为 `0x20`）|
| +0x48 | field 3（wireType 1，64 位）|
| +0x50 | field 1（wireType 5，32 位）|

导航路径上的长度校验：`cmp qword ptr [r8+0x18], 0x20 / jne`（候选 entry 的 value 必须 32 字节）。

### 3.3 搜索算法

`main.(*keySearch)` 状态机（`self` 字段偏移）：

| 偏移 | 含义 |
|---|---|
| +0x10/+0x18/+0x20 | 目标公钥 `[]byte`（ptr/len/cap）|
| +0x28/+0x30/+0x38 | `time.Time` 扫描截止时间 |
| +0x40 | int32 **命中标志** |
| +0x50 | `sync.Once`（完成通知）|
| +0x5c | int32 **失败标志** |
| +0x60/+0x68 | error 接口 |
| +0x70 | 完成回调 |
| +0x78 | 读取次数　+0x80 读取字节数　+0x88 块数　+0x90 短读次数　+0x98 校验次数（均 atomic）|
| +0xa0 | `sync.Mutex` |
| +0xc8… | 命中结果（区域 start/end/size/buffer）|

- **`read` / `readBlock`**：带缓存的进程内存读取层，块内命中走 `runtime.memmove`，越界回落到 `read`（进而调 `memscan.(*Process).ReadAt` 接口方法 `itab+0x18`）。
- **`probeHint`**（0x1799a0）：在 hint 地址读 32 字节，`n==0x20` 且 `verifyPriv` 通过 → 返回该 32 字节并打标 **`matched`**，同时记录 `addr`/`dist`。
- **`chase`**（0x17a860）+ `chase.func1`（0x181180）：**指针链遍历**。读 8 字节当指针 → 校验落在 `[0x10000, 0x7FFFFFFFFFFF]`（`lea rdx,[rbx-0x10000]; cmp r12,rdx; jb`，`r12=0x7ffffffeffff`）→ 再读该地址 32 字节 → 交给 `check(..., "pointer")`。步长 8，先试 `n-0x18`。
- **`anchor`**（0x17ab60）：以锚点为中心做 chase，标签 `adjacent`。
- **`scanHints`**（0x17af40）：hint 扫描，标签 `hint`/`udp4`，用 `0x%x`/`addr`/`dist`。
- **`scanAnchors`**（0x17b280）：多 worker（`WaitGroup`+`newproc`+`selectgo`+`time.Timer`），结果按分数 `sort.Slice` 排序；失败 `no_anchor`。
- **`scanWindows`**（0x17b6e0）：窗口扫描，标签 `window`。
- **`check`**（0x17a4e0）：**候选提交器**。`verifyPriv(self+0x10..0x20, cand, 0x20)` → 加锁 → 若 `+0x40 != 0` 直接返回（已命中）→ 存区域（`abs(rsi-r8)` 为长度、`growslice`+`memmove` 复制）→ `xchg [self+0x40], 1` → `sync.Once.Do(check.func1)` → 解锁 → 调 `self+0x70` 回调。
  - `check.func1`（0x181140）= `runtime.closechan`（关闭"命中"通道）。
- **`recoverWorker`**（0x17a100）：`runtime.gorecover()` 包装；panic 时写 error **`key scan worker failed`**、置 `+0x5c=1`、跑 `sync.Once`（`recoverWorker.func1` = `closechan`）。

### 3.4 命中后的去向

`main.main.func5`（采集器）引用字符串 **`Connection key verified and passed to parser`**，并发出事件 `key_ready`；同时通过 `main.event` 上报 `pub_check` / `key_error`。密钥与抓到的包一起经匿名管道流给启动器。

### 3.5 抓包侧

- `internal/pcapdev`：`SetBackend(auto|raw|npcap)`、`Available`、`Devices`、`Open`、`SetBuffer`、`SetMinToCopy`、`SetLocalUDPFilter`、`SetFilter`、`Read`、`Stats`、`UDPPortOwned`、`rawDevices`、`openRaw`。
- 过滤器字符串：`ip and udp`、`ip and udp and (`；Npcap 路径 `C:\Windows\System32\Npcap\wpcap.dll`；错误 `Npcap capture library is unavailable`、`Capture backend: auto, raw, or npcap`、`No active capture adapter; choose one with --dev`。
- `internal/capturefilter`：`UDP`、`(*Filter).Match`、`(*Filter).Discover`。
- 目标进程名：**`cs2.exe`**（`memscan.FindPid`）。

### 3.6 内存扫描的"安全开关"

字符串自述（可用于判断版本行为）：
- `Query memory region counts only; do not read memory or suspend the game`
- `Region metadata queried; no memory contents read, no suspension`
- `OpenProcess(pid=%d) `
- `VirtualQueryEx returned an empty region` / `VirtualQueryEx failed: %v`
- `no readable memory regions` / `region query limit reached`
- `游戏恢复调用未成功，请立即停止工具`

Windows API：`OpenProcess`、`VirtualQueryEx`、`ReadProcessMemory`、`SuspendThread`、`NtResumeProcess`、`CreateToolhelp32Snapshot`、`Process32FirstW/NextW`、`Thread32First/Next`、`Module32FirstW/NextW`、`CreateNamedPipeW`、`DuplicateTokenEx`、`SetEntriesInAclW`、`ImpersonateLoggedOnUser`、`RtlGetCurrentPeb`。

### 3.7 ⚠️ 一处必须修正的初判

二进制里同时出现 `AES-CBC`、`AnswerLength`、`header`、`answers`，一度看起来像"雷达自己用 AES-CBC 解密游戏包"。**字符串引用反查（`source/findrefs2.py`）否定了这个判断**：

| 字符串 | 唯一引用者 | 结论 |
|---|---|---|
| `AES-CBC` | `crypto/internal/fips140/aes.init.1` | Go 标准库自检常量，**非雷达代码** |
| `AnswerLength` | `vendor/golang.org/x/net/dns/dnsmessage.init` | DNS 库常量，**非雷达协议字段** |

即：**雷达本身不做 AES-CBC 解密**，它做的是"抓包 + 交出密钥/包"。

---

## 4. 卡密验证（问题 ②）

### 4.1 设备身份与 `device.bin`（已实证解密）

`internal/device`：

- `statePath()` = `os.UserConfigDir()` + `CS2Radar` + **`device.bin`**（`os.MkdirAll`）
- `loginPath()` = 同目录 + `sha256(TrimRight(login))` hex + `-login` + `.bin`（每卡密一份登录态）
- `Load()`：
  - 读注册表 `SOFTWARE\Microsoft\Cryptography` → **`MachineGuid`**，失败 → `无法识别本机设备`
  - `sha256("cs2-radar-device-v1:" + MachineGuid)` → 32 字节**设备指纹**
  - `readConfig(statePath())`；若不存在 → **`crypto/ed25519.GenerateKey`** 生成密钥对 → `writeConfig`
- `protect(data, mode)`（0x2cb4e0）：
  - `len(data)==0 || len(data)>0x4000` → `设备凭据损坏`
  - `mode!=0` → `CryptUnprotectData`；`mode==0` → `CryptProtectData`
  - 参数：description=NULL、**optionalEntropy=NULL**、reserved=NULL、promptStruct=NULL、flags=`1`(CRYPTPROTECT_UI_FORBIDDEN)
- `readConfig` = `os.ReadFile` → `protect(_,1)` → `json/v2.Unmarshal`（错误 `无法读取本机登录信息`）
- `writeConfig` = `json/v2.Marshal` → `protect(_,0)` → `os.CreateTemp(dir, ".radar-credentials-*.tmp")` → `Write`/`Sync`/`Close` → `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)`（原子替换）

**VM 内实测解密**（`source/dpapi_probe.py`，用户 `flare`）：

```
MachineGuid  = 3f969ad3-5a03-4c53-a027-85944947c056
sha256("cs2-radar-device-v1:"+MachineGuid) = bbbe856a6ef23b37bb37a395e6a8d7d28959dca4316c7c3fc4d70546eb988669
FILE device.bin len 342  magic 01000000        <- DPAPI blob 版本
  unprotect[no-entropy]  OK  plaintext=120 bytes
  unprotect[with-entropy] FAILED err=13        <- 熵未使用，MachineGuid 哈希只作设备指纹
明文：
{"server":"","card":"","key":"hdCbwlm+4PL5CkvThpdarN9aCoFpRGGNodbMPU7oTC6bMOWp4TsaJjhfP5Zm3tI/dLlsCgEXtxoKx/YVpWWN4w=="}
```

`device.bin` 头部 `01 00 00 00` + provider GUID `{df9d8cd0-1501-11d1-8c7a-00c04fc297eb}` 确认是标准 DPAPI blob；明文是 JSON，字段名与二进制里的 `json:"server"` / `json:"card"` / `json:"key"` 完全对应。

**`key` 是 64 字节标准 Go `ed25519.PrivateKey`（seed‖pub），已验证 seed→pub 推导一致**（`source/verify_devkey.py`）：

```
seed(32) = 85d09bc259bee0f2f90a4bd386975aacdf5a0a816944618da1d6cc3d4ee84c2e
pub (32) = 9b30e5a9e13b1a26385f3f9666ded23f74b96c0a0117b71a0ac7f615a5658de3
derived  = 9b30e5a9e13b1a26385f3f9666ded23f74b96c0a0117b71a0ac7f615a5658de3   MATCH: True
```

> 结论：**卡密的绑定锚点是"设备 Ed25519 密钥对"，不是 MachineGuid**。MachineGuid 只参与设备指纹；密钥对受 DPAPI（用户+机器）保护，拷到别的机器/别的用户都解不开。

### 4.2 挑战-签名协议

`internal/authwire`：

```go
// SignatureMessage @0x2c5ba0  （格式串 @0x385c9c，长度 0x23=35）
func SignatureMessage(cardKey, s1, s2, s3 string, flag bool, i1, i2 int64) []byte {
    k := strings.ToUpper(strings.TrimSpace(cardKey))
    h := sha256.Sum256([]byte(k))
    return []byte(fmt.Sprintf("radar-login-v1\n%x\n%s\n%s\n%s\n%t\n%d\n%d",
                              h, s1, s2, s3, flag, i1, i2))
}

// StreamMessage @0x2c5fc0
//   fmt.Sprintf("radar-stream-v2\n%x\n%s\n%s", challengeHex, s1, s2)

// RoomPasswordMessage @0x2c5da0
//   fmt.Sprintf("radar-room-password-v1\n%s\n%x", s1, challengeHex)

// RandomToken @0x2c5b40  = base64(crypto/rand.Read(32))
// ValidRoomID  @0x2c5f00  = base64 解码→再编码→memequal（规范化校验）
```

`agent.signedLogin`（0x2d4b20）：

1. `agent.serverURL(raw)` 校验（scheme 必须 `http`/`https`、必须有 host/port、拒绝 IPv6 与路径；错误 `请输入正确的服务器地址`）
2. `agent.post(ctx, base, "/api/client/challenge", ...)` ← 长度常量 `0x15`=21，**无请求体**
3. 取回 **32 字节 challenge**（`cmp rdx,0x20 / jb panicBounds`）
4. `base64(challenge)` → 组装 96 字节结构（5 个 string + 1 个 bool）
5. `SignatureMessage(...)` → `crypto/ed25519.sign(dst64, priv, msg)` ← **priv 是调用方传入的设备私钥**
6. `base64(sig64)` → 作为 `X-Radar-Signature` 头

`agent.post`（0x2d3780）：`json/v2.Marshal` → `runtime.concatstring2(base, path)` → `net/http.NewRequestWithContext("POST", ...)` → 头 `X-Radar-Request`、`Content-Type: application/json` → `(*Client).do` → 读体 → 状态 `0xc8`(200) 则 `Unmarshal` 成功体，否则 `Unmarshal` 错误体。

`agent.LoginDetails`（0x2d3f80）→ `signedLogin` 后 POST **`/api/client/login`**（长度常量 `0x11`=17）。
`agent.Check`（0x2d4740）→ `signedLogin` 后 POST **`/api/client/check`**（长度常量 `0x11`=17），响应为 **72 字节结构 = 4 个 string + 1 个 bool**。

其它端点：`/api/client/stream`（配 `X-Radar-Stream` 头）、`/client/latest.json`（更新检查，`clientupdate`）。

### 4.3 协议字段（从 Go 类型元数据提取的 JSON tag）

```
ack activatedAt afterRebind bindingVersion card code days device error
expiresAt initialRoomPassword key kind leaseSeconds message nonce ok
password path public rebind rebindDays roomID roomPasswordDefault
server sha256 signature size status token version
```

相关类型：`agent.Login`、`agent.LoginDetails`、`product.Auth`、`product.State`。
请求头：`X-Radar-Request`、`X-Radar-Signature`、`X-Radar-Nonce`、`X-Radar-Stream`、`Authorization`。

### 4.4 UI 侧流程

`main.begin`（0x2fc7e0）：
- `IsUserAnAdmin`；非管理员 → `ShellExecuteW("runas", exe, elevationArguments, ...)` 提权重启（`main.elevationArguments` 格式串 **`--connect --window-position %d %d`**）
- `device.Save`；`context.WithCancel`
- Win32 窗口文案：`请输入卡密`、`正在验证…`、`开始服务`、`停止服务`、`正在停止…`、`服务已停止`、`正在保存…`、`服务未启动`、`待激活`、`连接状态`、`卡密状态`、`到期时间`、`服务异常`
- 互斥体名 `CS2RadarClient-`；窗口类 `CS2Radar`；字体 `Microsoft YaHei UI`
- 采集未授权时提示 `采集需要管理员授权，请点击开始服务并允许授权`

`main.verifyCard`（0x2fc2a0）：读输入框 → `main.getText` → `strings.TrimSpace` → 存全局 → 置"验证中"标志 → `InvalidateRect`/`SetFocus`/`SetTimer` → `main.layoutWindow` → `runtime.newproc` 起 `verifyCard.func1`。

`main.verifyCard.func1`（0x309d80）：
`context.WithTimeout` → `agent.Check` → `errors.As`(取 `*agent.AuthError`) → 需换绑则 `main.rebindPrompt`（文案 `确认换绑`）→ 再 `agent.Check` → `device.Save` → `main.applyCardVerification` → `PostMessageW`/`EnableWindow`。

`main.applyCardVerification`（0x2fb160）：更新"卡密状态/到期时间/换绑后到期时间"等界面字段。

### 4.5 服务端错误码 → 中文文案（`product.State` / `product.Auth` 全表）

| 码 | 文案 |
|---|---|
| `waiting_client` | 请在绑定电脑上启动客户端 |
| `waiting_handshake` | 等待进入比赛 |
| `waiting_game` | 等待进入比赛 |
| `connecting_game` | 正在连接对局… |
| `reconnecting` | 正在重新连接… |
| （正常） | 运行正常 |
| `game_error` | 暂时无法连接对局，请重新连接比赛 |
| `network_delay` | 数据处理延迟过高，请重新连接比赛 |
| `capture_error` | 采集未能启动，请检查网络及管理员授权后重试 / 客户端内嵌采集程序不完整，请重新下载客户端 |
| `unauthorized` | 登录已失效，请重新登录 |
| `expired_card` | 卡密已过期，请更换卡密 |
| （卡密无效） | 卡密无效，请检查后重试 |
| `client_already_connected` | 该卡密已有客户端运行，请先关闭后再连接 |
| `insufficient_time` | 剩余有效期不足，无法换绑 |
| （已绑他机） | 卡密已在其他电脑绑定 |
| （已停用） | 卡密已停用，请联系提供方 |
| `invalid_room_password` / `room_password_error` | 房间密码错误 |
| （连接过多） | 观看连接过多，请关闭多余网页后重试 |
| （房间未生成） | 房间尚未生成，请先启动服务 |
| （密码校验） | 密码需为 6 至 64 个字符 / 两次输入的密码不一致 |
| （网络类） | 无法连接服务器，请检查网络 / 服务器暂不可用，请稍后重试 / 服务器响应异常，请重新连接网络 / 上传不稳定，请检查连接 / 服务繁忙，请稍后重试 |
| （采集类） | 采集数据中断，请重试 / 采集程序准备失败 / 请重新下载客户端后重试 |
| （环境） | 未知运行环境 / 开发环境只能连接本机服务端 / 生产环境必须配置远程 HTTPS 地址 |

换绑相关 UI 串：`换绑将扣除 %d 天`、`换绑后到期时间`、`原电脑将停止服务`、`是否确认换绑`。

### 4.6 其它

- `internal/buildconfig.Validate`：区分 `development`/`production`；`未知运行环境`、`服务器地址配置无效`、`开发环境只能连接本机服务端`、`生产环境必须配置远程 HTTPS 地址`（用 `url.splitHostPort` + `net.parseIP` + `IsLoopback`）。
- `internal/transport.Read`（启动器侧）：`io.ReadAtLeast` 读帧；错误 **`unsupported capture frame`** / **`capture frame too large`** → **长度前缀帧协议**。
- `internal/transport.Write`：错误 **`invalid frame`** → `writeAll`。
- 更新：`clientupdate.Check/IsNewer/DownloadURL/origin`，端点 `/client/latest.json`。

---

## 5. 可复现检查

```bash
# 1. 目标文件与覆盖层
cd D:\csleida\1\2026-10-13
"C:\Users\Administrator\.workbuddy-ai\binaries\python\envs\default\Scripts\python.exe" -c "import zlib;d=open(r'source\CS2radar-v2.0.5.exe','rb').read();o=zlib.decompressobj(31).decompress(d[0x778007:]);open(r'source\capture.exe','wb').write(o);print(len(o))"
# 期望 3802624，sha256 = fcc23d3cab1ddc0bc9b48d9fe7518791b9049b7c7cc36438f51310252ea3ebf0

# 2. 关键函数反汇编（需先有 gosyms.json / gosyms_capture.json）
PY="C:\Users\Administrator\.workbuddy-ai\binaries\python\envs\default\Scripts\python.exe"
$PY source/godis2.py --exe source/capture.exe --syms logs/gosyms_capture.json "main.verifyPriv"
$PY source/godis2.py --exe source/capture.exe --syms logs/gosyms_capture.json "main.(*keySearch).check"
$PY source/godis2.py --exe source/CS2radar-v2.0.5.exe --syms logs/gosyms.json "local/cs2-radar/internal/authwire.SignatureMessage"
$PY source/godis2.py --exe source/CS2radar-v2.0.5.exe --syms logs/gosyms.json "local/cs2-radar/internal/device.Load"

# 3. 字符串引用归属反查
$PY source/findrefs2.py        # 输出 logs/refs.txt

# 4. 设备密钥合法性验证
$PY source/verify_devkey.py    # 期望 MATCH: True

# 5. VM 内 DPAPI 解密 device.bin（需 VM 运行 + flare/102068）
#    PowerShell: vmrun -T ws -gu flare -gp 102068 copyFileFromHostToGuest D:\VM\FLARE-Win10\FLARE-Win10.vmx <src> C:\out\dpapi_probe.py
#                vmrun -T ws -gu flare -gp 102068 runProgramInGuest        D:\VM\FLARE-Win10\FLARE-Win10.vmx -interactive C:\Python313\python.exe C:\out\dpapi_probe.py
#    期望明文 120 字节 JSON，含 "key" 字段（见 §4.1）
```

---

## 6. 局限性

1. **未做动态验证**：本次全为静态分析 + 离线解密。`verifyPriv` 命中率、`scanHints` 缓存格式、`anchor` 具体锚点字节未在运行中的 CS2 上实测。
2. **签名消息的 3 个 string 与 bool/2 个 int 的确切语义未逐字确定**（受 Go 寄存器 ABI 与闭包传参影响）。已知第一个参数是卡密（`sha256(upper(trim(卡密)))`），其余疑为设备 ID / 房间 ID / 设备公钥 + 换绑标志 + 版本/时间戳，字段名可从 §4.3 的 JSON tag 推断，但未逐字节对齐。
3. **服务器侧不可见**：`154.12.82.177` 的接口实现、卡密库结构、换绑天数规则均未获取。
4. **`hsInfo` 的 field 3/field 1 语义未定**（64 位 / 32 位值，疑为协议版本与连接 ID）。
5. **未获取**：`-login.bin`（VM 内不存在，说明该机器从未成功登录）；服务器证书/HTTPS 配置（当前为明文 `https://` 但客户端不校验证书路径未验证）。
6. 采集器 `main.main` 的 flag 列表、`--dev` 参数语义、Npcap 与 raw 后端切换条件未逐一还原。

---

## 7. 下一步

1. **动态验证密钥搜索**：在 VM 内启动 CS2 → 启动客户端 → 用 x64dbg/Frida 在 `verifyPriv`(capture.exe 0x179ea0) 与 `keySearch.check`(0x17a4e0) 下断，记录候选命中地址与命中耗时，验证 §3.3 的 `[0x10000,0x7FFFFFFFFFFF]` 指针范围与 8 字节步长。
2. **抓包还原签名载荷**：用 Frida hook `crypto/ed25519.sign`（启动器 0x11f780）打印明文消息，逐字确定 `radar-login-v1` 的 3 个 string / bool / 2 个 int。
3. **服务端接口探测**（授权范围内）：对 `https://154.12.82.177/api/client/{challenge,login,check,stream}` 用固定设备密钥构造合法请求，观察响应字段与 `rebind`/`rebindDays` 语义。
4. **换绑逻辑**：抓 `rebindPrompt` 分支下第二次 `agent.Check` 的请求差异，确定"换绑确认"是如何在签名里表达的（对应 `json:"rebind"` / `json:"afterRebind"`）。
5. **`hsInfo` 字段语义**：在真实握手中比对 `parseHandshake` 输入输出，确定 field 3/field 1。
6. **合规/强度评估**：`app_secret` 级别的密钥未发现；客户端身份强度上限取决于设备 Ed25519 私钥的 DPAPI 保护强度（用户态 DPAPI，可用同用户身份解出，见 §4.1 实证）。

---

## 8. 进程访问方式与"检测规避"设计（补充分析）

> 本节回答"它是如何绕过检测从进程获取密钥的"。结论：**它不主动对抗反作弊，而是把自己做成"反作弊没理由检测"的形态——全程外部、只读、不注入、不写内存、不 hook 游戏代码。**

### 8.1 打开目标进程的权限（关键证据）

`memscan.openWithRights(pid, rights)`（capture.exe `0xe5d60`）内部就是 `OpenProcess(rights, FALSE, pid)`。全二进制只有两处调用：

| 调用点 | rights | 组成 |
|---|---|---|
| `main.main` `0x17f4f3` | **`0x400`** | PROCESS_QUERY_INFORMATION |
| `main.main.func4` `0x18643f` | **`0xC10`** | PROCESS_VM_READ(0x10) \| PROCESS_QUERY_INFORMATION(0x400) \| PROCESS_SUSPEND_RESUME(0x800) |

`0xC10` 就是整套规避设计的核心：**只要"读 + 查 + 暂停/恢复"三种权限**。
**从不申请** `PROCESS_VM_WRITE(0x20)`、`PROCESS_VM_OPERATION(0x8)`、`PROCESS_CREATE_THREAD(0x2)` —— 意味着它**物理上无法**写对方内存、无法在对方进程里分配/改保护内存、无法在对方进程里建线程，也就是**不具备任何注入能力**。

失败路径的错误串：
`OpenProcess(pid=%d) 失败：%v（尝试以管理员运行，或用 -pid 指定）`
→ 它**不尝试提权漏洞、不装驱动**，只是要求用户以管理员身份运行，或允许用 `-pid` 手动指定进程。

### 8.2 定位目标：250 ms 轮询 + 句柄按需开关

`main.main.func4`（`0x1861e0`）：
`time.NewTicker(0xee6b280 ns = 250 ms)` → 每 tick 调 `memscan.FindPid("cs2.exe")`（`CreateToolhelp32Snapshot` + `Process32FirstW`/`Process32NextW`，逐项 UTF16 比对进程名）→ pid 变化则 `(*Process).Close` 关旧句柄再 `openWithRights(pid, 0xC10)` → 成功发事件 `game_ready`（字符串 `Game process located`），失败发 `key_error`。
→ **不长期持有句柄**，目标不在/换 pid 就关掉。

### 8.3 读内存：最普通的 Win32 只读 API

- `memscan.(*Process).ReadAt`（`0xe64e0`）→ `syscall.(*LazyProc).Call` **5 个参数**（handle, baseAddr, buffer, size, &bytesRead）→ **ReadProcessMemory**。
- `memscan.(*Process).RegionsWithError`（`0xe5fc0`）→ **VirtualQueryEx** 循环枚举可读区域，带截止时间；相关串：`region query deadline reached`、`region query limit reached`、`VirtualQueryEx returned an empty region`、`VirtualQueryEx failed: %v`。
→ **不用驱动做物理内存读，也不用 `NtReadVirtualMemory`/`ZwReadVirtualMemory` 直接系统调用**（这两个串在二进制里不存在），走的是最标准、最"干净"的 API。

### 8.4 冻结/恢复：只为"读得干净"，不是反检测

- `FreezeFast`（`0xe5a80`）/ `ThawFast`（`0xe5c00`）：调用 Process 结构 `+0xa8`/`+0xb0` 两个 proc 槽，**单参数（进程句柄）**，且**返回 0 才算成功** → NTSTATUS 语义 → 即 **`NtSuspendProcess` / `NtResumeProcess`**（整进程挂起/恢复）。
- 另有一条按线程的路径：`OpenThread` + `SuspendThread`/`ResumeThread` + `Thread32First`/`Thread32Next` 枚举线程。
- `CloseThreadHandles`（`0xe58c0`）遍历两个线程句柄切片逐个 `CloseHandle` 并清零；`Frozen`（`0xe6620`）查询状态。
- 恢复失败的兜底提示：`游戏恢复调用未成功，请立即停止工具`。

→ 挂起的目的**只是避免"边读边变"导致密钥搜索命中率下降**；它本身**不是**反检测手段，反而恰恰是最容易被**内核级**反作弊注意到的动作（进程异常挂起）。

### 8.5 抓包：走 Npcap / raw socket，完全不碰游戏代码

- `pcapdev.Open` → `LoadLibraryW("wpcap.dll")` + `pcap_open_live`；`(*Handle).Read` → `pcap_next_ex`；另有 `pcap_compile`/`pcap_setfilter`/`pcap_setbuff`/`pcap_findalldevs`。
- `SetBackend(auto|raw|npcap)`、`NpcapAvailable`、`rawDevices`、`openRaw`、`sockaddrIPv4` → 无 Npcap 时退到原始套接字后端。
→ **完全不 hook cs2.exe 的网络代码**（不 hook `ws2_32` 的 send/recv、不注入模块），在内核驱动 / 原始套接字层旁路抓包。这是它不触发 IAT/inline-hook 完整性检查的关键。

### 8.6 它甚至专门提供了"不碰游戏进程"的开关

`main.main`（`0x17ef40` 起）注册的 flag：

| flag | 类型 | 二进制内原文说明 |
|---|---|---|
| `-dev` | string | Explicit Npcap device or description |
| `-backend` | string（默认 `auto`）| Capture backend: auto, raw, or npcap |
| `-ipc` | bool | Stream packets and keys to the launcher's anonymous pipe |
| `-duration` | duration | Stop after this duration |
| `-no-keys` | bool | **Capture without accessing the game process bytes**; incompatible with mutex flag mask |
| `-list-devices` | bool | List capture devices then exit |
| `-memory-info` | bool | **Query memory region counts only; do not read memory or suspend the game** |

- `-memory-info` 的自述就是"**不读内存、不挂起游戏**"；`-no-keys` 是"**完全不访问游戏进程内存**"。二者都走 `OpenProcess(pid, 0x400)`，只做区域元数据枚举。
- `-ipc` 会校验 stdout 是否为命名管道（`FileMode` bit 25 = `ModeNamedPipe`），否则报 `Start this collector through CS2 Radar Launcher; a pipe is required.`

### 8.7 采集器的 API 面（capture.exe 全量）

**存在**（字符串表 + 反汇编确认）：`OpenProcess`、`ReadProcessMemory`、`VirtualQueryEx`、`CreateToolhelp32Snapshot`、`Process32FirstW/NextW`、`OpenThread`、`SuspendThread`、`ResumeThread`、`Thread32First/Next`、`Module32FirstW/NextW`、`NtSuspendProcess`、`NtResumeProcess`、`CloseHandle`、`CreateNamedPipeW`、`SetEntriesInAclW`、`DuplicateTokenEx`、`ImpersonateLoggedOnUser`、`OpenProcessToken`、`GetTokenInformation`、`AdjustTokenPrivileges`、`LookupPrivilegeValueW`、`RevertToSelf`、`DeviceIoControl`、`wpcap.dll`/`pcap_*`。

**不存在**（字节级搜索 0 命中）：`WriteProcessMemory`、`VirtualProtectEx`、`CreateRemoteThread`、`NtCreateThreadEx`、`VirtualAllocEx`、`SetWindowsHookEx`。

→ **整个 API 面上没有任何"写内存 / 注入 / hook"能力**；令牌/管道/ACL 类 API（`OpenProcessToken`/`DuplicateTokenEx`/`ImpersonateLoggedOnUser`/`SetEntriesInAclW`/`CreateNamedPipeW`）属于**采集器与启动器之间的管道与权限管理**，不是用于攻击游戏。

### 8.8 提权：走 UAC，不是漏洞

启动器 `main.begin`：`IsUserAnAdmin()` → 非管理员则 `ShellExecuteW("runas", exe, "--connect --window-position %d %d", ...)` 用 **UAC** 重新以管理员启动自己。
→ 它需要管理员**只是为了拿到 `OpenProcess(VM_READ)` 别人的权限**，走的是正常 UAC 授权；**无提权漏洞利用、无内核驱动、无 `Se*Privilege` 字符串**（capture.exe 内 `Se[A-Z]\w*Privilege` 正则搜索 0 命中）。

### 8.9 结论：是"规避"还是"不触发"？

严格说，**它不是绕过反作弊检测，而是把自己设计成反作弊"没有理由检测"的形态**：

- **VAC 是用户态、进程内反作弊**：它检查 cs2.exe 自身的模块列表、代码完整性、线程、调用栈。一个**外部、只读、不注入**的进程根本不在它的可见范围内。
- 抓包走 Npcap 驱动 / 原始套接字，不 hook 游戏模块 → 不触发 IAT/inline-hook 完整性检查。
- 不写内存、不在目标建线程、不往目标加载 DLL → 不触发内存完整性 / 模块列表检查。
- 密钥靠**离线暴力搜索 + X25519 校验**得到，不需要 hook 游戏加密函数 → 进一步减少足迹。
- 句柄按需打开、pid 变化即关闭、扫描带截止时间 → 缩短"持有句柄"的时间窗口。

但它**没有**做任何**主动对抗**：不隐藏自身进程/句柄（无 handle-stripping、无 PEB 篡改、无进程名伪装、无驱动、无直接系统调用）。
因此能力边界很清楚：
> **能躲用户态 VAC 类反作弊，躲不了内核级反作弊。** 尤其是 `NtSuspendProcess` 挂起游戏线程这一动作，内核级反作弊（`ObRegisterCallbacks` 剥离 VM_READ 句柄、检测异常挂起时长）很容易捕捉。

这是**"低对抗面"策略**，不是**"高级对抗"**。
