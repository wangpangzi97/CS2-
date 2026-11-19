# 子 Agent C · 投递与鉴权

## 角色
负责「把密钥和原始包送到解码端」以及「卡密/设备身份」。

**关键变化（本轮）**：投递目标从"只有公网服务器"变成**可切换的两种**——
默认是**同进程本机解码**（`NewLocal`），可选才是远端 HTTPS 上行。
所以 C 现在持有的是「采集器 ↔ 解码端」的**投递接缝**，而不只是网络契约。

## 拥有（可写）
- `internal/uplink/uplink.go`（`Sink` 接口 / `Sender` / `NewLocal` / `New`）
- `internal/license/authwire.go` + `authwire_test.go`
- `internal/license/device.go`
- `cmd/collector/main.go` 中 `newSender()` / `radarURL()` / `localRadarHost()` / `startLocalRadar()` / flag 定义部分
- `cmd/launcher/main.go`

## 对外契约

### 投递接缝：`uplink.Sink`（改这些要同时改 D 端）
```go
type Sink interface {
    SetHandshake(pub []byte)
    SetKey(priv []byte)
    Push(p Packet)
    Flush(final bool) error
    Close() error
    Stats() map[string]any
    Mode() string          // "local" | "remote"
}
```
- `NewLocal(session, deliver func(*Batch) error) *Sender` —— **本机模式**：
  `Deliver` 里直接调 `radarsrv.Store.Ingest` + `Process`，**不碰网络**。
  批量阈值 `MaxPackets:64` / `FlushInterval:200ms`（比远端小，因为无网络成本）。
- `New(...)` —— **远端模式**：HTTPS 上行，默认 **256 包 / 2 秒**，先到先发。
- `Sender.Deliver != nil` 即为本机模式；`Mode()` 据此返回。
- `Flush()` 开头判断 `s.Deliver != nil` → 走本机分支，不发起 HTTP。

### 上行 JSON（`uplink.Batch`）—— 远端模式的唯一契约
改字段必须同步 `internal/radarsrv/store.go` 的 `Ingest` 解析：
```json
{
  "session":    "会话标识（客户端给，服务端按它分桶）",
  "server_pub": "base64(握手公钥 32B)",
  "key":        "base64(X25519 私钥 32B)",
  "packets": [
    { "dir": "c2s|s2c", "src": "...", "dst": "...", "data": "base64(UDP 载荷)" }
  ]
}
```
- `Close()` 会再发一个**空批次**（用于 flush）—— 解码端必须容忍空批次
  （历史上这个空批次触发过幽灵目标 bug）。
- **本机模式同样复用这个结构**（`NewLocal` 的 `Deliver` 收到的就是 `*Batch`），
  只是不经过 JSON 序列化。

### 鉴权与 TLS（仅远端模式用到）
| flag | 说明 |
|---|---|
| `-uplink` | 服务器上行地址；**留空 = 本机解码（默认）** |
| `-token` | 共享密钥；服务端配了 `-token` 就必须一致 |
| `-ca` | PEM 自签证书路径，用于校验服务端证书 |
| `-insecure` | 跳过证书校验（仅调试） |

### 本机模式相关 flag
| flag | 说明 |
|---|---|
| `-listen` | 本机雷达页监听地址，默认 `127.0.0.1:8766` |
| `-open-browser` | 本机服务起来后自动开浏览器（由 `net.Listen` 成功后触发，不是 bat 里 `start`） |
| `-print-radar-url` | 只打印雷达链接后退出 |

### 卡密侧
- 设备身份：`CryptProtectData`/`CryptUnprotectData`（entropy=NULL，flags=1），存 `%AppData%\CS2Radar\device.bin`
- 签名消息格式：`radar-login-v1\n%x\n%s\n%s\n%s\n%t\n%d\n%d`，首字段 = `sha256(upper(trim(cardKey)))`
- 路径常量：`PathChallenge` / `PathLogin` / `PathCheck` / `PathStream`，头 `HeaderSignature`

## 验证手段
```bash
export GOROOT="D:/csleida/1/2026-10-13/tools/go"
export GOCACHE="D:/csleida/1/2026-10-13/tools/gocache" GOPATH="D:/csleida/1/2026-10-13/tools/gopath"
export GOPROXY=off CGO_ENABLED=0
cd D:/csleida/1/2026-10-13/rebuild/cs2radar

"$GOROOT/bin/go.exe" test ./internal/license/ -v
"$GOROOT/bin/go.exe" build -o dist/capture.exe ./cmd/collector

# 端到端（本机模式，默认）—— 应看到 "解码出口: local" 且零对外连接
cd dist
./mksession.exe -out s.jsonl -frames 60 -players 3
./capture.exe -replay s.jsonl -session demo -listen 127.0.0.1:8766 -hold 30s &
curl -s --noproxy '*' "http://127.0.0.1:8766/api/v1/radar?session=demo"
netstat -ano | grep <capture.exe 的 PID>      # 应为空

# 端到端（远端模式，可选）—— 对真实服务器
./capture.exe -replay s.jsonl \
  -uplink https://109.206.245.172:8899/api/v1/ingest \
  -session demo -token <TOKEN> -ca server.crt
```
基线：本机模式 `出口=map[batches:1 failed:0 packets:60]`；
远端模式 `uplink=map[batches:1 failed:0 packets:60]`。

## 常见改动与注意
- **加字段**：先想清楚是否真需要 —— 远端模式下每加一个字段都要 D 端同步改解析，
  且老客户端会发不出来的字段；本机模式下 D 端就在同一个二进制里，同步成本低。
- **改批量阈值**：`MaxPackets` / `FlushInterval` 是 `Sender` 的字段。
  本机模式（`NewLocal`）用 64 / 200ms；远端用 256 / 2s（UDP 包不重传，调大风险高）。
- **`newSender()` 永不返回 nil**：本机模式返回 `*Sender`（带 `Deliver`），
  远端模式返回 `*Sender`（带 HTTP client）。所以调用点**不要写 `if sender != nil`** ——
  本轮就是因为这个判断在改成本机模式后失效，批量解包了 6 处。
- **卡密改动**：`SignatureMessage` 的字段顺序和分隔符是**协议**，服务端按同样格式验签。改一处必须两边同步。
- **证书**：服务器是自签的，`-ca` 必须拿到 `/opt/cs2radar/tls/server.crt`（用 `logs/py_remote.py pull` 取回）。**本机模式不需要证书**。

## 禁止
- ❌ 不要去掉 `Close()` 的空批次 —— 那是 flush 语义，去掉会丢最后不足阈值的包。
- ❌ 不要把 `key` 字段改成明文 HTTP 传输（那是私钥）。
- ❌ 不要改 `dir` 的 `c2s`/`s2c` 字面值（见 B）。
- ❌ 不要假设服务器一定启用了 TLS —— `-uplink` 的 scheme 决定，两种都要能跑。
- ❌ 不要给 `newSender()` 加回 `nil` 返回路径（会让调用点的 `if sender != nil` 复活）。
- ❌ 不要在 `Deliver` 里再起 goroutine 异步投递 —— 本机模式要的是**同步入 Store**，
  异步会让 `-replay` 的结果打印早于解码完成。
- ❌ 不要改 `radarURL()` 的默认分支去拼公网地址 —— 默认必须是 `127.0.0.1`。
