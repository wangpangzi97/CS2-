# 子 Agent D · 解码服务（本机 / 远端共用）

## 角色
负责「收包 → 算共享密钥 → 定位加解密方案 → 解密 → 出玩家坐标 → 出画面」。
这段代码**同时供两个宿主使用**：

- **本机模式（默认）**：内嵌在 `cmd/collector` 里，`127.0.0.1:8766` 出画面，零对外连接；
- **远端模式（可选）**：被 `cmd/radarserver` 复用，跑在服务器上。

链路里最复杂、最容易出隐蔽 bug 的一段。

## 拥有（可写）
- `internal/radarsrv/store.go` + `store_test.go`（**核心**：ingest / probe / decode / 会话淘汰）
- `internal/radarsrv/http.go`（路由 + `RadarPage`）
- `cmd/radarserver/main.go`（薄封装：flag → `NewStore` → TLS `ListenAndServe`）
- `internal/cs2crypto/crypto.go` + `crypto_test.go`
- `internal/cs2proto/netmsg.go` / `entity.go` + `netmsg_test.go`

> `cmd/collector` 里**调用** `radarsrv` 的那几行（`startLocalRadar()` / `newSender()` 的本机分支）
> 由 B / C 负责；D 只保证 `radarsrv` 的接口稳定。

## 对外契约（改这些要通知 C）
| 契约 | 位置 | 说明 |
|---|---|---|
| `radarsrv.NewStore(cfg Config) *Store` | `store.go` | 两个宿主共用的唯一构造入口 |
| `(*Store).Ingest(b *uplink.Batch) (int, error)` | `store.go` | 收一批包；本机模式下被 `uplink.NewLocal` 直接调用 |
| `(*Store).Process(id string)` | `store.go` | 触发一次 probe + decode（本机模式显式调用） |
| `(*Store).Handler(token string) http.Handler` | `http.go` | 全部 HTTP 路由；`token=""` 表示不鉴权（本机回环用） |
| `POST /api/v1/ingest` | `http.go` | 收 `uplink.Batch`，见 `agents/C-uplink-auth.md` |
| `GET /api/v1/radar?session=` | `http.go` | 雷达画面 JSON |
| `GET /api/v1/probe?session=` | `http.go` | 全部候选方案（含落选，排查用） |
| `GET /api/v1/sessions` / `GET /health` / `GET /radar` | `http.go` | — |
| `cs2proto.Decoder` 接口 | `entity.go:43` | **"明文 → 坐标"的唯一接缝** |
| `cs2crypto.ProbeFrom(shared, pub, frames, base, maxOffset)` | `crypto.go` | `base` = frames[0] 的绝对帧序号 |
| `cs2proto.ParseStream` / `Score` | `netmsg.go` | 分帧与打分 |

## 关键设计（改动前必须理解）

### 0. 为什么抽成 `internal/radarsrv`
原先全部逻辑在 `cmd/radarserver/main.go`（580 行），只能跑在服务器上。
本机方案要求采集器**同进程**解码，于是把这 580 行原样搬进 `internal/radarsrv`，
去掉对包级 `flag` 的依赖（改读 `Store.cfg`）。`cmd/radarserver` 只剩 88 行薄封装。
**两个宿主跑的是同一份代码**，所以本机验证过 = 远端也验证过（除网络层外）。

### 1. 方案定位是"枚举 + 打分"，不是"猜一个"
- `SharedSecret` = ECDH，**数学确定**。
- 未知维度：KDF（含 info/salt）、AEAD、nonce 构造、密文起始偏移 → 枚举 ~720 候选。
- 打分：解密结果能否切成合法 netmessage 流（`varint cmd + varint size + payload`，正好消费完整段）。
- 成立判据：`ok >= 3 && ok*2 >= frames`。随机字节误判率实测 0/200。

### 2. 帧序号 = 发送方包计数器，**不是缓冲区下标**
这是最容易踩的坑，已经踩过两次：
- **nonce 用绝对帧序号**。缓冲区有上限（`Config.MaxFrames`，默认 2000），头部会丢；丢了 k 帧后缓冲区下标 0 对应计数器 k。所以：
  - `session.c2sDropped` / `s2cDropped` 记录各方向已丢帧数；
  - `decode()` 的 `startAbs`/`endAbs` 是绝对序号，`off = startAbs - dropped`；
  - `ProbeFrom(..., base=dropped, ...)`。
- **游标必须在锁内原子领取**，否则并发 ingest 的多个 decode 协程会重复喂同一批帧。

### 3. `decode()` 必须是增量的
每次 ingest 都会 spawn 一次 `runProbe + decode`，而客户端 `Close()` 还会发一个空批次 → **decode 被多次调用是常态**。若从头重喂：
- 槽位已在最新位置，位移超过关联半径（256 单位）的目标会在**历史坐标处重新建槽** → 画面多出"幽灵目标"。

### 4. 槽位存活时间记在 `Player.UpdatedAt` 里
不要另开"以槽位下标为键"的旁路表 —— `Snapshot()` 会压缩 `slots` 数组，下标会错位，导致槽位被误判过期。

### 5. `Handler("")` 与鉴权
本机模式传 `token=""`，`authed()` 直接放行（服务只绑 `127.0.0.1`，外部访问不到）。
远端模式必须传非空 token（或在启动时显式 `-allow-insecure`）。

## 验证手段
```bash
export GOROOT="D:/csleida/1/2026-10-13/tools/go"
export GOCACHE="D:/csleida/1/2026-10-13/tools/gocache" GOPATH="D:/csleida/1/2026-10-13/tools/gopath"
export GOPROXY=off CGO_ENABLED=0
cd D:/csleida/1/2026-10-13/rebuild/cs2radar

"$GOROOT/bin/go.exe" test ./internal/radarsrv/ ./internal/cs2crypto/ ./internal/cs2proto/ -v

# 端到端（本机方案，默认）
"$GOROOT/bin/go.exe" build -o dist/capture.exe ./cmd/collector
cd dist
./mksession.exe -out s.jsonl -frames 60 -players 3
./capture.exe -replay s.jsonl -session demo -listen 127.0.0.1:8766 -hold 30s &
curl -s --noproxy '*' "http://127.0.0.1:8766/api/v1/radar?session=demo"

# 端到端（远端方案，可选）
"$GOROOT/bin/go.exe" build -o dist/radarserver.exe ./cmd/radarserver
./radarserver.exe -listen 127.0.0.1:8080 -allow-insecure -player-ttl 10m -debug-slots &
./capture.exe -replay s.jsonl -uplink http://127.0.0.1:8080/api/v1/ingest -session demo
curl -s --noproxy '*' "http://127.0.0.1:8080/api/v1/radar?session=demo"
```

**已锁死的回归测试（改这段代码后必须全绿）：**
| 测试 | 位置 | 锁的是什么 |
|---|---|---|
| `TestDecodeIsIncremental` | `radarsrv/store_test.go` | 重复 decode 不得新增目标（旧逻辑 3→6） |
| `TestDecodeSurvivesBufferTrim` | `radarsrv/store_test.go` | 丢帧后解码不得停摆（旧逻辑游标卡在 30） |
| `TestStoreEvictsOldestSession` | `radarsrv/store_test.go` | 会话表不得无上限增长 |
| `TestDecodeAppendsNewFrames` | `radarsrv/store_test.go` | 增量游标不得漏掉新帧 |
| `TestProbeFindsCorrectScheme` | `cs2crypto/crypto_test.go` | 候选枚举 Top-1 必须命中真方案 |
| `TestProbeRejectsWrongKey` | `cs2crypto/crypto_test.go` | 密钥错一位时无任何方案成立 |
| `TestScoreRejectsRandom` | `cs2proto/netmsg_test.go` | 随机字节误判率 0/200 |
| `TestSnapshotKeepsSlotAliveAfterCompaction` | `cs2proto/` 或 `radarsrv/` | 槽位压缩后不得被误判过期 |

> 注：这 4 个 `radarsrv` 测试原在 `cmd/radarserver/main_test.go`，本轮随代码迁移过来，
> 并把对包级 `flag` 的引用改成局部 `const maxFrames` / `NewStore(cfg)`。原文件已删。

## 常见改动与注意
- **扩候选空间**：往 `KDFs()` / `Ciphers()` / `NonceSchemes()` 加条目即可，打分逻辑不用动。加完先跑 `TestProbeFindsCorrectScheme` 确认 Top-1 没被新条目挤掉。
- **接真实实体解码器**：实现 `cs2proto.Decoder`（`Name` / `Feed` / `Snapshot`）替换 `HeuristicDecoder`，**两个宿主都不用动**。
- **调 TTL**：`Config.PlayerTTL`（flag `-player-ttl`）默认 10s。离线回放要调大，否则回放结束画面立刻清空。
- **本机模式端口**：由 `cmd/collector` 的 `-listen` 决定（默认 `127.0.0.1:8766`），D 不感知。

## 禁止
- ❌ 不要把帧序号改回"缓冲区下标"—— 丢帧后 nonce 会错位、游标会卡死。
- ❌ 不要去掉 `decode()` 里的锁内原子领取。
- ❌ 不要在 `decode()` 里重新遍历全部帧。
- ❌ 不要用"以槽位下标为键"的旁路表记存活时间。
- ❌ 不要放松成立判据 `ok>=3 && ok*2>=frames`。
- ❌ 不要让 `radarsrv` 重新依赖包级 `flag` —— 那会毁掉"两个宿主共用一份代码"的前提。
- ❌ 远端模式不要删 `-token` 的强制校验（留空必须显式 `-allow-insecure` 才能启动）。
- ❌ 远端模式不要监听 `0.0.0.0` 却不配 TLS —— `key` 字段是明文私钥。
- ❌ 本机模式不要绑 `0.0.0.0` —— 那会把"位置数据不出本机"这条承诺破坏掉。
