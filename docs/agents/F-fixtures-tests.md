# 子 Agent F · 靶标与测试

## 角色
负责「在没有真实 CS2、没有真实抓包的情况下，把整条链路验证到可信」。**本工程所有"实测通过"的结论都由这个 Agent 提供。**

## 拥有（可写）
- `tools/mksession/`（合成会话）、`tools/plantkey/`（埋私钥靶标）、`tools/keyscan/`（跨进程验证器）
- 全部 `*_test.go`
- `logs/verify_*.py`、`logs/smoke_auth.sh`、`logs/query_radar.py`

## 为什么需要靶标
本环境**没有 CS2、没有 Npcap 真实流量**。所以：
- 密钥挖掘 → 用 `plantkey` 在**自己进程**里埋一个随机 X25519 私钥，再用 `keyscan` 跨进程挖出来比对；
- 解密链路 → 用 `mksession` 造一条**用真实 X25519 + 真实 AES-GCM + 真实 netmessage 分帧**加密的合成会话。

**靶标用的是真算法，只是"对手"是自己造的。** 这能验证"实现是否正确"，但不能验证"对真实流量是否适用"——后者只能靠真机联调。

## 靶标工具

### `tools/plantkey` —— 埋私钥
把随机 X25519 私钥写进自己 4 MB 堆，打印 PID 后常驻。
```bash
"$GOROOT/bin/go.exe" build -o dist/plantkey.exe ./tools/plantkey
./dist/plantkey.exe
```

### `tools/keyscan` —— 跨进程挖私钥
```bash
"$GOROOT/bin/go.exe" build -o dist/keyscan.exe ./tools/keyscan
./dist/keyscan.exe -pid <PID>     # 期望 VERDICT=PASS，私钥逐字节一致
```
**基线：1.02 秒命中。**

### `tools/mksession` —— 合成会话
```bash
"$GOROOT/bin/go.exe" build -o dist/mksession.exe ./tools/mksession
./dist/mksession.exe -out s.jsonl -frames 60 -players 3 \
  -kdf hkdf-sha256/info-empty -cipher aes-256-gcm -nonce ctr-le-u64 -offset 2
# 打印：候选空间规模 + 真实方案名 + 每个玩家的末帧真实坐标
```
输出的 JSONL：第一行是 `{server_pub, key}`，之后每行 `{dir,src,dst,ts_ms,data(base64)}`。

**合成数据的运动量是刻意设计的**（p0 位移 172、p1 231、**p2 303**），正好让 p2 越过关联半径 256 —— 这是"幽灵目标"回归测试的触发条件，别随意改。

## 测试清单与各自的职责

| 测试 | 锁住的行为 |
|---|---|
| `TestDecodeIsIncremental` | 重复 decode 不得新增目标（旧逻辑 3→6） |
| `TestDecodeSurvivesBufferTrim` | 丢帧后解码不得停摆（旧逻辑游标卡在 30） |
| `TestDecodeAppendsNewFrames` | 增量游标不得漏新帧 |
| `TestStoreEvictsOldestSession` | 会话表不得无上限增长 |
| `TestSnapshotKeepsSlotAliveAfterCompaction` | 槽位压缩后不得被误判过期 |
| `TestProbeFindsCorrectScheme` | 候选枚举 Top-1 必须命中真方案 |
| `TestProbeRejectsWrongKey` | 密钥错一位时无任何方案成立 |
| `TestProbeDistinguishesNonceScheme` | 不同 nonce 方案不得混淆 |
| `TestScoreRejectsRandom` | 随机字节误判率 0/200 |
| `TestScanFloat3RejectsGarbage` | 非规格化浮点不得被当坐标 |
| `TestHeuristicDecoderTracksMovingTarget` | 移动目标不得被拆成多槽 |
| `TestFindInSelfProcess`（hint/pointer/window） | 四条路径真实命中 |
| `TestRecoveredDeviceKey` | 设备密钥恢复与校验 |
| `TestParsePB` / `TestParseHandshake` / `TestParsePBAltPath` | 握手解析主/备路径 |

## 验证姿势（重要）

```bash
export GOROOT="D:/csleida/1/2026-10-13/tools/go"
export GOCACHE="D:/csleida/1/2026-10-13/tools/gocache" GOPATH="D:/csleida/1/2026-10-13/tools/gopath"
export GOPROXY=off CGO_ENABLED=0
cd D:/csleida/1/2026-10-13/rebuild/cs2radar
"$GOROOT/bin/go.exe" vet ./... && "$GOROOT/bin/go.exe" test ./...
```

**写回归测试的硬要求：必须证明它能抓到那个 bug。**
做法：临时把修复改回旧逻辑 → 跑测试 → **必须失败** → 恢复修复 → 必须通过。
本次三个 bug 的测试都做了这一步（`3→6`、游标卡在 30、第二次 Snapshot 返回 0）。没做这一步的测试不算数。

## 常见改动与注意
- **加回归测试**：先想清楚"旧代码在这条测试下会怎样失败"，再写断言。
- **改合成数据**：`streamAt` / `buildStream` 的坐标公式被多个测试依赖，改了要同步跑全量。
- **加靶标**：放进 `tools/`，并在本文档登记基线与期望输出。

## 禁止
- ❌ 不要写"只验证正确路径"的测试 —— 要能抓到回归。
- ❌ 不要改 `mksession` 的运动量而不重跑幽灵目标测试。
- ❌ 不要在测试里依赖网络/真实游戏进程。
- ❌ 不要把"未执行的步骤"写成"已验证"。
