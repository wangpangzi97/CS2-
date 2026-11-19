# 子 Agent A · 密钥挖掘

## 角色
负责「从目标进程内存里挖出 X25519 私钥」。这是整个链路的第一环，也是最依赖逆向结论的一环。

## 拥有（可写）
- `internal/keyfind/keyfind.go` + `keyfind_test.go`
- `internal/handshake/handshake.go` + `handshake_test.go`
- `internal/memscan/process.go`
- `internal/winapi/winapi.go`

## 对外契约（改这些要通知 B/C/D）
| 契约 | 位置 | 说明 |
|---|---|---|
| `keyfind.New(proc, targetPub, deadline) *Search` | `keyfind.go:108` | 构造搜索器 |
| `Search.FindPrivWithHints(regions) ([]byte, string, uintptr, error)` | `keyfind.go:409` | 主入口，返回私钥 + 命中路径标签 + 地址 |
| `Search.Check(cand []byte, tag string, addr uintptr) bool` | `keyfind.go:157` | **四条路径共用的唯一判据入口** |
| `handshake.ParseHandshake([]byte) ([]byte, error)` | `handshake.go` | 提取 32 字节握手公钥 |
| `memscan.OpenReadRights = 0xC10` / `OpenQueryRights = 0x400` | `process.go` | 权限常量，别改数值 |

## 核心判据（不许放松）
```go
pub := ecdh.X25519().NewPrivateKey(cand).PublicKey().Bytes()
return bytes.Equal(pub, targetPub)
```
数学确定，**不存在假阳性**。任何"降低精度以提速"的想法都是错的 —— 错一位就必然不等。

## 四条路径与依据
| 路径 | 标签 | 依据 |
|---|---|---|
| 1 | `hint/udp4` | 逆向确证：先拿到握手包，再挖私钥 |
| 2 | `pointer` | 逆向确证：指针链是 **8 字节步长** |
| 3 | `adjacent/anchors` | 堆上对象连续排布 |
| 4 | `window` | 兜底；默认 8 字节对齐，`WindowStride=1` 可命中非对齐落点（**实测**） |

## 验证手段
```bash
export GOROOT="D:/csleida/1/2026-10-13/tools/go"
export GOCACHE="D:/csleida/1/2026-10-13/tools/gocache" GOPATH="D:/csleida/1/2026-10-13/tools/gopath"
export GOPROXY=off CGO_ENABLED=0
cd D:/csleida/1/2026-10-13/rebuild/cs2radar

"$GOROOT/bin/go.exe" test ./internal/keyfind/ ./internal/handshake/ -v

# 跨进程真实验证（必须跑，不能只看单测）
"$GOROOT/bin/go.exe" build -o dist/plantkey.exe ./tools/plantkey
"$GOROOT/bin/go.exe" build -o dist/keyscan.exe  ./tools/keyscan
./dist/plantkey.exe &            # 埋随机私钥进自己 4 MB 堆，打印 PID
./dist/keyscan.exe -pid <PID>    # 期望 VERDICT=PASS，私钥逐字节一致，约 1 秒
```
基线：`plantkey` → `keyscan` **1.02 秒命中，VERDICT=PASS**。

## 常见改动与注意
- **加一条新搜索路径**：只需在 `FindPrivWithHints` 里插一段，所有候选都走 `Check()`，不要另写判据。
- **调扫描预算**：`MaxCandidates` / deadline / `budgetExceeded()` 三重。放大前先想清楚内存占用 —— 目标机可能只有几 GB 空闲。
- **适配新游戏/新版本**：先确认 `parseHandshake` 的字段路径（`f4→f4→f2` 主 / `f7→f1→f2` 备），再确认指针步长。

## 禁止
- ❌ 不要为了提速改成"部分字节匹配"—— 会引入假阳性，且失去"数学确定"这个唯一优势。
- ❌ 不要在 `Check()` 之外另立判据。
- ❌ 不要删 `recoverWorker` 的 panic 兜底 —— 扫描中途挂掉会让游戏留在挂起态。
- ❌ 不要改 `OpenReadRights = 0xC10`（少了 `SUSPEND_RESUME` 就无法冻结游戏）。
- ❌ 恢复游戏失败必须保持"请立即停止工具"的提示语，不要弱化。
