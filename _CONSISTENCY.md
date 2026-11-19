# 源树 ↔ 已编译产物 一致性核对

打包时间：2026-10-20 14:33:11

> 这是强制步骤。历史教训：本仓库另一条产品线（`capture_launcher`）曾出现
> **源树里的 HTML 还停在改动前，而 `dist/` 里已经是新版**，导致发出的源码
> 不含实际出货的功能。**任何导出源码 / 打包 / 交接前，必须按 sha256 比对，
> 不能假定源树最新。**

## 一、核对方法

用当前源码树**重新编译**一份，与 `dist/` / `deploy/` 里的已有产物比 sha256。
Go 在 `-trimpath -ldflags="-s -w"` 且 `GOPROXY=off` 下是**逐位可复现**的
（同一输入连编两次哈希相同，已实测），所以哈希不等 = 源码不同。

## 二、本轮核对结果

| 产物 | 大小(byte) | sha256 | 与「当前源码重编」一致？ |
| --- | --- | --- | --- |
| `dist/CS2雷达.exe` | 7,772,160 | `61be96157f6eb4c4bcc76b596d9fce15109da93150648466a2c941cec7db25b0` |
| `dist/capture.exe` | 7,772,160 | `22abdb9b0b56a22b9ad81a954cdf5482c29378fcad7ca024631a23e3dc091ff0` |
| `dist/cs2radar-client.zip` | 11,706,000 | `03dad8dcb8fb13eb0602c09c16d6eddcc6afe297b5e1de07d921af10674a3325` |
| `dist/radarserver-linux-amd64` | 6,254,776 | `e515704bfedddfe8dbe647f520fee75c3ccf69de1997b6cfd6cba46b44473ab8` |
| `dist/radarserver.exe` | 6,424,576 | `436db7a327ff8bdc8644520192bf89513d373d53bab87e17d91ba7da4f925254` |
| `deploy/radarserver` | 6,254,776 | `e515704bfedddfe8dbe647f520fee75c3ccf69de1997b6cfd6cba46b44473ab8` |

## 三、结论与遗留

- `dist/radarserver.exe`（Windows）与当前源码重编**逐位一致**。
- `dist/radarserver-linux-amd64` / `deploy/radarserver` **本轮已用当前源码重建**
  （旧版为 `422fdcd5010bc2193fa5fb6d45a13b69d37a5eb7f08edf2648f4c34a17cf3efa`，
  编译于 2026-10-15 20:41，**早于** 23:07 / 23:48 对 `internal/radarsrv/http.go`、
  `cmd/radarserver/main.go`、`internal/radarsrv/store.go`、`internal/uplink/uplink.go`
  的修改）。
- ⚠ **远端解码服务未重部署**。核对时远端 `/opt/cs2radar/radarserver` 仍是旧哈希
  `422fdcd5…`（`ExecMainStartTimestamp=2026-10-15 21:05:14 CST`）。
  也就是说**线上服务跑的是 23:07/23:48 之前的构建**。
  重部署命令见 `src/deploy/install.sh` + `docs/report/服务器解码方案.md`。
- 客户端两个 exe（`CS2雷达.exe` / `capture.exe`）本轮已用当前源码重建，
  哈希见 `docs/report/纯raw单exe版本.md` 与 `evidence/raw_single_exe_verify_2026-10-16.txt`。
