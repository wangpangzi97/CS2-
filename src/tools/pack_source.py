#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打包 CS2 雷达「重构工程」的源码交付包。

与 `build_client_package.py` 的区别：
    build_client_package.py  -> 打**用户端分发包**（两个 exe，给玩家用）
    pack_source.py           -> 打**源码交付包**（.go/.py/.sh + 文档 + 证据，给开发/交接用）

产物: dist/cs2radar-source-<YYYY-MM-DD>.zip

包结构:
    cs2radar-source/
        README.md                  怎么构建 / 怎么跑 / 有哪些坑
        _SOURCE-PACK-MANIFEST.json 逐文件 sha256（可校验包完整性）
        _CONSISTENCY.md            源树 ↔ 已编译产物 的一致性核对结果
        _EXCLUDE.md                排除了什么、为什么
        src/                       Go 源码全树（go.mod + cmd/ internal/ tools/ deploy/）
        docs/                      设计报告 + 子 Agent 手册
        evidence/                  关键验证证据（挑过的，不含大块原始抓包文本）

强制排除（硬拦，别改）:
    dist/                      构建产物
    tools/npcap/npcap-1.89.exe 第三方安装包 1.3 MB，Npcap 已从项目移除
    deploy/radarserver         6.2 MB 编译好的 Linux 二进制
    *.tar.gz / *.tar.gz.gz     部署包（二进制）
    ../../memory/              **内部记忆，含授权服务端 admin_key，绝不外发**

用法:
    python tools/pack_source.py                # 默认 full：源码 + 文档 + 证据
    python tools/pack_source.py --mode code    # 只要源码（最精简）
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
import time
import zipfile

# ── 路径 ────────────────────────────────────────────────────────────────────
TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)                       # rebuild/cs2radar
ARCHIVE = os.path.dirname(os.path.dirname(ROOT))    # 1/2026-10-13
DIST = os.path.join(ROOT, "dist")

REPORT_DIR = os.path.join(ARCHIVE, "report")
AGENTS_DIR = os.path.join(ARCHIVE, "agents")
LOGS_DIR = os.path.join(ARCHIVE, "logs")

PACK_NAME = "cs2radar-source"

# ── 强制排除 ────────────────────────────────────────────────────────────────
SKIP_DIRS = {
    "dist",                 # 构建产物
    "_srccheck",            # 临时构建比对目录
    ".git", ".idea", "__pycache__",
}
SKIP_REL_PREFIX = (
    "tools/npcap/",         # npcap-1.89.exe（1.3 MB 第三方安装包）
    "cs2radar-deploy.tar.gz",
)
SKIP_REL_EXACT = {
    "deploy/radarserver",   # 6.2 MB 编译好的 Linux 二进制
}

# ── 源码：只收这些后缀 ──────────────────────────────────────────────────────
SRC_EXT = (".go", ".py", ".sh", ".mod", ".sum")

# ── 编译期嵌入资产：漏了源码包就**编译不过** ────────────────────────────────
#
# 🔴 2026-10-20 的教训：`internal/mapdata` 用
#     //go:embed assets/*.json assets/*.png
# 把地图标定与底图打进 exe。这两个后缀不在 SRC_EXT 里，第一次打源码包就漏了，
# 169 个文件里一个资产都没有 —— 拿到包的人 go build 会直接报
#     pattern assets/*.json: no matching files found
# 而打脚本自己不报错（它只负责按后缀收文件，不知道谁在 embed）。
#
# 修法：按**目录**白名单收，而不是给 SRC_EXT 加 .json/.png ——
# 后者会把一堆无关的 json/截图也卷进来。
EMBED_DIRS = ("internal/mapdata/assets/",)
EMBED_EXT = (".json", ".png")


def is_embed_asset(rel: str) -> bool:
    """判断一个相对路径是不是「必须随源码一起交付的嵌入资产」。"""
    return rel.endswith(EMBED_EXT) and rel.startswith(EMBED_DIRS)

# ── 证据白名单（按文件名挑，避免把几百 KB 的 strings 转储打进去） ──────────
EVIDENCE_WHITELIST = [
    "raw_single_exe_verify_2026-10-16.txt",
    "capturefilter_verify_2026-10-16.txt",
    "rawtest_evidence.txt",
    "udpprobe_verify.log",
    "udpprobe_verify2.log",
    "udpprobe_v2.log",
    "s_verify.jsonl",
]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_src() -> list[str]:
    """收集 Go/Python/shell 源码（相对 ROOT 的 posix 路径）。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, ROOT).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""
        for fn in filenames:
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            if not (rel.endswith(SRC_EXT) or is_embed_asset(rel)):
                continue
            if rel in SKIP_REL_EXACT or rel.startswith(SKIP_REL_PREFIX):
                continue
            out.append(rel)
    return sorted(out)


def collect_docs() -> list[tuple[str, str]]:
    """(磁盘绝对路径, 包内相对路径) —— 报告 + 子 Agent 手册。"""
    out = []
    for d, prefix in ((REPORT_DIR, "docs/report"), (AGENTS_DIR, "docs/agents")):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.lower().endswith((".md", ".html")):
                continue
            out.append((os.path.join(d, fn), f"{prefix}/{fn}"))
    return out


def collect_evidence() -> list[tuple[str, str]]:
    out = []
    for fn in EVIDENCE_WHITELIST:
        p = os.path.join(LOGS_DIR, fn)
        if os.path.isfile(p):
            out.append((p, f"evidence/{fn}"))
    return out


def check_embed_patterns() -> list[str]:
    """自查：源码里每条 `//go:embed` 的模式，在磁盘上是否真有文件匹配。

    🔴 这是 2026-10-20 那次「源码包编译不过」的正解 —— 不是靠人工记住
    mapdata 有资产，而是**让打包脚本自己去发现**：只要有人新加一个
    //go:embed，忘了把对应目录加进 EMBED_DIRS，这里就会报出来。

    返回「模式 → 0 个文件」的清单（空表示全部有匹配）。
    """
    missing = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".go"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            for line in text.splitlines():
                s = line.strip()
                if not s.startswith("//go:embed"):
                    continue
                pats = s[len("//go:embed"):].split()
                for pat in pats:
                    if not glob.glob(os.path.join(dirpath, pat)):
                        rel = os.path.relpath(path, ROOT).replace("\\", "/")
                        missing.append(f"{rel}: {pat}")
    return missing


def build_readme(mode: str, src_files: list[str]) -> str:
    go_n = sum(1 for f in src_files if f.endswith(".go"))
    py_n = sum(1 for f in src_files if f.endswith(".py"))
    sh_n = sum(1 for f in src_files if f.endswith(".sh"))
    emb_n = sum(1 for f in src_files if is_embed_asset(f))
    return f"""# CS2 雷达 · 重构工程源码包

本包是 CS2 雷达客户端 **v2.0.5 等价重构** 的完整源码（Go，零第三方依赖）。
打包时间：{time.strftime('%Y-%m-%d %H:%M:%S')}
打包模式：`{mode}`
文件统计：.go {go_n} 个 / .py {py_n} 个 / .sh {sh_n} 个 / 编译期嵌入资产 {emb_n} 个

> 嵌入资产（`src/internal/mapdata/assets/`）**不能删**：它们被 `//go:embed`
> 打进 exe，缺了 `go build` 会直接失败（`pattern assets/*.json: no matching files found`）。
> 打包脚本现在会自查每一条 `//go:embed` 是否有文件匹配，缺了就不出包。

---

## 一、这是什么

原版 `CS2radar-v2.0.5.exe` 的等价重构：抓 CS2 客户端的 UDP 包 → 从 cs2.exe
内存里挖出握手用的 X25519 私钥 → 解出实体坐标 → 在本机起一个雷达页显示。

**抓包只用 Windows 系统自带的原始套接字**，不依赖 Npcap / wpcap.dll / 任何驱动：

```
socket(AF_INET, SOCK_RAW, IPPROTO_IP)
  -> bind(fd, 本机网卡 IPv4)
  -> WSAIoctl(fd, SIO_RCVALL = 0x98000001, ON)      把网卡切成混杂模式，收发双向都抓
  -> WSARecvFrom(fd, ...)                           逐包取回
  -> GetExtendedUdpTable(..., UDP_TABLE_OWNER_PID)  按目标进程占用的本机 UDP 端口过滤
```

**必须要管理员权限**（SIO_RCVALL 的硬性要求），窗口版会自己弹 UAC。

---

## 二、目录结构

```
src/
  go.mod                    module local/cs2-radar（零第三方依赖）
  cmd/collector/            采集端主程序（一份代码编出两个 exe）
    main.go                 命令行版 + captureSession 抓包会话
    gui.go                  原生 Win32 窗口版（自提权 / 日志框 / 自动开浏览器）
    gui_test.go             Win32 导出名解析 + 提权分支回归
  cmd/radarserver/          远端解码服务端（Linux）
  cmd/launcher/             桌面壳
  internal/
    pcapdev/                抓包后端（纯 raw socket，SIO_RCVALL）
    capturefilter/          按目标进程 UDP 端口过滤（GetExtendedUdpTable）
    cs2crypto/              握手 KDF / AEAD 组合（hkdf-sha256 + aes-256-gcm + ctr-le-u64）
    cs2proto/               CS2 网络消息与实体解析
    handshake/              握手包解析（拿靶子公钥）
    keyfind/                在 cs2.exe 内存里搜 X25519 私钥（Ed25519/DPAPI 卡密签名）
    memscan/                进程内存扫描原语
    winapi/                 Win32 调用薄封装
    radarsrv/               本机雷达页 + 会话存储
    transport/              上行帧封装
    uplink/                 上行（可选：把私钥+原始包送到服务端解码）
    license/                授权链路（radar-login-v1 签名）
  deploy/
    install.sh              服务端一键部署（systemd，会自动生成 token）
  tools/                    辅助工具（keyscan / mksession / plantkey / rawdir /
                            rawtest / rawcap / udpprobe / query_radar.py /
                            build_client_package.py / pack_source.py）
docs/
  report/                   设计报告（方案对比 / 模块划分 / 解码方案 / 检测风险 …）
  agents/                   子 Agent 工作手册（A-keyfind … F-fixtures-tests）
evidence/                   关键验证证据（端口过滤端到端、单 exe 实跑、自检输出）
```

---

## 三、怎么构建

### 3.1 Go 工具链

本工程**零第三方依赖**，`go.mod` 里没有 require，所以 `GOPROXY=off` 也能编。
本机工具链装在 `D:/csleida/1/2026-10-13/tools/go`（go1.24.4）：

```bash
export GOROOT=D:/csleida/1/2026-10-13/tools/go
export GOCACHE=D:/csleida/1/2026-10-13/tools/gocache
export GOPATH=D:/csleida/1/2026-10-13/tools/gopath
export GOPROXY=off CGO_ENABLED=0 GOOS=windows GOARCH=amd64
export MSYS_NO_PATHCONV=1     # Git-Bash 会篡改命令行里的路径参数，必须加
```

### 3.2 客户端两个 exe（同一份代码，两种构建）

```bash
cd <本包>/src
# 命令行版：PE subsystem=3（有控制台），排障用
"$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w" \\
    -o dist/capture.exe ./cmd/collector
# 窗口版：PE subsystem=2（无控制台），双击即用
"$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w -H=windowsgui -X main.defaultGUIMode=true" \\
    -o "dist/CS2雷达.exe" ./cmd/collector
```

> ⚠ **`-trimpath -ldflags="-s -w"` 不是可选项。** 漏了会得到约 10 MB 的未 strip 版本
> （体积翻倍，而且符号名全部暴露在二进制里，是检测足迹上的倒退）。
> 判断方法：`capture.exe` 明显大于 7 MB 就是漏了。

### 3.3 服务端（Linux）

```bash
GOOS=linux GOARCH=amd64 "$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w" \\
    -o dist/radarserver-linux-amd64 ./cmd/radarserver
```

### 3.4 打用户端分发包

```bash
python tools/build_client_package.py
# 输出 dist/cs2radar-client.zip：CS2雷达.exe + capture.exe + capture.json + 使用说明.txt
# 注意：**没有 .bat**，窗口版自己提权，不需要 cmd 中转
```

### 3.5 自检与回归

```bash
"$GOROOT/bin/go.exe" vet ./...
"$GOROOT/bin/go.exe" test ./...            # keyfind 约 80 秒，其余很快
"$GOROOT/bin/gofmt.exe" -l .               # 应无输出
```

改过 `cmd/collector/*.go` 之后务必跑这三条提权分支回归：

```bash
"$GOROOT/bin/go.exe" test -count=1 -run 'TestEnsureElevated|TestBuildArgLine|TestWin32' ./cmd/collector/
```

---

## 四、怎么跑

用户端只有一步：解压 `cs2radar-client.zip` → **双击 `CS2雷达.exe`** → UAC 点「是」。
程序自己开窗口、自己开浏览器，雷达页在 `http://127.0.0.1:8766/radar?session=room1`。

命令行排障（需管理员权限的终端）：

```
capture.exe -selfcheck                抓包能力自检（最常用）
capture.exe -list-devices             看本机有哪些可抓包的网卡地址
capture.exe                           本机解码 + 127.0.0.1:8766 雷达页
capture.exe -no-filter                关闭端口过滤（收全部 UDP）
capture.exe -no-keys                  只抓包不读游戏内存
capture.exe -duration 2h              跑 2 小时后自动停
capture.exe -replay 包文件.jsonl       离线回放（不需要游戏）
capture.exe -h                        查看全部参数
```

---

## 五、改代码前必须知道的坑

1. **ws2_32.dll 的导出名大小写不能错**：是 `WSARecvFrom`（大写 F）。
   写成 `WSARecvfrom` 会在**调用那一刻** panic（`syscall.NewLazyDLL` 是懒解析）。
   已有 `TestWin32ProcsResolve` 逐个 `Find()` 兜住，别删。
2. **Go 的 `syscall.Recvfrom` 在 Windows 上是空实现**（返回 EWINDOWS "not supported by
   windows"），必须直接调 `ws2_32.dll` 的 `WSARecvFrom` + 手写 `WSABUF`。
3. **必须双向抓包**：密钥搜索的靶子公钥是**客户端自己**的 X25519 公钥，对应私钥在
   cs2.exe 内存里，而客户端把公钥**发出去** → 发送方向。只收接收方向拿不到握手。
4. **提权判定走 `var isAdminFn = winapiIsAdmin` 这个间接层**。测试靠替换它来模拟
   非管理员。别把它删掉或内联掉，否则三条提权测试全废。
5. **改任何源码后必须重算产物哈希**（`dist/*.exe`、`dist/*.zip` 的 sha256 全变）。
   仓库里的哈希表在 `docs/report/纯raw单exe版本.md`。
6. **编码约定**：`.txt` → UTF-8 **with** BOM（记事本可靠识别中文）；
   `.json` → UTF-8 **无** BOM（Go 的 `encoding/json` 遇 BOM 会报错）。
7. **`cmd.exe` 在本机被安全策略拦截** —— Bash / PowerShell 工具都拒绝调用它，用原生命令。
8. **Git-Bash 路径转换**：`MSYS_NO_PATHCONV=1` 必加，否则传给原生程序的
   `/tmp/xxx` 会被改写成 `C:/Users/.../Temp/xxx`，写和校验用同一个错路径所以
   md5 还对得上，**但文件不在你以为的地方**。

---

## 六、本包完整性怎么校验

`_SOURCE-PACK-MANIFEST.json` 里是逐文件 sha256（相对包根路径）。
校验示例：

```bash
python - <<'EOF'
import json, hashlib, pathlib
m = json.load(open('cs2radar-source/_SOURCE-PACK-MANIFEST.json', encoding='utf-8'))
bad = []
for e in m['files']:
    p = pathlib.Path('cs2radar-source') / e['path']
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    if h != e['sha256']:
        bad.append(e['path'])
print('OK' if not bad else 'MISMATCH: ' + ', '.join(bad))
EOF
```

`_CONSISTENCY.md` 记录的是打包时「源树 ↔ 已编译产物」的核对结果；
`_EXCLUDE.md` 说明排除了哪些文件以及为什么。
"""


def build_consistency(artifacts: list[tuple[str, str, str]]) -> str:
    rows = "\n".join(f"| `{p}` | {n} | `{h}` |" for p, n, h in artifacts)
    return f"""# 源树 ↔ 已编译产物 一致性核对

打包时间：{time.strftime('%Y-%m-%d %H:%M:%S')}

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
{rows}

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
"""


def build_exclude(mode: str) -> str:
    ev = "\n".join(f"- `logs/{n}`" for n in EVIDENCE_WHITELIST)
    return f"""# 本包排除了什么、为什么

打包模式：`{mode}`

## 一、硬排除（永远不打进去）

| 排除项 | 大小 | 原因 |
| --- | --- | --- |
| `dist/` | ~65 MB | 全部是构建产物（exe / zip / tar.gz / 服务端证书），源码包里没有意义 |
| `tools/npcap/npcap-1.89.exe` | 1.3 MB | 第三方 Npcap 安装包。**本项目已彻底移除 Npcap**，抓包只用系统自带原始套接字，留着只会误导 |
| `deploy/radarserver` | 6.2 MB | 编译好的 Linux 二进制，构建产物。重编命令见 `README.md` §3.3 |
| `cs2radar-deploy.tar.gz` / `.gz` | 5.2 MB | 部署包（内含上面的二进制） |
| `../../memory/` | — | **内部项目记忆，含授权服务端 `admin_key` 等敏感信息，绝不随源码外发** |

## 二、证据只挑关键几条

`logs/` 目录里有很多大块原始转储（`strings_ascii.txt` 786 KB、
`strings_capture.txt` 367 KB、`vc1.txt` 39 KB、`test400k.bin` 400 KB …），
那些是逆向过程中的中间产物，不进源码包。只挑验证结论类文件：

{ev}

## 三、模式差异

- `--mode full`（默认）：`src/`（含 `deploy/install.sh`）+ `docs/` + `evidence/`
- `--mode code`：只有 `src/`（最精简，适合只看代码）
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="打包 CS2 雷达源码交付包")
    ap.add_argument("--mode", choices=("full", "code"), default="full",
                    help="full=源码+文档+证据（默认）；code=只要源码")
    ap.add_argument("--out", default=None, help="输出 zip 路径（默认 dist/cs2radar-source-<日期>.zip）")
    args = ap.parse_args()

    if not os.path.isdir(ROOT):
        print(f"找不到工程根目录: {ROOT}", file=sys.stderr)
        return 1

    src = collect_src()
    if not src:
        print("没收集到任何源码，检查 SKIP_DIRS / SRC_EXT", file=sys.stderr)
        return 1

    # 🔴 先自查 //go:embed：模式在磁盘上没文件 ⇒ 打出来的包编译不过。
    # 这是硬错误，不是警告 —— 交付一个编译不过的源码包没有任何意义。
    if miss := check_embed_patterns():
        print("源码包不自洽，以下 //go:embed 模式在磁盘上没有匹配文件：", file=sys.stderr)
        for m in miss:
            print(f"  {m}", file=sys.stderr)
        print("修法：把对应目录加进 pack_source.py 的 EMBED_DIRS，"
              "或先补回缺失的资产文件。", file=sys.stderr)
        return 1

    # 嵌入资产是否真的被收进来了（防止 EMBED_DIRS 漏配某张图）。
    emb = [r for r in src if is_embed_asset(r)]
    if not emb:
        print("⚠ 源码里存在 //go:embed，但一个嵌入资产都没收到 —— 检查 EMBED_DIRS",
              file=sys.stderr)
        return 1
    print(f"嵌入资产 : {len(emb)} 个")
    for r in emb:
        print(f"  {r}")

    members: list[tuple[str, bytes]] = []   # (包内路径, 内容)

    for rel in src:
        with open(os.path.join(ROOT, rel), "rb") as f:
            members.append((f"src/{rel}", f.read()))

    if args.mode == "full":
        for abs_p, rel in collect_docs():
            with open(abs_p, "rb") as f:
                members.append((rel, f.read()))

        for abs_p, rel in collect_evidence():
            with open(abs_p, "rb") as f:
                members.append((rel, f.read()))

    # 注意：`deploy/install.sh` 已由 collect_src() 收成 `src/deploy/install.sh`
    # （SRC_EXT 含 .sh），所以包内只有一份，不另做顶层副本，避免"哪份是权威"的歧义。

    # ── 一致性核对（读现有产物哈希） ──────────────────────────────────────
    artifacts: list[tuple[str, str, str]] = []
    for rel in ("dist/CS2雷达.exe", "dist/capture.exe", "dist/cs2radar-client.zip",
                "dist/radarserver-linux-amd64", "dist/radarserver.exe",
                "deploy/radarserver"):
        p = os.path.join(ROOT, rel)
        if os.path.isfile(p):
            artifacts.append((rel, f"{os.path.getsize(p):,}", sha256_file(p)))
        else:
            artifacts.append((rel, "-", "(缺失)"))

    readme = build_readme(args.mode, src).encode("utf-8")
    consistency = build_consistency(artifacts).encode("utf-8")
    exclude = build_exclude(args.mode).encode("utf-8")

    members.append(("README.md", readme))
    members.append(("_CONSISTENCY.md", consistency))
    members.append(("_EXCLUDE.md", exclude))

    # ── 清单 ──────────────────────────────────────────────────────────────
    manifest = {
        "pack": PACK_NAME,
        "mode": args.mode,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source_root": ROOT,
        "file_count": len(members),
        "note": "path 为包内相对路径（不含 cs2radar-source/ 前缀）；sha256 为内容哈希",
        "files": [
            {"path": rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for rel, data in sorted(members)
        ],
    }
    members.append(("_SOURCE-PACK-MANIFEST.json",
                    json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")))

    out = args.out or os.path.join(
        DIST, f"{PACK_NAME}-{time.strftime('%Y-%m-%d')}.zip")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.exists(out):
        os.remove(out)

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel, data in sorted(members):
            zi = zipfile.ZipInfo(f"{PACK_NAME}/{rel}", date_time=time.localtime()[:6])
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)

    print(f"输出     : {out}  {os.path.getsize(out):,} bytes")
    print(f"文件数   : {len(members)}")
    print(f"模式     : {args.mode}")
    print(f"zip sha256: {sha256_file(out)}")
    print("")
    print("包内顶层：")
    tops = sorted({rel.split("/")[0] for rel, _ in members})
    for t in tops:
        n = sum(1 for rel, _ in members if rel.split("/")[0] == t)
        print(f"  {t:<28} {n} 项")
    print("")
    print("一致性核对：")
    for rel, size, h in artifacts:
        print(f"  {rel:<34} {size:>14}  {h[:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
