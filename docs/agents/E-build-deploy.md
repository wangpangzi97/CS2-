# 子 Agent E · 构建部署

## 角色
负责「编译 → 打包 → 上传 → 部署 → 复验」。**本机没有 Go**，工具链是手工装的，所有命令必须显式带环境变量。

## 拥有（可写）
- `rebuild/cs2radar/tools/build_client_package.py`（**客户端分发包打包**）
- `rebuild/cs2radar/deploy/install.sh`
- `logs/py_remote.py` / `logs/py_chunked_upload.py` / `logs/rsh.sh` / `logs/chunked_upload.sh`
- `logs/remote_redeploy.sh` / `logs/cleanup_remote.sh`

## 环境（必须记住）

### Go 工具链
```bash
export GOROOT="D:/csleida/1/2026-10-13/tools/go"          # go1.24.4 windows/amd64，手工解压
export GOCACHE="D:/csleida/1/2026-10-13/tools/gocache"
export GOPATH="D:/csleida/1/2026-10-13/tools/gopath"
export GOPROXY=off CGO_ENABLED=0
```
**不带这些变量会污染 `%USERPROFILE%\go`。** 调用一律用 `"$GOROOT/bin/go.exe"`。

### 目标服务器
| 项 | 值 |
|---|---|
| 主机 | `109.206.245.172` |
| SSH | **端口 22809**（不是 22），root 免密 |
| 系统 | CentOS 7.6.1810 / x86_64 / 内核 3.10 / glibc 2.17 |
| 安装目录 | `/opt/cs2radar/` |
| 监听 | `0.0.0.0:8899`（HTTPS 自签 + token） |
| 服务 | systemd `cs2radar.service` |
| 不可干扰 | `gamesense-lic.service`(8787)、宝塔(8888)、nginx(80/443/888)、mysqld(3306) |

## 交叉编译与打包

> ⚠ **`-trimpath -ldflags="-s -w"` 不是可选项。** 2026-10-16 漏过一次：
> 未 strip 的 `capture.exe` 是 10,044,928 字节（strip 后 6,895,616）——
> 体积翻倍，而且**符号名全部暴露在二进制里**，是检测足迹上的倒退。
> 判断方法：`capture.exe` 明显 > 7 MB 就是漏了。

```bash
cd D:/csleida/1/2026-10-13/rebuild/cs2radar
GOOS=linux GOARCH=amd64 "$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w" -o dist/radarserver-linux-amd64 ./cmd/radarserver
GOOS=windows GOARCH=amd64 "$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w" -o dist/radarserver.exe ./cmd/radarserver
# 客户端两个 exe（同一份代码，两种构建）
GOOS=windows GOARCH=amd64 "$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w" \
    -o dist/capture.exe ./cmd/collector
GOOS=windows GOARCH=amd64 "$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w -H=windowsgui -X main.defaultGUIMode=true" \
    -o "dist/CS2雷达.exe" ./cmd/collector
cp dist/radarserver-linux-amd64 deploy/radarserver
cd deploy && tar czf ../cs2radar-deploy.tar.gz install.sh radarserver && cd ..
gzip -9 -c cs2radar-deploy.tar.gz > cs2radar-deploy.tar.gz.gz
sha256sum dist/radarserver-linux-amd64    # 部署后必须与远端 /opt/cs2radar/radarserver 一致
```

## 客户端分发包（本机方案，默认形态）
**两个 exe 都编好**（见上）之后，用 `tools/build_client_package.py` 组包 —— **可重复执行**：
```bash
cd D:/csleida/1/2026-10-13/rebuild/cs2radar
export MSYS_NO_PATHCONV=1
"C:/Users/Administrator/.workbuddy-ai/binaries/python/envs/default/Scripts/python.exe" tools/build_client_package.py
# 输出 dist/cs2radar-client/ 与 dist/cs2radar-client.zip，并打印各 exe / zip 的 sha256
```

> ❌🔴 **exe 必须编到 `dist/`，不能编到 `build/dist/`。**
> `build_client_package.py` 的 `DIST = <ROOT>/dist`（`ROOT` = `rebuild/cs2radar`）。
> 2026-10-17 第十三轮踩过：把 exe 编到 `build/dist/` 后脚本照样"成功"，
> 包里装的却是上一次的旧 exe —— 直到对比哈希才发现（脚本打印的 sha256
> 和 `dist/*.exe` 对不上）。
> **打包后必做一步核对**：
> ```bash
> sha256sum dist/*.exe dist/cs2radar-client/*.exe dist/cs2radar-client.zip
> # 三行 exe 哈希里，前两组必须两两相等
> ```
> 另外 `build/dist/` 这个目录已经删掉，别再建。

> 同步交付副本：`cp dist/cs2radar-client.zip ../../report/cs2radar-client.zip`
> （`report/` 下那份才是用户拿到的，哈希要和 `dist/` 里的一致）。
分发包内容（**本机模式：无 server.crt、无 token、无驱动、无 .bat**）：
`CS2雷达.exe`（双击即用，窗口版）+ `capture.exe`（命令行排障版）+
`capture.json`（`{listen,session,proc}`）+ `使用说明.txt`。

> 2026-10-16 起**不再有 .bat**：窗口版自己弹 UAC 提权，不需要 cmd 中转。
> `backend` / `dev` 配置项也已删除（抓包只有 raw socket 一条路）。

**编码硬约定（改脚本别破坏）：**
| 文件 | 编码 | 原因 |
|---|---|---|
| `使用说明.txt` | **UTF-8 with BOM** | 记事本可靠识别中文 |
| `capture.json` | **UTF-8 无 BOM** | Go 的 `encoding/json` 遇 BOM 会报错 |
| `.exe` | 二进制 | 窗口版 PE subsystem 必须 = 2（GUI） |

组包后必做的校验（见 `report/纯raw单exe版本.md` §5）：
1. 逐文件编码校验（`.txt` 有 BOM、`.json` 无 BOM）；
2. 用 Python 读 PE 头确认 `CS2雷达.exe` subsystem=2、`capture.exe` subsystem=3；
3. 干净目录解压 → `capture.exe -replay <样本>` 应 exit 0 且解出目标坐标；
4. 干净目录解压 → `"CS2雷达.exe" -duration 8s -auto-exit` 应 exit 0；
5. `netstat -ano | grep <端口>` 在退出后**应为空**（进程真的收干净了）。

改了 `cmd/collector/*.go` 之后还要跑这三条（提权分支的回归网，别删）：
```bash
"$GOROOT/bin/go.exe" test -count=1 -run 'TestEnsureElevated|TestBuildArgLine|TestWin32' ./cmd/collector/
```
- `TestEnsureElevatedAlreadyAdmin` —— 已是管理员不得重入（重入 = 死循环）
- `TestEnsureElevatedStopsLoopWhenStillNotAdmin` —— 带 `-elevated` 却仍非管理员**必须报错**
- `TestBuildArgLine` —— 重入命令行重建（追加 `-elevated`、带空格参数加引号）
- `TestWin32ProcsResolve` —— 23 个 Win32 导出逐个 `Find()`

> 提权判定走 `var isAdminFn = winapiIsAdmin` 这个间接层，测试就是靠替换它来模拟
> 非管理员。**别把这个间接层删掉/内联掉**，否则这三条测试全废。

## 上传（三个坑，全踩过）

### 坑 1：系统 ssh 基本不可用
OpenSSH 10.3 给包打 IPQoS DSCP 标记 → 被中间设备静默丢包 → **约 50% 概率卡在 banner exchange**。
加 `-o IPQoS=none` 能缓解，但仍会偶发；**短时间猛发连接会被限速**，连 `mkdir` 都过不去。

### 坑 2：单连接传输量有硬限制
一条连接传 2.6 MB 会被 `Socket is closed` 掐断；`ControlMaster` 复用也会 `Connection reset by peer`。
**唯一可行姿势 = 128 KB 分块 + 每块独立短连接。**

### 坑 3：Git-Bash 会篡改命令行里的路径参数 ⚠️
Git-Bash 把形如 `/tmp/xxx` 的**参数**自动转成 Windows 路径再传给原生程序。
→ 远端实际收到了 `C:/Users/.../Temp/xxx`，写和校验用同一个错路径所以 md5 还对得上，**但文件不在你以为的地方**。
**解法：`export MSYS_NO_PATHCONV=1`**（heredoc 里的路径不受影响，所以只有"命令行参数"会中招）。

### 正确姿势：paramiko 分块上传
```bash
cd D:/csleida/1/2026-10-13/logs
export MSYS_NO_PATHCONV=1
PY="C:/Users/Administrator/.workbuddy-ai/binaries/python/envs/default/Scripts/python.exe"
"$PY" py_chunked_upload.py "D:/csleida/1/2026-10-13/rebuild/cs2radar/cs2radar-deploy.tar.gz.gz" /tmp/cs2radar-vN.tar.gz.gz 131072
# 期望结尾：REMOTE md5=<与本地一致> / UPLOAD_OK
```
paramiko 自带 SSH 实现、不打 DSCP，2~3 次尝试即连上；实测约 70 KB/s，2.6 MB 约 40 秒。
**注意：本地路径也必须用 `D:/...` 写法**（Python 是 Windows 版，不认 `/d/...`）。
**该服务器的 SFTP 写入不可用**（`open(...,'wb')` 返回 ENOENT），所以走 `exec_command("cat > file")` + 写 stdin。

## 远端执行
```bash
"$PY" py_remote.py run '<远端命令>'
"$PY" py_remote.py pull /opt/cs2radar/tls/server.crt server.crt
```

## 部署与复验
```bash
"$PY" py_remote.py run 'set -e; cd /tmp && gunzip -c /tmp/cs2radar-vN.tar.gz.gz > /tmp/cs2radar-vN.tar.gz \
  && rm -rf /tmp/cs2radar-deploy && mkdir -p /tmp/cs2radar-deploy \
  && tar xzf /tmp/cs2radar-vN.tar.gz -C /tmp/cs2radar-deploy \
  && sha256sum /tmp/cs2radar-deploy/radarserver \
  && cd /tmp/cs2radar-deploy && bash install.sh 2>&1 | tail -6 \
  && sha256sum /opt/cs2radar/radarserver && systemctl is-active cs2radar.service'
```
`install.sh` **幂等**：保留已有 token 与证书，只换二进制并重启服务；会自动放行 firewalld。

复验（期望 `targets=3`、坐标与 `mksession` 打印的真值一致）：
```bash
cd D:/csleida/1/2026-10-13/rebuild/cs2radar/dist
export MSYS_NO_PATHCONV=1
TOKEN=<从 install.sh 输出里取>
./mksession.exe -out s.jsonl -frames 60 -players 3
./capture.exe -replay s.jsonl -uplink https://109.206.245.172:8899/api/v1/ingest -session demo -token "$TOKEN" -ca server.crt
curl -sk -H "X-Auth-Token: $TOKEN" "https://109.206.245.172:8899/api/v1/radar?session=demo"
```
> ⚠️ **查询要紧接着上行**：`-player-ttl` 默认 10s，而 HTTPS 上行本身可能耗时数秒，隔太久会看到 `targets=0`（那是 TTL 过期，不是 bug）。

## 禁止
- ❌ 不要用 `scp`/`ssh` 传大文件（见坑 1/2），也不要再试 `ControlMaster`。
- ❌ 不要忘记 `MSYS_NO_PATHCONV=1`（会静默写到错路径）。
- ❌ 不要监听 `0.0.0.0` 而不配 TLS（远端模式）。
- ❌ 不要动 8787 授权服务、宝塔、nginx、mysql。
- ❌ 不要在 `install.sh` 里重新生成 token/证书 —— 会让已分发的客户端全部失效。
- ❌ **不要改分发包的编码约定**（bat 必须 GBK 无 BOM；txt 必须 UTF-8 BOM；json 必须 UTF-8 无 BOM）。
- ❌ **不要把 `server.crt` / token 加回本机分发包** —— 本机模式不需要，加了反而泄露远端凭据。
- ❌ 不要在 bat 里用 `start` 开浏览器 —— 必须用 `capture.exe -open-browser`（服务监听成功后才开）。
