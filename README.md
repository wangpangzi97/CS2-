# CS2 雷达 · 重构工程源码包

本包是 CS2 雷达客户端 **v2.0.5 等价重构** 的完整源码（Go，零第三方依赖）。
打包时间：2026-10-20 14:33:11
打包模式：`full`
文件统计：.go 116 个 / .py 8 个 / .sh 1 个 / 编译期嵌入资产 18 个

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
"$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w" \
    -o dist/capture.exe ./cmd/collector
# 窗口版：PE subsystem=2（无控制台），双击即用
"$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w -H=windowsgui -X main.defaultGUIMode=true" \
    -o "dist/CS2雷达.exe" ./cmd/collector
```

> ⚠ **`-trimpath -ldflags="-s -w"` 不是可选项。** 漏了会得到约 10 MB 的未 strip 版本
> （体积翻倍，而且符号名全部暴露在二进制里，是检测足迹上的倒退）。
> 判断方法：`capture.exe` 明显大于 7 MB 就是漏了。

### 3.3 服务端（Linux）

```bash
GOOS=linux GOARCH=amd64 "$GOROOT/bin/go.exe" build -trimpath -ldflags="-s -w" \
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
