# 本包排除了什么、为什么

打包模式：`full`

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

- `logs/raw_single_exe_verify_2026-10-16.txt`
- `logs/capturefilter_verify_2026-10-16.txt`
- `logs/rawtest_evidence.txt`
- `logs/udpprobe_verify.log`
- `logs/udpprobe_verify2.log`
- `logs/udpprobe_v2.log`
- `logs/s_verify.jsonl`

## 三、模式差异

- `--mode full`（默认）：`src/`（含 `deploy/install.sh`）+ `docs/` + `evidence/`
- `--mode code`：只有 `src/`（最精简，适合只看代码）
