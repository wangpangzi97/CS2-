# GuYi v2 授权对接（2026-10-22）

本变更仅负责授权；未更改抓包、内存/密钥提取、反作弊策略、地图、100ms 页面刷新或昵称功能。

## 配置与使用

1. 后台创建应用，记录公开 app_key 与数字 app_id；api_secret 和任何管理令牌绝不可分发。
2. 将 license.json.example 复制为 exe 同目录 license.json，填入实际公开应用信息。示例 APP_KEY/0 故意无效，不能作为已部署配置。
3. 连接目标必须有有效 HTTPS 证书（域名 DNS SAN 或 IP SAN）；已部署 IP 为 118.25.176.85。私有 CA 可在 ca_file 指定本地 PEM 文件（相对 license.json 目录）；没有跳过证书检查选项。
4. 先运行 `guyi-license.exe activate`，交互输入卡密；在当前 Windows 用户的 AppData/GuYiAccess 下用 DPAPI 保存，不放入命令行/配置/日志。
5. 用 `capture.exe -license-check` 或 `guyi-license.exe check` 仅检查授权，不打开网卡或游戏进程。授权后再由用户正常启动程序。
6. 换机需明确运行 `guyi-license.exe unbind`；服务端扣 12 小时、24 小时冷却规则继续生效。

GUI 与 CLI 共用 startCapture 的授权闸门，在 newSender 和 pcapdev.Open 之前执行；缺配置、无卡、错误证书、拒绝、撤销或协议错误均不能进入采集。
每分钟心跳，短期会话到期前重新激活；请求失败即通知停止现有采集，不回退旧接口。会话密钥仅留在内存，签名与响应 AES 密钥由不同 HKDF info 派生。
受保护响应必须同时通过 GCM tag 与 app_id/key_version/本次 nonce 的 AAD 检查，不能用明文 code=200 绕过。

原 cmd/launcher 的 radar-login-v1 是历史重构入口，不作为本次分发入口，也未在本次运行；不能通过改一个旧服务器 URL 来接入 GuYi v2。分发以 collector 的 GUI/CLI 和 guyi-license 为准。
授权检查不是防逆向/防篡改技术；修改自己客户端的用户仍可能绕过本地界面逻辑。设备哈希也不是设备硬件证明。

## 验证范围

PHP 原生 hash_hkdf/HMAC/AES 互操作向量；TLS 本地服务的激活/心跳/解绑与负面响应测试；真实 PHP 控制器 + 独立 MariaDB 测试库的 TLS 联调。
不自动运行实时抓包，不宣称已经完成服务器上线或实机业务验证。部署状态以同目录交付记录为准。
