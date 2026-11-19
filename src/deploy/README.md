# 部署入口迁移：仅离线准备，尚未安装

旧 `install.sh` 与旧 `cmd/launcher` 已停用，退出码固定为 2；不要使用历史包或手动恢复静态 token、自签名、`-insecure`、stdout 密钥包/SSE 页面。正式客户端入口是原生 collector GUI，数据端仅允许设备持钥授权和有效 IP HTTPS。

## 生成可审查配置，不启动任何服务

1. 复制 `deployment.example.json`，把 `app_id: 0` 改为确认后的应用 ID；0 是禁止误运行的未配置值，不是有效默认应用。保持当前独立 IP HTTPS origin；该工具不支持域名或 HTTP 回退。
2. 用 Python 3 标准库运行 `python -B deploy/render.py --config deployment.json --out fresh-output`。输出目录必须不存在；不接受额外字段、重复字段、凭据 URL、路径/换行注入、本地 IP 或非 443 端口。
3. 输出只是11份文件，不安装账户、不改 Nginx/防火墙/证书、不迁移数据库、不启用 systemd。`approved-releases.json`和新增的`approved-rollouts.json`总是空列表，`release-trust.json`的公钥指纹为null，不生成任何公钥/私钥，默认禁止首次安装和版本切换。新增`rollout.py`是尚未批准/安装的管理员编排源码，不是自动上线授权。

## 权限与现有站点边界

- systemd 以专用 `gamesense-radar` 非登录账户/组运行，不加入 root/www-data 组，不授予 sudo；运行目录、代码、发布指针和 admin 控制文件只能由管理员写。单实例、回环 `127.0.0.1:18081`，公网不开放此端口。
- 单元使用 `ProtectSystem=strict`、空 capabilities、`NoNewPrivileges`、私有临时目录及回环 IP 限制。参考 [systemd.exec 官方文档](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)。实际 systemd/kernel 对限制项的支持必须验证；解析成功不等于运行时隔离已经生效。
- 当前已在授权服务器Linux6.1/systemd252/cgroup v2的独立短生命周期单元中，以合成程序和现有非root UID65534验证选定运行时限制；不是正式服务部署。实测仅有`ProtectSystem=strict`时根挂载只读，但该主机`/run`仍可写，故增加显式`ReadOnlyPaths=/run`并以世界可写合成canary复测EROFS，不能把普通文件权限拒绝当成只读挂载生效。私有`/tmp`仍须可写；只读挂载不禁止连接其中的AF_UNIX套接字。模板实际运行账户、PHP/数据库配置与完整程序尚需另行上线验收，不能由替代身份的沙箱探针推断可用性。
- 仅将 locations 片段加入**现有 IP HTTPS 的 server 块**，upstream 片段按 include 路径安装；不得替换整个既有站点。443证书/续期、GuYi路由、SSH隧道后台均保持独立。片段在非 HTTPS 上直接拒绝；覆盖 `X-GS-TLS`/`X-GS-Client-IP`，清除转发身份头。参考 [Nginx proxy_set_header、proxy_pass、buffering 官方文档](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)。应用层签名、限流和归属检查仍由 Go 执行，代理不是鉴权替代物。
- Nginx 仅转发明确的 auth/ingest/pixel/maps/map/固定 PNG 路由，其余数据API、旧 radar/events 拒绝，公共 health 隐藏。服务端自行校验方法、原始路径、正文、签名和 nonce；不提供任何公开原始视图。
- 运行账户只读取 `/etc/gamesense-radar/license-db.php`（root:gamesense-radar，0640），该文件在服务器另行配置最小数据库权限，不复制到客户端包。不得把现有 root/Web 数据库配置直接拷贝或 chmod 给服务；模板明确阻断 `/etc/guyi-access`。PHP CLI 的 sodium 配置路径针对现有 PHP8.2 布局，若更换 PHP 版本，先改模板并重新验收，不能跳过扩展。
- 数据库迁移使用独立管理员身份；数据服务权限与 Web 身份分开。合成夹具已验证列级权限、事务FOR UPDATE和真实HTTP激活/心跳/踢线/解绑等选定链路，见 `../server/README-DATA-GRANTS.md`。生产准备必须另行批准；加法schema、身份和候选目录准备不等于服务启用，不能据此宣称完整管理后台/生产数据链已验收。
- 内存512M、Tasks128等为待压测起点，不代表容量承诺；单实例重启使数据资格失效，要求客户端重新认证，禁止横向扩容直接复制内存会话。

## 旧部署回滚入口（只读，与源码四角色 ROLLBACK.sh 不同）

固定目录 `/opt/gamesense-radar`：`releases/<manifest SHA256>/` 放只读 `radarserver`、`server/LicenseAuthority.php`、`server/license-authority-cli.php` 和 `manifest.json`；`current` 是相对链接 `releases/<SHA256>`。`admin/` 放 `release_check.py`、`policy.json`、`approved-releases.json`，全部 root 所有且组/其他用户不可写。

manifest 精确字段：`schema:1`、`security_epoch:1`、`public_origin`、`app_id`、`entrypoint:"remote-device-proof-v1"`、`files`。files 恰好包含上述3个可执行/适配器文件的 SHA256；release目录名为 manifest 原始字节的 SHA256。 release中还必须有64字节原始Ed25519签名`manifest.ed25519.sig`，签名覆盖固定上下文和manifest原始字节（见下文）。签名与审批必须同时通过；只改审批哈希不能使未签名发布通过。经签名构建校验、全流程测试和管理员批准后，才能将 digest 加入审批列表；渲染工具不会自动批准。此清单是管理员审批，不等于数字签名，也不能证明程序不含缺陷。

`rollback-release.sh EXPECTED_CURRENT_SHA256 TARGET_MANIFEST_SHA256 --plan`仍只读验证两版的签名/审批、兼容策略与指针。**`--apply`现在固定exit2/COHERENT_ROLLOUT_REQUIRED，不再写指针或调用服务。** 仅切数据二进制会绕过双后台/路由一致事务，所以所有部署写操作统一通过下面的独立批准编排。不要将源码ZIP回滚、仅业务release的只读guard与完整生产部署混为一谈。

本阶段只对隔离夹具验证审批与完整性逻辑、语法和拒绝分支；没有在 `/opt` 切换版本、调用生产服务重启或执行真实生产回滚。


## 独立发布签名信任与首次安装验收

发布签名key必须与客户端设备/卡密/应用key分离，由管理员单独保管。渲染器不会生成或信任生产key；另行授权生成key也不等于批准发布。管理员在`admin/release-signing-public.der`安装规范44字节Ed25519 SPKI DER公钥（前缀`302a300506032b6570032100`及32字节公钥），经可信渠道核对该DER的SHA256，再配置root控制的`admin/release-trust.json`：精确字段`schema:1, algorithm:"Ed25519", public_key_sha256`。不接受manifest自选公钥、网络自动取key或卡密设备key作为发布信任。公钥/信任配置/审批表、所有release及父目录须root所有且组/其他用户不可写，普通文件不得是符号链接。

签名消息的精确字节为ASCII `gamesense-release-manifest-v1`、一个LF，再紧接manifest.json原始UTF-8字节；不是hex摘要，也不重新序列化JSON。私钥保管环境按此格式生成message.bin，用OpenSSL Ed25519命令`openssl pkeyutl -sign -rawin -in message.bin -inkey release-private.pem -out manifest.ed25519.sig`产生原始64字节签名。私钥不随release、配置或客户端分发；服务端只需公钥。这只说明格式，不授权生成生产私钥/自动批准。

验签使用固定`/usr/bin/openssl`，不自写密码算法、不依赖PATH选择程序；子进程忽略调用者OpenSSL配置/模块环境，限时5秒。缺少运行库/key/signature、指纹不符、错误签名/上下文、改动正文或artifact、未批准、策略/路径/权限不符均拒绝。签名证明受信key签署这些字节，不证明代码没有缺陷或root管理员未失陷。

首次安装不能虚构旧release调用双版本回滚。经批准的只读材料安装到固定`/opt/gamesense-radar`后，以Linux root运行`python3 /opt/gamesense-radar/admin/release_check.py --first-install TARGET_MANIFEST_SHA256`。它仅输出只读验收结果，不安装、不建current、不启动服务。任何既存current（文件、链接、悬空链接）都拒绝首次模式。新增编排在同一管理员锁内重新验证，不能复用一次离线验收来代替生产迁移、完整沙箱和实机验收。

## 受控首装与双后台/路由一致维护事务

`rollout.py`生产CLI固定`/opt/gamesense-radar`、`/opt/guyi-access/releases`、`/run/lock/gamesense-radar-release.lock`及下表8个配置目标；不接受root/owner/命令/可执行文件路径覆盖。标准库实现，不用shell执行计划内容。库的`Layout`/`Runtime`参数仅供隔离夹具替代文件根和服务动作，不是生产CLI后门。发布签名、发布审批**和独立维护计划审批**三者都必须通过；程序不自签、不写审批、不生成账户或凭据、不执行DB迁移/恢复、不启用systemd自启动。

维护计划放`admin/rollouts/<计划原始字节SHA256>/plan.json`，8份精确after配置字节放同目录`files/<slot>`。`admin/approved-rollouts.json`精确字段为`schema:1, plan_sha256:[...]`，默认为空；只能在明确批准本次停机范围和全部字节后由管理员填写。单独批准源包、业务release、数据库准备或执行`--plan`都不构成此批准。

计划精确字段：`schema:1`、`mode:first-install|switch`、`expected_current:null|旧manifest SHA256`、`target:目标manifest SHA256`、`maintenance_stop_all_nginx_and_php_fpm:true`、`backends`、`before`、`after`。首次模式必须没有任何current；切换/部署回退必须两版均已签署/批准且同策略。`backends`精确含api/admin，各自是`name`（gamesense-dataauth-12位小写hex-api/admin）和`tree_sha256`；每个后台恰65个普通文件，无链接、root控制，SHA取相对路径→文件SHA字典的UTF-8、sort_keys=true、分隔符逗号/冒号且无空白JSON。不会信任调用者随意指定的项目目录。`before/after`必须精确含下表8槽；before为现有字节SHA或不存在时null，after为对应files/<slot>字节SHA。无额外目标/重复键/路径穿越；root及父目录不可由运行用户修改。

| slot | 固定目标 |
|---|---|
| site_api | /etc/nginx/sites-available/guyi-ip-api |
| site_legacy_api | /etc/nginx/sites-available/guyi-access |
| site_admin | /etc/nginx/sites-available/guyi-tunnel-admin |
| pool_api | /etc/php/8.2/fpm/pool.d/guyi-access.conf |
| pool_admin | /etc/php/8.2/fpm/pool.d/guyi-http-admin.conf |
| unit | /etc/systemd/system/gamesense-radar.service |
| upstream | /etc/nginx/snippets/gamesense-radar-upstream.conf |
| locations | /etc/nginx/snippets/gamesense-radar-locations.conf |

计划不是任意配置生成器：管理员需先以原配置做最小编辑，保留证书、GuYi路由、SSH隧道限制、站点及FPM其他选项，再审查整个前后字节/hash；编排本身不声称能从任意Nginx文本推断其语义。两套站点/FPM候选必须分别绑定两套已校验后台，旧域名/API站点也绑定同一新API后台；三个sites-enabled链接必须精确指向本次审阅的sites-available文件，unit绑定固定current、专用身份/配置和API后台。安装前仍须审查管理头像/上传等持久化写目录。**该策略会短暂停止整个nginx和PHP-FPM进程（影响同实例其他站点），必须单独批准维护窗口；不支持无停机多站点发布。** 这避免部分指针/配置切换时仍向混合版本发送请求，不能夸称跨多个文件的原子rename。

CLI格式为`rollout.py PLAN_SHA256 --plan|--apply`，PLAN_SHA256必须是实际已审查且批准的plan.json原始字节SHA。`--plan`只加同一锁并只读校验，不动服务/配置/current（可能首次创建root锁文件）；`--apply`也在锁内重新读全部材料，调用实际专用UID的双后台PHP probe。通过后先写root私有事务备份/WAL，再停Nginx→PHP-FPM→数据服务并确认18081端口空，停机后再重验所有前置哈希和审批；安装全部配置及current后运行nginx -t、php-fpm8.2 -t、daemon-reload。先启动私有PHP-FPM/数据服务并有界检查回环health，最后才启动Nginx放行流量。

任一步失败，先再次确认所有服务停止，然后仅当当前字节仍为本事务before/after且current为本事务前后值时，恢复本事务保存的原配置字节/权限和原指针，**保持服务停止，不自动启动旧服务/本地模式**。有外部改动或不能确认停机时不覆盖配置，journal标MANUAL_RECOVERY_REQUIRED。事务备份可能含私有配置，全部root0600/目录0700，不能下载到客户端或放公网。状态在`admin/transactions/<UUID>/journal.json`，包含计划SHA、指针和原槽位hash/mode/gid；非COMMITTED/FAILED_CLOSED事务阻止下一次apply。进程被SIGKILL/断电时不能承诺自动回滚：先停服务、人工核对该WAL/批准计划/服务器私有备份再恢复，程序不会猜测或盲重放。

`test_rollout.py`在root私有Linux夹具使用真实文件、flock、相对symlink、fsync、OpenSSL签名和实际子进程死亡；服务动作由合成Runtime替代，没有调用生产systemd/nginx或运行游戏。测试覆盖首次/切换、空审批/坏签/后端或配置篡改、锁竞争、停机后重验、部分写/解析/启动/health/开站失败、外部改动拒绝覆盖和崩溃WAL。该测试不是完整正式服务沙箱、真实nginx语义、实际停机/重启或游戏客户端验收。

## 上线前仍须通过

合成HTTP/数据最小权限已验证的选定用例 → 生产账号/迁移评审和实际配置、配额/负载与运行时沙箱检查 → 签名发布与审批清单 → 首次受控部署及故障演练。当前不得直接执行 `--apply`；当前空审批表会拒绝。客户端密钥获取/少量试解密校验仍在本机，不宣称完全零本地加密代码。

本地无网络策略测试：`python -B deploy/test_deployment.py`。Windows策略夹具模拟 current 指针；Linux隔离夹具另行验证实际符号链接和文件权限。测试不执行游戏、采集、服务重启或任何正式版本切换。
