# 数据授权适配器：列级最小权限与 HTTP 验收

这是**待审查、待部署**的授权矩阵，不是线上数据库变更。只适用于新的、无继承角色的独立 `*_data` 数据适配器账号，不是 root、Web/API 或后台管理账号。

## 为什么不能继续 SELECT c.*

卡密状态校验只需要卡密ID、状态、设备绑定、有效期、代次，以及应用状态/版本和活动设备状态。读取卡密备注、自定义内容、时长等无关列会使列级账号失败；不能为此把账号放宽到整个库。本适配器现用显式列投影，enroll也显式列出会话输入。卡密/应用/活动设备仅SELECT，只有公钥登记表允许SELECT/INSERT/UPDATE。

| 表 | 数据服务权限 |
|---|---|
| cards | SELECT(id,app_id,card_code,status,device_hash,expire_time,data_epoch) |
| applications | SELECT(id,status,key_version,api_secret) |
| active_devices | SELECT(card_code,app_id,device_hash,status,expire_time) |
| api_sessions | SELECT(session_id,app_id,card_code,device_hash,key_version,expires_at) |
| blacklists | SELECT(id,type,value) |
| data_device_keys | SELECT, INSERT, UPDATE；无DELETE |

不授予CREATE/ALTER/DROP、FILE、SUPER、用户管理或GRANT OPTION。不允许改卡密状态/应用秘密、删除设备登记，或读取后台账号、usage_logs、卡密自定义内容/时长。

`api_secret` 读取仅用于服务端验证原生会话派生HMAC，不能发给客户端。列级权限**不是按app_id隔离的数据库行级权限**；应用归属仍由固定启动AppID和SQL条件保证，不能夸大为可抵抗已失陷的服务进程。数据账号能够写公钥登记，仍是服务端信任边界。

## 生成 SQL，仅审查不连接数据库

复制 `data-grants.example.json`，填入实际数据库名和新建的专用 `*_data` 账号，host保留 `127.0.0.1`；空值会拒绝。然后：

```powershell
python -B server/render_data_grants.py --config data-grants.json --out fresh-authority-grants.sql
```

输出是原生SQL，但脚本自身没有数据库连接或执行功能，也不创建账号、不处理密码。仅接受严格小写标识符和回环账号，拒绝未知/重复字段及现有输出文件。SQL含全局REVOKE该**专用身份**已有权限；不要对共享账号执行，也不能认为REVOKE ALL会自动消除其已授予角色。先用安全运维渠道创建无角色的新账号，确认有效权限，再由独立迁移管理员审查执行。密码只保存在服务器root控制、数据服务可读的独立配置，不进入客户端包/命令行/聊天。

权限语法参考 [MariaDB GRANT官方文档](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/grant)。`FOR UPDATE` 在显式事务中的锁语义参考 [MariaDB官方文档](https://mariadb.com/docs/server/reference/sql-statements/data-manipulation/selecting-data/for-update)。实际验证版本为MariaDB11.4.6/InnoDB；其他MySQL/MariaDB版本、主机匹配、继承角色与权限组合要重新验证，不能仅看SHOW GRANTS推断实际拒绝效果。

## 本阶段实际验证边界

独立本机MariaDB实例中仅使用新合成库；独立Web/API CRUD账号与数据列级账号。原生Go SDK经测试TLS终结器转到真实GuYi公开入口、VerifyV2/Protocol/DeviceProof与真实PDO/InnoDB，不再用伪造的PHP成功响应代替控制器。内层仅回环HTTP，明确启用已有回环例外；另起不允许例外的进程，实际确认普通HTTP返回426。所有签名、nonce、设备证明和AES-GCM响应校验保持开启。

验证激活、加密心跳、真实nonce重放409、缺失/错误设备证明403、未授权管理403；签名管理kick、ban/unban及持钥unbind后，通过真实HTTP立即重新激活，再用**旧token+新nonce+有效设备签名**请求，等明确的两秒缓存边界后仍403。旧Store被删除，新会话可重新登记/200，旧token不复活；解绑冷却返回409。时延包含刻意缓存等待，不是生产SLA。像素视图仅使用合成空批次，不是游戏坐标解码测试。

同时直接执行账号权限负例，观察MariaDB1142/1143拒绝；允许的公钥登记INSERT/UPDATE在事务中回滚。Web身份的权限只覆盖这些API测试，不等于完整管理后台所需权限已验收；后台账号/迁移账号必须分开。

`internal/guyi/full_http_integration_test.go` 只在显式隔离夹具环境下运行；普通测试没有环境时跳过，不会触碰线上。夹具控制器、数据库口令、私有配置和进程脚本不包含在源码ZIP内。完整结果、原始命令与监听关闭状态由外层验证记录保存。本阶段未安装补丁、未创建生产账号、未改线上数据库；运行时沙箱、压测/配额、签名审批和受控首次部署仍在后续。
