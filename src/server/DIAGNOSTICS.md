# 生产诊断边界

正式 `collector` 和 `radarserver` 不导出原始包、连接密钥、IV、明文、内存上下文或完整 goroutine 栈。

- 服务端旧 `dumpGNSDiag`、`dumpFrameHeads`、`savePlain`、`savePlainBin`、`noteSignonStream`、`saveUnrel` 已退役；不再为落盘累积明文、signon、netchan 或消息副本。解析器正常工作所需的会话内存不属于诊断副本。
- `DebugSlots` 仅保留源码兼容，不能开启原始世界坐标日志。底层详细日志出口静默；运行日志仅保留限频数值计数。
- 客户端不自动生成诊断报告、日志文件或 UI 栈转储。`ipc/dump/diagnose/logfile/ui-freeze/hints-info` 在授权、界面桥接和采集之前拒绝；旧 IPC 包/密钥写出分支也已移除。
- 客户端事件仅输出受限事件名及明确类型的包数/字节数，不输出事件 payload。历史密钥诊断 printf 和 JSON 复现文件出口静默。关键的进程恢复失败警告仍保留，但不含底层内存/错误详情。
- 不存在能重新开启敏感转储的运行参数、环境变量或诊断 build tag；自定义 tag 仍执行同一套关闭策略。测试仅使用合成数据。

边界说明：这不是内存清零或防本机管理员读取机制。采集、握手识别、密钥获取/试解密校验仍在本机；完整雷达解码/实体解析仅链接进服务端。关闭诊断不等于已经完成服务器部署。历史离线工具和旧 launcher/install.sh 不属于获准发布入口，部署入口迁移完成前不要运行它们或分发这些候选构建。
