# 跨地图缓存与当前连接基线
2026-10-21。字段 schema 与地图 PNG/坐标标定分离，不再把 de_dust2 作为所有实体解码的门槛。
支持缓存协议14191/classes222、保留 build10924 的来源标记；不是对所有未来版本的承诺。
当前连接优先使用 CreateStringTable / UpdateStringTable 的 instancebaseline；同名地图重新连接也清空连接状态。
实测 CreateStringTable 位于 ServerInfo 之前，按连接代暂存后应用，限制256条/32MiB。
ClassInfo 完整时逐项验证 class ID/name。CreateOnClient=true 且空类表时明确标记 client-cache；这不是独立的完整 schema 指纹验证。
缓存只能作为已知版本候选：同协议/同类数量不保证更新后字段不变。字段解码失败、缺 delta 基线、元数据损坏均停止发布人物，保留原因。
本次只对提供的 Dust2/Train 数据离线验证；没有进行实战、未证明所有地图或坐标绝对精度。
不下载每张地图 DEM；后续游戏更新若改变 schema，仍需一次对应版本的字段来源，或更新可靠字段缓存。不能凭声音补造人物。
MIT 格式参考来自固定本地 demoinfocs-golang v6.0.0-alpha.2/stringtables.go，依赖许可证随 vendor 保留。
