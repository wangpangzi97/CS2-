# v16 混淆构建（2026-10-31）

使用匹配的 v16 源码和原运行包作为公开资源模板。Go 1.27.2、Garble v0.18.0。
源码副本仅在 authorizeCaptureWithCard 增加控制流注释，不修改只读分享、授权、姓名或地图逻辑。
三份可执行文件均使用 -literals -tiny -seed=random；环境 GARBLE_EXPERIMENTAL_CONTROLFLOW=1。
-tiny 是调试信息裁剪，不是控制流开关，会降低崩溃排障能力。混淆不是加密，也不保证免封号。

在 src 目录调用 tools/build_v16_protected.py，提供 --go、--garble、--runtime-template、
--source-sha256、--out。模板必须是对应源码的原 v16 运行包；回执源码哈希不匹配就拒绝。
构建 capture.exe、gamesense.exe 和设备凭据修复.exe，保留原包 atlas、地图、公开配置、说明与许可。
重新计算 SHA256SUMS.txt 并追加混淆构建记录；不分发源码、随机种子或私有编译日志。
此次不做 Authenticode 签名，也不增加云更新，不修改或部署远端服务。
设备凭据修复程序只编译不启动，避免触碰真实设备凭据。只读分享回归使用本地合成测试，不代表真实手机或公网验收。
请完整解压客户包，不要只复制 EXE；公开配置与素材保持目录关系。
