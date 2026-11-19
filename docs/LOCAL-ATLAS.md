# 本地地图工作台（2026-10-29）

这次只改原生客户端内置的 `internal/uibridge` 本地页面与参考数据存储，不修改采集、密钥、解析、鉴权和线上服务。新增接口仍在原有 loopback、Cookie、Origin、Sec-Fetch-Site、授权新鲜度边界内。

## 使用

完整解压 v14 客户端，保留 `maps` 与 `atlas` 文件夹。正常登录后打开雷达视图：

- 原有 17 张本地 PNG 字节不变；11 张参考覆盖的地图提供 97 个可开关中文名称，不把文字烧进底图。
- 滚轮以鼠标位置缩放，拖动平移，按钮或数字 0 居中。视口变换对底图、实时像素与参考图层统一生效。
- 地名和可选道具名称采用屏幕空间避让；放不下时隐藏标签。v14只提供视口基础；v15新增人物名字与动态跟随，见 PLAYER-NAMES-FOLLOW.md，仍不新增朝向。
- 自带数据只有 Dust2、Ancient、Inferno：38 个站位、52 个道具、63 个截图引用（56 份去重文件）。其他地图没有的数据保持空白。
- 道具库支持名称/说明搜索、分类、T/CT 筛选；点击列表定位并查看操作说明与原截图。
- 编辑点位、百分比坐标或点击重新定位，保存前先备份；支持重新加载、导出 JSON、恢复上一版。
- 当前用户的 `%APPDATA%\gamesense\atlas\data.json` 跨本地端口与重启保留；`data.json.bak` 是最近一版备份。不是多版本历史归档，不会上传服务器。
- 损坏数据不会被静默重置；并发编辑使用文件锁和修订号，冲突要求重新加载。

## 对齐限制

参考道具来自不同版本的底图，导入只做初步视觉对齐，**不是实机精准投掷校准**。Ancient、Inferno 的点位应先对照截图，在原图中用本地编辑校正。中文位置也需要用户按熟悉的叫法复核。Nuke/Vertigo 保持原有合成底图布局，不新增楼层/Z 推断。

## 构建与素材

Go 离线构建使用仓库 vendor。生产构建方式不增加本地解析回退：

```sh
go build -mod=vendor -trimpath -buildvcs=false -ldflags '-s -w -H=windowsgui -X main.defaultGUIMode=true' -o gamesense.exe ./cmd/collector
```

`atlas_seed.json` 嵌入二进制；截图必须保留客户端随附的 `atlas/images` 文件。每个截图按嵌入的 SHA256、文件名白名单、大小和图片尺寸检查，不能把任意路径当截图。原始底图继续从 `maps/<mapid>/overview.png` 读取。

参考包 `cs-prop-spots-main (1).zip` SHA256：`9d8db832c25fecb5ed823a125fa5c0eb0abd745197526cfddb8b86648cdaa18f`。交互思路参考 cs-prop-spots，MIT ©2026 nc3021；客户端保留原许可证及来源说明。游戏地图和截图不因代码 MIT 而获得重新授权，公开/商业分发应另外核实权利。

测试以隔离合成像素、临时用户数据和公开随附素材进行，不采集游戏、不读取设备凭据、不调用生产服务。真实对局与精确点位验收需另测；Windows 客户端未做 Authenticode 签名，不应关闭系统安全检查。
