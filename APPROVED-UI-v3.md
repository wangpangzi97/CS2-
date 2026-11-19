# 已审定 UI v3 / 2026-11-01

只修改 Go 原生视觉/控件可见性与嵌入的雷达 HTML/CSS/JS。保留原授权、设备凭据、采集、上行、姓名协议、地图/atlas、分享边界。
品牌为逐字流彩，先显示品牌，再由真实字形采样的方块碎散，最后登录窗口从72%展开。
登录仅品牌和原生掩码卡密输入（Enter提交）；失败时显示脱敏诊断，登录后仅地图、可信人物、声音、打开雷达。
雷达移除两个手动地图选择器，依服务端 map_id 自动同步；人物姓名、跟随、道具、分享保持。
授权入口控制流注释保留；三个 EXE 继续 -literals -tiny -seed=random，GARBLE_EXPERIMENTAL_CONTROLFLOW=1，不签名。
-tiny 用于裁剪信息，不是控制流开关。保留完整 maps/atlas 和公开配置；不包含业务密钥。
build_v16_protected.py 新增 --origin-source-sha256 校验对应 v16 运行包 receipt，--source-sha256 记录本次源码父包。
不包含云更新或3D修改。原生 GDI 呈现并非浏览器像素级复刻；浏览器雷达沿用审定 CSS，修正旧 h1 span 样式冲突。
