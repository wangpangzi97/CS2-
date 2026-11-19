#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 cs2_webradar 的地图资产转成本工程的 mapdata 定义 + 运行期底图目录。

来源（两个仓库，2026-10-20 核对）：
  clauadv/cs2_webradar  —— 地图资产原始作者是 Lexogrine（2021），
                           每张图目录里带 MIT LICENSE。
                           本脚本读取它被打包进 chao-shushu/CS2-DMA 的副本。
  Mzzzj/CS2_DMA_Radar   —— 另一套 12 张 1024px 彩色底图，**无任何许可证文件**，
                           因此不作为交付资产（只做过对齐验证）。

坐标约定换算（关键，错了整张图会偏）：
  webradar 的 meta.json5：
      resolution  = 每像素多少游戏单位（对 **1024 参考宽度**而言）
      offset.x/y  = 世界原点 (0,0) 距底图**左下角**多少单位
  本工程：
      origin_world_x = 左上角世界 X = -offset.x
      origin_world_y = 左上角世界 Y = -offset.y + 1024*resolution
      units_per_pixel = resolution
  两边 span 相同（1024*resolution），只是原点从「左下」换成「左上」。

输出：
  internal/mapdata/assets/<id>.json     内置地图定义（不含图片）
  dist/maps/<id>/overview.png           运行期底图（放 exe 同目录 maps/）
  dist/maps/<id>/meta.json5             原样保留，便于日后核对标定
  dist/maps/<id>/LICENSE                上游 MIT 许可证（有则拷）

用法：
  python tools/gen_map_assets.py --src "D:\\csleida\\2\\work\\_chao\\external\\webradar\\webapp\\maps"
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys

# 地图 ID → (显示名, 中文/常用别名)。别名让 -map 和下拉框都能用中文。
NAMES = {
    "de_dust2":    ("炙热沙城", ["dust2", "炙热沙城", "沙漠2", "d2", "dust ii"]),
    "de_mirage":   ("荒漠迷城", ["mirage", "荒漠迷城", "沙漠2号", "mirage2"]),
    "de_inferno":  ("炼狱小镇", ["inferno", "炼狱小镇", "小镇", "inf"]),
    "de_nuke":     ("核子危机", ["nuke", "核子危机", "核弹", "核子"]),
    "de_overpass": ("死亡游乐园", ["overpass", "死亡游乐园", "游乐园", "op"]),
    "de_train":    ("列车停放站", ["train", "列车停放站", "火车", "列车"]),
    "de_cache":    ("死城之谜", ["cache", "死城之谜", "死城"]),
    "de_ancient":  ("远古遗迹", ["ancient", "远古遗迹", "遗迹"]),
    "de_anubis":   ("阿努比斯", ["anubis", "阿努比斯"]),
    "de_vertigo":  ("殒命大厦", ["vertigo", "殒命大厦", "大厦", "跳楼大厦"]),
    "cs_office":   ("办公室", ["office", "办公室"]),
    "cs_italy":    ("意大利", ["italy", "意大利"]),
    "cs_agency":   ("事务所", ["agency", "事务所"]),
    "de_thera":    ("忒拉", ["thera", "忒拉"]),
    "de_palacio":  ("王宫", ["palacio", "王宫"]),
    "de_grail":    ("圣杯", ["grail", "圣杯"]),
    "de_golden":   ("黄金", ["golden", "黄金"]),
}

# 已经手工验证过的图，不覆盖（避免把「验过的数字」冲成「抄来的数字」）。
SKIP = {"de_dust2"}

# 🔴 许可证必须逐张如实写，不能笼统说「MIT」。
# 实测：17 张图里**只有 de_ancient / de_anubis 目录带 LICENSE**（MIT © 2021 Lexogrine），
# 其余 15 张上游根本没有许可证文件；而 cs2_webradar 这个仓库本身是 GPL-3.0。
# 另外这些底图都是从 Valve 的 CS2 overview 美术资源加工来的，版权归 Valve。
# 写清楚来源，别人才知道能怎么用。
CALIB_SRC_BASE = "cs2_webradar/meta.json5"
CALIB_SRC_MIT = "cs2_webradar/meta.json5 + 同目录 LICENSE（MIT © 2021 Lexogrine）"


def strip_json5(t: str) -> str:
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    t = re.sub(r"//[^\n]*", "", t)
    t = re.sub(r",\s*([}\]])", r"\1", t)
    return t


def png_size(path: str) -> tuple[int, int]:
    """读 PNG 头里的宽高，不依赖 PIL。"""
    with open(path, "rb") as f:
        head = f.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("不是 PNG")
    return (int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big"))


def build_map(mid: str, meta: dict, w: int, h: int, has_lic: bool = False) -> dict:
    res = float(meta["resolution"])
    off = meta.get("offset") or {}
    ox = -float(off.get("x", 0))
    oy = -float(off.get("y", 0)) + 1024.0 * res
    span = 1024.0 * res
    disp, alias = NAMES.get(mid, (mid, []))

    levels = []
    zr = meta.get("zRange") or {}
    if "min" in zr and "max" in zr:
        levels.append({
            "id": "main", "name": "主层",
            "z_min": float(zr["min"]), "z_max": float(zr["max"]),
        })
    for i, sp in enumerate(meta.get("splits") or []):
        sz = sp.get("zRange") or {}
        if "min" in sz and "max" in sz:
            levels.append({
                "id": f"split{i+1}", "name": f"分层 {i+1}",
                "z_min": float(sz["min"]), "z_max": float(sz["max"]),
            })

    note = (f"标定取自上游 meta.json5（resolution={res}，offset=({off.get('x')}, {off.get('y')}) "
            f"以底图左下角为基准），已换算成本工程的左上角原点。"
            f"**未用现场数据验证**：这张图还没有抓到过对局坐标，"
            f"点数够（≥12）且覆盖率 ≥90% 时才会被自动认图。")
    if not has_lic:
        note += (" 该图目录**没有附带许可证文件**（上游即如此），底图本身源自 Valve 的 "
                 "CS2 overview 美术资源，版权归 Valve；仅供本机使用，不要再分发。")
    if len(levels) > 1:
        note += (" 该图有多层（zRange + splits），目前只画主层底图，"
                 "下层视角偏移尚未实现。")

    return {
        "id": mid,
        "display_name": disp,
        "aliases": alias,
        "material": "",
        "ref_width": 1024,
        "ref_height": 1024,
        "origin_world_x": round(ox, 4),
        "origin_world_y": round(oy, 4),
        "units_per_pixel": res,
        "world_bounds": {
            "min_x": round(ox, 4),
            "min_y": round(oy - span, 4),
            "max_x": round(ox + span, 4),
            "max_y": round(oy, 4),
        },
        "levels": levels,
        "anchors": [],
        "calibration": {
            "source": CALIB_SRC_MIT if has_lic else CALIB_SRC_BASE,
            "verified": False,
            "points": 0,
            "coverage": 0.0,
            "note": note + f" 上游底图 {w}×{h}（会等比缩放到 1024 参考框，不影响标定）。",
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="webradar 的 maps 目录")
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    assets = os.path.join(root, "internal", "mapdata", "assets")
    distmaps = os.path.join(root, "dist", "maps")
    os.makedirs(assets, exist_ok=True)
    os.makedirs(distmaps, exist_ok=True)

    done, skipped = [], []
    for mid in sorted(os.listdir(args.src)):
        d = os.path.join(args.src, mid)
        mp = os.path.join(d, "meta.json5")
        ip = os.path.join(d, "radar.png")
        if not (os.path.isfile(mp) and os.path.isfile(ip)):
            print(f"  跳过 {mid}：缺 meta.json5 或 radar.png")
            continue
        if mid in SKIP:
            # 🔴 SKIP 只跳过**生成 JSON**，底图照拷。
            # 第一版写成 `continue`，结果 dust2 的 overview.png 根本没进 dist/maps，
            # 交付包里唯一验证过的那张图反而缺了。
            skipped.append(mid)
        try:
            meta = json.loads(strip_json5(open(mp, encoding="utf-8").read()))
            w, h = png_size(ip)
        except Exception as e:
            print(f"  跳过 {mid}：{e}")
            continue
        if w != h:
            print(f"  跳过 {mid}：底图不是正方形（{w}×{h}），标定假设是正方形")
            continue

        has_lic = os.path.isfile(os.path.join(d, "LICENSE"))
        if mid not in SKIP:
            md = build_map(mid, meta, w, h, has_lic)
            with open(os.path.join(assets, mid + ".json"), "w", encoding="utf-8") as f:
                json.dump(md, f, ensure_ascii=False, indent=2)
                f.write("\n")
        else:
            md = {"origin_world_x": 0, "origin_world_y": 0, "units_per_pixel": 0}

        od = os.path.join(distmaps, mid)
        os.makedirs(od, exist_ok=True)
        shutil.copy2(ip, os.path.join(od, "overview.png"))
        shutil.copy2(mp, os.path.join(od, "meta.json5"))
        if has_lic:
            shutil.copy2(os.path.join(d, "LICENSE"), os.path.join(od, "LICENSE"))
        done.append(mid)
        print(f"  {mid:14s} {w}x{h}  origin=({md['origin_world_x']:.1f}, "
              f"{md['origin_world_y']:.1f})  {md['units_per_pixel']} u/px")

    print(f"\n底图 {len(done)} 张（含手工验证、不覆盖定义的：{skipped or '无'}）")
    print(f"地图定义 {len(done) - len(skipped)} 份（手工验证的那几张保留原定义）")
    print(f"  定义 -> {assets}")
    print(f"  底图 -> {distmaps}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
