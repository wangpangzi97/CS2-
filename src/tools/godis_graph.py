#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""建立 Go PE 的直接调用图（只认 E8 rel32），用来回答「谁调了谁、按什么顺序」。

用法：
    python godis_graph.py <exe> callers <名字子串...>     # 谁调用它
    python godis_graph.py <exe> callees <函数名>          # 它调用谁（按地址顺序）
    python godis_graph.py <exe> tree <函数名> [深度]       # 向下展开
"""
import sys

import capstone

from godis_pcln2 import parse as parse_pcln, rva_to_off, parse_pe


def build(path):
    b = open(path, "rb").read()
    _, secs = parse_pe(b)
    _, meta, funcs, _ = parse_pcln(path)
    for f in funcs:
        f["file_off"] = rva_to_off(f["text_rva"], secs)
    fs = sorted([f for f in funcs if f["file_off"] is not None], key=lambda x: x["file_off"])
    for i, f in enumerate(fs):
        f["file_end"] = fs[i + 1]["file_off"] if i + 1 < len(fs) else min(len(b), f["file_off"] + 200000)
    by_rva = {}
    for f in fs:
        by_rva.setdefault(f["text_rva"], f["name"])

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True          # 不加这句 operands 会抛 CS_ERR_DETAIL
    calls = {}   # caller_name -> [(addr, target_rva, target_name)]
    for f in fs:
        lo, hi = f["file_off"], f["file_end"]
        if hi - lo > 400000:
            hi = lo + 400000
        code = b[lo:hi]
        if not code:
            continue
        lst = []
        for insn in md.disasm(code, f["text_rva"]):
            if insn.mnemonic == "call" and insn.operands and \
                    insn.operands[0].type == capstone.x86.X86_OP_IMM:
                t = insn.operands[0].imm
                lst.append((insn.address, t, by_rva.get(t, "?%#x" % t)))
        calls[f["name"]] = lst
    return fs, by_rva, calls


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    path, mode = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]
    fs, by_rva, calls = build(path)

    if mode == "callers":
        for sub in args:
            print("== 谁调用 *%s* ==" % sub)
            for caller, lst in calls.items():
                for addr, t, tn in lst:
                    if sub in tn:
                        print("  %-52s %#08x → %s" % (caller, addr, tn))
            print()
        return 0

    if mode == "callees":
        key = args[0]
        hit = [c for c in calls if key in c]
        for caller in hit:
            print("== %s 调用 ==" % caller)
            for addr, t, tn in calls[caller]:
                print("  %#08x → %s" % (addr, tn))
            print()
        return 0

    if mode == "tree":
        key = args[0]
        depth = int(args[1]) if len(args) > 1 else 3
        seen = set()

        def walk(name, d, indent):
            if d < 0 or name in seen:
                return
            seen.add(name)
            lst = []
            for c, l in calls.items():
                if c == name or (key in c and name == c):
                    lst = l
                    break
            else:
                # name 可能只是子串，找第一个匹配
                for c, l in calls.items():
                    if name in c:
                        lst = l
                        break
            mains = [(a, tn) for a, t, tn in lst if not tn.startswith(("runtime.", "internal/", "sync.", "syscall.", "unicode"))]
            for a, tn in mains:
                print("%s%#08x %s" % (indent, a, tn))
                walk(tn, d - 1, indent + "    ")

        print("== tree %s ==" % key)
        walk(key, depth, "  ")
        return 0

    print("未知模式 %s" % mode)
    return 2


if __name__ == "__main__":
    sys.exit(main())
