#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对 Go PE 做「带符号注释」的反汇编：CALL 解析成函数名，LEA/RIP 引用解析成字符串。

配合 godis_pcln2.py（负责恢复符号表）使用。

用法：
    python godis_dis.py <exe> <函数名或 rva> [--max 400] [--hex]
    python godis_dis.py source/capture.exe main.verifyPriv
    python godis_dis.py source/capture.exe 0x178ea0

输出每行：
    rva  字节  mnemonic operands   ; 注释（call → 函数名 / lea → 字符串）
"""
import sys
import struct

import capstone

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
from godis_pcln2 import parse as parse_pcln, rva_to_off, parse_pe  # noqa: E402


def load(path):
    b = open(path, "rb").read()
    imgbase, secs = parse_pe(b)
    _, meta, funcs, _ = parse_pcln(path)
    by_rva = {}
    for f in funcs:
        by_rva.setdefault(f["text_rva"], f["name"])
    return b, secs, meta, funcs, by_rva


def rd_str(b, off, maxlen=120):
    if off is None or off < 0 or off >= len(b):
        return None
    e = b.find(b"\x00", off)
    if e < 0 or e - off > maxlen:
        return None
    raw = b[off:e]
    if len(raw) < 3:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not all(32 <= ord(c) < 127 or c in "\t" for c in s):
        return None
    return s


def find_func(funcs, key):
    if key.startswith("0x") or key.startswith("0X"):
        want = int(key, 16)
        for f in funcs:
            if f["text_rva"] == want or f["file_off"] == want:
                return f
        return None
    exact = [f for f in funcs if f["name"] == key]
    if exact:
        return exact[0]
    part = [f for f in funcs if key in f["name"]]
    return part[0] if part else None


def disasm(path, key, maxn=400):
    b, secs, meta, funcs, by_rva = load(path)
    # 计算每个函数的文件偏移与结束位置
    for f in funcs:
        f["file_off"] = rva_to_off(f["text_rva"], secs)
    funcs_sorted = sorted([f for f in funcs if f["file_off"] is not None],
                          key=lambda x: x["file_off"])
    for i, f in enumerate(funcs_sorted):
        f["file_end"] = funcs_sorted[i + 1]["file_off"] if i + 1 < len(funcs_sorted) else len(b)

    tgt = find_func(funcs_sorted, key)
    if not tgt:
        print("找不到函数 %r" % key, file=sys.stderr)
        return 2

    start = tgt["file_off"]
    end = min(tgt.get("file_end", start + 4096), start + maxn * 15)
    code = b[start:end]
    base_rva = tgt["text_rva"]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    print("== %s  rva=%#x  file=%#x  size=%d ==" %
          (tgt["name"], tgt["text_rva"], start, end - start))
    n = 0
    for insn in md.disasm(code, base_rva):
        n += 1
        if n > maxn:
            break
        note = ""
        # CALL rel32 → 目标 RVA
        if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
            t = insn.operands[0].imm
            note = "→ " + by_rva.get(t, "?%#x" % t)
        elif insn.mnemonic == "lea" and len(insn.operands) == 2:
            op = insn.operands[1]
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                addr = insn.address + insn.size + op.mem.disp
                off = rva_to_off(addr, secs)
                s = rd_str(b, off) if off is not None else None
                if s:
                    note = 'str "%s"' % s.replace("\t", "\\t")
                elif off is not None:
                    note = "data@%#x (file %#x)" % (addr, off)
                else:
                    note = "@%#x" % addr
        elif insn.mnemonic in ("mov", "movups", "movdqu", "cmp") and insn.operands:
            # 立即数里可能是字符常量，不做处理
            pass

        print("  %#08x  %-24s %-8s %-28s%s" % (
            insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str,
            ("   ; " + note) if note else ""))
    print("== %d 条指令 ==" % min(n, maxn))
    return 0


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    maxn = 400
    args = sys.argv[3:]
    if "--max" in args:
        i = args.index("--max")
        maxn = int(args[i + 1])
    return disasm(sys.argv[1], sys.argv[2], maxn)


if __name__ == "__main__":
    sys.exit(main())
