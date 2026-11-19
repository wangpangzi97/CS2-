#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 Go PE 的 pclntab 恢复完整符号表（函数名 → 入口 RVA / 文件偏移）。

为什么不用 `go tool objdump`：原版 exe 的 COFF 符号表被剥（nsym=0），
objdump 会直接报 `no runtime.pclntab symbol found`，而 pclntab 其实完好。

Go 1.18+ 的 pclntab 头（64 位）：
    0x00 magic uint32 = 0xFFFFFFF1
    0x04 pad1, pad2 uint8
    0x06 minLC uint8
    0x07 ptrSize uint8
    0x08 nfunc  uint64
    0x10 nfiles uint64
    0x18 textStart uint64
    0x20 funcnameOffset uint64   <- 函数名表基准
    0x28 cuOffset uint64
    0x30 filetabOffset uint64
    0x38 pctabOffset uint64
    0x40 pclnOffset uint64       <- functab 基准

    functab[i] = {entryoff uint32, funcoff uint32}，都在 pclntab 基址上偏
    _func      = pclntab + funcoff
                 {entryOff uint32, nameOff int32, ...}
    name       = pclntab + funcnameOffset + nameOff

坑（第一版踩过）：
  1. funcnameOffset 字段在 pclntab+0x20，不是在 0x18 —— 0x18 是 textStart。
  2. **`funcoff` 相对的是 functab 基址，不是 pclntab 基址。**
     验证方法：funcoff[0] == 0xE7C8 == (nfunc+1)*8 == functab 数组自身的长度
     —— 也就是第一个 _func 结构紧跟在 functab 数组后面。按 pclntab 基址解释
     会落到函数名表里，读出 "time.initMetrics.func13" 这种字符串（看着像名字，
     其实是错位 0x48 字节的巧合）。
  3. functab 的基准是 `pclntab + pclnOffset`，不是 `pclnOffset` 本身。
  4. textStart 在 PE 上是 0，entryoff 要再加上 .text 节的 RVA 才是真正的 RVA。

用法：
    python godis_pcln2.py <exe> [名字过滤子串 ...]
输出：JSON（--json）或人类可读列表。
"""
import json
import struct
import sys

MAGICS = {
    b"\xf1\xff\xff\xff\x00\x00\x01\x08": "go1.18+",
    b"\xfa\xff\xff\xff\x00\x00": "go1.16/1.17",
}


def find_pclntab(b):
    """返回 (偏移, 版本标签)。"""
    best = None
    for mag, tag in MAGICS.items():
        i = 0
        while True:
            j = b.find(mag, i)
            if j < 0:
                break
            # 只接受 ptrSize==8 的（64 位）
            if b[j + 7] == 8:
                cand = (j, tag)
                if best is None or j > best[0]:
                    best = cand
            i = j + 1
    return best


def parse_pe(b):
    """返回 (ImageBase, [(name, va, vsize, rawoff, rawsize)])。"""
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    assert b[pe:pe + 4] == b"PE\x00\x00", "不是 PE"
    nsec = struct.unpack_from("<H", b, pe + 6)[0]
    optsz = struct.unpack_from("<H", b, pe + 20)[0]
    base = pe + 24
    imgbase = struct.unpack_from("<I", b, base + 28)[0]
    secs = []
    so = base + optsz
    for i in range(nsec):
        o = so + i * 40
        name = b[o:o + 8].rstrip(b"\x00").decode("latin1")
        vs, va, rs, ro = struct.unpack_from("<IIII", b, o + 8)
        secs.append((name, va, vs, ro, rs))
    return imgbase, secs


def rva_to_off(rva, secs):
    for name, va, vsize, rawoff, rawsize in secs:
        if va <= rva < va + max(vsize, rawsize):
            d = rva - va
            if d < rawsize:
                return rawoff + d
            return None
    return None


def read_str(b, off):
    e = b.find(b"\x00", off)
    if e < 0:
        return None
    try:
        return b[off:e].decode("utf-8")
    except UnicodeDecodeError:
        return None


def parse(path):
    b = open(path, "rb").read()
    imgbase, secs = parse_pe(b)
    hit = find_pclntab(b)
    if not hit:
        raise SystemExit("没找到 pclntab magic")
    pc, tag = hit

    nfunc, nfiles, textstart, funcnameoff = struct.unpack_from("<QQQQ", b, pc + 8)
    cuoff, filetaboff, pctaboff, pclnoff = struct.unpack_from("<QQQQ", b, pc + 0x28)

    ftab = pc + pclnoff
    fnamebase = pc + funcnameoff

    # ⚠ textStart 在 PE 上是 0，而 .text 节 RVA 是 0x1000。entryoff 相对的是
    # 「代码段起点」，所以要补上 .text 的 RVA，否则文件偏移会整体偏低一页
    # （反汇编出来是上一个函数的尾巴 —— 第一版就这么被骗了）。
    text_base = textstart
    if text_base == 0:
        for name, va, vsize, rawoff, rawsize in secs:
            if name == ".text":
                text_base = va
                break

    out = []
    for i in range(nfunc):
        o = ftab + i * 8
        if o + 8 > len(b):
            break
        entryoff, funcoff = struct.unpack_from("<II", b, o)
        fo = ftab + funcoff          # ← 相对 functab 基址（见文件头坑 2）
        if fo + 8 > len(b):
            continue
        _entry, nameoff = struct.unpack_from("<Ii", b, fo)
        nm = read_str(b, fnamebase + nameoff)
        if not nm:
            continue
        out.append({
            "i": i,
            "name": nm,
            "entry_rva": entryoff,
            "text_rva": text_base + entryoff,
            "funcoff": funcoff,
        })

    meta = {
        "file": path,
        "size": len(b),
        "go_version_tag": tag,
        "pclntab_off": pc,
        "nfunc": nfunc,
        "nfiles": nfiles,
        "textStart": textstart,
        "funcnameOffset": funcnameoff,
        "pclnOffset": pclnoff,
        "functab_off": ftab,
        "funcname_base": fnamebase,
        "image_base": imgbase,
        "parsed": len(out),
    }
    return b, meta, out, secs


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    filters = sys.argv[2:]
    b, meta, funcs, secs = parse(path)

    if filters and filters[0] == "--json":
        print(json.dumps({"meta": meta, "funcs": funcs}, ensure_ascii=False, indent=1))
        return 0

    print("== 元信息 ==")
    for k, v in meta.items():
        print("  %-16s %s" % (k, hex(v) if isinstance(v, int) and k != "size" and k != "nfunc"
                              and k != "nfiles" and k != "parsed" else v))
    print("== 节 ==")
    for name, va, vsize, rawoff, rawsize in secs:
        print("  %-10s VA=%#010x VSize=%#010x RawOff=%#010x RawSize=%#010x"
              % (name, va, vsize, rawoff, rawsize))

    sel = funcs
    if filters:
        sel = [f for f in funcs if any(s in f["name"] for s in filters)]
    print("== 函数 %d / %d ==" % (len(sel), len(funcs)))
    for f in sel:
        off = rva_to_off(f["text_rva"], secs)
        f["file_off"] = off
        print("  %-58s rva=%#08x file=%s" %
              (f["name"], f["text_rva"], hex(off) if off is not None else "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
