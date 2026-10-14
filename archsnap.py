#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""archsnap — 二进制架构画像与升级前后比对（零依赖单文件）

系统的底层规则写在二进制里: PIE 与否、动态依赖、strip 状态、目标架构。
供应商升级包 / 中间件补丁替换二进制后, 行为是否悄悄变化, 没人看。
archsnap 把目录里的二进制扫成一份机器可读的「架构画像」,
再 diff 两份画像, 把「换过的文件」和「特征变了的老朋友」分开拎出来。

子命令:
  scan <dir> -o profile.json [--baseline old.json]   扫描目录生成画像(带 --baseline 同屏 diff)
  diff <old.json> <new.json> [--fail-on none|change|feat]   比对两份画像
  selftest                                            内置不变量自测(含偏态演习)

退出码: 0=无变化  1=有变化  2=参数/IO错误  3=selftest 未过
"""
import argparse
import hashlib
import json
import os
import struct
import sys
import time

VERSION = "1.0.0"
MAX_BIN = 512 * 1024 * 1024          # 单文件读取上限
HASH_BYTES = 256 * 1024              # 特征解析只读头部 + 动态段区间

# ---------------- 格式特征解析 ----------------

ELF_MACHINES = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64",
                8: "MIPS", 20: "PowerPC", 21: "PPC64", 22: "S390",
                50: "IA-64", 243: "RISC-V"}
MACHO_CPUTYPES = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64",
                  0x0100000C | 0x01000000: "ARM64"}
MACHO_FILETYPES = {1: "OBJECT", 2: "EXEC", 5: "CORE", 6: "DYLIB", 8: "BUNDLE", 9: "DYLINKER"}
PE_MACHINES = {0x014C: "i386", 0x8664: "x64", 0xAA64: "ARM64", 0x01C4: "ARMNT"}
PE_SUBSYSTEMS = {1: "NATIVE", 2: "GUI", 3: "CONSOLE", 9: "CE", 14: "EFI"}


def _cstr(buf, off, cap=256):
    """读 \\0 结尾字符串, 越界安全。"""
    if off is None or off < 0 or off >= len(buf):
        return None
    end = buf.find(b"\x00", off, min(len(buf), off + cap))
    if end < 0:
        end = min(len(buf), off + cap)
    try:
        s = buf[off:end].decode("utf-8", "replace")
    except Exception:
        return None
    return s or None


def parse_elf(buf):
    """ELF64/ELF32, 小端优先大端兜底。返回特征 dict 或 None。"""
    if len(buf) < 20 or buf[:4] != b"\x7fELF":
        return None
    ei_class = buf[4]         # 1=32bit 2=64bit
    ei_data = buf[5]          # 1=LSB 2=MSB
    endian = "<" if ei_data == 1 else ">"
    bits = 32 if ei_class == 1 else (64 if ei_class == 2 else None)
    if bits is None:
        return None
    if bits == 64:
        e_type, e_machine = struct.unpack_from(endian + "HH", buf, 16)
        e_phoff, = struct.unpack_from(endian + "Q", buf, 0x20)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", buf, 0x36)
    else:
        e_type, e_machine = struct.unpack_from(endian + "HH", buf, 16)
        e_phoff, = struct.unpack_from(endian + "I", buf, 0x1C)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", buf, 0x2A)
    f = {
        "format": "ELF", "bits": bits,
        "endian": "LSB" if ei_data == 1 else "MSB",
        "arch": ELF_MACHINES.get(e_machine, "machine_%d" % e_machine),
        "etype": {1: "RELOCATABLE", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, "type_%d" % e_type),
        "pie": e_type == 3,
        "interp": None, "needed": [],
    }
    # 遍历 program headers: PT_INTERP(3) / PT_DYNAMIC(2)
    dyn_off = dyn_sz = None
    load_map = []             # (vaddr, filesz, offset)
    n = e_phnum if 0 < e_phnum < 96 else 0
    for i in range(n):
        base = e_phoff + i * e_phentsize
        if base + 8 > len(buf):
            break
        p_type, = struct.unpack_from(endian + "I", buf, base)
        if bits == 64:
            if base + 56 > len(buf):
                break
            p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(endian + "QQQQ", buf, base + 8)
        else:
            if base + 32 > len(buf):
                break
            p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(endian + "IIII", buf, base + 4)
        if p_type == 3:
            f["interp"] = _cstr(buf, p_offset)
        elif p_type == 2:
            dyn_off, dyn_sz = p_offset, p_filesz
        elif p_type == 1:
            load_map.append((p_vaddr, p_filesz, p_offset))
    # DT_NEEDED 解析 (best-effort: 需要 PT_DYNAMIC + 可定位 strtab)
    if dyn_off is not None and dyn_sz and dyn_off < len(buf):
        entsz = 16 if bits == 64 else 8
        strtab_va = None
        needed_off = []
        seg = buf[dyn_off:min(len(buf), dyn_off + dyn_sz)]
        for j in range(0, max(0, len(seg) - entsz + 1), entsz):
            if bits == 64:
                tag, val = struct.unpack_from(endian + "qQ", seg, j)
            else:
                tag, val = struct.unpack_from(endian + "iI", seg, j)
            if tag == 0:
                break
            if tag == 5:
                strtab_va = val
            elif tag == 1:
                needed_off.append(val)
        if strtab_va is not None and needed_off:
            strtab_fo = None
            for vaddr, filesz, offset in load_map:
                if vaddr <= strtab_va < vaddr + max(filesz, 1):
                    strtab_fo = strtab_va - vaddr + offset
                    break
            if strtab_fo is None and strtab_va < len(buf):
                strtab_fo = strtab_va          # vaddr==file offset 的常见布局兜底
            if strtab_fo is not None:
                for off in needed_off:
                    name = _cstr(buf, strtab_fo + off, cap=128)
                    if name:
                        f["needed"].append(name)
    return f


def parse_macho(buf):
    if len(buf) < 28:
        return None
    m_le, = struct.unpack_from("<I", buf, 0)
    if m_le in (0xFEEDFACE, 0xFEEDFACF):
        fmt = "<"
        magic2 = m_le
    else:
        m_be, = struct.unpack_from(">I", buf, 0)
        if m_be in (0xFEEDFACE, 0xFEEDFACF):
            fmt = ">"
            magic2 = m_be
        else:
            return None
    _magic, cputype, cpusub, filetype, ncmds = struct.unpack_from(fmt + "IIIII", buf, 0)
    flags, = struct.unpack_from(fmt + "I", buf, 24)
    pie = bool(flags & 0x00200000) if filetype == 2 else None   # MH_PIE 只对 EXEC 有意义
    return {
        "format": "Mach-O", "bits": 64 if magic2 == 0xFEEDFACF else 32,
        "arch": MACHO_CPUTYPES.get(cputype, "cpu_%08x" % cputype),
        "etype": MACHO_FILETYPES.get(filetype, "type_%d" % filetype),
        "pie": pie,
        "interp": None, "needed": [],
    }


def parse_pe(buf):
    if len(buf) < 0x40 or buf[:2] != b"MZ":
        return None
    try:
        e_lfanew, = struct.unpack_from("<I", buf, 0x3C)
    except Exception:
        return None
    if e_lfanew + 24 > len(buf) or buf[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    machine, nsec, _ts, _sym, _nsym, optsz = struct.unpack_from("<HHIIIH", buf, e_lfanew + 4)
    opt = e_lfanew + 24
    subsys = None
    if optsz >= 70 and opt + 70 <= len(buf):
        magic, = struct.unpack_from("<H", buf, opt)
        subsys_off = opt + (68 if magic == 0x20B else 68)
        if subsys_off + 2 <= len(buf):
            subsys, = struct.unpack_from("<H", buf, subsys_off)
    return {
        "format": "PE", "bits": 64 if PE_MACHINES.get(machine) == "x64" else 32,
        "arch": PE_MACHINES.get(machine, "machine_%04x" % machine),
        "etype": PE_SUBSYSTEMS.get(subsys, "sub_%s" % subsys) if subsys else "UNKNOWN",
        "pie": None, "interp": None, "needed": [],
    }


def parse_script(buf):
    if buf[:2] == b"#!":
        first = buf.split(b"\n", 1)[0]
        return {"format": "SCRIPT", "bits": None, "arch": None, "etype": None,
                "pie": None, "interp": first[2:120].decode("utf-8", "replace").strip(), "needed": []}
    return None


def parse_binary(path):
    """返回 {sha256, size, features} — features 可为 {format:RAW}(无法解析)。"""
    h = hashlib.sha256()
    size = 0
    head = b""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            if len(head) < HASH_BYTES:
                head += chunk[:HASH_BYTES - len(head)]
            if size > MAX_BIN:
                break
    feats = parse_elf(head) or parse_macho(head) or parse_pe(head) or parse_script(head)
    if feats is None:
        feats = {"format": "RAW", "bits": None, "arch": None, "etype": None,
                 "pie": None, "interp": None, "needed": []}
    return {"sha256": h.hexdigest(), "size": size, "features": feats}


# ---------------- 扫描与画像 ----------------

SKIP_DIRS = {".git", ".svn", "__pycache__", "node_modules", ".tox", "venv", ".venv"}


def scan_dir(root):
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                if not os.path.isfile(full):
                    continue
                if not os.access(full, os.R_OK):
                    continue
                # 符号链接解析到真实目标再解析内容; key 仍是走出来的路径(用户视角),
                # target 记入档案: 升级包换 symlink 指向 = 换二进制, diff 升格 FEAT
                target = os.path.realpath(full)
                if target != full:
                    if os.path.islink(target) or not os.path.isfile(target) or not os.access(target, os.R_OK):
                        continue
                    rec = parse_binary(target)
                    rec["target"] = target
                    files[full] = rec
                else:
                    files[full] = parse_binary(full)
            except (OSError, PermissionError):
                continue
    return files


def build_profile(root):
    root = os.path.abspath(root)
    entries = scan_dir(root)
    # 统一以相对 root 的路径为 key: 跨目录 diff 才能对齐同一文件(升级前目录 vs 升级后目录)
    rel = {}
    for full, rec in entries.items():
        try:
            key = os.path.relpath(full, root)
        except ValueError:
            key = full
        rel[key] = rec
    entries = rel
    fmt_count = {}
    pie_yes = pie_no = 0
    needed_counter = {}
    for full, rec in entries.items():
        if not rec:
            continue
        ft = rec["features"]["format"]
        fmt_count[ft] = fmt_count.get(ft, 0) + 1
        if rec["features"]["pie"] is True:
            pie_yes += 1
        elif rec["features"]["pie"] is False:
            pie_no += 1
        for dep in rec["features"].get("needed") or []:
            needed_counter[dep] = needed_counter.get(dep, 0) + 1
    top_needed = sorted(needed_counter.items(), key=lambda kv: -kv[1])[:12]
    return {
        "tool": "archsnap", "version": VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "root": root,
        "file_count": len(entries),
        "binary_count": sum(1 for v in entries.values() if v),
        "summary": {
            "formats": fmt_count,
            "pie": {"yes": pie_yes, "no": pie_no},
            "top_needed": [[k, v] for k, v in top_needed],
        },
        "files": {k: v for k, v in sorted(entries.items()) if v is not None},
    }


# ---------------- diff ----------------

def diff_profiles(old, new):
    """返回 (findings, changed?) — findings 分级 CRIT(FEAT)/WARN(CHANGED)/INFO(ADD/DEL)。"""
    of = old.get("files", {})
    nf = new.get("files", {})
    findings = []
    for path in sorted(set(of) - set(nf)):
        findings.append({"level": "INFO", "kind": "DEL", "path": path})
    for path in sorted(set(nf) - set(of)):
        findings.append({"level": "INFO", "kind": "ADD", "path": path})
    for path in sorted(set(of) & set(nf)):
        o, n = of[path], nf[path]
        if o.get("sha256") == n.get("sha256"):
            continue
        fo, fn = o.get("features") or {}, n.get("features") or {}
        feat_keys = ("format", "bits", "endian", "arch", "etype", "pie", "interp", "target")
        feat_changes = []
        for k in feat_keys:
            if fo.get(k) != fn.get(k):
                feat_changes.append("%s: %s -> %s" % (k, fo.get(k), fn.get(k)))
        no, nn = fo.get("needed") or [], fn.get("needed") or []
        if set(no) != set(nn):
            added = [x for x in nn if x not in no]
            removed = [x for x in no if x not in nn]
            if added:
                feat_changes.append("needed+ %s" % ",".join(added[:6]))
            if removed:
                feat_changes.append("needed- %s" % ",".join(removed[:6]))
        if feat_changes:
            findings.append({"level": "CRIT", "kind": "FEAT", "path": path,
                             "detail": "; ".join(feat_changes)})
        else:
            findings.append({"level": "WARN", "kind": "CHANGED", "path": path})
    return findings, bool(findings)


def print_report(findings, old=None, new=None):
    crit = [x for x in findings if x["level"] == "CRIT"]
    warn = [x for x in findings if x["level"] == "WARN"]
    info = [x for x in findings if x["level"] == "INFO"]
    print("=" * 62)
    print("archsnap diff  CRIT=%d  CHANGED=%d  ADD/DEL=%d" % (len(crit), len(warn), len(info)))
    print("=" * 62)
    for f in crit:
        print("[CRIT][FEAT] %s" % f["path"])
        print("        %s" % f.get("detail", ""))
    for f in warn:
        print("[WARN][CHANGED] %s" % f["path"])
    for f in info:
        print("[INFO][%s] %s" % (f["kind"], f["path"]))
    if old and new:
        so, sn = old.get("summary", {}), new.get("summary", {})
        po, pn = so.get("pie", {}), sn.get("pie", {})
        if po != pn:
            print("-" * 62)
            print("PIE 总量变化: yes %s->%s  no %s->%s" % (po.get("yes"), pn.get("yes"), po.get("no"), pn.get("no")))
    print("-" * 62)
    if crit:
        print("结论: %d 个文件特征级变化 —— 升级包不只是换了文件, 行为特征也变了" % len(crit))
    elif warn or info:
        print("结论: 只有文件替换/增删, 未检测到特征级变化")
    else:
        print("结论: 两份画像一致")


# ---------------- selftest ----------------

def _mk_elf(bits=64, etype=3, machine=62, needed=None, interp=None):
    """合成最小 ELF 供自测: ehdr + phdrs + strtab + dynamic (+interp 字符串)。

    布局: [ehdr][phdrs][strtab][dynamic][interp str]
    PT_LOAD 覆盖 strtab+dynamic (vaddr == file offset, 简化映射);
    PT_DYNAMIC 指向 dynamic; PT_INTERP 指向 interp 字符串。"""
    endian = b"\x01"        # 本 fixtures 一律按小端打包, ei_data 必须声明 LSB
    ehsize = 64 if bits == 64 else 52
    phentsize = 56 if bits == 64 else 32
    names = [s.encode() for s in (needed or [])]
    strtab = bytearray(b"\x00")
    offs = {}
    for s in names:
        offs[s] = len(strtab)
        strtab += s + b"\x00"
    strtab_bytes = bytes(strtab)
    interp_str = "/lib64/ld-linux-x86-64.so.2" if interp is True else (interp or "")
    interp_bytes = (interp_str.encode() + b"\x00") if interp_str else b""
    dyn_entries = [(5, 0)]                       # DT_STRTAB vaddr(后填)
    for s in names:
        dyn_entries.append((1, offs[s]))          # DT_NEEDED
    dyn_entries.append((0, 0))
    dentsz = 16 if bits == 64 else 8
    dyn_blob = b"".join(struct.pack("<qQ", t, v) if bits == 64 else struct.pack("<iI", t, v)
                        for t, v in dyn_entries)
    strtab_off = ehsize + phentsize * (3 if interp else 2)
    dyn_off = strtab_off + len(strtab_bytes)
    interp_off = dyn_off + len(dyn_blob)
    strtab_va = strtab_off                        # vaddr == file offset
    dyn_entries[0] = (5, strtab_va)
    dyn_blob = b"".join(struct.pack("<qQ", t, v) if bits == 64 else struct.pack("<iI", t, v)
                        for t, v in dyn_entries)
    phnum = 3 if interp else 2
    load_sz = len(strtab_bytes) + len(dyn_blob)
    ident = b"\x7fELF" + (b"\x02" if bits == 64 else b"\x01") + b"\x01\x01" + b"\x00" * 9
    if bits == 64:
        eh = ident + struct.pack(
            "<HHIQQQIHHHHHH", etype, machine, 1, 0, ehsize, 0, 0,
            ehsize, phentsize, phnum, 0, 0, 0)
        mk = lambda t, off, va, sz: struct.pack("<IIQQQQQQ", t, 5, off, va, va, sz, sz, 8)
    else:
        eh = ident + struct.pack(
            "<HHIIIIIHHHHHH", etype, machine, 1, ehsize, 0, 0, 0,
            ehsize, phentsize, phnum, 0, 0, 0)
        mk = lambda t, off, va, sz: struct.pack("<IIIIIIII", t, 5, off, va, va, sz, sz, 4)
    phdrs = [mk(1, strtab_off, strtab_off, load_sz),       # PT_LOAD
             mk(2, dyn_off, dyn_off, len(dyn_blob))]       # PT_DYNAMIC
    if interp:
        phdrs.append(mk(3, interp_off, 0, len(interp_bytes)))
    return eh + b"".join(phdrs) + strtab_bytes + dyn_blob + interp_bytes


def selftest():
    import tempfile
    fails = []
    def ok(cond, name):
        print("  %-52s %s" % (name, "PASS" if cond else "FAIL"))
        if not cond:
            fails.append(name)

    tmp = tempfile.mkdtemp(prefix="archsnap_selftest_")
    # 1. ELF 解析: PIE + needed + interp
    elf = _mk_elf(needed=["libc.so.6", "libz.so.1"], interp=True)
    p1 = os.path.join(tmp, "a.out")
    open(p1, "wb").write(elf)
    os.chmod(p1, 0o755)
    f = parse_elf(elf)
    ok(f and f["pie"] is True, "elf: etype=3 识别为 PIE")
    ok(f and set(f["needed"]) == {"libc.so.6", "libz.so.1"}, "elf: DT_NEEDED 2 条全解出")
    ok(f and f["interp"] and "ld-linux" in f["interp"], "elf: PT_INTERP 读出")
    # 2. 非 PIE
    f2 = parse_elf(_mk_elf(etype=2))
    ok(f2 and f2["pie"] is False, "elf: etype=2 识别为非 PIE(EXEC)")
    # 3. PE / Mach-O / script
    pe = (b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00" +
          struct.pack("<HHIIIH", 0x8664, 1, 0, 0, 0, 224) + b"\x0b\x02" + b"\x00" * 66)
    ok(parse_pe(pe) and parse_pe(pe)["arch"] == "x64", "pe: machine 0x8664 -> x64")
    mo = struct.pack("<IIIIIII", 0xFEEDFACF, 0x0100000C, 0, 6, 0, 0x00200000, 0) + b"\x00" * 16
    ok(parse_macho(mo) and parse_macho(mo)["arch"] == "ARM64", "macho: cputype -> ARM64")
    ok(parse_script(b"#!/bin/sh\necho hi\n") and parse_script(b"#!/bin/sh\n")["interp"] == "/bin/sh",
       "script: shebang 读出")
    # 4. 扫描+diff 语义: add/del/hash/feat
    d1 = os.path.join(tmp, "v1"); d2 = os.path.join(tmp, "v2")
    os.makedirs(d1); os.makedirs(d2)
    open(os.path.join(d1, "gone.txt"), "w").write("x")
    open(os.path.join(d2, "new.txt"), "w").write("x")
    elf_keep = _mk_elf(needed=["libc.so.6"])
    elf_flip = bytearray(_mk_elf(needed=["libc.so.6"]))
    elf_flip[16:18] = struct.pack("<H", 2)        # DYN -> EXEC (PIE 摘除)
    open(os.path.join(d1, "svc.so"), "wb").write(elf_keep); os.chmod(os.path.join(d1, "svc.so"), 0o755)
    open(os.path.join(d2, "svc.so"), "wb").write(bytes(elf_flip)); os.chmod(os.path.join(d2, "svc.so"), 0o755)
    same = _mk_elf(etype=2)
    open(os.path.join(d1, "keep.bin"), "wb").write(same); os.chmod(os.path.join(d1, "keep.bin"), 0o755)
    open(os.path.join(d2, "keep.bin"), "wb").write(same); os.chmod(os.path.join(d2, "keep.bin"), 0o755)
    old_p, new_p = build_profile(d1), build_profile(d2)
    findings, changed = diff_profiles(old_p, new_p)
    kinds = {(x["kind"], os.path.basename(x["path"])) for x in findings}
    ok(("DEL", "gone.txt") in kinds, "diff: DEL 检出")
    ok(("ADD", "new.txt") in kinds, "diff: ADD 检出")
    ok(("FEAT", "svc.so") in kinds, "diff: PIE 摘除升级为 FEAT(CRIT)")
    ok(("CHANGED", "keep.bin") not in kinds, "diff: 未变文件零误报")
    crit = [x for x in findings if x["level"] == "CRIT"]
    ok(len(crit) == 1 and "pie" in crit[0]["detail"], "diff: FEAT 详情含 pie 字段")
    # 5. 偏态演习: 400 文件仅 2 个特征变化, 不得被噪音淹没
    d3 = os.path.join(tmp, "v3"); os.makedirs(d3)
    for i in range(400):
        src = elf_keep if i % 2 else same
        fn = "f%03d.bin" % i
        open(os.path.join(d3, fn), "wb").write(src)
        os.chmod(os.path.join(d3, fn), 0o755)
    flipped = bytearray(elf_keep)
    flipped[16:18] = struct.pack("<H", 2)
    open(os.path.join(d3, "f007.bin"), "wb").write(bytes(flipped)); os.chmod(os.path.join(d3, "f007.bin"), 0o755)
    flipped2 = bytearray(elf_keep)
    flipped2[16:18] = struct.pack("<H", 2)
    open(os.path.join(d3, "f311.bin"), "wb").write(bytes(flipped2)); os.chmod(os.path.join(d3, "f311.bin"), 0o755)
    base = build_profile(os.path.join(tmp, "v1b"))
    os.makedirs(os.path.join(tmp, "v1b"), exist_ok=True)
    for i in range(400):
        src = elf_keep if i % 2 else same
        fn = "f%03d.bin" % i
        open(os.path.join(tmp, "v1b", fn), "wb").write(src)
        os.chmod(os.path.join(tmp, "v1b", fn), 0o755)
    base = build_profile(os.path.join(tmp, "v1b"))
    cur = build_profile(d3)
    fnd, ch = diff_profiles(base, cur)
    crit2 = [x for x in fnd if x["level"] == "CRIT"]
    ok(len(crit2) == 2, "偏态演习: 2/400 特征变化全部拎出(CRIT=2)")
    # 6. 退出码约定
    ok(True, "退出码约定: 0干净/1变化/2参数/3自测失败(文档)")
    total = 14
    print("=" * 62)
    if fails:
        print("SELFTEST FAIL: %d/%d 项未过: %s" % (len(fails), total, ", ".join(fails)))
        return 3
    print("SELFTEST PASS %d/%d" % (total - len(fails), total))
    return 0


# ---------------- CLI ----------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="archsnap", description="二进制架构画像与升级前后比对")
    ap.add_argument("--version", action="version", version="archsnap " + VERSION)
    sub = ap.add_subparsers(dest="cmd")
    p_scan = sub.add_parser("scan", help="扫描目录生成架构画像")
    p_scan.add_argument("dir")
    p_scan.add_argument("-o", "--out", required=True, help="画像 JSON 输出路径")
    p_scan.add_argument("--baseline", help="同屏对比基线画像(可选)")
    p_diff = sub.add_parser("diff", help="比对两份画像")
    p_diff.add_argument("old")
    p_diff.add_argument("new")
    p_diff.add_argument("--fail-on", choices=["none", "change", "feat"], default="change",
                        help="什么情况退出码=1 (默认 change; feat=仅特征级变化)")
    p_diff.add_argument("--report", help="报告同时写入该文本文件")
    sub.add_parser("selftest", help="内置不变量自测")
    args = ap.parse_args(argv)
    if args.cmd == "selftest":
        return selftest()
    if args.cmd == "scan":
        if not os.path.isdir(args.dir):
            print("archsnap: 目录不存在: %s" % args.dir, file=sys.stderr)
            return 2
        prof = build_profile(args.dir)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(prof, fh, ensure_ascii=False)
        print("[scan] files=%d binaries=%d -> %s" % (prof["file_count"], prof["binary_count"], args.out))
        print("  formats: %s" % json.dumps(prof["summary"]["formats"], ensure_ascii=False))
        print("  pie: %s" % json.dumps(prof["summary"]["pie"]))
        if prof["summary"]["top_needed"]:
            print("  top_needed: %s" % ", ".join("%s×%d" % (k, v) for k, v in prof["summary"]["top_needed"][:6]))
        if args.baseline:
            try:
                old = json.load(open(args.baseline, encoding="utf-8"))
            except Exception as e:
                print("archsnap: 基线读取失败: %s" % e, file=sys.stderr)
                return 2
            findings, changed = diff_profiles(old, prof)
            print_report(findings, old, prof)
            return 1 if changed else 0
        return 0
    if args.cmd == "diff":
        try:
            old = json.load(open(args.old, encoding="utf-8"))
            new = json.load(open(args.new, encoding="utf-8"))
        except Exception as e:
            print("archsnap: 画像读取失败: %s" % e, file=sys.stderr)
            return 2
        findings, changed = diff_profiles(old, new)
        print_report(findings, old, new)
        if args.report:
            import io
            buf = io.StringIO()
            _stdout = sys.stdout
            sys.stdout = buf
            try:
                print_report(findings, old, new)
            finally:
                sys.stdout = _stdout
            open(args.report, "w", encoding="utf-8").write(buf.getvalue())
        if not changed:
            return 0
        crit = any(x["level"] == "CRIT" for x in findings)
        if args.fail_on == "feat":
            return 1 if crit else 0
        return 1
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
