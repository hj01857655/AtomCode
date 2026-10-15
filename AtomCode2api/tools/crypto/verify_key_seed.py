#!/usr/bin/env python3
"""verify_key_seed.py — 验证运行时钟钥是否由编译期嵌入的路径串哈希而来。

静态链路（已还原）：
  0x140450d99  OnceCell::get_or_init(cell@0x14292f570, closure@0x14135ae90)
  closure+0x00 -> 0x14135ae18 (.rdata, 112B Rust 工具链路径串)
  closure+0x08 -> 0x70 (=112, 捕获长度)
  vtable@0x140f08c90 -> thunk 0x140566fd2 -> tail-call 0x140566fec (真正闭包体)

frida 实测运行时钟钥（本机一次运行）：
  e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123

本脚本：
  1. dump 0x14135ae18 完整 112B
  2. 对该串做 SHA-256 / SHA-512-截断 / 前后缀变体，逐一与实测密钥对拍
  3. capstone 反汇编 0x140566fec，确认闭包体真实算法
"""
import hashlib
import re
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from dump_key_region import BIN, parse_pe

TARGET = bytes.fromhex("e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123")

data = open(BIN, "rb").read()
image_base, secs = parse_pe(data)


def off_of_rva(rva):
    for name, vsize, vaddr, rawptr, rawsize in secs:
        if vaddr <= rva < vaddr + vsize:
            return rawptr + (rva - vaddr)
    return None


def dump(va, length, title):
    rva = va - image_base
    off = off_of_rva(rva)
    if off is None:
        print(f"[!] {title}: RVA {rva:#x} 不在任何段内")
        return b""
    raw = data[off:off + length]
    print(f"=== {title} @ {va:#x} (rva={rva:#x}) len={length} ===")
    for i in range(0, len(raw), 16):
        row = raw[i:i + 16]
        print(f"  {va + i:#x}: {row.hex(' ')}  "
              f"{''.join(chr(b) if 32 <= b < 127 else '.' for b in row)}")
    return raw


# ── 1. dump 闭包捕获的路径串 ──────────────────────────────
path_raw = dump(0x14135ae18, 0x70, "closure captured env (.rdata path string)")
print()

# 截到 NUL / 保留完整 112B 两种
path_nul = path_raw.split(b"\x00", 1)[0]
print(f"[path] with NUL-trim : {len(path_nul)}B  {path_nul!r}")
print(f"[path] full 112B     : {len(path_raw)}B")
print()

# ── 2. 哈希对拍 ────────────────────────────────────────
print("=== 哈希对拍 (target e97250f0...637123) ===")


def check(label: str, blob: bytes) -> bool:
    h = hashlib.sha256(blob).digest()
    h512 = hashlib.sha512(blob).digest()
    cands = {
        "sha256": h,
        "sha512[:32]": h512[:32],
        "sha512[32:]": h512[32:],
        "sha256[:16]": h[:16],
        "sha256[16:]": h[16:],
    }
    for name, c in cands.items():
        mark = "  <<< MATCH" if c == TARGET else ""
        if c[:4] == TARGET[:4]:
            print(f"  {label:<40s} {name:<12s} {c.hex()}{mark}")
    return any(c == TARGET for c in cands.values())


hit = False
hit |= check("path_nul", path_nul)
hit |= check("path_raw(112B)", path_raw)
hit |= check("path_nul + b'\\x00'", path_nul + b"\x00")
# 正/反斜杠归一化、大小写、有无盘符冒号
for label, blob in [
    ("path_nul forward-slash", path_nul.replace(b"\\", b"/")),
    ("path_nul lower", path_nul.lower()),
    ("path_nul no drive colon", path_nul.replace(b":", b"")),
    ("path_raw forward-slash", path_raw.replace(b"\\", b"/")),
]:
    hit |= check(label, blob)
print(f"\n[result] {'HIT — 密钥 = 路径串哈希，逆向完成' if hit else 'NO HIT — 需看闭包体真实算法'}")
print()

# ── 3. 反汇编闭包体 0x140566fec ─────────────────────────
tname, tvsize, tvaddr, toff, tsize = next(s for s in secs if s[0] == ".text")
TL = image_base + tvaddr
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True
print("=== 闭包体 0x140566fec (tail-called by thunk 0x140566fd2) ===")
a = toff + (0x140566fec - image_base - tvaddr)
b = toff + (0x140567160 - image_base - tvaddr)
for ins in md.disasm(data[a:b], 0x140566fec):
    note = ""
    m = re.search(r"\[rip\s*([+-])\s*0x([0-9a-f]+)\]", ins.op_str)
    if m:
        d = int(m.group(2), 16)
        d = -d if m.group(1) == "-" else d
        t = ins.address + ins.size + d
        trva = t - image_base
        nm, oo = None, None
        for n2, v2, va2, rp2, rs2 in secs:
            if va2 <= trva < va2 + v2:
                nm, oo = n2, rp2 + (trva - va2)
                break
        if oo is not None:
            txt = "".join(chr(b) if 32 <= b < 127 else "." for b in data[oo:oo + 56])
            if txt.strip("."):
                note = f"  ; {nm} '{txt[:48]}' @ {t:#x}"
    print(f"  {ins.address:#x}: {ins.mnemonic:<9}{ins.op_str}{note}")
    if ins.mnemonic == "ret":
        break
