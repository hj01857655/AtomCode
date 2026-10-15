#!/usr/bin/env python3
"""disasm_sign.py — 全段反汇编 sign_v1，钉死消息构造/HKDF/HMAC2/输出的确切边界。

静态已知（capstone + frida 复核）：
  cell  @ 0x14292f570  32B 运行时钟钥（稳定值 e97250f0...637123）
  OnceCell init   @ 0x140450d99  -> get_or_init(cell, closure)
  HMAC1 key call  @ 0x140450585  -> 0x140566c89  (new_from_slice, rdx=key)
  HMAC1 update    @ 0x14045059a  -> 0x140566cd5  (update, rdx=cell 32B)
  ipad 循环后     @ 0x140450607  rsp+0x2c0 = ipad 块
  opad call       @ 0x140450686  rdx = opad 块
  HKDF 完成后     @ 0x1404508a8  rsp+0x440 = OKM 32B
"""
import re
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from dump_key_region import BIN, parse_pe

LO = 0x1404509f0
HI = 0x140450d00

data = open(BIN, "rb").read()
image_base, secs = parse_pe(data)
tname, tvsize, tvaddr, toff, tsize = next(s for s in secs if s[0] == ".text")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True


def off_of_rva(rva):
    for name, vsize, vaddr, rawptr, rawsize in secs:
        if vaddr <= rva < vaddr + vsize:
            return rawptr + (rva - vaddr)
    return None


print(f"=== disasm sign_v1 {LO:#x}..{HI:#x} (image_base {image_base:#x}) ===")
a = toff + (LO - image_base - tvaddr)
b = toff + (HI - image_base - tvaddr)
count = 0
for ins in md.disasm(data[a:b], LO):
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
                note = f"  ; {nm} '{txt[:52]}' @ {t:#x}"
    # call 目标也标注
    if ins.mnemonic == "call":
        mm = re.match(r"0x([0-9a-f]+)", ins.op_str)
        if mm:
            tgt = int(mm.group(1), 16)
            if image_base + tvaddr <= tgt < image_base + tvaddr + tsize:
                note += f"  ; -> text {tgt:#x} (rva {tgt - image_base:#x})"
    print(f"  {ins.address:#x}: {ins.mnemonic:<9}{ins.op_str}{note}")
    count += 1
print(f"[insns: {count}]")
