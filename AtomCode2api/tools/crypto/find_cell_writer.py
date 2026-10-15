#!/usr/bin/env python3
"""find_cell_writer.py — 静态追踪谁往静态密钥 cell 0x14292f570 写值。

hook 已证实该 cell 运行时被填充 32B，且被当作 HmacSha256 key 使用。
现在静态找 store 到该 cell 的指令（mov [rip+disp32], reg/imm），
反汇编写入点前后窗口，判断密钥是：
  - 从另一个静态常量 memcpy 来（→ 可离线提取）
  - 由某段代码计算出来（→ 需还原派生逻辑）
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from dump_key_region import BIN, parse_pe

CELL_VA = 0x14292f570

# store 模式：REX.W + 89 (/r) 或 REX.W + c7 (/0 imm32)
STORE_PATTERNS = [b"\x48\x89", b"\x4c\x89", b"\x48\xc7", b"\xc7"]
# 读模式也顺带扫（看谁读这个 cell，定位使用点）
LOAD_PATTERNS = [b"\x48\x8b", b"\x4c\x8b", b"\x48\x8d", b"\x4c\x8d", b"\x8d", b"\x8b"]


def scan_stores(data, toff, tsize, text_va_base, target_va, patterns, label):
    hits = []
    pos = toff
    end = toff + tsize
    for pat in patterns:
        p = pos
        while p < end:
            i = data.find(pat, p, end)
            if i < 0:
                break
            m = i + len(pat)
            if m + 4 < len(data) and (data[m] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", data, m + 1)[0]
                # rip 指向 disp32 之后：instr_va + len(pat) + 1(modrm) + 4(disp32)
                instr_va = text_va_base + (i - toff)
                target = instr_va + len(pat) + 1 + 4 + disp
                if target == target_va:
                    hits.append((i, instr_va, pat.hex()))
            p = i + 2
    print(f"\n[+] {label} -> 0x{target_va:x}: {len(hits)} hit(s)")
    for foff, iva, pat in hits:
        print(f"    instr@0x{iva:x} (file 0x{foff:x})  opcode={pat}")
    return hits


def dis_window(data, image_base, secs, text, va, before=48, after=112, title=""):
    tname, tvsize, tvaddr, toff, tsize = text
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    lo_va = va - before
    hi_va = va + after
    lo = toff + (lo_va - image_base - tvaddr)
    hi = toff + (hi_va - image_base - tvaddr)
    lo = max(toff, lo)
    hi = min(toff + tsize, hi)
    print(f"\n--- disasm window around 0x{va:x} [{title}] ---")
    for ins in md.disasm(data[lo:hi], lo_va):
        mark = "  <== HIT" if ins.address == va else ""
        note = ""
        import re
        m = re.search(r"\[rip\s*([+-])\s*0x([0-9a-f]+)\]", ins.op_str)
        if m:
            d = int(m.group(2), 16)
            if m.group(1) == "-":
                d = -d
            t = ins.address + ins.size + d
            # 尝试读目标字符串
            trva = t - image_base
            for name, vsize, vaddr, rawptr, rawsize in secs:
                if vaddr <= trva < vaddr + vsize:
                    o2 = rawptr + (trva - vaddr)
                    s = data[o2:o2 + 48]
                    txt = "".join(chr(b) if 32 <= b < 127 else "" for b in s)
                    if len(txt) >= 3:
                        note = f"  ; '{txt[:40]}' @ {t:#x}"
                    break
        print(f"  {ins.address:#012x}: {ins.mnemonic:<8} {ins.op_str}{note}{mark}")


def main() -> int:
    data = open(BIN, "rb").read()
    image_base, secs = parse_pe(data)
    text = next((s for s in secs if s[0] in (".text", "text")), None)
    if not text:
        text = max(secs, key=lambda s: s[4])
    tname, tvsize, tvaddr, toff, tsize = text
    text_va_base = image_base + tvaddr

    print(f"[+] image_base=0x{image_base:x}  .text VA=0x{text_va_base:x}  size=0x{tsize:x}")
    print(f"[+] cell VA=0x{CELL_VA:x}  RVA=0x{CELL_VA - image_base:x}")

    stores = scan_stores(data, toff, tsize, text_va_base, CELL_VA, STORE_PATTERNS, "STORE")
    loads = scan_stores(data, toff, tsize, text_va_base, CELL_VA, LOAD_PATTERNS, "LOAD/LEA")

    if stores:
        print(f"\n{'=' * 72}\nSTORE SITES ({len(stores)})\n{'=' * 72}")
        for foff, iva, pat in stores[:10]:
            dis_window(data, image_base, secs, text, iva, title=f"store@0x{iva:x}")
    else:
        print("\n[!] 未找到直接 store —— 可能是间接写入（通过指针）或 memcpy。")
        print("    下一步：hook 0x14292f570 处内存写（MemoryAccessMonitor），或追踪填充它的 LazyLock init。")

    if loads:
        print(f"\n{'=' * 72}\nLOAD SITES (first 5)\n{'=' * 72}")
        for foff, iva, pat in loads[:5]:
            dis_window(data, image_base, secs, text, iva, before=32, after=64,
                       title=f"load@0x{iva:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
