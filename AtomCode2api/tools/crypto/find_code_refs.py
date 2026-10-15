#!/usr/bin/env python3
"""find_code_refs.py — 用 capstone 定位引用 v1.rs 常量/静态密钥的代码点。

思路：PE 符号被 strip，但 .text 里引用 .rdata 常量（info 串、静态密钥、panic
串）的指令一律是 RIP-relative LEA/MOV。先精确定位这些常量的 VA，再对 .text
做 raw opcode 扫描（48/4c 8d|8b + modrm mod=00 rm=101）找 disp32 命中目标的
指令，最后在命中点前后反汇编窗口，读出消息拼装顺序与 key 长度。
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RIP

from dump_key_region import BIN, NEEDLE, parse_pe, entropy

PANIC_NEEDLE = b"crates\\atomcode-codingplan-crypto\\src\\versions\\v1.rs"


def high_entropy_run(data: bytes, start: int, cap: int = 128, thresh: float = 3.6) -> bytes:
    """从 start 起向后延伸高熵字节串（每 8 字节滑窗熵 >= thresh 才继续）。"""
    end = start
    while end < min(len(data), start + cap):
        w = data[end:end + 8]
        if len(w) < 8:
            break
        if entropy(w) < thresh:
            break
        end += 8
    return data[start:end]


def find_all(data: bytes, needle: bytes, lo: int = 0, hi: int = -1):
    out = []
    start = lo
    while True:
        i = data.find(needle, start, len(data) if hi < 0 else hi)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def raw_scan_rip_refs(data: bytes, text_off: int, text_size: int, text_va: int,
                      ranges: list, max_hits: int = 200):
    """扫 .text 中 RIP-relative LEA/MOV，收集目标落入 ranges 的指令。

    ranges: [(lo_va, hi_va, label)] 闭开区间
    """
    def in_ranges(target: int):
        for lo_va, hi_va, label in ranges:
            if lo_va <= target < hi_va:
                return label
        return None

    patterns = [(b"\x48\x8d", 3), (b"\x4c\x8d", 3), (b"\x49\x8d", 3), (b"\x4d\x8d", 3),
                (b"\x48\x8b", 3), (b"\x4c\x8b", 3), (b"\x8d", 2), (b"\x8b", 2)]
    hits = []
    for pat, ilen in patterns:
        pos = text_off
        end = text_off + text_size
        while pos < end:
            i = data.find(pat, pos, end)
            if i < 0:
                break
            m = i + len(pat)
            if m + 4 < len(data) and (data[m] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", data, m + 1)[0]
                instr_va = text_va + (i - text_off)
                target = instr_va + ilen + 4 + disp
                label = in_ranges(target)
                if label:
                    hits.append((i, instr_va, target, label, pat.hex()))
                    if len(hits) >= max_hits:
                        return hits
            pos = i + 2
    return hits


def dump_va_region(data: bytes, image_base: int, secs: list, va: int, label: str, size: int = 64) -> bytes:
    """从 VA 反查 file offset 并 dump 原始字节。"""
    rva = va - image_base
    for name, vsize, vaddr, rawptr, rawsize in secs:
        if vaddr <= rva < vaddr + vsize:
            off = rawptr + (rva - vaddr)
            chunk = data[off:off + size]
            print(f"\n  --- dump {label} @ VA {va:#x} (file {off:#x}, {size}B) ---")
            for row_off in range(0, len(chunk), 16):
                row = chunk[row_off:row_off + 16]
                hexs = " ".join(f"{b:02x}" for b in row)
                txt = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
                print(f"    {off + row_off:08x}  {hexs:<47}  |{txt}|")
            return chunk
    print(f"\n  [!!] {label}: VA {va:#x} not in any section")
    return b""


def main() -> int:
    data = open(BIN, "rb").read()
    image_base, secs = parse_pe(data)

    def va_of(file_off: int) -> int:
        for name, vsize, vaddr, rawptr, rawsize in secs:
            if rawptr <= file_off < rawptr + rawsize:
                return image_base + vaddr + (file_off - rawptr)
        return 0

    text = next((s for s in secs if s[0] in (".text", "text")), None)
    if not text:
        # 兜底：取最大的可执行段（按名称含 x）
        text = max(secs, key=lambda s: s[4])
    tname, tvsize, tvaddr, toff, tsize = text
    print(f"[+] .text section: {tname} VA=0x{tvaddr:x} size=0x{tsize:x}")

    # dump 反汇编里看到的关键 VA（密钥候选 + 消息前缀候选）
    dump_va_region(data, image_base, secs, 0x14292f570, "KEY_CAND (32B from sign fn)", 32)
    dump_va_region(data, image_base, secs, 0x140f08d80, "MSG_PREFIX (from sign fn)", 64)
    dump_va_region(data, image_base, secs, 0x140f08f20, "CONTEXT string", 64)
    dump_va_region(data, image_base, secs, 0x140f08ea3, "STRING_31B", 40)

    # 1. 定位 info 串与其后高熵串（静态密钥候选）
    needle_hits = find_all(data, NEEDLE)
    print(f"\n[+] '{NEEDLE.decode()}' hits: {[hex(x) for x in needle_hits]}")
    ranges = []
    for i in needle_hits:
        va = va_of(i)
        run = high_entropy_run(data, i + len(NEEDLE))
        print(f"    @file 0x{i:x} VA=0x{va:x}")
        print(f"      high-entropy run after info: {len(run)} bytes")
        print(f"      hex   = {run.hex()}")
        print(f"      ascii = {''.join(chr(b) if 32 <= b < 127 else '.' for b in run)}")
        ranges.append((va, va + len(NEEDLE) + 8, "info_str"))
        if run:
            kva = va_of(i + len(NEEDLE))
            ranges.append((kva, kva + len(run), "key_cand(%dB)" % len(run)))

    # 2. 定位 panic 串（v1.rs 编译残留，同函数内引用）
    panic_hits = find_all(data, PANIC_NEEDLE)
    print(f"\n[+] v1.rs panic string hits: {[hex(x) for x in panic_hits]}")
    for i in panic_hits:
        va = va_of(i)
        if va:
            ranges.append((va, va + len(PANIC_NEEDLE), "panic_str"))

    print(f"\n[+] target ranges ({len(ranges)}):")
    for lo_va, hi_va, label in ranges:
        print(f"    0x{lo_va:x}..0x{hi_va:x}  {label}")

    # 3. raw 扫描 .text 找引用点
    hits = raw_scan_rip_refs(data, toff, tsize, tvaddr + image_base, ranges)
    print(f"\n[+] rip-relative refs into target ranges: {len(hits)}")
    for foff, iva, target, label, pat in hits:
        print(f"    instr@{iva:#x} (file {foff:#x}) -> {target:#x}  [{label}]  opcode={pat}")

    if not hits:
        print("[!] 未找到引用点——可能密钥经寄存器/立即数加载，或 info 串只在 HKDF 参数构造处引用。")
        return 1

    # 4. 命中点前后反汇编窗口
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    labels = {}
    for lo_va, hi_va, label in ranges:
        for a in range(lo_va, hi_va):
            labels[a] = label

    print(f"\n{'=' * 72}\nDISASSEMBLY WINDOWS\n{'=' * 72}")
    for idx, (foff, iva, target, label, pat) in enumerate(hits[:12]):
        print(f"\n--- window #{idx}: ref site {iva:#x} -> {target:#x} [{label}] ---")
        # 覆盖整个签名函数：从 0x140450400 到 0x140451200
        lo_va = 0x140450400
        hi_va = 0x140451200
        lo = toff + (lo_va - image_base - tvaddr)
        hi = toff + (hi_va - image_base - tvaddr)
        lo = max(toff, lo)
        hi = min(toff + tsize, hi)
        for ins in md.disasm(data[lo:hi], lo_va):
            mark = ""
            if ins.address == iva:
                mark = "   <== REF SITE"
            rip_note = ""
            try:
                import re
                m = re.search(r"\[rip\s*([+-])\s*0x([0-9a-f]+)\]", ins.op_str)
                if m:
                    disp = int(m.group(2), 16)
                    if m.group(1) == "-":
                        disp = -disp
                    t = ins.address + ins.size + disp
                    # dump 目标字符串（如果可读）
                    note = f"; @ {t:#x}"
                    if t in labels:
                        note = f"; {labels[t]} @ {t:#x}"
                    else:
                        # 尝试读目标处字符串
                        trva = t - image_base
                        for name, vsize, vaddr, rawptr, rawsize in secs:
                            if vaddr <= trva < vaddr + vsize:
                                toff2 = rawptr + (trva - vaddr)
                                s = data[toff2:toff2 + 48]
                                txt = "".join(chr(b) if 32 <= b < 127 else "" for b in s)
                                if len(txt) >= 3:
                                    note = f"; '{txt[:40]}' @ {t:#x}"
                                break
                    rip_note = "   " + note
            except Exception:
                pass
            print(f"  {ins.address:#012x}: {ins.mnemonic:<7} {ins.op_str}{rip_note}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
