#!/usr/bin/env python3
"""dump_key_region.py — 定位 atomcode-signing-v1 邻域的静态密钥候选。

思路：v1.rs 编译残留里 info 串 "atomcode-signing-v1" 与密钥常量常在同一
PE section 内相邻放置。精确 dump 邻域 hex + 逐窗熵，找高熵 16/32/48/64 字节
候选，作为 HMAC key 的静态来源假设。
"""
import math
import struct
import sys

BIN = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
NEEDLE = b"atomcode-signing-v1"


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for c in b:
        counts[c] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def parse_pe(data: bytes):
    """极简 PE 解析：返回 [(name, vsize, vaddr, raw_ptr, raw_size, section_name)]"""
    if data[:2] != b"MZ":
        raise SystemExit("not a PE")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise SystemExit("no PE signature")
    coff = pe_off + 4
    n_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    # PE32+ magic = 0x20b
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    sec_off = opt + opt_size
    secs = []
    for i in range(n_sections):
        s = sec_off + i * 40
        name = data[s:s + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        secs.append((name, vsize, vaddr, rawptr, rawsize))
    return image_base, secs


def main() -> int:
    data = open(BIN, "rb").read()
    print(f"[+] binary size = {len(data):,} bytes")

    image_base, secs = parse_pe(data)
    print(f"[+] image base = 0x{image_base:x}")
    print(f"[+] sections ({len(secs)}):")
    for name, vsize, vaddr, rawptr, rawsize in secs:
        print(f"    {name:<8} VA=0x{vaddr:08x}  vsize=0x{vsize:x}  raw=0x{rawptr:x}  rawsize=0x{rawsize:x}")

    # 找到所有出现位置
    hits = []
    start = 0
    while True:
        i = data.find(NEEDLE, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    print(f"\n[+] '{NEEDLE.decode()}' occurrences: {len(hits)}")
    for i in hits:
        sec = next((s for s in secs if s[3] <= i < s[3] + s[4]), None)
        secname = sec[0] if sec else "?"
        va = (image_base + sec[1] + (i - sec[3])) if sec else 0
        print(f"    file_off=0x{i:x}  section={secname}  VA=0x{va:x}")

    # 逐个命中点 dump 邻域
    for n, i in enumerate(hits):
        print(f"\n{'=' * 72}\n=== occurrence #{n} @ file_off 0x{i:x} ===\n{'=' * 72}")
        lo = max(0, i - 256)
        hi = min(len(data), i + len(NEEDLE) + 384)
        chunk = data[lo:hi]
        # hexdump
        for off in range(0, len(chunk), 16):
            row = chunk[off:off + 16]
            fa = lo + off
            hexs = " ".join(f"{b:02x}" for b in row)
            txt = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            mark = ""
            if lo + off <= i < lo + off + 16:
                mark = "  <-- NEEDLE starts here"
            print(f"  {fa:08x}  {hexs:<47}  |{txt}|{mark}")

        # 邻域高熵窗扫描（key 候选）
        print(f"\n  --- entropy scan around occurrence #{n} ---")
        region = data[max(0, i - 512):min(len(data), i + len(NEEDLE) + 512)]
        for size in (16, 32, 48, 64):
            cands = []
            for off in range(0, len(region) - size + 1):
                w = region[off:off + size]
                e = entropy(w)
                if e >= 3.6:  # 高熵门槛
                    cands.append((off, e, w))
            if not cands:
                continue
            # 合并重叠窗，取最长高熵段
            print(f"    size={size}: {len(cands)} high-entropy windows (E>=3.6)")
            shown = 0
            seen_ranges = []
            for off, e, w in cands:
                fa = max(0, i - 512) + off
                if any(a <= fa < b for a, b in seen_ranges):
                    continue
                seen_ranges.append((fa, fa + size))
                print(f"      file_off=0x{fa:x}  E={e:.3f}")
                print(f"        hex = {w.hex()}")
                print(f"        ascii = {''.join(chr(b) if 32 <= b < 127 else '.' for b in w)}")
                shown += 1
                if shown >= 6:
                    print(f"      ... ({len(cands)} total, showing first 6)")
                    break
    return 0


if __name__ == "__main__":
    sys.exit(main())
