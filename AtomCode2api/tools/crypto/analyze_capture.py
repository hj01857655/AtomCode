#!/usr/bin/env python3
"""analyze_capture.py — 解析 capture_v2.log，提取两轮真实中间量，离线枚举 OKM 推导并验证 sig。

关键实证（capture_v2.log）：
  两轮请求的 M 不同（token/D1/D2 均变），但 OKM 完全相同
  → OKM 与 M 无关，必为静态密钥 K 的确定性函数（per-process 常量）。
  原假设 PRK=HMAC(M,K)→HKDF 方向错误，本脚本改为枚举 K-only 推导。
"""
import hashlib
import hmac
import re

LOG = "capture_v2.log"
K = bytes.fromhex("e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123")
INFO = b"atomcode-signing-v1"

text = open(LOG, encoding="utf-8", errors="replace").read()

# ── 按 M_ready 切分成轮 ────────────────────────────────
parts = re.split(r'\{"type": "phase", "phase": "M_ready"[^\n]*\}', text)
rounds = []
for seg in parts[1:]:
    mems = re.findall(r"### MEM \[([^\]]+)\] ptr=(\S+) len=(\d+)\n\s*hex\s*:\s*([0-9a-f]*)", seg)
    r = {"dumps": mems}
    m = re.search(r"M_meta[^\n]*ptr=(\S+) len=(\d+)", seg)
    if m:
        r["m_meta"] = (m.group(1), int(m.group(2)))
    rounds.append(r)
print(f"[*] 解析到 {len(rounds)} 轮签名\n")

# ── 提取每轮关键量 ─────────────────────────────────────
def get_tag(r, prefix):
    out = []
    for tag, ptr, ln, hx in r["dumps"]:
        if tag.startswith(prefix):
            out.append((tag, hx))
    return out

for i, r in enumerate(rounds, 1):
    mb = get_tag(r, "M_bytes")
    okm = get_tag(r, "OKM")
    upd = sorted(get_tag(r, "upd#"), key=lambda t: int(t[0].split("#")[1]))
    h64 = get_tag(r, "hex64#")
    h16 = get_tag(r, "hex16#")
    r["M"] = bytes.fromhex(mb[0][1]) if mb else None
    r["OKM"] = okm[0][1] if okm else None
    r["upds"] = [bytes.fromhex(h) for _, h in upd]
    r["canonical"] = b"".join(r["upds"])
    r["h64_in"] = {t: h for t, h in h64 if t.endswith(".in")}
    r["h64_out"] = {t: h for t, h in h64 if ".out+" in t}
    r["h16_out"] = {t: h for t, h in h16 if ".out+" in t}
    print(f"── Round {i} ──")
    print(f"  M({len(r['M'] or b'')}B) = {(r['M'] or b'').hex()}")
    print(f"  OKM      = {r['OKM']}")
    print(f"  canonical({len(r['canonical'])}B) = {r['canonical']!r}")
    for t, h in sorted(r["h64_in"].items()):
        print(f"  {t} = {h}")
    for t, h in sorted(r["h64_out"].items()):
        print(f"  {t} = {h}")
    for t, h in sorted(r["h16_out"].items()):
        print(f"  {t} = {h}")
    print()

# ── 实证检查：M 变 / OKM 不变 ──────────────────────────
if len(rounds) >= 2:
    m_same = rounds[0]["M"] == rounds[1]["M"]
    okm_same = rounds[0]["OKM"] == rounds[1]["OKM"]
    print(f"[实证] M 两轮相同? {m_same}    OKM 两轮相同? {okm_same}")
    if not m_same and okm_same:
        print("[实证] ✅ OKM 与 M 无关 → 必为 K 的纯函数，枚举 K-only 推导\n")

# ── OKM 暴力枚举（全部为 K 的函数）─────────────────────
okm_target = bytes.fromhex(rounds[0]["OKM"])
sha256 = hashlib.sha256
cands = {
    "HKDF-Expand(K, info)=HMAC(K, info|0x01)": hmac.new(K, INFO + b"\x01", sha256).digest(),
    "HMAC(K, info)": hmac.new(K, INFO, sha256).digest(),
    "HMAC(K, K)": hmac.new(K, K, sha256).digest(),
    "Expand(HMAC(K,K), info)": hmac.new(hmac.new(K, K, sha256).digest(), INFO + b"\x01", sha256).digest(),
    "SHA256(K)": sha256(K).digest(),
    "HMAC(K, SHA256(K))": hmac.new(K, sha256(K).digest(), sha256).digest(),
    "HMAC(SHA256(K), K)": hmac.new(sha256(K).digest(), K, sha256).digest(),
    "Expand(SHA256(K), info)": hmac.new(sha256(K).digest(), INFO + b"\x01", sha256).digest(),
    "SHA256(K||info)": sha256(K + INFO).digest(),
    "SHA256(info||K)": sha256(INFO + K).digest(),
    "HMAC(info, K)": hmac.new(INFO, K, sha256).digest(),
    "HMAC(K, b'')": hmac.new(K, b"", sha256).digest(),
    "SHA256(info)": sha256(INFO).digest(),
    "HMAC(K, K||info)": hmac.new(K, K + INFO, sha256).digest(),
    "HMAC(K, info||K)": hmac.new(K, INFO + K, sha256).digest(),
}
print("[枚举] OKM 推导候选（K-only）：")
hit = None
for label, blob in cands.items():
    mark = "✅ HIT" if blob == okm_target else "  .."
    print(f"  {mark}  {label}")
    if blob == okm_target:
        hit = label
if not hit:
    # info 变体再扫一轮
    info_vars = [INFO + b"\n", INFO + b"\x00", b"AtomCode-signing-v1", b"atomcode-signing",
                 b"atomcode-signing-v1\n", b"v1", b"atomcode-signing-v2"]
    for iv in info_vars:
        for label, blob in {
            "HMAC(K, info|0x01)": hmac.new(K, iv + b"\x01", sha256).digest(),
            "HMAC(K, info)": hmac.new(K, iv, sha256).digest(),
        }.items():
            if blob == okm_target:
                hit = f"{label} info={iv!r}"
                print(f"  ✅ HIT  {label} info={iv!r}")
print(f"\n[结论] OKM 推导 = {hit or '未命中，需回查 disasm 或重新 hook'}\n")

# ── sig 验证（每轮）────────────────────────────────────
for i, r in enumerate(rounds, 1):
    sig_dump = r["h16_out"].get("hex16#3.out+0")
    sig_cap = bytes.fromhex(sig_dump) if sig_dump else None
    sig_hex = sig_dump if sig_dump else "(未抓到)"
    okm_bytes = bytes.fromhex(r["OKM"])
    sig_calc = hmac.new(okm_bytes, r["canonical"], sha256).hexdigest()
    match = sig_calc == sig_hex
    print(f"Round {i}: sig = HMAC(OKM, canonical)")
    print(f"  calc = {sig_calc}")
    print(f"  cap  = {sig_hex}  {'✅ MATCH' if match else '❌ MISMATCH'}")
    # 交叉验证：canonical 末字段 vs hex64#1.out（body hash）
    b1 = r["h64_out"].get("hex64#1.out+0")
    if b1:
        ok = b1.encode() in r["canonical"]
        print(f"  bodyhash 字段在 canonical 中? {'✅' if ok else '❌'}  ({b1[:16]}...)")
    # 交叉验证：hex64#2.in 是否 == OKM
    h2in = r["h64_in"].get("hex64#2.in")
    if h2in:
        print(f"  hex64#2.in == OKM? {'✅' if h2in == r['OKM'] else '❌'}")
