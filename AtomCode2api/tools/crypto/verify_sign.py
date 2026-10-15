#!/usr/bin/env python3
"""verify_sign.py — 用 capture_v2.log 抓到的真实中间量，离线逐层复算对拍 sign_v1。

数据来源：capture_v2.log（frida spawn 真实请求，2026-10-14 两轮完整签名周期）

已抓到的证据链（round 1）：
  M        = 97B   @0x14045058a hook：token(24) + 0x01 + LE64(ts//3600) + D1(32) + D2(32)
  静态密钥  = 32B   @0x14045059a（cell 0x14292f570，跨运行稳定 e97250f0...637123）
  OKM      = 32B   @0x1404508a8：76b515ac72a85b25e71c6c595898520026c51a385a2800ab7bbb076c1b59305b
  canonical（HMAC2 update 分片按序拼接，round 1）：
    "v1\\n" + "POST" + "\\n" + "/v1/chat/completions" + "\\n" + "1791929391" + "\\n"
    + "60b4e7328f68d083248bf2dd0ceb2022"(nonce hex) + "\\n"
    + "d99894b3b9b27f4778a03cead07202ed3c743c650720a969d871e6d8895e035e"(64hex, 疑 sha256(body))
  最终签名 = "cd990df2898d4a363759cb154f4565b034b748949899df81b9f481ce7b7208f7"（hex16#3 输出）

算法假设（静态反汇编 + 文档骨架）：
  PRK = HMAC-SHA256(key=M, msg=静态密钥)
  OKM = HKDF-Expand(PRK, info="atomcode-signing-v1", L=32)
  sig = hex(HMAC-SHA256(key=OKM, msg=canonical))

本脚本逐层验证 + 测试 M 的 D1/D2 来源假设（sha512(token)[:32]、sha512("5.2.3")[:32] 等）。
"""
import hashlib
import hmac

# ── 抓到的真实数据 ──────────────────────────────────────
M_HEX = ("363761656539303163623033326636623863626233623775"
         "015e9807000000000001"  # 0x01 + LE64(497758 = ts//3600)
         "ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa27a"
         "199c7cfd1a6389f213f6f7658a03681a0831e1e084fd5cd5b2299369a6625d")
M = bytes.fromhex(M_HEX)
assert len(M) == 97, len(M)

STATIC_KEY = bytes.fromhex(
    "e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123")
OKM_CAP = "76b515ac72a85b25e71c6c595898520026c51a385a2800ab7bbb076c1b59305b"
TS = "1791929391"
NONCE_HEX = "60b4e7328f68d083248bf2dd0ceb2022"
BODYHASH_HEX = "d99894b3b9b27f4778a03cead07202ed3c743c650720a969d871e6d8895e035e"
SIG_CAP = "cd990df2898d4a363759cb154f4565b034b748949899df81b9f481ce7b7208f7"

INFO = b"atomcode-signing-v1"


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand：T(1)=HMAC(PRK, T(0)||info||0x01)，32B 只需一轮。"""
    t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t[:length]


def hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


results = []

# ── 第 1 层：PRK ───────────────────────────────────────
prk = hmac.new(M, STATIC_KEY, hashlib.sha256).digest()
print(f"[1] PRK  = HMAC-SHA256(key=M, msg=static_key)")
print(f"    PRK  = {prk.hex()}")
results.append(("PRK(无对拍基准，仅中间量)", None))

# ── 第 2 层：OKM（有对拍基准）─────────────────────────
okm = hkdf_expand(prk, INFO, 32)
okm_hit = (okm.hex() == OKM_CAP)
print(f"[2] OKM  = HKDF-Expand(PRK, info='atomcode-signing-v1', 32)")
print(f"    OKM  = {okm.hex()}")
print(f"    实拍 = {OKM_CAP}")
print(f"    {'✅ MATCH' if okm_hit else '❌ MISMATCH'}")
results.append(("OKM", okm_hit))

# ── 第 3 层：canonical 与签名（有对拍基准）────────────
canonical = (f"v1\nPOST\n/v1/chat/completions\n{TS}\n"
             f"{NONCE_HEX}\n{BODYHASH_HEX}").encode()
print(f"[3] canonical 消息（{len(canonical)}B）：")
print("    " + repr(canonical))

sig = hmac_hex(okm, canonical)
sig_hit = (sig == SIG_CAP)
print(f"[4] sig  = hex(HMAC-SHA256(key=OKM, msg=canonical))")
print(f"    sig  = {sig}")
print(f"    实拍 = {SIG_CAP}")
print(f"    {'✅ MATCH' if sig_hit else '❌ MISMATCH'}")
results.append(("sig", sig_hit))

# ── M 的 D1/D2 来源假设测试 ────────────────────────────
token = b"67aee901cb032f6b8cbb3b75"
hours_le = (497758).to_bytes(8, "little")
D1 = M[33:65]
D2 = M[65:97]
print(f"\n[5] M 结构解剖（97B）：")
print(f"    token(24) = {M[:24]!r}")
print(f"    ver  byte = {M[24]:#04x}")
print(f"    hours LE64= {int.from_bytes(M[25:33], 'little')}  (= {TS}/3600 = {int(TS)//3600} ✓)")
print(f"    D1(32)    = {D1.hex()}")
print(f"    D2(32)    = {D2.hex()}")

cands = [
    ("sha512(token)[:32]", hashlib.sha512(token).digest()[:32]),
    ("sha512(token+ver+hours)[:32]", hashlib.sha512(token + b"\x01" + hours_le).digest()[:32]),
    ("sha512(token+hours)[:32]", hashlib.sha512(token + hours_le).digest()[:32]),
    ("sha512(b'5.2.3')[:32]", hashlib.sha512(b"5.2.3").digest()[:32]),
    ("sha512(b'AtomCode v5.2.3')[:32]", hashlib.sha512(b"AtomCode v5.2.3").digest()[:32]),
    ("sha512(b'atomcode/5.2.3')[:32]", hashlib.sha512(b"atomcode/5.2.3").digest()[:32]),
    ("sha512(b'v5.2.3')[:32]", hashlib.sha512(b"v5.2.3").digest()[:32]),
]
print(f"\n[6] D1/D2 来源假设测试：")
d1_hit = d2_hit = False
for label, blob in cands:
    if blob == D1:
        print(f"    D1 ✅ {label}")
        d1_hit = True
    if blob == D2:
        print(f"    D2 ✅ {label}")
        d2_hit = True
if not d1_hit:
    print(f"    D1 ❌ 无命中（{len(cands)} 个候选）")
if not d2_hit:
    print(f"    D2 ❌ 无命中（{len(cands)} 个候选）")

# ── 汇总 ───────────────────────────────────────────────
print("\n" + "=" * 60)
okm_ok = okm_hit
sig_ok = sig_hit
if okm_ok and sig_ok:
    print("✅✅✅ 全链路对拍成功：sign_v1 算法完全还原并验证")
    print("    PRK = HMAC-SHA256(M, static_key)")
    print("    OKM = HKDF-Expand(PRK, 'atomcode-signing-v1', 32)")
    print("    sig = 'v1:' + hex(HMAC-SHA256(OKM, canonical))")
elif okm_ok:
    print("⚠️ OKM 对拍成功（HKDF 链正确），但 canonical 拼装有偏差 —— 检查消息模板")
elif sig_ok:
    print("⚠️ sig 对拍成功（异常：OKM 不匹配但 sig 匹配？检查数据）")
else:
    print("❌ 对拍失败，需回查假设")
print(f"\nM 来源假设：D1 {'✅' if d1_hit else '❌'}  D2 {'✅' if d2_hit else '❌'}"
      f"（不命中也可用：M 可由 sign_v1 调用点直接捕获/复用）")
