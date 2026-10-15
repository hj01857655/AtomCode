# D1 =? KDF(某固定 info 串, 某材料)：二进制 strings × 本地材料 全组合穷举
# 变换：HMAC(m,s)/HMAC(s,m)/SHA256(m+s)/SHA256(s+m)/SHA256(m+s+m) × 全部候选串
import pefile, re, hashlib, hmac as H, pathlib, json

D1  = bytes.fromhex("01ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa2")
K   = bytes.fromhex("e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123")
EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"

pe = pefile.PE(EXE)
img = pe.get_memory_mapped_image()
# 候选 info 串：可打印 ASCII 6..64，命中关键词
kw = re.compile(rb"(atomcode|coding|plan|sign|device|seed|derive|salt|hkdf|key|master|install|machine|uuid|session|crypto)", re.I)
cands = {}
for m in re.finditer(rb"[\x20-\x7e]{6,64}", img):
    s = m.group()
    if kw.search(s):
        cands[s] = None
print("string candidates:", len(cands))

# 材料池
mats = {"K": K, "D1self": D1, "tok24": b"67aee901cb032f6b8cbb3b75", "ver": b"5.2.3",
        "D2": hashlib.sha256(b"5.2.3").digest(), "info1": b"atomcode-signing-v1\x01"}
home = pathlib.Path.home() / ".atomcode"
for fn, tag in [("device_id", "devid"), ("auth.toml", None)]:
    fp = home / fn
    if fp.exists():
        if tag: mats[tag] = fp.read_text(errors="ignore").strip().encode()
        else:
            for k, v in re.findall(r'(?m)^([a-z_]+)\s*=\s*"([^"]+)"', fp.read_text(errors="ignore")):
                if len(v) <= 512: mats[f"auth.{k}"] = v.encode()
print("materials:", list(mats))

hits = []
mat_items = [(n, b) for n, b in mats.items() if b]
for s in cands:
    for n, m in mat_items:
        for name, v in [("hmac(m,s)", H.new(m, s, hashlib.sha256).digest()),
                        ("hmac(s,m)", H.new(s, m, hashlib.sha256).digest()),
                        ("sha(m|s)", hashlib.sha256(m + s).digest()),
                        ("sha(s|m)", hashlib.sha256(s + m).digest())]:
            if v == D1:
                hits.append((n, name, s[:60]))
# 纯串也互算一轮（s1 作 key, s2 作 msg）抽样太大，先只测常见组合
if hits:
    for h in hits: print("HIT!", h)
else:
    print("MISS —— D1 非 (二进制内串 × 已知材料) 的标准 HMAC/SHA 组合")
