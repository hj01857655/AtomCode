# D1 来源假设穷举：对 ~/.atomcode 本地凭据的每个字段测 D1 =? f(field)
# 变换：SHA256(s) / SHA256(unhex(s)) / HMAC(K,s) / 前32B / 末32B / hex解码前32B / MD5…
# 只输出字段名+变换名+命中与否，绝不明文打印字段值。
import hashlib, hmac as _hmac, pathlib, re, json

D1 = bytes.fromhex("01ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa27a")
K  = bytes.fromhex("e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123")
home = pathlib.Path.home() / ".atomcode"

fields = []  # (label, value-str)
def scan_toml(fp, rel):
    for m in re.finditer(r'(?m)^([A-Za-z0-9_\-]+)\s*=\s*"([^"]*)"', fp.read_text(encoding="utf-8", errors="ignore")):
        fields.append((f"{rel}:{m.group(1)}", m.group(2)))
def scan_json(fp, rel):
    for m in re.finditer(r'"([A-Za-z0-9_\-]+)"\s*:\s*"?([^",}\s]+)"?', fp.read_text(encoding="utf-8", errors="ignore")):
        fields.append((f"{rel}:{m.group(1)}", m.group(2)))

for fn in ["auth.toml", "config.toml", "codingplan_sync.json", "device_id"]:
    fp = home / fn
    if not fp.exists(): continue
    if fn.endswith(".toml"): scan_toml(fp, fn)
    elif fn.endswith(".json"): scan_json(fp, fn)
    else: fields.append((fn, fp.read_text(errors="ignore").strip()))
# sessions/ 目录内的 id/元数据字段
for fp in list(home.glob("sessions/**/*.json"))[:20] + list(home.glob("sessions/*"))[:20]:
    if fp.is_file():
        try:
            if fp.suffix == ".json": scan_json(fp, fp.name)
            else: fields.append((fp.name, fp.read_text(errors="ignore").strip()[:200]))
        except Exception: pass

def variants(label, s):
    b = s.encode("utf-8", "ignore")
    yield "sha256(s)", hashlib.sha256(b).digest()
    yield "hmacK(s)", _hmac.new(K, b, hashlib.sha256).digest()
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        try:
            raw = bytes.fromhex(s)
            yield "sha256(unhex)", hashlib.sha256(raw).digest()
            yield "raw[:32]", raw[:32]
            yield "raw[-32:]", raw[-32:]
        except Exception: pass
    if len(b) >= 32:
        yield "b[:32]", b[:32]
        yield "b[-32:]", b[-32:]

print("fields:", len(fields))
hits = []
for label, s in fields:
    for name, v in variants(label, s):
        if v == D1:
            hits.append((label, name))
if hits:
    for h in hits: print("HIT!", h[0], "==>", h[1])
else:
    print("MISS —— 本地存储字段均非 D1 直接变换；等 d1_trace backtrace 定生成点")
