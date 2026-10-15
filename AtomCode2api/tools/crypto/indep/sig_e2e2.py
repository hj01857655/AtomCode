# 端到端 v2：全部材料取当轮 d_capture.log（token/D1 实时），自签发 llm-api 三发
# 判读：A=200 ⇒ 全链闭环实锤；A=INVALID 且 B=REPLAY ⇒ 服务端接受结构但 HMAC 不过（密钥域/材料问题）
import json, hashlib, hmac, os, re, time, urllib.request, pathlib, requests

INDEP = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep")
K    = bytes.fromhex("e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123")
INFO = b"atomcode-signing-v1\x01"
VER  = "5.2.3"
HOST = "https://llm-api.atomgit.com"
PATH = "/v1/chat/completions"

L = [json.loads(x) for x in INDEP.joinpath("d_capture.log").read_text(encoding="utf-8").splitlines() if x.strip()]
Mev = [e["data"] for e in L if e.get("evt") == "keyder" and e.get("len") == 97]
assert Mev, "no M in d_capture.log — 先跑 d_capture.py"
Mnow = bytes.fromhex(Mev[-1])
token, D1 = Mnow[:24], Mnow[33:65]
hours = int.from_bytes(Mnow[25:33], "little")
print(f"current M: token={token.decode()} hours={hours} D1={D1.hex()[:16]}…")
auth = (pathlib.Path.home() / ".atomcode" / "auth.toml").read_text(encoding="utf-8", errors="ignore")
bearer = re.search(r'(?m)^access_token\s*=\s*"([^"]+)"', auth).group(1)

body = json.dumps({"model": "qwen3.8-27b", "messages": [{"role": "user", "content": "reply with the single word pong"}],
                   "max_tokens": 8, "stream": False}).encode()

def sign():
    ts = str(int(time.time())).encode()
    nonce = os.urandom(16)
    M = token + b"\x01" + (int(ts) // 3600).to_bytes(8, "little") + D1 + hashlib.sha256(VER.encode()).digest()
    D = hmac.new(M, K, hashlib.sha256).digest()
    okm = hmac.new(D, INFO, hashlib.sha256).digest()
    canon = (b"v1\nPOST\n" + PATH.encode() + b"\n" + ts + b"\n" + nonce.hex().encode()
             + b"\n" + hashlib.sha256(body).hexdigest().encode())
    return {"X-AtomCode-Sig": "v1:" + hmac.new(okm, canon, hashlib.sha256).hexdigest(),
            "X-AtomCode-Ts": ts.decode(), "X-AtomCode-Nonce": nonce.hex(),
            "X-AtomCode-Alg": "1", "X-AtomCode-Ver": VER}

def fire(label, hdrs):
    r = requests.post(HOST + PATH, data=body, headers=hdrs, timeout=30)
    print(f"{label}: {r.status_code} | {r.text[:170]}")
    return r.status_code

base = {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json", "User-Agent": f"atomcode/{VER}"}
h = sign(); fire("A 当轮材料自签", {**base, **h}); time.sleep(1.5)
bad = dict(h); s = bad["X-AtomCode-Sig"]; bad["X-AtomCode-Sig"] = s[:-1] + ("0" if s[-1] != "0" else "1")
fire("B 篡改一位      ", {**base, **bad}); time.sleep(1.5)
fire("C 无签名头      ", base)
