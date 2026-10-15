# D 原像终验：从 d_capture.log 取 M(97B)/K/D/OKM 实值，验证假设
#   H1: D = HMAC-SHA256(key=M, msg=K)                    （即 HKDF-Extract(salt=M, ikm=K)）
#   H2: OKM = HMAC-SHA256(key=D, msg="atomcode-signing-v1"||0x01)
#   H3: M 结构 = token(24B ASCII)||0x01||LE64(ts//3600)||D1(32B)||D2(32B)，D1/D2 对上已知值
import json, hashlib, hmac, pathlib

INDEP = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep")
K = bytes.fromhex("e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123")
INFO = b"atomcode-signing-v1\x01"
D1_KNOWN = "01ac078b"   # 06 抓到的 D1 前缀
D2 = hashlib.sha256(b"5.2.3").digest()

events = [json.loads(l) for l in INDEP.joinpath("d_capture.log").read_text(encoding="utf-8").splitlines() if l.strip()]

M_ev = [e for e in events if e.get("evt") == "keyder" and e.get("len") == 97]
fins = [e["out"] for e in events if e.get("evt") == "finalize_out" and len(e.get("out", "")) == 64]
ups  = [e for e in events if e.get("evt") == "update"]
print(f"keyder(M)={len(M_ev)}  finalize_out={len(fins)}  updates={len(ups)}")

for M_e in M_ev[:1]:
    M = bytes.fromhex(M_e["data"])
    assert len(M) == 97, len(M)
    token = M[:24]; sep = M[24]; hours = int.from_bytes(M[25:33], "little"); d1 = M[33:65]; d2 = M[65:97]
    print("M token:", token.decode(errors="replace"), " sep:", sep, " hours:", hours,
          " D1 match 06:", d1.hex().startswith(D1_KNOWN), " D2==sha256('5.2.3'):", d2 == D2)
    D_h1 = hmac.new(M, K, hashlib.sha256).digest().hex()          # H1
    D_alt = hashlib.sha256(M + K).hexdigest()                      # 退化对照
    print("H1 D=HMAC(M,K)     :", D_h1)
    print("   实拍 D (fin#1)   :", fins[0] if fins else "-")
    print("   H1 hit           :", D_h1 == fins[0])
    print("   对照 SHA256(M||K):", D_alt == fins[0])
    if fins:
        D = bytes.fromhex(fins[0])
        OKM_calc = hmac.new(D, INFO, hashlib.sha256).digest().hex()  # H2
        print("H2 OKM=HMAC(D,info) :", OKM_calc, " hit:", OKM_calc == fins[1])
        print("   实拍 OKM (fin#2)  :", fins[1] if len(fins) > 1 else "-")
    # canonical 重建：连续 10 段长度序列 [3,4,1,20,1,10,1,32,1,64] 且首段 == "v1\n"
    want = [3, 4, 1, 20, 1, 10, 1, 32, 1, 64]
    best = None
    for i in range(len(ups) - 9):
        lens = [ups[j]["len"] for j in range(i, i + 10)]
        if lens == want and bytes.fromhex(ups[i]["data"]) == b"v1\n":
            best = i
    if best is not None:
        canonical = b"".join(bytes.fromhex(ups[j]["data"]) for j in range(best, best + 10))
        ts = canonical.split(b"\n")[3]
        hrs = int(ts) // 3600
        print(f"canonical rebuilt: {len(canonical)}B  ts={ts.decode()}  ts//3600={hrs} == M.hours={hours}:", hrs == hours)
        if len(fins) > 1:
            sig_calc = hmac.new(bytes.fromhex(fins[1]), canonical, hashlib.sha256).hexdigest()
            print("sig = HMAC(OKM, canonical) =", sig_calc)
