# AtomCode CodingPlan 请求签名规范（sign_v1）

> **本文是 AtomCode 签名知识的唯一权威文档**（2026-10-14 合并原 06 还原记录 / 07 规范 / desktop 版三文档而成；原 05 历史存档已废弃删除，MITM 工具链保留作回归）。
> 目标二进制：`@atomgit.com/atomcode-win32-x64/bin/atomcode.exe` **5.2.3**（构建 d8918f0，43,809,424 B，strip）。闭源 crate `atomcode-codingplan-crypto`，函数 `sign_v1`，RVA `0x140450400–0x140450ded`（`.pdata` 定界，645 指令）。
> 证据等级：**算法链每一环均有逐字节对拍命中，且自签请求已通过服务端真实验签（10-14 E2E 200）**；无假设项。

## 1. 协议面

`sign_v1` 产出五个 HTTP 请求头：

| 头 | 值 | 示例 |
|---|---|---|
| `X-AtomCode-Sig` | `"v1:" + hex64(HMAC-SHA256(OKM, canonical))` | `v1:cd990df2…08f7` |
| `X-AtomCode-Ts` | Unix 秒十进制 ASCII | `1791967696` |
| `X-AtomCode-Nonce` | 16B 随机的 32 字符 hex | `ea6db5f3…352534` |
| `X-AtomCode-Alg` | 固定 `"1"`（算法代际号，**不是** hmac-sha256） | `1` |
| `X-AtomCode-Ver` | 客户端版本串 | `5.2.3` |

五头名在二进制内是连续常量簇（`.rdata 0x140f08cbe→0x140f08cf7`，打包结构 @`0x140f08c90`）。

## 2. 算法定义

整套 = **教科书 HKDF-SHA256（Extract+Expand）+ 一次 HMAC 终签**，对称方案，无非对称/无 PoW。

```
输入：method、path、body、token(登录 token ASCII 24B)、version、常量 K、D1

ts      = unix 秒（十进制 ASCII）
hours   = ts // 3600
nonce   = getrandom 16B

M       = token ‖ 0x01 ‖ LE64(hours) ‖ D1 ‖ SHA256(version)          # 97B
D       = HMAC-SHA256(key = M, msg = K)                               # HKDF-Extract
OKM     = HMAC-SHA256(key = D, msg = "atomcode-signing-v1" ‖ 0x01)    # HKDF-Expand 单轮，32B
canonical = "v1\n" ‖ method ‖ "\n" ‖ path ‖ "\n" ‖ ts ‖ "\n" ‖ hex(nonce) ‖ "\n" ‖ hex(SHA256(body))
Sig     = "v1:" ‖ hex( HMAC-SHA256(key = OKM, msg = canonical) )
```

要点：
- `D` 随**小时桶**变化（M 内 hours），同小时内恒定——历史上"D 跨运行会变"的原因即在此，与内存布局/ASLR 无关；
- canonical 各段全部是**文本**：ts 是十进制 ASCII，nonce 是 hex 字符串，body 是"先 SHA256 再取 64 位小写 hex"，段间以 `\n`(0x0A) 分隔，开头 `"v1\n"`；
- 137B 实拍样本（2026-10-14 d_capture 轮 1，逐 update 序列拼接、与静态拼装序全等）：

```
v1\nPOST\n/v1/chat/completions\n1791967696\nea6db5f37d5d9397b2fece313e135254\nb05fcc8a481f1fcb59d0c86356b357cea67b423a4b5a2f4e3270f43013280bd6
```

- 二进制内部细节（对外行为等价、实现无需关心）：HMAC#1 的 key 块先由 M(97B>64B) 派生 `SHA256(M)`，随后被 `D` 覆盖，再走 ipad/opad——即 hmac crate 的常规路径，最终对外只呈现 `D = HMAC(M, K)`。

## 3. 密钥材料

| 名 | 值 | 角色 | 性质 |
|---|---|---|---|
| `K` | `e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123` | Extract 的 ikm（HMAC#1 message） | 32B，**编译期常量（已破）**：`.rdata 0xf08df3` ⊕ `0xf08e13` 双掩码，init=`0x140566f83`（32B XOR 循环），异或值与实测全等；cell 文件映像自带初始状态字（OnceLock::from(MaybeUninit) 模式，故旧记"搜不到/0 store"） |
| `D1` | `01ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa2`（M[33:65] 实拍切片为准） | M 的构成段 | 32B，同安装/登录态跨运行恒定；**生成公式未还原（全链唯一遗留）**。勘误：本值早期从缩写手扩成 `…12bfa27a`（多一字节 33B），导致自签 INVALID；以本行为唯一正例 |
| `D2` | `SHA256("5.2.3")` = `199c7cfd1a6389f213f6f7658a03681a0831e1e084fd5cd5b2299369a6625d` | M 尾段 | 纯函数，version 变则重算 |
| `info` | `"atomcode-signing-v1"`(19B) + `0x01` | Expand 的 info‖counter | 算法代际常量（v2 换代大概率只换这里） |
| `token` | M[0:24] ASCII，例 `67aee901cb032f6b8cbb3b75` | M 头段 | 登录 token，24B |

**诚实边界**：除 D1 的"是谁算出来的"之外，签名链没有任何黑盒；离线自主签发（§4）已完全可行且经服务端验签实过（§5 E2E）。

D1 来源取证定性（10-14 深夜收官，六路夹击后只剩一种可能）：① **非服务端下发（逻辑封死）**——完整启动周期 DNS 只解 `llm-api.atomgit.com`，无任何认证/控制面域名接触；若非本地算出，重启后必须重新拉取，而重启轮根本没出网 ⇒ 不可能是会话态下发；② **非任何存储层**——磁盘全域 5 编码零痕、`CryptUnprotectData`/PBKDF2/BCrypt 全零调用、注册表零碰 `MachineGuid`（仅 TLS 证书链常规噪音）；③ **非硬件指纹/安装资源**——`GetAdaptersInfo/Addresses`、`GetVolumeInformationW` 零调用，文件读清单无 bin 目录资源访问；④ **非单层代数组合**——748 字段×变换 + 4103 枚二进制串×材料全 MISS；⑤ **非常驻——随签名初始化懒算**：非代跑启动轮堆内零痕，签名轮堆内恰现 2 副本与 token 同堆区；⑥ 结构定性：sign_v1 从 provider 状态对象 `obj[0x28..]` 切片表取用。

**归约终态**：D1 = 纯本地确定性派生，输入只剩两个候选源——**二进制内嵌种子**（编译期常量/混淆 immediates，K 本身也是运行期展开 ⇒ 两者很可能同为 master 经不同 info 的 HKDF 两输出）或 **auth 文件内容的多层组合**。唯一能终局的路径 = 剖开 LazyLock 闭包的 vtable 间接调用链（`get_or_init@0x140e82c60 → call [rsi+0x20]`）找到初始化函数本体；静态旧记录已勘误（见附录 A）。工具链已备齐：d_api_trace / d_dns_trace / d_guard（页保护抓写者）/ d_host_probe / mitm_reverse。

**10-14 深夜静态收官（K 已破、D1 定性升维）**：
- **K 已破**：`0x450458` flag = `OnceLock::from(MaybeUninit)` 编译期内联，init `0x140566f83` = 双掩码 XOR（`.rdata 0xf08df3/0xf08e13`），还原值与实测 K 全等。
- **D1 全二进制排除**：`.rdata` 27MB + `.text` 14MB + K 掩码邻域 stride1 全组合零命中 ⇒ 无编译期字节形态。
- **内存宿主勘误二（10-14 深夜四，终版）**：所谓"两个 D1 堆副本/48B 宿主 String"实为**正在拼装的 M 缓冲本身**：holder 地址距 16B 对齐基址恰为 **0x21=33 = D1 在 M 的偏移**（token24+1+LE64 8）；多轮 holder 间距恒 0x3F0、全段（含栈）零指针引用——临时拷贝无人引用属自然，"零引用"不构成"运行期新产生"证据。D1 真宿主＝**与 token 同堆竞技场的登录态对象**（d1_trace extend src 指针实锤：0x…4010a20=token 区、D1 源在其邻页），其填充者（写入堆区的代码）才是出生点——需 Stalker 污点追踪级工具，现有钩点集合（finalize/one-shot sha/DPAPI/KDF API/磁盘全域 raw+hex 形态/网络/DNS）均已探尽：D1 的 hex 文本形态在 AppData/ProgramData/home 全树（约 4.3 万文件）零命中，明文配置线彻底排除。
- **可能性最终枚举与后续两刀（10-14 凌晨收官）**：④′ **签名轮 IO 差分零命中**（d_diff_iolist：真触发签名的轮次全进程仅新增读 0 个文件，唯一多出的写是自家 wire-dump 产物）⇒ 填 D1 不伴任何文件/注册表/DPAPI 动作，输入必为镜像内常量或已加载数据；⑤′ **8B 碎片零命中**（D1 与 K 的四段 8B、LE/BE 双序全镜像扫描均无）——对照 K 已破形态同为 8B 零命中，证明混淆等级统一（非对齐切分/多段掩码），滑窗类算术扫描到此为设计极限。幸存假说收敛：(a) 随机生成+自实现密文存储 或 (c′) **多段混淆掩码运行期重组**（K 的双掩码模板升级版）。终局二选：x64dbg 硬件写断点（十分钟级，需人工 GUI）或静态反混淆跨指令常量传播（天级）。

## 4. 参考实现（Python，可直接运行）

```python
import hashlib, hmac, os, time

K    = bytes.fromhex("e97250f05303162c8ecd68c688b2f55c1d81e508d243d88466472e7f54637123")
D1   = bytes.fromhex("01ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa2")
INFO = b"atomcode-signing-v1\x01"

def atomcode_sign(method: str, path: str, body: bytes, token: str, version: str = "5.2.3") -> dict:
    assert len(token) == 24
    ts    = str(int(time.time())).encode()
    nonce = os.urandom(16)
    M     = (token.encode() + b"\x01"
             + (int(ts) // 3600).to_bytes(8, "little")
             + D1
             + hashlib.sha256(version.encode()).digest())
    D     = hmac.new(M, K, hashlib.sha256).digest()
    okm   = hmac.new(D, INFO, hashlib.sha256).digest()
    canonical = (b"v1\n" + method.encode() + b"\n" + path.encode()
                 + b"\n" + ts + b"\n" + nonce.hex().encode()
                 + b"\n" + hashlib.sha256(body).hexdigest().encode())
    return {
        "X-AtomCode-Sig":   "v1:" + hmac.new(okm, canonical, hashlib.sha256).hexdigest(),
        "X-AtomCode-Ts":    ts.decode(),
        "X-AtomCode-Nonce": nonce.hex(),
        "X-AtomCode-Alg":   "1",
        "X-AtomCode-Ver":   version,
    }
```

## 5. 自检向量与回归

| 向量 | 期望 | 数据源 |
|---|---|---|
| canonical 拼装 | 逐字节 = §2 样本 / 10-13 轮 `cd990df2…` `cd8f20d4…` 两轮的 137B 原文 | `capture_v2.log`，`analyze_capture.py` |
| `D = HMAC(M, K)` | `4d5d3f6ca8bc5ab79501cfabee5314e827f72c5c3de5622d4b3d64ae8689b990`（hours=497768 轮） | `indep/d_capture.log`，`indep/match_d_preimage.py`（全命中） |
| `OKM = HMAC(D, info‖01)` | `1bd29bc7d8b289125e1753f3309548f9574942e6882320a9283b23e0701ca690` | 同上 |
| ts 一致性 | canonical 段 ts//3600 == M 内 LE64(hours) | 同上 |
| **E2E 实签** | `llm-api.atomgit.com POST /v1/chat/completions` + atomcode UA + 自签五头 = **200 真实补全**；篡改 sig 一位 = 403 `ATOMCODE_SIG_INVALID`；无签 = 403 `ATOMCODE_SIG_MISSING`（均 10-14 实测，`indep/sig_e2e2.py`） | 完成体 id `chatcmpl-97939f2d63f87796` |

## 6. 运行期取证（frida 钩点速查）

image_base=`0x140000000`（VA = base+RVA；钩点必须落在指令边界）。5.2.3 实测表：

| RVA | 指令/函数 | 用途 |
|---|---|---|
| `0x45058a` | M 就绪点 | dump M 97B → 切 D1 = M[33:65] |
| `0x450591` | `mov r8d,0x20` | rdx = K 指针（校 K 值） |
| `0x4505ed`/`0x450637` | ipad/opad 循环头 | `[rsp+0x2c0]` = 当前 key 块 |
| `0x4508a8` | HKDF 循环出口 | `[rsp+0x440]` = OKM |
| `0x27a02b` | sha256 compress(state, block, n) | 回放全部压缩块 |
| `0x566b4b` | hmac key 派生(out, data, len) | M→key 块 |
| `0x566c89` | HmacSha256::new_from_slice(self, ptr, len) | HMAC 实例化 |
| `0x566cd5` | update(self, data, len) | 全部数据流（canonical 逐段） |
| `0x566e17` | clone(out, self) | 状态克隆 |
| `0x566f1b` | finalize(out32, self) | D / OKM / 内层 digest 输出点 |
| `0x566576` | key 块二次写入(dst, src, len) | D→key 块覆盖 |
| `0x566950`/`0x5668bf` | hex64 / hex16 | body-hash/nonce/sig 编码 |

现成脚本（`tools/crypto/indep/`）：`d_capture.py`（spawn 登录态 `-p ping`，干净字节读法全钩上述点位）+ `match_d_preimage.py`（离线对拍全部向量）。注意 `readByteArray` 读法，勿用 `hexdump()`（ASCII 栏会污染 hex）。

## 7. 适用性与现状（10-14 晚重大反转：验签已强制）

- **服务端验签已开启**（仅针对 `atomcode/*` UA 通道）：缺签 `SIG_MISSING`、错签 `SIG_INVALID`、自签正确即 200（§5 E2E 行）。03 篇时代"不签名也能过"的结论在 atomcode UA 下已作废；非 atomcode UA 通道（换 UA 的网关路径）是否仍验签待重测。
- 验签顺序侧证：篡改一位的 B 发首报曾返 `SIG_REPLAY`（409）——服务端**先登记 ts/nonce 再比密钥**；连续重放同一 nonce 会被拦。
- **触发面（10-14 深夜终说，重登实验修正）**：签名是否发生是**会话级 gate**——重登（logout+OAuth，RT 轮换）后新会话三连实测**均不签名仍正常补全**（gate 放；早前轮"必签名"实为当时会话 gate 开）。取证铁律不变：要钩签名需当轮真触发了 sign（本进程 keyder 有事件）。
- **D1 绑定级别实测判定（10-14 深夜，重登后探针）**：RT 已轮换、全新 OAuth 会话下，用**旧 D1 自签仍 200 过验**（`chatcmpl-af5851049144af2c`）⇒ D1 绑定是**账号/设备级跨会话**，非会话临时密钥；"(b) 登录下发轮换"直接否。幸存假说：(a) 首次初始化随机生成+自实现加密态存储（或凭据管理器类未扫描面）或 (c) 混淆常量重组——若 (c)，重登后 gate 关但客户端仍能随对同一 D1 取数，两者均兼容；终局仍需 x64dbg 硬件断点或未来 gate 重开轮次的 d_capture 对比。
- 算法版本化：`Alg:1` / `v1` 前缀 / info 串三位一体；错误文案"请升级到最新版"提示换代时旧代签名会被直接拒。

## 附录 A　静态骨架（disasm_sign.log，302 条指令摘录）

反汇编窗口 `0x140450400..0x140450a00` + 尾段。关键序列：

| 地址 | 行为 |
|---|---|
| `0x140450453` | hasher A：先哈希整段 body（compress#1 = body 文本实证） |
| `0x14045046b` | `mov ecx,0xe10; div` = `ts // 3600` |
| `0x1404504cc–0x53c` | 4× `extend_from_slice` 拼 M(97B) |
| `0x140450559` | key 块派生：M(>64B) → `SHA256(M)` |
| `0x14045058a–0x59a` | update(K, 32B)——HMAC#1 message = K |
| `0x1404505bf/0x5d2` | clone + finalize → `D` |
| `0x1404505e8` | key 块 ← D（覆盖 SHA256(M)） |
| `0x1404505ed/0x637` | ipad `^0x36` / opad `^0x6a` |
| `0x1404506e0` | `'atomcode-signing-v1'` LEA（info） |
| `0x140450717–0x8a3` | HKDF-Expand 循环（单轮，T 计数器 0x01） |
| `0x1404508ff` | HMAC2 = new_from_slice(OKM) |
| `0x140450904–` | canonical 逐段 update（`v1\n`/method/path/ts/hex(nonce)/hex64(bodyHash)） |
| `0x140450ab0/0xae9` | `"v1:"` 前缀 + hex64(finalize) |

`sign_v1` strip 无符号。**终版定性（10-14 深夜二）**：`0x450d99` 区是 sign_v1 自身尾块/冷路径（`jmp 0x450466` 回跳），非独立初始化入口；`0x450458` flag 检查 = OnceLock 内联展开，init 函数 `0x140566f83` = K 的双掩码 XOR（`.rdata 0xf08df3/0xf08e13`，还原值与实测 K 全等）；`0x4504a7 call 0x5669c6` 为 **hex_digit**（M 各段在内存中是 hex 文本形态，String{ptr,cap=0x60,len=0x30}）。D1 无编译期字节形态（.rdata 27MB + .text 14MB + 邻域 stride1 穷举全 MISS），详见 §3 定性段。

## 附录 B　证据文件与工具（tools/crypto/）

| 文件 | 内容与结论 |
|---|---|
| `disasm_sign.py → disasm_sign.log` | 静态反汇编 302 指令（附录 A 全部地址出处） |
| `capture_full.py → capture_v2.log` | 10-13 两轮全量抓取：M/OKM/canonical/sig，sig 对拍 `cd990df2…`/`cd8f20d4…` 全中 |
| `capture_compress.py → capture_compress.log` | compress+update 序列回放：D=`3165cb61…` 轮、OKM 公式二次命中 |
| `capture_hmac1.py → capture_hmac1.log` | ipad/opad 入口栈：证伪 "key=M"，抓到 D=`5eae9d51…` |
| `hook_cell_write.py` / `find_cell_writer.py` / `keysearch.log` | K cell 写入者分析（0 直接 store）、密钥字节全二进制搜索 NOT FOUND |
| `verify_key_seed.py → verify_key_seed.log` | 路径串=密钥假设证伪记录 |
| `analyze_capture.py` | capture_v2 逐轮对拍器（回归入口） |
| `indep/d_capture.py → d_capture.log` | 10-14 同场双抓（干净字节读法）：D/OKM/canonical 全向量 |
| `indep/match_d_preimage.py` | `D=HMAC(M,K)` 终验：三假设逐字节命中（§5 向量表） |
| `indep/sig_e2e2.py` | **端到端实签**：当轮 M 切片材料自签 llm-api = 200 真实补全；篡改/缺签分别 INVALID/MISSING |
| `indep/d1_hypo.py` | D1 本地字段穷举（748 字段×变换）——MISS，D1 非本地存储直接变换 |
| `indep/d1_trace_daemon.py` → d1_trace.log | extend 广网取证：M 四段拼装源指针+backtrace（D1=对象[+0x28]）；须 spawn 同进程 attach，daemon attach 零事件 |
| `verify_sign.py` | 历史错误假设（PRK=HMAC(M,K)）留档，勿再走 |

## 附录 C　版本漂移与重验方法

函数 RVA 随构建漂移（5.2.2 在 `0x140445xxx` 区，5.2.3 平移到 `0x140450xxx`）。不依赖本文地址的重验路线：`.pdata` 找含字符串 `"atomcode-signing-v1"` 的 LEA 所在函数 → 按 §6 钩子序列对号入座；K/D1 值用 `d_capture.py` 重抓比对（K 变了说明换代，D1 变了说明登录态迁移）。42MB 级 Rust 束勿走静默 headless 反编译器，定点窗口反汇编（capstone/`disasm_sign.py`）即可。

## 附录 D　历史判定摘要（防回潮）

- **5.2.2 纯静态解读版（desktop 旧文档）判误 5 处**：把 hmac/hkdf crate 的 `InvalidLength` **panic 文案**（`"HMAC can take a key of any size"` / `"HMAC accepts any key length"`，panic Location 结构 ptr 落 crate 源文件路径）当成 HKDF salt；消息分隔符、nonce/ts 编码、Alg 值、`v1:` 前缀均错；其文末 Rust 实现不能产出合法签名。教训：**字符串簇在位 ≠ 数据流存活**。
- **"D 依赖运行期状态（ASLR/句柄）"**：作废——D 是 `HMAC(M,K)` 的确定值，跨运行差异 = hours 小时桶。
- **"免费档不走签名 / 需付费档 + gate"**：作废（§7）。
- **05 历史存档（穷举 800 万+ 未命中、MITM 抓包线）**：文件已删；其 MITM 工具链价值并入本附录 B 备注。
