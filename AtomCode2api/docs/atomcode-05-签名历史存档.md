# AtomCode 逆向 05：签名历史（作废存档）

> 日期：2026-09-30　**状态：2026-10-09 起整段作废，仅存档**
> 保留理由：将来若上游收紧 UA 门（改为真校验签名），这里有完整的历史记录可参考。
> 证伪记录见 [03-data-plane.md](atomcode-03-数据面与UA门.md)。

## 签名格式（历史记录，勿据此实施）

### 实测捕获的完整签名头（MITM 抓包）

```
POST /v1/chat/completions HTTP/1.1
host: llm-api.atomgit.com
authorization: Bearer <TOKEN>
content-type: application/json
user-agent: atomcode/5.1.0
x-atomcode-sig:  v1:e829a4d577ae0909f6b14857ce81073e467de6acb1777102d6a410ef76ce0c79
x-atomcode-ts:   1790785283            # unix 秒（字符串）
x-atomcode-nonce:9062db3f5016941bf8034f1ff6a97fa8   # 16 随机字节 hex
x-atomcode-alg:  1                     # 算法版本号（字符串 "1"）
x-atomcode-ver:  5.1.0                 # 客户端版本
```

行为矩阵（本日实测）：

| 场景 | 结果 |
|---|---|
| 完全不带签名头 | `400 {"detail":{"code":"ATOMCODE_SIG_MISSING","message":"请升级到最新版 AtomCode 后再试。"}}` |
| 头名对但值空/缺 `X-AtomCode-Ts` | 同上（校验顺序最前：完整性） |
| 带随机值（缺算法正确性） | 同上（无法区分"错算法"与"缺失"，服务端只报 MISSING） |

→ 服务端错误面不泄露校验细节，**离线对拍是唯一验证通道**（抓真样本 → 本地复算 → 比对 64hex）。

> ⚠️ **2026-10-09 修订：上面这张表漏掉了一个变量——UA**。三次「缺失」实验全都带着
> 官方 `user-agent: atomcode/5.1.0` 发出，于是三次都撞在 UA 门上。换成任意非
> `atomcode/*` 的 UA，**一个签名头都不带也能拿到 200**。

### 已确定的算法要素

- 摘要算法族：**HMAC-SHA256**（binary 中 `hmac-0.12.1` + `ring-0.17.14`，
  字符串 `"HMAC accepts any key length"` / `"HMAC can take a key of any size"` 均出自
  `atomcode-codingplan-crypto/src/versions/v1.rs` 编译残留）；输出 64hex 符合 32 字节。
- 签名输入必然覆盖 **body**（同 prompt 不同 body → 不同 sig；ts/nonce 每请求变化）。
- 消息中大概率字段：`method|POST`、`path|/v1/chat/completions`、`ts`、`nonce(hex)`、
  `sha256(body) 的 hex`（或 raw body）、`user_id`、`client_version`。
- `"atomcode-signing-v1"` 字符串紧邻签名头常量出现，**最可能是 HKDF 的 info 参数**
  （binary 同区有 `hkdf-0.12.4` 的编译残留）。
- 签名头名常量表（.rdata 连续区）：`X-AtomCode-Sig X-AtomCode-Ts X-AtomCode-Nonce
  X-AtomCode-Alg X-AtomCode-Ver`，紧跟 HKDF 库符号 → key 很可能 `hkdf(ikm=token/uid?, info="atomcode-signing-v1")`。

### 已穷举未命中（避免重复劳动）

| 轮次 | 覆盖 | 组合数 | 结果 |
|---|---|---|---|
| crack_sig.py | token/uid 派生静态 key × 消息模板（含 HKDF 8 组参数、raw body 变体） | ~14k×4 样本 | ✗ |
| crack_sig2.py | AWS-SigV4 规范化请求、raw nonce、36 key × 80 消息 | 2.9k | ✗ |
| crack_sig3.py | 逐请求派生 key（salt=ts/nonce，info=sigv1 等）× 74 消息 | 101 key×74 msg/样本 | ✗ |
| crack_final.py | 87 静态 + 101 逐请求 key × 74 消息 × 4 算法(hmac256/512、sha256 k‖m、m‖k) | ~44k/样本 | ✗ |
| scan_secret.py | .rdata+.data 228k 高熵 32B 窗口 × 20 消息 | ~8M | ✗ |
| 字符串密钥 | binary 全量 20k 可打印串 × 20 消息 | ~800k | ✗ |
| utf16/短口令 | 常见产品名/版本串（含 utf-16le 变体） | 880 | ✗ |

**推论**：密钥是**编译进 overlay 的静态 secret 字节串**（熵扫描阈值 3.4 可能漏掉低熵
口令式密钥，或密钥在 XOR/编码后存储、运行时重建）。下一步只能靠下文的静态/动态断点。

### 样本资产（本目录保留）

- `tools/mitm/save_flows.py` —— mitmproxy 落盘脚本（按 `llm_<时间>_POST__v1_chat_completions.json`
  保存 method/url/headers/body/resp）。
- 4 组真实 chat/completions 样本（headers + 完整 body），已用于上述对拍。
- MITM CA 已装入**当前用户**受信任根证书存储（`mitmproxy` 证书；如需卸载：
  `certutil -delstore -user Root <指纹>`）。

## MITM 通道（签名逆向与后续维护的核心工具链）

1. `pip install mitmproxy` → CA 生成于 `~/.mitmproxy/mitmproxy-ca-cert.cer`。
2. `certutil -addstore -user Root mitmproxy-ca-cert.cer`（装当前用户根存储即可——
   Windows 下 atomcode 走 SChannel，信任系统/用户存储，源码 openai_compat.rs:442 证实）。
3. `mitmdump -s save_flows.py -p 8888`。
4. `HTTPS_PROXY=http://127.0.0.1:8888 HTTP_PROXY=http://127.0.0.1:8888 atomcode -p "..." --no-tools --ephemeral`。
5. 流量即被解密落盘，**含完整签名头**（上文即由此捕获，HTTP 200 全链路验证通过）。

注意：`rustls-native-certs` 虽在依赖树，但 Windows 构建实际走 native-tls/SChannel；
若未来官方切到 rustls 后端，需确认是否 `install_native_certs`（未启用时 MITM 失效，
需改用 `SSL_CERT_FILE` 注入——openai_compat.rs:507 证实该 env 生效）。

## 签名收尾方案（作废，仅存档）

1. **Ghidra/radare2 静态**（首选，一次装工具即可）：
   - 定位 `crates\atomcode-codingplan-crypto\src\versions\v1.rs` 编译残留字符串
     （.rdata VA≈0x40b55xxx 区）→ 反查引用函数（Rust 常量经 `mov r64, imm32`/LEA 双形式，
     已验证普通 RIP 扫描不可靠，用 `refs` 全量 + 立即数双通道，或 Ghidra 的 cross-reference）。
   - 沿 `sign_v1` 的 8 参数签名定位入口：8 个参数中 `nonce:[u8;16]` 是独特的
     16 字节栈参数，调用点特征明显。
   - 数据流追踪到 `hmac::HmacSha256::new_from_slice(key)` 的 key 来源
     （`const [u8;N]` 立即数加载或 .rdata 指针）→ 直接读出 secret。
   - 同时确认消息拼装顺序（string join 的常量串会成对出现）。
2. **动态断点**（静态受阻时）：x64dbg 在 `hmac` crate 的 `Hmac::new_from_slice`
   （或 ring `hmac::Key::new`）下断，跑一次 `atomcode -p` ，读 key 寄存器/栈值 +
   消息 buffer 内容，一次拿全。
3. **对拍验证**：本地复算 sig 与样本 64hex 全等即成功；随后走一次真实
   `curl` 全链路（200 + SSE）确认。

> ⚠️ 2026-10-09 修订：本节整体作废，**不要**照此实现 signer 或 alg 分发。
> 唯一保留的是 MITM 工具链本身——将来若上游真的收紧 UA 门，用它重新取证。
