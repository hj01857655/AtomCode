# AtomCode 逆向 01：侦察与架构

> 日期：2026-09-30（**2026-10-09 修订**：签名关卡证伪，见 [03-data-plane.md](atomcode-03-数据面与UA门.md)）
> 目标：为 atomcode2api 网关建立完整的事实依据。
> 环境：atomcode 5.1.0（npm `@atomgit.com/atomcode` → `atomcode-win32-x64/bin/atomcode.exe`，PE32+ 37.7MB，Rust 编译）。
> 测试账号：CodingPlan **Lite-beta 体验版**（2026-10-09 领取，2026-10-16 到期，7 天）。
> 账号凭据一律脱敏引用（`<TOKEN>`），完整值在 `~/.atomcode/auth.toml`。

## 一句话结论

AtomCode 是**开源 MIT 的 Rust TUI CLI + 闭源签名 overlay**。把它的 CodingPlan 免费额度变成
OpenAI/Anthropic 兼容 API，管理面（模型/额度/领取）与数据面（聊天）协议已全部摸清。

**2026-10-09 修订后的结论：数据面不需要签名。** 官方客户端确实会带一套闭源签名
（`atomcode-codingplan-crypto`，开源源码树里只有 `unreachable!()` 占位），但网关是
**按 User-Agent 决定要不要这套签名**，而不是校验签名本身：请求声称 `atomcode/*`
才会被判缺失签名，换任何其它身份直接放行。因此只需「换到 `api-ai.gitcode.com`
+ 不发 `atomcode/*` UA」，即可拿到 200 真实 SSE 补全。

原「离线穷举 800 万+ 组合未命中、需 Ghidra/x64dbg 收尾」的路线**整段作废**
——不是没破，是不需要。签名算法规范见 [06-签名算法规范.md](atomcode-06-签名算法规范.md)。

## 安装与本地布局

| 项 | 值 |
|---|---|
| npm 壳 | `C:\Users\<u>\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode`（仅 `bin/atomcode.js` spawn 平台二进制） |
| 实体 | `...\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe` |
| 配置 | `~/.atomcode/config.toml`（provider/models/ui 等） |
| 凭据 | `~/.atomcode/auth.toml`（`access_token`/`refresh_token`/`expires_in`/`created_at` + `[user] id/username/...`） |
| 设备 | `~/.atomcode/device_id`（普通 UUID，**未**进入签名） |
| 公开仓库 | `gitcode.com/atomgit_atomcode/atomcode`（MIT，已克隆至 `tools/atomcode-src/`） |

关键源码坐标（公开部分）：

- `crates/atomcode-codingplan-crypto/src/lib.rs` —— **占位 stub**：
  `unreachable!("request signing requires the official build")`，注释说明真 crate 由
  官方构建 overlay 注入。即：**签名算法不在公开仓库里**。
- `crates/atomcode-auth/src/gateway_crypto.rs` —— 签名调用边界，`sign_v1` 的完整参数签名：

  ```rust
  sign_v1(method: &str, path: &str, body: &[u8], oauth_token: &str, user_id: &str,
          timestamp_unix: u64, nonce: &[u8; 16], client_version: &str)
      -> Vec<(&'static str, String)>   // 返回要附加的响应式头
  ```

- `crates/atomcode-capabilities/src/provider/atomgit_sign.rs` —— 实际调用点：
  `method="POST"`、`path=canonical_chat_completions_path(base_url)`（恒为 `/v1/chat/completions`）、
  `nonce=getrandom 16B`、`ts=unix 秒`。签名仅当 `is_codingplan_llm_gateway(base_url)`
  （host ∈ {llm-api.atomgit.com, pre-llm-api-cce.atomgit.com, api-ai.gitcode.com}，仅 HTTPS）时启用。
- `crates/atomcode-config/src/endpoints.rs` —— 全部服务端地址 + **env 覆盖**（见下文）。
- `crates/atomcode-capabilities/src/provider/openai_compat.rs:442-448` —— Windows 上
  `trust_os_roots` 分支被编译期跳过，注释明示：**Windows 走 native-tls(SChannel)，
  天然信任 Windows 系统证书存储** → MITM 可行。

## 三个服务面（全部 env 可覆盖，自托管友好）

| 面 | 默认地址 | env 覆盖 | 认证 |
|---|---|---|---|
| 平台认证 | `https://acs.atomgit.com` | `ATOMCODE_PLATFORM_SERVER` | OAuth 流 |
| CodingPlan 控制面 | `https://api.gitcode.com/api/v5` | `ATOMCODE_CODINGPLAN_API_BASE` | `Bearer <token>` |
| LLM 数据面 | `https://api-ai.gitcode.com/v1`（**免签名**，见 [03-data-plane.md](atomcode-03-数据面与UA门.md)） | `ATOMCODE_CODINGPLAN_LLM_BASE_URL` | `Bearer <token>` |
| ~~LLM 数据面~~ | ~~`https://llm-api.atomgit.com/v1`~~ **不可用**：三个 UA 全 403 | — | — |

公共请求头：`user-agent: atomcode/5.1.0`（客户端自带）。

> ⚠️ **这个 UA 本身就是陷阱**：数据面网关按它决定是否索要闭源签名。复现实验时照抄
> 官方 UA，等于自己把门关上——这正是签名历史里一度误判「签名必填」的原因。

详见：
- 控制面（模型/额度/领取）→ [02-control-plane.md](atomcode-02-控制面与额度.md)
- 数据面（聊天/UA 门）→ [03-data-plane.md](atomcode-03-数据面与UA门.md)
- 认证流（OAuth/刷新）→ [04-auth.md](atomcode-04-认证流.md)

## 服务端地址 env 覆盖（自托管/测试潜力）

`endpoints.rs` 提供全套 override：`ATOMCODE_PLATFORM_SERVER`、
`ATOMCODE_CODINGPLAN_API_BASE`、`ATOMCODE_CODINGPLAN_LLM_BASE_URL`、
`ATOMCODE_TRUSTED_HOSTS`、`ATOMCODE_CODINGPLAN_PROVIDER_PREFIX`、`ATOMCODE_APP_RELAY` 等。
`is_codingplan_llm_gateway` 按 host 判定是否启用签名：非白名单 host 走普通 API-key 通道。
→ **可用本地 mock 网关 + env 覆盖驱动官方二进制做签名行为对拍**（签名只认白名单 host，
mock 需改 hosts 文件，仅作备选）。

> ⚠️ 2026-10-09 修订后，这条「对拍」路线也不再必要——签名已不需要。

## 与 ZCode 项目的对照（架构借鉴点）

| 维度 | zcode2api（GLM Coding Plan） | atomcode2api（本规划） |
|---|---|---|
| 反代难点 | 阿里云 captcha 一次性参数（需 playwright 农场） | **无**——闭源签名可整条绕开（换主机 + 换 UA） |
| 上游协议 | Anthropic 原生 | OpenAI 原生（含 `reasoning_content`） |
| 额度模型 | token（billing/balance） | **5h 窗 N 次调用**（status-v2，Lite=200） |
| 账号来源 | BigModel/Z.AI OAuth 双渠道 | GitCode OAuth 单渠道（+ refresh 轮换） |
| 风控 | 3007/3012 行为分 | `audit_status` + 窗口配额（未见行为分） |

结论：atomcode2api **不需要 captcha 农场与风控冷却体系**，也不需要签名器，
复杂度显著低于 zcode2api；核心模块 = 账号池(token/RT) + 额度看板 + 双协议转换。
