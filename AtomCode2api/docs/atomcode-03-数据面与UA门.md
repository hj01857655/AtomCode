# AtomCode 逆向 03：数据面与 UA 门

> 日期：2026-09-30（**2026-10-09 修订：签名关卡证伪**）
> 依赖：[01-recon.md](atomcode-01-侦察与架构.md) 的服务面总览

## 数据面（免签名，但需换主机 + 换 UA）

- **可用端点**：`POST https://api-ai.gitcode.com/v1/chat/completions` —— OpenAI 格式，SSE 流式。
  同门主机里的这一个对同一 Bearer **不要求签名**，前提是请求不自称官方客户端。
- **不可用端点**：`https://llm-api.atomgit.com/v1/chat/completions`（官方客户端默认值）——
  实测三个 UA（中性 / 无 / `atomcode/5.1.0`）**全部 403**，换 UA 救不了，别用。
- 原记录的「`GET /v1/models` 受 plan 门控 403 `model is not enabled for codingplan`」
  **是误判**：那是 UA 门造成的假象，同一模型换 UA 就返回 200。模型列表仍走控制面
  `models-v2`（它是权威目录），但不必因为那条「403」而回避数据面的裸请求。
- 响应为 LiteLLM 代理（`X-Litellm-*` 头），SSE chunk 里思考块走
  `choices[].delta.reasoning_content`（非 OpenAI 标准字段，OpenAI 客户端可忽略；
  Anthropic 侧需映射为 thinking block）。

## 修订记录（2026-10-09）：签名关卡不存在

### 触发

GitHub 上 `collegeming/cpa-jethub-plugins` 的 `plugins/atomcode/config.go` 与 README
（CLIProxyAPI 插件，其实测日 2026-10-01）记录了一条关键反常：同一个 token、同一请求体，
**只改 `User-Agent`** 就能决定 200 还是 403。

### 本地复测（2026-10-09，本机账号，`POST /v1/chat/completions`，`model=qwen3.8-27b`）

| 主机 | 中性 UA | 无 UA | `atomcode/5.1.0` |
|---|---|---|---|
| `api-ai.gitcode.com` | **200，真实 SSE** | **200，真实 SSE** | 403 |
| `llm-api.atomgit.com` | 403 | 403 | 403 |
| `pre-llm-api-cce.atomgit.com` | ERR（SSL EOF，连不上） | ERR | ERR |

结论：**必须同时换主机和换 UA，只换一个都不行。**

- 主机必须是 `https://api-ai.gitcode.com/v1`——同门主机，官方客户端自己在
  `crates/atomcode-auth/src/gateway_crypto.rs:140-142` 里把它列为 first-party。
- 在该主机上**绝不能发 `atomcode/*`**。

### 403 的两种错误体（别被误导）

- `api-ai.gitcode.com` + `atomcode/*` → `403 {"error":{"message":"user has no codingplan",...}}`
- `llm-api.atomgit.com` + 任意 UA → 同样的 `user has no codingplan`
- 外部记录（2026-10-01）在 `api-ai.gitcode.com` + `atomcode/*` 上见到的是 `ATOMCODE_SIG_MISSING`

错误体随版本/账号状态变化，但**行为一致**：都是 UA 门。

⚠️ **这两种 403 都不是真的权限判定**——同一 token、同一模型，换个 UA 就 200 正常推理。

### 对实施的影响

- **原 Phase 0（签名逆向）整段作废**，实施从原 Phase 1 起算。
- 不再需要 signer 模块、mock signer、`X-AtomCode-*` 五个头、alg 版本可插拔设计。
- 仍成立的部分：控制面免签名、额度模型（5h 窗 N 次调用）、**RT 轮换**（见
  [04-auth.md](atomcode-04-认证流.md)；实测当天依然准确：`/oauth/refresh` 返回新 AT + 新 RT，旧 RT 作废）。
- 新增注意：`user_id` 不再是签名输入，仅作账号标识。

### 复核用命令

```bash
# 换 UA 前后各打一发，对比 200 / 403
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer <TOKEN>" -H 'Content-Type: application/json' \
  -H 'User-Agent: atomcode2api/0.1.0' \
  -d '{"model":"qwen3.8-27b","stream":true,"messages":[{"role":"user","content":"hi"}]}' \
  https://api-ai.gitcode.com/v1/chat/completions

# 把 UA 换成 atomcode/5.1.0 再打一次，应得 403
```
