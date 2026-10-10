# AtomCode 逆向 02：控制面与额度

> 日期：2026-09-30（**2026-10-10 实测再修订**）
> 依赖：[01-recon.md](atomcode-01-侦察与架构.md) 的服务面总览
> 控制面基址：`https://api.gitcode.com/api/v5`，仅需 `Bearer <token>`，免签名。

## 端点清单（本日全部实跑 200）

| 端点 | 说明 | 实测 |
|---|---|---|
| `GET /coding-plan/models-v2?plan_type={Max\|Pro\|Lite}` | 模型目录 | ✅ 返回 `[{display_model_name, base_url, context_window, supports_vision, type:"openai", reasoning_effort_levels, plan_available, is_atomcode_exclusive, ...}]` |
| `GET /coding-plan/usage?plan_type=X` | 60 天用量 | ✅ `days/start_date/end_date/models/rows[{date, model_counts, model_tokens, total_counts, total_tokens}]` |
| `GET /coding-plan/status-v2?plan_type=X` | 套餐+窗口额度 | ✅ 见下文额度模型 |
| `POST /coding-plan/claim-v2` body `{"plan_type":"Max"}` | 领取套餐（级联 Max→Pro→Lite，源码 `PlanType::CASCADE_ORDER`） | ✅ 2026-10-09 实测：三个 plan_type 均级联到 Lite-体验版，`{success:true, duplicate:false, plan_type:"Lite-beta"}` |

## status-v2 实测样例（2026-10-09，claim-v2 领取后）

```json
{
  "codingplan_free": {"plan_name": "CodingPlan Lite-体验版", "plan_type": "Lite-beta",
                      "status": 1, "claimed_at": "2026-10-09", "expires_at": "2026-10-16",
                      "remaining_days": 7, "total_days": 7, "apply_id": 56099},
  "current_usage": {"placeholder": false, "window_token_limit": 200, "window_tokens_used": 0,
                    "window_hours": 5, "reset_at": "2026-10-09T07:13:08",
                    "seconds_until_reset": 17912, "usage_percent": 0,
                    "usage_status_desc": "当前时间窗口用量约 0%"},
  "rate_limit_windows": [{"rule_index": 0, "call_limit": 200, "calls_used": 0,
                          "window_size_seconds": 18000, "window_hours": 5,
                          "quota_exhausted": false, "reset_at": "2026-10-09T07:13:08"}],
  "audit_status": 1, "plan_type": "Lite-beta", "expires_at": "2026-10-16",
  "window_quota_exhausted": false
}
```

领取前 `codingplan_free` 显示"CodingPlan Lite"（正式版, total_days:30, status:-1），
`current_usage.placeholder: true`，额度字段全 null；领取后切为"Lite-体验版"(7天)，窗口激活。
`status-v2` 的 `plan_type` 查询参数对结果无影响（始终返回同一 codingplan_free）。

## 额度模型关键

- **5 小时滚动窗 200 次**（Lite-体验版，`call_limit:200`）。
- `reset_at` 精确到秒，`seconds_until_reset` 可直接做看板倒计时。
- 领取前 `placeholder:true` + 全 null；领取后 `placeholder:false` + 窗口激活。
- **claim-v2 是必须步骤**——不领取则额度窗口永远为空（placeholder）。
  网关应在启动时 / 套餐到期后自动调 claim-v2，详见 [网关设计.md](网关设计.md) §3.3。

## 修订记录（2026-10-10）：窗口计数是控制面软提示，不是数据面硬闸

### 触发

2026-10-10 00:07 实查 `status-v2` 显示 `calls_used:200/200`、`window_quota_exhausted:true`、
「额度已满，将在 03:13 重置」；但同一时刻反代网关日志 00:04–00:07 十几发 `glm5.3-flash`
连续 200 成功。两次复查（相隔数分钟）`calls_used` 冻结在 200 不再增长。

### 直探数据面（00:10 左右）

绕过反代直接 `POST https://api-ai.gitcode.com/v1/chat/completions`（中性 UA）：
**HTTP 200 + 正常 SSE 流**，`reasoning_content` 正常吐字。窗口「已满」期间数据面照常放行。

### 结论（2026-10-10 00:15 补客户端侧证据后修正）

同日晚些时候官方客户端 UI 同步显示「5小时窗口已用尽，约 03:13 恢复（还有 3h2m） ·
已保留已完成内容 · 可换模型或稍后重试」——03:13 与 `status-v2` 的 `reset_at` 完全同源。
据此把上一版「数据面不拦」修正为**按路径分层校验**：

- **官方客户端路径**（`llm-api.atomgit.com` + 签名 + `atomcode/*` UA）：强校验套餐 + 窗口，
  窗口满即被拒，客户端才显示恢复倒计时。文案是限流场景提示，不是本地预检。`~/.atomcode`
  内无独立限流状态文件（sessions/ 只有 ui/rewind/todos），窗口状态完全来自控制面。
- **本反代路径**（`api-ai.gitcode.com` + 中性 UA、无签名）：实测窗口满时照常 200 + SSE，
  无任何 429/403。这条路绕开了校验链，不消耗也不被拦。
- `calls_used` 冻结在 200 不涨：反代路径的大量成功调用未计入（或异步批量同步），
  计数只反映官方路径的用量，勿拿它估反代消耗。
- **勿以 `status-v2` 判断反代可用性**——它只描述官方路径；反代的可用性以数据面实发为准。
- 同一时段反代日志中出现 2 个 502（msgs=2 的新会话请求，第 3 发成功）——
  为上游 LiteLLM 数据面瞬时 5xx，与窗口无关；重试即可。

## /model 可选模型全览（2026-10-09 从 ~/.atomcode/config.toml 提取）

AtomCode 的 `/model` 命令列出所有已配置 provider 的模型。除了 CodingPlan 独占的 2 个，
用户还可配 OpenRouter 等第三方 provider 的模型——这些走各自的 API key 和端点，
**不消耗 CodingPlan 额度**。

### CodingPlan 独占（AtomGit provider，免 API key，走 CodingPlan 额度）

| 选择 ID | 实际模型 | 上下文 | 视觉 | 推理级别 |
|---|---|---|---|---|
| AtomGit-qwen3.8-27b | qwen3.8-27b | 262K | ✅ | low / medium / xhigh |
| AtomGit-glm5.3-flash | glm5.3-flash | 512K | ✅ | low / high |

### OpenRouter 免费模型（openrouter provider，需 OPENROUTER_API_KEY，不走 CodingPlan 额度）

| 选择 ID | 实际模型 | 上下文 |
|---|---|---|
| openrouter/stealth/space-bunny-alpha | Space Bunny Alpha | 1M |
| openrouter/nvidia/nemotron-3-ultra-550b-a55b:free | NVIDIA Nemotron 3 Ultra | 1M |
| openrouter/nvidia/nemotron-3.5-lightning:free | NVIDIA Nemotron 3.5 Lightning | 1M |
| openrouter/thinkingmachines/inkling-small:free | Thinking Machines Inkling Small | 1M |
| openrouter/thinkingmachines/inkling:free | Thinking Machines Inkling | 1M |

> **网关反代 CodingPlan 的 2 个独占模型 + 上面 5 个 OpenRouter 免费模型**
> （`/v1/models` 聚合输出，`openrouter/` 前缀路由到 OpenRouter API，不消耗 CodingPlan 额度。
> 2026-10-09 注：~~与网关无关~~ → 10-10 实现时已反代，带官方同款 attribution 头）。
> 源码 `provider_preset.rs` 里还内置了 opencode（OpenCode Zen, `opencode.ai/zen/v1`）、
> deepseek、anthropic、openai 等 18+ 个 provider 预设，用户按需在 config.toml 里配。
