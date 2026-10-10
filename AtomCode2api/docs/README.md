# AtomCode 逆向系列索引

目标：AtomCode（GitCode/AtomGit CodingPlan 套餐，官方 CLI 专属额度）→ 本地 OpenAI/Anthropic 双协议兼容 API
环境：atomcode 5.1.0（Rust TUI CLI），测试账号 CodingPlan Lite-体验版
工作区：`E:\VSCodeSpace\ZCode\AtomCode2api\docs\`（本文档）　`tools/`（MITM 工具 + 样本，git-ignored）

## 阅读顺序 / 索引

| 篇 | 文件 | 主题 | 一句话结论 |
|---|---|---|---|
| 00 | [binary-report](reverse-engineering-report.md) | 二进制分析（初始报告） | PE 结构、crate 划分、全部端点、环境变量清单、CLI 命令面、错误码 |
| 01 | [recon](atomcode-01-侦察与架构.md) | 侦察与架构 | Rust TUI + 闭源签名 overlay；三服务面全 env 可覆盖；复杂度显著低于 zcode2api |
| 02 | [control-plane](atomcode-02-控制面与额度.md) | 控制面与额度 | models-v2/usage/status-v2/claim-v2 全部 Bearer 直通；5h×200 次窗口；claim-v2 是必须步骤；含 /model 全览（CodingPlan 2 个 + OpenRouter 5 个） |
| 03 | [data-plane](atomcode-03-数据面与UA门.md) | 数据面与 UA 门 | **签名不需要**：api-ai.gitcode.com 按 UA 放行，换掉 atomcode/* 即 200 |
| 04 | [auth](atomcode-04-认证流.md) | 认证流 | OAuth + RT 轮换刷新（7 天 AT / 60 天 RT），刷新返回新 RT 旧值作废 |
| 05 | [signature-archive](atomcode-05-签名历史存档.md) | 签名历史（作废） | 穷举 800 万+ 未命中但已不需要；MITM 工具链保留做回归 |
| — | [codingplan-quota](codingplan-quota.md) | 额度机制详解 | 滑动窗口规则、响应结构体还原、字段速查、错误码、quota.sh 查询用法 |

## 网关设计

- [网关设计.md](网关设计.md) — 架构、流程、配置；**§12 实现状态**（已落地 Python/Flask：
  `server.py`+`auth.py`，含 /login OAuth、共用 auth.toml、OpenRouter 反代；初版 Node.js 规划以 §12 为准）

## 关键事实速查

- 数据面：`POST https://api-ai.gitcode.com/v1/chat/completions`，OpenAI 格式 + SSE
- 硬约束：**不得携带 `atomcode/*` 的 User-Agent**——那是签名门的开关
- 控制面：`https://api.gitcode.com/api/v5/coding-plan/*`，Bearer token，免签名
- 额度：5h 滚动窗 200 次调用（Lite-体验版），claim-v2 领取后激活，7 天有效期
- 刷新：`POST https://acs.atomgit.com/oauth/refresh`，RT 轮换
- 模型：CodingPlan 独占 qwen3.8-27b（262K）+ glm5.3-flash（512K）；用户可另配 OpenRouter 等第三方 provider（不走 CodingPlan 额度）
- 源码内置 18+ provider 预设（`provider_preset.rs`）：atomgit / opencode-zen / openrouter / deepseek / anthropic / openai / ollama / zhipu / moonshot 等
