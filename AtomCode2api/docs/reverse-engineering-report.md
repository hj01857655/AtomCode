# AtomCode CLI v5.1.0 逆向分析报告

> 分析对象：`D:\Downloads\Programs\atomcode-v5.1.0-windows-x64.exe`
> SHA-256：`9794ae6c4a04b98256c4ef616904ef36ae864f7494fb56f80ab36e20430d2195`
> 分析日期：2026-09-26（2026-10-09 修订：数据面端点与签名结论按实测更新，见 03 篇）
> 分析方式：静态字符串分析 + PE 结构解析 + 本地配置检查 + 实际 API 验证
> 本文侧重二进制层细节（PE/crate/env/CLI/错误码）；协议与额度实测见 01–04 篇。

---

## 1. 基本信息

| 属性 | 值 |
|---|---|
| 文件类型 | PE32+ executable (console) x86-64, MS Windows, 6 sections |
| 大小 | 37,750,928 bytes (~36 MB) |
| 版本 | atomcode 5.1.0 (72b538e) |
| 语言/栈 | **Rust** 原生编译（非 Go / 非 Electron / 非 Node 打包） |
| 异步运行时 | tokio |
| CLI 框架 | clap 4.6.0 |
| 日志 | tracing / tracing-subscriber 0.3.23 |
| 协议 | 实现 ACP（agent-client-protocol 2.0.0 / schema 1.5.0），JSON-RPC |

### PE 节布局

| 节 | 虚拟大小 | 原始大小 | 说明 |
|---|---|---|---|
| .text | 0xae8f10 | 0xae9000 | 代码，约 11 MB |
| .rdata | 0x18998b0 | 0x1899a00 | 只读数据，约 26 MB（含大量内嵌字符串/资源） |
| .data | 0x150f0 | 0xe600 | 可写数据 |
| .pdata | 0x414cc | 0x41600 | 异常展开表 |
| .rsrc | 0x15570 | 0x15600 | 资源 |
| .reloc | 0x15498 | 0x15600 | 重定位 |

## 2. 内部模块结构（crate workspace）

从 panic 路径字符串还原出的 crate 划分：

```
crates\
├── atomcode-cli          # 主 CLI 入口 (main.rs, schedule_cmd.rs, telemetry_cmd.rs, vision.rs)
├── atomcode-daemon       # HTTP daemon（IDE 集成），含 api_codingplan.rs
├── atomcode-codingplan   # CodingPlan 额度/登录逻辑 (setup.rs)
├── atomcode-auth         # OAuth 认证
├── atomcode-kernel       # 核心引擎
├── atomcode-telemetry    # 遥测
└── atomcode-capabilities # 能力声明（字符串出现 67 次，权限/工具能力体系）
```

## 3. 网络端点

| 端点 | 用途 |
|---|---|
| `https://llm-api.atomgit.com/v1` | 官方客户端默认 LLM 后端（**实测对任意 UA 均返回 403，网关不可用**，见 03 篇） |
| `https://api-ai.gitcode.com/v1` | **数据面可用端点**（OpenAI 格式 + SSE；不要求签名，但不能带 `atomcode/*` UA） |
| `https://api.gitcode.com/api/v5` | **CodingPlan 平台 API**（额度查询等，`ATOMCODE_CODINGPLAN_API_BASE` 可覆盖） |
| `https://acs.atomgit.com` | 平台服务器（`ATOMCODE_PLATFORM_SERVER`），实际仅 `/api/v1/events` 遥测可用 |
| `https://acs.atomgit.com/api/v1/events` | 遥测上报 |
| `https://api.atomgit.com/api/v5` | AtomGit 仓库 API |
| `https://api.gitcode.com/api/v5` | GitCode API（与 AtomGit 同源凭据体系） |
| `https://relay-atomcode.atomgit.com` | App relay（`ATOMCODE_APP_RELAY`） |
| `https://atomcode.atomgit.com/docs/` | 官方文档 |
| `https://atomgit.com/atomgit_atomcode/atomcode` | 源码/issue 仓库 |
| `https://raw.atomgit.com/atomgit_atomcode/atomcode/raw/main/latest.json` | 更新清单 |
| `https://api.deepseek.com/v1` | 可选自定义模型后端 |
| `https://openrouter.ai/api/v1` | 可选自定义模型后端 |
| `https://mcp.exa.ai/mcp` | 内置 MCP 搜索 |
| `https://html.duckduckgo.com/html/` | 网页搜索 provider |
| `https://github.com/login/oauth` | GitHub OAuth（MCP GitHub 集成） |
| `https://pgy.oray.com` | 蒲公英/Oray（内网穿透相关，出现一次，用途待查） |

## 4. CodingPlan 额度体系（核心发现）

### 4.1 机制概述

- 登录方式：AtomGit OAuth（`atomcode login` / `/login`），登录时自动 claim CodingPlan 并注册 provider
- 额度是**滑动时间窗口限流**，不是总量包
- 服务端计票，客户端仅查询展示

### 4.2 API 端点（已实测验证）

```
GET https://api.gitcode.com/api/v5/coding-plan/status-v2
Authorization: Bearer <access_token>
```

配套端点（同一 base）：
- `/coding-plan/claim-v2` — 领取套餐
- `/coding-plan/models-v2` — 可用模型列表
- `/coding-plan/usage` — 用量

> 注意：二进制内默认平台服务器是 `acs.atomgit.com`，直接请求 404；
> 真正生效的 base 来自环境变量默认值 `https://api.gitcode.com/api/v5`。

### 4.3 响应结构体（从二进制还原）

```rust
struct StatusResponse {
    codingplan_free: PlanInfo,
    current_usage: UsageInfo,
    rate_limit_windows: Vec<RateLimitWindow>,
    audit_status: i32,
    plan_type: String,
    expires_at: String,
    window_quota_exhausted: bool,
    window_quota_hint: Option<String>,
}

struct PlanInfo {
    plan_name: String,      // "CodingPlan Lite-体验版"
    plan_type: String,      // "Lite-beta"
    status: i32,
    claimed_at: String,     // 领取日期
    expires_at: String,     // 到期日期
    remaining_days: i32,
    total_days: i32,
    apply_id: i64,
}

struct UsageInfo {
    placeholder: bool,
    window_token_limit: i64,   // 本窗口调用上限
    window_tokens_used: i64,   // 本窗口已用（实际语义是调用次数）
    usage_percent: i32,
    window_hours: i32,
    reset_at: String,          // ISO 时间
    reset_at_display: String,  // "20:41"
    seconds_until_reset: i64,
    reset_label: String,
    usage_status_desc: String,
}

struct RateLimitWindow {
    rule_index: i32,
    show_enable: i32,
    window_size_seconds: i64,  // 18000 = 5 小时
    window_hours: i32,
    call_limit: i64,           // 200
    calls_used: i64,
    usage_percent: i32,
    quota_exhausted: bool,
    reset_at: String,
    seconds_until_reset: i64,
}
```

### 4.4 错误码/状态字符串

`insufficient_quota` / `billing_hard_limit_reached` / `payment_required` /
`insufficient_balance` / `quota_exhausted` / `rateLimited`（多种变体）/
`__cascade_upstream_fail` / HTTP 403 → "CodingPlan 未领取或已失效，请运行 /login 重新登录并领取"

## 5. 配置文件（`~/.atomcode/`，即 `%USERPROFILE%\.atomcode`）

| 文件/目录 | 内容 |
|---|---|
| `config.toml` | 主配置（provider、base_url 等） |
| `auth.toml` | OAuth 凭据（access_token / refresh_token / username 等） |
| `codingplan_sync.json` | CodingPlan 同步标记（仅 last_sync_unix_secs） |
| `device_id` | 设备标识 |
| `sessions/` | 会话状态 |
| `history-v2` | 命令历史 |
| `plugins/` | 技能/命令插件 |
| `logs/atomcode.log` | 运行日志 |
| `telemetry/queue/` | 遥测队列（ndjson） |
| `hooks/`、`.mcp.json` | 钩子与 MCP 配置 |

### 关键环境变量（完整清单）

```
ATOMCODE_HOME                    # 数据根目录
ATOMCODE_SEED_CONFIG             # 首次运行配置种子
ATOMCODE_API_KEY                 # 自定义 provider 的 key
ATOMCODE_CODINGPLAN_API_BASE     # CodingPlan API base（默认 https://api.gitcode.com/api/v5）
ATOMCODE_CODINGPLAN_LLM_BASE_URL # LLM base
ATOMCODE_CODINGPLAN_REPORT       # 用量上报
ATOMCODE_PLATFORM_SERVER         # 默认 https://acs.atomgit.com
ATOMCODE_APP_RELAY               # https://relay-atomcode.atomgit.com
ATOMCODE_ENABLE_RELAY
ATOMCODE_TELEMETRY / DO_NOT_TRACK / ATOMCODE_TELEMETRY_ENDPOINT  # 遥测开关
ATOMCODE_WIRE_DUMP               # 抓 API 通信
ATOMCODE_GOAL_MAX_ROUNDS / ATOMCODE_GOAL_MAX_DURATION_SECS       # 自主任务上限
ATOMCODE_STREAM_TIMEOUT_SECS / ATOMCODE_FIRST_TOKEN_TIMEOUT_SECS
ATOMCODE_MAX_PARALLEL_TOOLS
ATOMCODE_OLLAMA_NUM_CTX          # 本地 Ollama 支持
ATOMCODE_DANGEROUSLY_ALLOW_REMOTE_NO_AUTH
ATOMCODE_DAEMON_*                # daemon 相关（token、idle timeout、dangerous tools）
ATOMCODE_PLUGIN_*                # 插件市场（auto install / marketplaces / root）
ATOMCODE_UPDATE_MANIFEST_URL / ATOMCODE_UPDATE_DOWNLOAD_BASE / ATOMCODE_DESKTOP_DOWNLOAD_URL
ATOMCODE_TRUSTED_HOSTS / ATOMCODE_TLS_MAX / ATOMCODE_OFFLINE
ATOMCODE_MEMORY_* / ATOMCODE_PROJECT_MEMORY_DIR / ATOMCODE_LOCAL_MEMORY_DIR
ATOMCODE_AI_SESSION_NAMING
ATOMCODE_GITHUB_MCP_CLIENT_ID
ATOMCODE_WEB_SEARCH_PROVIDER
ATOMCODE_BRAND_NAME / ATOMCODE_OAUTH_PROVIDER_NAME
ATOMCODE_HOOK_*                  # 钩子事件上下文
ATOMCODE_CODE_REWIND / ATOMCODE_REWIND_VERSION
ATOMCODE_SUBAGENT
```

## 6. CLI 命令面（v5.1.0）

```
login / logout / status     # OAuth + CodingPlan 认证流
resume                      # 恢复会话（TUI 或 headless）
upgrade / rollback          # 自升级 / 回滚
mcp                         # 管理 .mcp.json
daemon                      # IDE 集成 HTTP 服务
webui                       # 本地浏览器界面
telemetry                   # 遥测控制
plugin                      # 技能/命令插件管理
uninstall / setup           # 安装卸载
hooks / schedule            # 钩子与定时任务
completion                  # shell 补全
```

Headless 模式：`-p "prompt"`（支持 `--output-format jsonl`、`--ephemeral`、`--no-tools`、`-y` 跳过权限确认）。

## 7. 实测额度数据（2026-09-26 查询）

```json
{
  "plan_name": "CodingPlan Lite-体验版",
  "plan_type": "Lite-beta",
  "claimed_at": "2026-09-26",
  "expires_at": "2026-10-03",
  "remaining_days": 7,
  "window_token_limit": 200,
  "window_tokens_used": 61,
  "usage_percent": 30,
  "window_hours": 5,
  "reset_at": "2026-09-26T20:41:42",
  "quota_exhausted": false
}
```

规则：**每 5 小时一个窗口，200 次调用，窗口结束自动回满**。

## 8. 快速查询命令

```bash
# 读取本地 token 并查询额度（bash / Git Bash）
tok=$(grep -m1 "^access_token" ~/.atomcode/auth.toml | sed 's/.*= *"//;s/"//')
curl -s -H "Authorization: Bearer $tok" \
  "https://api.gitcode.com/api/v5/coding-plan/status-v2"
```

或直接用 CLI 抓通信：

```bash
ATOMCODE_WIRE_DUMP=1 atomcode status
```

## 9. 其他观察

- 二进制内含中文 UI 字符串（GBK 显示为乱码，实际 UTF-8），面向中英双语用户
- 遥测默认开启，可 `ATOMCODE_TELEMETRY=0` 或 `DO_NOT_TRACK=1` 关闭，或 `--no-telemetry` 单次关闭
- 支持技能（skills）、命令（commands）、hooks、MCP 插件体系，官方插件市场在 atomgit 仓库 `atomcode-skills` / `atomcode-plugins-official`
- 会话支持命名、rewind（`ATOMCODE_CODE_REWIND`）、AI 自动命名
- 内含 `claude` 字样字符串与 ACP 协议实现，兼容 Claude Code 式工作流（`-p` headless 输出格式明确对标 Claude Code）
