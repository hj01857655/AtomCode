# CodingPlan 额度机制详解

> 来源：逆向 atomcode-v5.1.0-windows-x64.exe + 实际 API 调用验证
> 验证日期：2026-09-26（最新实测样例见 [02 篇](atomcode-02-控制面与额度.md)；
> claim-v2 领取流程与模型目录也见 02 篇）

## 1. 额度模型

AtomCode 官方模型调用采用 **CodingPlan** 订阅制，核心规则：

- **滑动时间窗口限流**，不是总量包
- 默认窗口：**5 小时**（`window_size_seconds: 18000`）
- 默认窗口上限：**200 次调用**（`call_limit: 200`）
- 窗口结束**自动回满**，无需任何操作
- 当前使用套餐：**CodingPlan Lite-体验版**（`Lite-beta`），7 天有效期

### 关键点

"额度用完"永远只意味着"当前窗口用完"，等到 `reset_at` 时间点即恢复。
每次模型调用（一轮对话 = 1 次或多次 API call）计入窗口计数。

## 2. 查询 API

### 端点

```
GET https://api.gitcode.com/api/v5/coding-plan/status-v2
Authorization: Bearer <access_token>
```

- `access_token` 存于本地 `~/.atomcode/auth.toml`（Windows: `C:\Users\<用户名>\.atomcode\auth.toml`）
- 该 base 地址来自二进制内默认值 `ATOMCODE_CODINGPLAN_API_BASE`，**不是**默认平台服务器 `acs.atomgit.com`（直接请求 acs 会 404）

### 配套端点（同一 base）

| 端点 | 方法 | 用途 |
|---|---|---|
| `/coding-plan/status-v2` | GET | 套餐状态 + 窗口用量（最全） |
| `/coding-plan/usage` | GET | 仅用量 |
| `/coding-plan/models-v2` | GET | 可用模型列表 |
| `/coding-plan/claim-v2` | POST | 领取/激活套餐 |

## 3. 响应结构（从二进制还原的 Rust struct）

```json
{
  "codingplan_free": {
    "plan_name": "CodingPlan Lite-体验版",
    "plan_type": "Lite-beta",
    "status": 1,
    "claimed_at": "2026-09-26",
    "expires_at": "2026-10-03",
    "remaining_days": 7,
    "total_days": 7,
    "apply_id": 50839
  },
  "current_usage": {
    "placeholder": false,
    "window_token_limit": 200,
    "window_tokens_used": 61,
    "usage_percent": 30,
    "window_hours": 5,
    "reset_at": "2026-09-26T20:41:42",
    "reset_at_display": "20:41",
    "seconds_until_reset": 17406,
    "reset_label": "当前窗口结束即重置额度（每 5 小时一个窗口）",
    "usage_status_desc": "当前时间窗口用量约 30%"
  },
  "rate_limit_windows": [
    {
      "rule_index": 0,
      "show_enable": 1,
      "window_size_seconds": 18000,
      "window_hours": 5,
      "call_limit": 200,
      "calls_used": 61,
      "usage_percent": 30,
      "quota_exhausted": false,
      "reset_at": "2026-09-26T20:41:42",
      "reset_at_display": "20:41",
      "seconds_until_reset": 17406,
      "reset_label": "当前窗口结束即重置额度（每 5 小时一个窗口）",
      "usage_status_desc": "当前时间窗口用量约 30%"
    }
  ],
  "audit_status": 1,
  "plan_type": "Lite-beta",
  "expires_at": "2026-10-03",
  "window_quota_exhausted": false,
  "window_quota_hint": null
}
```

字段速查：

| 字段 | 含义 |
|---|---|
| `window_token_limit` | 窗口调用上限（名字带 token，语义是调用次数） |
| `window_tokens_used` / `calls_used` | 本窗口已用次数 |
| `usage_percent` | 使用百分比 |
| `reset_at` / `seconds_until_reset` | 窗口重置时间点 / 剩余秒数 |
| `window_quota_exhausted` | 是否已耗尽 |
| `quota_hint` | 服务端附带的提示信息（可为 null） |

## 4. CLI 内部实现位置

- crate：`atomcode-codingplan`（setup.rs）、`atomcode-daemon`（api_codingplan.rs）
- 登录流：`atomcode login` = OAuth → claim → 拉取 models → 注册 provider → 拉取 status，每步有进度输出
- 登录后自动同步（auto-sync）：更新 `~/.atomcode/codingplan_sync.json` 的时间戳，合并本地 config
- 403 处理：提示 "CodingPlan 未领取或已失效，请运行 /login 重新登录并领取"
- 上游级联失败错误码：`__cascade_upstream_fail`

## 5. 额度相关错误码

服务端/客户端会识别并展示：

```
insufficient_quota
billing_hard_limit_reached
payment_required
insufficient_balance
quota_exhausted
rateLimited / rate_limited / RateLimitedServer
```

## 6. 与 Claude Code 的对标

二进制字符串显示 `-p` headless 输出格式明确标注 "Claude Code -p style"；
内含 `agent-client-protocol`（ACP）实现，兼容 Claude Code 系工具协议。
额度体验上也对标 Claude Code 的 5 小时窗口模式。

## 7. 快速查询

方法一：官方 CLI 抓通信

```bash
ATOMCODE_WIRE_DUMP=1 atomcode status
```

方法二：直接调 API（auth.toml 中取 access_token）

```bash
curl -s -H "Authorization: Bearer <access_token>" \
  "https://api.gitcode.com/api/v5/coding-plan/status-v2"
```

方法三：仓库内脚本 `quota.sh`（Windows Git Bash 下注意 `$HOME` 可能指向
MSYS 主目录而非 Windows 用户目录，可用 `ATOMCODE_AUTH_FILE` 环境变量显式指定
auth.toml 路径）：

```bash
ATOMCODE_AUTH_FILE="/c/Users/<用户名>/.atomcode/auth.toml" bash quota.sh
ATOMCODE_AUTH_FILE="..." bash quota.sh --json   # 原始 JSON
```
