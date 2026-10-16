# atomcode resume/fork 快照机制审计

审计日期：2026-10-16
审计对象：`@atomgit.com/atomcode` 5.2.3 (d8918f0)，原生实现
`AppData/Roaming/npm/node_modules/@atomgit.com/atomcode/node_modules/@atomgit.com/atomcode-win32-x64/bin/atomcode.exe`（43,809,424 B）
运行时数据：`C:\Users\12925\.atomcode\`

**性质**：只读审计。未修改任何配置、会话文件或二进制。所有数值来自实测统计，字符串证据来自二进制内可打印片段与 atomcode 自身 CHANGELOG 文本。

---

## 1. 结论

| 编号 | 结论 | 置信 |
|---|---|---|
| A-1 | resume 的实现是**事件日志全量重放**，不是原地续用 | 已证实 |
| A-2 | resume 一个**仍在运行（busy）的会话**会 fork 出新会话并携带快照；空闲会话的 resume 不 fork。**属设计如此**——单写者租约使 busy 日志不可原地续写（§4.1） | 已证实 |
| A-3 | 孤儿副本（fork 后不回收、一次对话散成多份会话行）是**缺陷**，由官方在 **v5.0.3 修复 #1212**；本机 5.2.3 实测无该碎裂形态 | 已证实（缺陷已修 + 本地反证） |
| A-4 | atomcode **没有 tool search / 工具 schema 惰性加载**，且在其所用协议上无法存在 | 已证实（双重原因，见 §3） |
| A-5 | 压缩频率的分母是各 model 声明的 `context_window`，跨 131K～1M，两个数量级 | 已证实 |
| A-6 | resume 重放会把"摘要 + 原始请求"同时载入，放大上下文 | 部分证实（官方 changelog 自述，本地未复现计数） |

`truncate_resumed_history` 与 `recap` 在本机 `[ui]` 段**已被显式设为 `true`**，所以 A-6 那条缓解措施已经处于开启状态。这一点是本审计对早期一轮口头推断的更正（见 §7）。

---

## 2. resume = 重放（A-1）

二进制中的自述文本，逐条互证：

```
a resume replays this file
0 (the session store; a resume replays this file)
minted when absent, and `resume = true` continues that session by replaying the events
`-c / resume only scans the current session's directory at startup.`
acp: resume replay: invalid session id
```

存储形态印证了"重放"这个说法：会话是 append-only 事件日志，不是最终状态快照。

```
~/.atomcode/sessions/<cwd-hash>/<session-uuid>.events     JSONL：第 1 行 header，其后每行一条事件
每行结构：{"seq":N, "at":<ms>, "event":{"kind","origin","text","turn"}}
配套文件：同 id 的 .index / .lease / .meta.lock
```

`b994f1c18a6c018e` 目录下 597 个条目 = 149 × (`.events` + `.index` + `.lease`) + 150 × `.lock`，即 149 份会话。

---

## 3. fork 的触发条件与落盘形态（A-2）

### 3.1 只有 busy 才 fork

CHANGELOG 条目原文：

```
Fixes: an interactive /resume of a busy session now forks it; replies cut off by the length limit happen...
```

前端侧配套证据：

```
e.ok && e.forkedFrom && e.sessionId → In.current = h(`sync.sessionForked`)
?{sessionId:n.session_id}:{}, ...n.forked_from ? {forkedFrom:n.forked_from} : {}
```

即 fork 后 UI 直接把活动会话切到新 id，旧文件留在原地不再续写。

### 3.2 快照字段就在元数据结构里

```
struct SessionMeta / struct ForkInfo / struct ImportInfo / struct InflightSnapshot
... import_info fork_info detached_model_usage detached_unattributed_tokens format_version InflightSnapshot ...
```

`.events` 第 1 行 header 的实际键集（全量 319 份统计）：

| header 键组合 | 份数 | 含义 |
|---|---|---|
| `context, created_at, cwd, id, inherited, version` | 308 | 普通会话 |
| `created_at, id, inherited, parent, version` | 7 | `sub-` 子代理会话 |
| `context, created_at, cwd, id, inherited, parent, version` | 2 | **带父引用的 fork** |
| `created_at, id, inherited, member, parent, version` | 1 | 团队会话成员 |

`parent` 出现率：**10 / 319（3.1%）**。
`inherited` 取值分布：**318 份为 0，1 份为 101**。

那个唯一的非零样本：

```
sessions\361b3f48c74a19d1\f3801c39-d7cf-4059-8c79-5503dcbd82e2.events
inherited = 101 | parent = 34f4fb56-7e30-4c26-a… | len(context) = 94
```

`inherited=101` 形如"继承 101 条事件"，与"截快照后 fork"的语义精确对应。全库只 1 例，说明该路径**不是每次 resume 都走**。

### 3.3 历史前缀重叠检测

取每份 `.events` 前 8 条文本事件做 SHA-1 前缀哈希，同一 cwd 内分组比对：

| cwd 哈希 | 非子代理会话数 | 共享前缀的分组 |
|---|---|---|
| `b994f1c18a6c018e` | 4 | 0 |
| `00e9b9a4fd978fae` | 9 | 0 |
| `3f66e5afbde283be` | 55 | **1**：`02f5398b-f` ↔ `9dc4d4ed-3` |

312 份里实测出 1 组真实的历史复制。**"每次 resume 都 fork"在本地数据里不成立**，成立的是"特定条件下会 fork 且副本不回收"。

### 3.4 一个必须澄清的误读

`header.context` 字段名容易读成"历史快照"，实测不是。最大那份（38,148 字符）的开头：

```
You are AtomCode, an AI coding agent by AtomGit running the glm5.3-flash model.
When asked who or what model you are, identify yourself as AtomCode running glm5.3-flash...
```

它是**会话创建时固化的系统提示**（310/319 份非空，长度 min 88 / median 792 / max 38,153）。历史继承走 `inherited` + `parent`，不在这个字段里。

固化系统提示本身是一份合理设计（保证同一会话内品牌/模型自称不漂移），但副作用是：**换 model 后 fork 出的副本仍携带旧 model 的自称文本**，除非有 `detached_*` 那类字段介入修正。

---

## 4. fork 的设计前提，与已被修复的孤儿副本缺陷（A-2/A-3）

### 4.1 fork 是单写者租约逼出来的，属设计如此

会话是 append-only 事件日志，且每份会话配一个 `.lease`（`b994f1c18a6c018e` 目录 150 个 `.lease` 对 149 个 `.events`）。相关串：

```
SESSION_BUSY  This session has an active turn. Stop it, then try again.
an active session lease
prepared session lease is for
Into the session store, under the lease of the session the runtime opened:
current session was released but its live projection is still pending
```

即**同一份日志不允许多写者**。因此恢复 busy 会话时不原地续写、而是 fork 新日志——CHANGELOG 里

```
Fixes: an interactive /resume of a busy session now forks it
```

是**为此写的修复**，不是引入的问题。同族设计还有 `This release introduces a new local web UI that shares the same live session with the terminal`：Web UI 与终端共享同一 live session，租约是这套共享的前提。

### 4.2 孤儿副本是缺陷，且已在 v5.0.3 修复

CHANGELOG 原文条目：

```
#1212 BUG: v5.0.2 fork_native_session leaves orphaned fork copies
         shattering one conversation into many session rows
```

**版本归属（已核实）**：该条位于 `## v5.0.3 (2026-07-30)` 的 `### Issues` 小节，与同批

```
#1204  atomcode 5.0.2 /cost
#1210  BUG: v5.0.2 crash-orphaned .lease / .meta.lock 0-byte files block SessionManager::delete
#1211  BUG: v5.0.2 legacy .json + native .ui.json dual-form coexistence causes session click to jump to a new session
#1212  BUG: v5.0.2 fork_native_session leaves orphaned fork copies …
```

并列，四条均标注 `v5.0.2` → **在 5.0.3 修复**。本机为 5.2.3，属修复后的版本。

这与 §3.3 的实测一致：319 份会话中带 `parent` 仅 10 份、`inherited>0` 仅 1 份、历史前缀重叠仅 1 组——**未见 #1212 所述碎裂形态**。

`#1211`（"点击会话跳到新会话"）与"每次 resume 都像 fork"这一主观观感字面最接近，同为已修项。

因此同一目录累积的 149 份会话应归因于**设计上的永久保留（无 GC）**，而非缺陷泄漏。

本地体量印证碎裂程度（按 cwd 聚合的会话数）：

```
149 | E:\VSCodeSpace\Agent\AtomCode\atomcode-desktop
 57 | E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep
 44 | E:\VSCodeSpace\Agent\AtomCode
 25 | C:\Users\12925\.atomcode\desktop
```

单个项目目录 149 份会话文件，与 §3.3 里 `3f66e5af` 目录 55 份同量级。

磁盘侧观察（只测体量，未判定归属）：

| 目录 | 文件数 | 字节 |
|---|---|---|
| `wire-dump` | 5,596 | 2,772,035,467 |
| `datalog` | 2,382 | 590,994,751 |
| `sessions` | 1,550 | 81,717,048 |
| `sessions-backup-20261012` | 70 | 267,049,228 |
| `rewind` | 9,246 | 14,242,932 |
| `history-v2` | 12 | 227,957 |

`wire-dump` 一项就占 2.77 GB——它是发给模型的完整请求体落盘（见 §5）。

`sessions-backup-20261012` 内 14 个 `.events` 与会存续活的 319 个 **session id 零重叠**，说明该备份不是 fork 副本的归档，是另一批会话。

**未证实**：fork 副本是否有任何自动回收路径。二进制里未找到 GC/清理相关字符串，但也未做穷尽搜索，故不下断言。

---

## 5. atomcode 没有 tool search（A-4）——双重原因

### 5.1 代码层：实现不存在

对该 exe（43,809,424 B）逐关键词扫描可打印字符串：

| 关键词 | 命中 |
|---|---|
| `defer_loading` / `deferLoading` | **0** |
| `tool_search` / `toolSearch` / `ToolSearch` | **0** |
| `tool_reference` / `toolReference` | **0** |
| `ENABLE_TOOL_SEARCH` | **0** |
| `search_tools` / `lazyTool` / `dynamicTool` / `tool_filter` / `toolFilter` | **0** |

`deferred` 有 5 个唯一串，逐条查验均为无关 Rust 文本（`linq deferred-execution`、`background session projection deferred`、`flushdeferred`、测试断言 `deferred_dirs should be non-empty`），无一指向工具加载。

对照：`mcpServers` 有 10 处命中，其中一条明说

```
write `~/.atomcode/mcp.json` instead of `<dir>/.mcp.json`
```

即 **MCP 支持，工具全量常驻**。注意本机 `~/.atomcode/mcp.json` 目前**不存在**（`mcp.json` / `mcp.toml` 均 absent；`config.toml` 内 `mcp` 字样仅 1 处），所以 atomcode 侧此刻并未挂载任何 MCP server。

### 5.2 协议层：这些字段在该协议上不存在

5,539 份请求体 dump 全量解析（0 失败）：

```
顶层键：model, messages, stream, stream_options, max_tokens, tools,
        reasoning_effort(1480), temperature(321), tool_choice(315)
tools[].type        ：恒为 "function"
betas               ：0 份出现
defer_loading       ：0 次
```

`type: "function"` + 工具名嵌套在 `function.name` + `stream_options` + `tool_choice: none` —— 这是 **OpenAI Chat Completions 风格**。`config.toml` 亦印证：10 个账号的 `provider` 为 `openai`×9 + `openrouter`×1 + `responses`×1（`opencode2api-responses`）。

而 `defer_loading` / `tool_search_tool_regex_20251119` / `tool_reference` 全部是 Anthropic Messages API 的参数与内容块类型。**atomcode 不是"没做"，是在它所用的协议上没有这个位置**；要做只能像 Claude Code 那样在 harness 侧自行过滤后再发请求，而那层它确实没写。

### 5.3 工具面本身不是变量

按 model 聚合每请求的 `tools` schema 体积：

| model | 请求数 | 最大请求体 (B) | tools schema (B) | 最大工具数 |
|---|---|---|---|---|
| `space-bunny-free` | 1,570 | 473,689 | 52,187 | 40 |
| `glm5.3-flash` | 1,344 | 2,034,433 | 52,219 | 40 |
| `cline-free/step-5-preview` | 803 | 383,598 | 52,187 | 40 |
| `qwen3.8-27b` | 459 | 875,821 | 50,180 | 40 |
| `GLM-5.2` | 452 | 387,039 | 52,187 | 40 |
| `glm-5.3-flash` | 351 | 2,039,765 | 52,219 | 40 |
| `hy3` | 215 | 612,168 | 41,167 | 36 |
| `hy4-preview` | 191 | 1,385,117 | 52,219 | 40 |
| `deepseek-v4.1-flash` | 165 | 2,049,822 | 52,187 | 40 |

11 个 model 的 schema 体积几乎恒定（50,180～52,219 B，约 1.4 万 token），工具数恒为 40（`hy3` 为 36）。**"换 provider 后频繁压缩"与工具面无关。**

参考阈值：tool search 在 schema 超过约 10K token 时才开始划算，atomcode 这 52 KB（≈1.4 万 token）已越过——若它将来支持惰性加载本可受益，但受 §5.2 协议限制。

---

## 6. 频繁压缩的真实分母（A-5、A-6）

### 6.1 context_window 跨两个数量级

`config.toml` 中 31 个 model 各自声明，实测分布：

```
131072   ← space-bunny / nemotron-3.5 / nemotron-3-ultra / step-5(-free) / muse-spark-1.2/1.3(-contributor)
           ling-3.0/3.1-flash / mimo-v2.6-flash(-free) / jev-1.13 / big-pickle / cline2api-step-5-preview
180000   ← qoder2api-Qwen3.8-Flash
192000   ← workbuddy2api-hy3
202752   ← codearts2api-GLM-5.2 / codearts2api-glm-5.2-sft-harmony
262144   ← AtomGit-qwen3.8-27b
512000   ← atomcode2api-glm5.3-flash / AtomGit-glm5.3-flash
960000   ← workbuddy2api-hy4-preview
1000000  ← workbuddy2api-glm-5.3-flash / bjskcz-glm-5.3-flash / codearts2api-deepseek-v4.1-flash
           workbuddy2api-deepseek-v4.1-flash / codearts2api-deepseek-v4-pro-0813
1048576  ← codearts2api-deepseek-v4-flash-0731 / codearts2api-glm-5.3-flash
```

`default_provider = AtomGit-qwen3.8-27b`（262144）、`default_model = codearts2api-GLM-5.2`（202752）。

**压缩阈值没有可配项**：`auto_compact` 这个键名在二进制中 **0 命中**，`config.toml` 中 `compact|summar|prune|trim` 合计仅 1 处。阈值由 `\compaction.rs` 按各 model 的 `context_window` 计算。因此可调的只有那个声明值。

从 512K/1M 的目录把会话恢复到 131K 的 model 上，重放历史立刻贴顶 → 触发 `(compacting with LLM summary...)` → 而历史仍在 `.events` 文件里，下次恢复又从头重放 → 表现为**每次恢复都要压一遍**。

### 6.2 重放时的摘要/原文并存

CHANGELOG 条目：

```
Fixes: sessions resumed after compression still begin with the original request
```

即修复前"已压缩的会话恢复时开头仍挂着原始请求"，摘要与原文同时进上下文。

二进制中配套文本：

```
Prior compacted context:
These turns were compacted. What was asked:
'; the next request continues on the compacted context
(check provider/network status, or run /compact if context is full, then continue
(compacting with LLM summary...)
(compaction interrupted
- **/compact no longer hangs**: generating the summary is capped at 120 seconds.
```

**缓解开关已开**：`[ui]` 段实测存在

```
recap = true
truncate_resumed_history = true
keep_interrupted_context = true
```

`truncate_resumed_history` 在 `config.toml` 中显式出现 1 次、值为 `true`，对应 CHANGELOG 的 `configurable /resume history truncation`。**这是官方为该放大问题准备的开关，本机处于开启态。**

`keep_interrupted_context = true` 与被压缩后的重放叠加时的行为未测。

---

## 7. 本审计对早期一轮口头推断的更正

| 早先说法 | 实测 | 判定 |
|---|---|---|
| "`truncate_resumed_history` 我没在 config.toml 里看到被显式设置，也就是走默认值" | `[ui]` 段第 1 处显式赋值 `= true` | **说法错误**，该开关已开启，A-6 不是当前故障源 |
| "每次 resume 都相当于截快照 + fork 新会话" | `parent` 10/319、`inherited>0` 1/319、前缀重叠 1 组/312 份 | **仅在会话 busy 时 fork**，空闲 resume 为纯重放 |
| "工具 schema 可能随 provider 变化" | 11 个 model 恒定 50,180～52,219 B | **不随 provider 变**，排除该方向 |
| "MCP 被拿掉可能解释压缩" | 工具面恒定；且 `~/.atomcode/mcp.json` 不存在 | **不解释**，压缩由 `context_window` 分母驱动 |

前两条更正源于把 `header.context`（固化的系统提示）误读为历史快照。

---

## 8. 尚未验证

1. 会话是否有任何自动回收/GC 路径：`SessionManager::delete`、`Ctrl+D twice deletes one`、`failed to release current session before delete` 等串证明**删除路径存在但是手动的**；未见任何自动清理。149 份/目录的累积量与"永久保留"一致，但未穷尽搜索确认无后台清理任务。
2. `inherited` 计数的确切语义（101 是事件条数还是 token 数）
3. `detached_model_usage` / `detached_unattributed_tokens` 是否使每份副本独立计费——字段名指向此处，但未取证
4. 压缩实际频次（每会话几次）——可用 `logs/atomcode.log`（2,413,595 B）内 `[compact]` 前缀行量化
5. 各 model 声明的 `context_window` 是否等于其真实上限——若某 provider 真实窗口小于声明值，压缩只是症状而非配置错误

## 9. 复现方法

纪律：**只测尺寸与枚举键名，不读正文**。本审计全过程即按此执行，因为读会话/请求体正文本身会占满上下文。

```bash
EXE="$APPDATA/npm/node_modules/@atomgit.com/atomcode/node_modules/@atomgit.com/atomcode-win32-x64/bin/atomcode.exe"
# 注意包路径：真正的 exe 在嵌套的 node_modules 里。
# 顶层 @atomgit.com/atomcode-win32-x64 不存在；bin/atomcode.js 只有 1887 B，是平台分发壳。
# 对壳 grep 得到 0 命中不能证明功能不存在（本审计踩过一次）。

python - <<'PY'
import re,os
data=open(os.environ['EXE'],'rb').read()
for k in [rb'defer_loading',rb'tool_search',rb'ENABLE_TOOL_SEARCH',rb'tool_reference',rb'auto_compact']:
    print(k.decode(), len(re.findall(k,data)))
PY
```

会话头部键集统计与 fork 检测（§3.2/§3.3）、请求体聚合（§5.2/§5.3）均可从
`~/.atomcode/sessions/*/*.events` 第 1 行与 `~/.atomcode/wire-dump/*.req.json` 复算，
全程无需读会话正文。
