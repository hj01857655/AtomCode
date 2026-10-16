# 【功能请求】MCP 工具 schema 延迟加载 / tool search，避免大型 MCP server 撑爆上下文

> 提交对象：atomcode issue tracker（`atomgit.com/atomgit_atomcode/atomcode`）
> 关联：同题 issue **#1664**。本文在其诉求之上补入**源码层证据**（`master @ 4e51fde`），可作其更新，或作为独立新 issue 提交。
> 证据强度：源码链路逐点可查（见 §四 / §七）；桌面版行为见 `resume-fork-snapshot-audit.md` §5（二进制层互证）。

---

## 一、问题

atomcode 把**所有已挂载 MCP 工具的完整 JSON schema**（`input_schema`）注入**每一轮**请求的 `tools` 数组。挂载大型 MCP server 时，无论本轮是否调用这些工具，schema 都每轮全量重发，直接吃掉上下文预算。

两个放大因素：

1. `tools` 位于请求顶层，**不参与对话历史**，压缩（compaction）摘不掉它；
2. 它是**常量重复**——同一份 schema 在整段会话里每轮重发一次。

结果：长会话一旦挂了大型 MCP server，就会陷入"压缩也放不下"的循环——因为要缩的那部分（`tools`）不在可压缩的内容里。

---

## 二、实测影响

挂载一个含 34 个工具的大型 MCP server 时：

| 指标 | 值 |
|---|---|
| 单请求 `prompt_tokens` | **314,267**（上下文满） |
| 顶层 `tools` 数组体积 | ~430 KB+ |
| 34 个 MCP 工具 schema | 估算 ~121 K token（占大头） |
| 长会话压缩 | 触发 `overflow_compacted` 到 **(3/3)**——压三轮仍放不下 |

对照：**不挂 MCP** 时工具面恒定（50,180～52,219 B ≈ 1.4 万 token，40 个工具，跨 11 个 model 实测几乎不变，见 `resume-fork-snapshot-audit.md` §5.3）。这 52 KB 是底座，**MCP server 是纯叠加项**——每挂一个大 server，就是在这底座上加一份常驻 schema 税。

**唯一 workaround 是不挂 MCP**，但这等于放弃"随时可用工具"的能力，与 MCP 的设计目的相悖。

---

## 三、现状核实（源码层）

对 atomcode 源码 `master @ 4e51fde`（802 个 `.rs`）全量检索，**该机制不存在**：

| 关键词 | 命中 |
|---|---|
| `tool_reference` | 0 |
| `ENABLE_TOOL_SEARCH` / `MCPSearch` | 0 |
| `enabled_tools` / `disabled_tools` / `tool_families` | 0 |
| `toolFilter` / `dynamicTool` / `lazyTool` | 0 |
| `defer` + tool/schema、`lazy` + schema | 0（`defer` 命中均为 bash 闸门/审批 TLS 等无关语义） |

配置层同样没有开关：`McpServerConfig`（`mcp/config.rs:93-106`）只有 `name` / `disabled` / `config` / `source` / `trust` / `auto_approve` —— `disabled` 是**整台 server** 开关，`auto_approve` / `trust` 只影响**审批弹框**，都**不改变发给模型的 schema 集合**。`config.toml` 与 `mcp.json` 里没有任何工具子集 / family / enable-disable 键。

> ⚠️ 一个易误认点：源码里确有 `tool-search` / `tool-search-world` 这个名字，但它是**挂载 `grep`+`glob` 两个检索工具的插件 bundle 名**（`harness/plugins/tools.rs:1-13` 注释原话："grep and glob are search, not a view of one execution world"），**与 MCP schema 延迟加载无关**。

---

## 四、全量注入的具体链路（可复现的改动坐标）

从内核到 provider 共 5 个环节，每轮无条件全量：

**① 每轮取当轮工具快照** —— `crates/atomcode-kernel/src/agent/engine.rs:2105-2106`

```rust
let turn_tools = self.tools.snapshot();
let defs = turn_tools.defs();          // 全量 ToolDef
```

**② 每个 def 携带完整 schema** —— `crates/atomcode-kernel/src/tool.rs:362-378`

```rust
.map(|t| ToolDef {
    name: t.name().to_string(),
    description: t.description().to_string(),
    parameters: t.parameters_schema(),   // ← 完整 JSON Schema，无降级形态
})
```

**③ 原样交给 provider（trait 无"子集"位）** —— `engine.rs:2438 / 2465`，`provider.rs:179-184`

```rust
async fn chat_stream(&self, messages: &[Message], tools: &[ToolDef], options: &ChatOptions)
// tools: &[ToolDef] —— 只能整体传
```

**④ provider 逐条把完整 schema 序列化进 `tools`** —— `provider/openai_compat.rs:1434-1447`（`tools.iter()` 无条件全量）

```rust
let t: Vec<Value> = tools.iter().map(|td| json!({
    "type": "function",
    "function": { "name": td.name, "description": td.description,
                  "parameters": normalize_openai_tool_schema(&td.parameters) }
})).collect();
body.insert("tools".into(), json!(t));
```

同构于 `anthropic.rs:546`、`responses.rs:152`、`ollama.rs:505-509`。

**⑤ MCP 工具走同一条路** —— `mcp/tool.rs:107` 存下远端 `input_schema`，`:126-128` 的 `parameters_schema()` 原样返回完整 schema。

---

## 五、参考：Claude Code 的做法

Claude Code 用 `ENABLE_TOOL_SEARCH` / MCPSearch：初始只下发工具名 + 一个搜索元工具，命中后靠 Anthropic Messages API 的 **`tool_reference` beta 块**按需带回完整 schema。

**不能直接复用**：atomcode 连任意大模型，请求体是 OpenAI Chat Completions 风格——实测 5,539 份请求 dump 顶层键为 `model / messages / stream / stream_options / max_tokens / tools / reasoning_effort / temperature / tool_choice`，`tools[].type` 恒为 `"function"`，`betas` **0 份出现**、`defer_loading` **0 次**。该协议里**没有 `tool_reference` 这个位置**（`resume-fork-snapshot-audit.md` §5.2）。

这意味着：**atomcode 要实现等价能力，只能由 harness 侧自行过滤后再发请求**——而这层目前没写。

---

## 六、请求

实现等价的 MCP 工具 schema 延迟加载，任一方向即可大幅改善：

1. **客户端 schema 延迟**（收益最高）：初始只送工具名 + 简短描述，模型首次调用某工具时再注入其完整 schema（或经一个 search 元工具按需获取）。
2. **按 MCP server 配置工具子集**（改动最小，可先落地）：`mcp.json` 支持 `enabled_tools` / `tool_families`，限定暴露的 schema 集合；复用现有装配期挂载机制即可，几乎不动内核。
3. **超阈值自动延迟**：MCP 工具 schema 总量超上下文窗口某比例（如 10%）时自动切到延迟模式，对应 Claude Code 的 auto 模式。

**建议优先级**：方向 2 当天可落地，立刻给用户"只暴露我常用的几个工具"的能力；方向 1/3 需改内核 `Tool` trait，属中期。

---

## 七、复现方法

```bash
# ① 机制不存在
grep -rniE 'tool_reference|ENABLE_TOOL_SEARCH|MCPSearch|enabled_tools|tool_families|toolFilter|dynamicTool|lazyTool' \
  --include='*.rs' --include='*.toml' --include='*.md' --include='*.json' \
  . --exclude-dir=target --exclude-dir=.git
# 预期：0 命中

# ② 全量注入链路
sed -n '2105,2106p' crates/atomcode-kernel/src/agent/engine.rs
sed -n '362,378p'   crates/atomcode-kernel/src/tool.rs
sed -n '1434,1447p' crates/atomcode-capabilities/src/provider/openai_compat.rs

# ③ 配置结构
sed -n '93,106p' crates/atomcode-capabilities/src/mcp/config.rs
```

---

## 八、意义

- **MCP 生态直接受限**：没有这个能力，挂任何大型 MCP server 都不实际——每轮 schema 税会把长会话拖进压缩循环。
- **对"连接任意大模型"的定位尤其关键**：非 Anthropic 后端没有 `tool_reference` beta 可用，**客户端自己解决是唯一出路**。
- **成本**：schema 常驻还会抬高每个请求的输入 token 计费（每轮重发）。

---

# 附：已提交 issue #1664 原文（供比对）

> 用途：以下是**已经提报**的 #1664 全文与元数据。与本文（新草稿）逐节比对后，再决定是**直接编辑 #1664** 还是**另提新 issue**——见文末「处置建议」。

## 元数据

| 字段 | 值 |
|---|---|
| 编号 | **#1664** |
| 状态 | open（待办的），未关闭 |
| 标题 | 【功能请求】MCP 工具 schema 延迟加载 / tool search，避免大型 MCP server 撑爆上下文 |
| 标签 | `enhancement` |
| 作者 | qq_43660926（hj01857655） |
| 指派 | duxin（duxin-空空star） |
| 创建 | 2026-10-16 16:10:20 +08:00 |
| 更新 | 2026-10-16 16:11:59 +08:00 |
| 评论 | 1 条（atomgit-bot 自动回复） |
| 链接 | https://atomgit.com/atomgit_atomcode/atomcode/issues/1664 |

## 正文原文

```markdown
## 问题

AtomCode 当前把所有 MCP 工具的完整 JSON schema 注入每轮请求的 `tools` 数组。挂载大型 MCP server 时，无论本轮是否调用这些工具，schema 每轮全量重发，直接吃掉大量上下文。

## 实测影响

挂载一个含 34 个工具的大型 MCP server 时：

- 单请求 `prompt_tokens: 314267`（上下文满），其中顶层 `tools` 数组 ~430KB+，34 个 MCP 工具 schema 占大头（估算 ~121K token）
- 长会话触发 `overflow_compacted` 到 **(3/3)**——请求压三轮还是放不下，因为 `tools` 数组每轮重发、压缩摘不掉
- 唯一 workaround 是不挂 MCP，但这就失去了随时用工具的能力

## 现状

AtomCode 的 34 个可编辑设置（`config.toml`）里没有 tool search / schema 延迟加载 / 工具子集 任何相关开关。`config.toml` 和 `mcp.json` 配置里也没有按工具 family 裁剪的机制。

## 参考

Claude Code 有 `ENABLE_TOOL_SEARCH` / MCPSearch 机制（Anthropic API beta：`tool_reference` 块），只送工具名 + 一个搜索元工具，模型按需拉 schema。但这是 Anthropic API 专有能力，AtomCode 连接的是任意大模型（GLM-5.2、Qwen 等），不能直接复用。

## 请求

为 AtomCode 实现等价的 MCP 工具 schema 延迟加载。几个方向，任一即可大幅改善：

1. **客户端 schema 延迟**：初始只送工具名 + 简短描述，模型首次调用某工具时再注入其完整 schema（或通过一个 search 元工具按需获取）
2. **按 MCP server 配置工具子集**：`mcp.json` 里支持 `enabled_tools` / `tool_families`，限定暴露的 schema 集合
3. **自动延迟**：MCP 工具 schema 总量超上下文窗口某阈值（如 10%）时自动切换到延迟模式，类似 Claude Code 的 auto 模式

## 意义

没有这个能力，挂任何大型 MCP server 都不实际——每轮 schema 税会让长会话陷入压缩循环，严重限制 AtomCode 的 MCP 生态。这对"连接任意大模型"的定位尤其重要：非 Anthropic 后端没有 `tool_reference` beta 可用，只能靠客户端自己解决。

> 注：通过 issue 搜索 API 检索 "tool search" / "MCP schema" / "deferred tool" 均命中同一个 issue（id 4065967），疑似已有相关讨论，如重复请合并。
```

## 唯一评论（atomgit-bot 自动回复）

```
[194172004] @atomgit-bot: 你好，谢谢反馈。我们已收到这条 Issue，会由维护者继续处理。
代码相关结论需要读仓库核实后再说；若方便可补充版本号与最小复现。
```

## 新草稿相对 #1664 的增量

| 维度 | #1664 原文 | 本文（新草稿） |
|---|---|---|
| 问题描述 | 有 | 保留，补「两个放大因素」（`tools` 在顶层不可压缩 + 常量重复） |
| 实测数据 | 有（314K / 430KB / 121K / 压 3/3） | 同，并补「不挂 MCP 时恒为 52KB 底座」对照 |
| 现状核实 | 只说"34 个设置里没有" | **源码层 5 环节 file:line + 关键词全 0 表 + tool-search 假阳性警示** |
| 协议分析 | 一句"Anthropic 专有、不能复用" | **wire-dump 证据（OpenAI 风格、`betas` 0、`defer_loading` 0）** |
| 方案 | 3 方向 | 3 方向 + **落点 file:line + 优先级建议** |
| 复现 | 无 | **有（3 条命令）** |
| 版本/最小复现 | 未写版本号 | 补 5.2.3 / `master @ 4e51fde` 与复现命令（正是 bot 提示要补的两项） |

## 处置建议

- **倾向"编辑 #1664"而非新提**：#1664 已 open、已被 assign 给维护者、已有 bot 回执，而且标题与诉求完全一致。另开新 issue 会造成重复、很可能被判合并，反而稀释权重。
- **具体做法**：把本文**第四节（全量注入链路）**与**第七节（复现方法）**作为一条 comment 补进 #1664 —— 这正好回应 bot 那句"若方便可补充版本号与最小复现"；如需，再顺带用本文 §一/§五的表替换正文相应段。
- **保留"新提"的可能**：仅当维护者在 #1664 上明确表示"这是既定设计、不做"时，才考虑另开独立 issue 或转 discussion。
- **未决项**：#1664 正文自注的疑似重复件（搜索命中的 id `4065967`，非 issue 号）本次未解析出对应 issue，可留待提交前再核一次。