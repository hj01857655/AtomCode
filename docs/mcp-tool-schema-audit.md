# atomcode MCP 工具 schema 全量注入问题审计

审计日期：2026-10-16
审计对象：`atomcode` 源码 `master @ 4e51fde`（`atomgit.com/atomgit_atomcode/atomcode`，本地 clone 802 个 `.rs`）
互证对象：发行版 `@atomgit.com/atomcode` 5.2.3 (d8918f0) 二进制（43,809,424 B，见 `resume-fork-snapshot-audit.md` §5）
关联问题：atomcode issue **#1664**

**性质**：只读审计。源码层只做检索与调用链追踪，未改动任何文件；未修改配置、会话或二进制。所有 `file:line` 来自本地 clone（`master @ 4e51fde`）。

---

## 1. 结论

| 编号 | 结论 | 置信 |
|---|---|---|
| B-1 | atomcode（源码层）**没有 MCP 工具 schema 延迟加载 / tool search**：`tool_reference` / `defer_loading` / `ENABLE_TOOL_SEARCH` / `MCPSearch` / `enabled_tools` / `tool_families` 全部 **0 命中** | 已证实 |
| B-2 | 每轮请求把**当轮挂载的全部工具**连同**完整 JSON schema** 注入 `tools` 数组，无任何按需加载或裁剪路径 | 已证实（链路见 §3） |
| B-3 | 配置层（`config.toml` / `mcp.json`）**没有任何工具子集 / family / enable-disable 开关**；`McpServerConfig` 只有 server 级 `disabled` 与审批用 `auto_approve` | 已证实 |
| B-4 | 代码里的 `tool-search` / `tool-search-world` 是**挂载 grep+glob 两个搜索工具的插件 bundle 名**，与 MCP schema 延迟加载无关（易误认） | 已证实 |
| B-5 | 工具子集的唯一控制点是**装配期挂载列表**（宿主/插件层），非用户可配；一旦挂上即全量下发 | 已证实 |
| B-6 | 5.2.3 发行版二进制与源码层结论一致：实现不存在，且所用 OpenAI 协议无原生 defer 字段 → 只能靠 harness 侧自行实现，而该层未写 | 已证实（§9 与 `resume-fork-snapshot-audit.md` §5 互证） |

**一句话**：issue #1664 描述准确——功能确实不存在，三个方向（客户端延迟 / `mcp.json` 工具子集 / 超阈值自动延迟）一个都没做。

---

## 2. 问题

MCP（Model Context Protocol）server 把自己对外暴露的工具，连同每个工具的**完整 JSON Schema**（`input_schema`）经 `tools/list` 交给 atomcode。atomcode 把这些工具当作与内置工具同级的 `ToolDef` 挂载，并在**每一轮**请求里把**全部已挂载工具**的完整 schema 重新塞进发给模型的 `tools` 数组。

后果：挂载大型 MCP server 时，无论本轮是否调用这些工具，schema 都每轮全量重发，直接吃掉上下文预算；而 `tools` 数组位于请求顶层、不参与对话历史，压缩（compaction）摘不到它——于是长会话陷入"压缩也放不下"的循环。

issue #1664 的实测数据（用户环境，一个含 34 个工具的大型 MCP server）：

| 指标 | 值 |
|---|---|
| 单请求 `prompt_tokens` | **314,267**（上下文满） |
| 顶层 `tools` 数组体积 | ~430 KB+ |
| 34 个 MCP 工具 schema | 估算 ~121 K token（占大头） |
| 长会话压缩 | 触发 `overflow_compacted` 到 **(3/3)** —— 压三轮仍放不下 |

对照：不挂 MCP 时工具面恒定（`resume-fork-snapshot-audit.md` §5.3：11 个 model 的 `tools` schema 恒为 50,180～52,219 B ≈ 1.4 万 token、40 个工具）。**这 52 KB 是底座，MCP server 是叠加项**——每挂一个大 server，就是在这个底座上再加一份常驻 schema 税。

---

## 3. 请求链路：每轮全量注入（B-2）

从内核到 provider 的完整链路，逐点可查：

**① 每轮取当轮工具快照**

`crates/atomcode-kernel/src/agent/engine.rs:2105-2106`

```rust
let turn_tools = self.tools.snapshot();
let defs = turn_tools.defs();
```

注释明说该快照就是"advertised to the provider"的集合（`engine.rs:2103-2104`：`A turn must execute against the exact same tool set advertised to the provider.`）。

**② 快照里的每个 def 携带完整 schema**

`crates/atomcode-kernel/src/tool.rs:362-378`（`MountedToolsSnapshot::new`）

```rust
let defs = selected
    .values()
    .map(|t| ToolDef {
        name: t.name().to_string(),
        description: t.description().to_string(),
        parameters: t.parameters_schema(),   // ← 完整 JSON Schema
    })
    .collect::<Vec<_>>()
    .into();
```

`ToolDef.defs()` 返回**全量** `Vec<ToolDef>`（`tool.rs:384-386`），没有"仅名字/仅描述"的降级形态。

**③ 原样交给 provider**

`engine.rs:2438` 与 `2465`

```rust
.on_request(&messages, &defs, &request_options, &turn_ctx)
...
opened = self.provider.chat_stream(&messages, &defs, &request_options) => opened,
```

provider trait 签名本身就没有"子集"位 —— `crates/atomcode-kernel/src/provider.rs:179-184`

```rust
async fn chat_stream(
    &self,
    messages: &[Message],
    tools: &[ToolDef],        // ← 只能整体传
    options: &ChatOptions,
) -> Result<BoxStream<'static, StreamEvent>, ProviderError>;
```

**④ provider 逐条把完整 schema 序列化进 `tools`**

`crates/atomcode-capabilities/src/provider/openai_compat.rs:1434-1447`

```rust
if !tools.is_empty() {
    let t: Vec<Value> = tools
        .iter()
        .map(|td| {
            let parameters = normalize_openai_tool_schema(&td.parameters);
            json!({
                "type": "function",
                "function": {
                    "name": td.name,
                    "description": td.description,
                    "parameters": parameters,   // ← 全量 schema
                }
            })
        })
        .collect();
    body.insert("tools".into(), json!(t));
}
```

`tools.iter()` 是**无条件全量**遍历，没有按名过滤、没有按体积降级。四个 adapter 同构：

| adapter | 注入点 |
|---|---|
| `provider/openai_compat.rs` | `:1444` `body.insert("tools".into(), json!(t));` |
| `provider/anthropic.rs` | `:546` `body.insert("tools".into(), json!(t));` |
| `provider/responses.rs` | `:152` `body.insert("tools".into(), json!(t));` |
| `provider/ollama.rs` | `:505-509` 同上（`function.parameters`） |

**⑤ MCP 工具就是这条路上的普通工具**

`crates/atomcode-capabilities/src/mcp/tool.rs:107`（构造时把远端 schema 存下）

```rust
schema: info.input_schema,
```

`mcp/tool.rs:126-128`（`parameters_schema()` 直接吐完整 schema）

```rust
fn parameters_schema(&self) -> serde_json::Value {
    self.schema.clone()
}
```

即：MCP 工具的完整 `input_schema` 与内置工具走**同一条**无裁剪的注入路径。

---

## 4. 无延迟加载 / 搜索机制（B-1）

对本地 clone 全量源码（`*.rs` / `*.toml` / `*.md` / `*.json`，排除 `target/`、`.git/`）逐关键词检索：

| 关键词 | 命中 |
|---|---|
| `tool_reference` | **0** |
| `ENABLE_TOOL_SEARCH` / `MCPSearch` / `McpSearch` | **0** |
| `enabled_tools` / `enabledTools` / `disabled_tools` | **0** |
| `tool_families` / `toolFamily` / `enabledTools` | **0** |
| `toolFilter` / `tool_filter` / `dynamicTool` / `lazyTool` | **0** |
| `defer` + `tool/schema` / `lazy` + `schema` | **0**（`defer` 的命中全部无关，见下） |

`defer` / `deferred` 的实际命中均为无关语义，逐条查验：

- `tools/bash_workspace_gate.rs` 的 `BashWorkspaceVerdict::Defer`（bash 工作区闸门"交回常规流程"）
- `tools/credential_bash_gate.rs` / `write_approval.rs` / `open_file.rs` 的"defer to 审批"
- `provider/openai_compat.rs:492` 的 TLS 证书校验"推迟到 `.build()`"
- `cli/acp/*` 的 `deferred Responder`（ACP 回包句柄）

无一指向工具加载。

---

## 5. 配置层无裁剪开关（B-3）

`crates/atomcode-capabilities/src/mcp/config.rs:93-106`：

```rust
pub struct McpServerConfig {
    pub name: String,
    pub disabled: bool,               // server 级总开关（整台 server 关掉）
    pub config: McpTransportConfig,
    pub source: McpConfigSource,
    pub trust: bool,                  // 每台 server 免审批（OPT-IN）
    pub auto_approve: Vec<String>,    // per-tool 免审批白名单（autoApprove 数组）
}
```

关键区分：`auto_approve` / `trust` 只影响**审批弹框是否出现**，**不影响发给模型的 schema 集合**；`disabled` 是**整台 server** 开关，粒度到不了单个工具。

- `docs/config.example.toml` 的 `[tools.*]` / `[permissions]` 等段落里搜不到 `search` / `defer` / `subset` / `family` / `enable` 任何相关键。
- `.mcp.json.example` 里同样只有 `disabled` / `trust` / `autoApprove`（及 `command` / `url` / `env` 等传输项）。
- MCP 注册表 `mcp/registry.rs:760` 的 `list_all_tools()` 把各 server 的 `tools/list` 结果**不做子集过滤**地整体返回。

---

## 6. 一个必须澄清的假阳性：tool-search 插件（B-4）

源码里确有一个名字高度可疑的 `tool-search` / `tool-search-world`，容易误读成"已经有了 tool search"。它不是。

`crates/atomcode-harness/src/plugins/tools.rs:1-13`（模块头注释原文）：

```
//! `tool-fs` is the alternative to `tool-fs-world`: ...
//! `tool-search` is orthogonal to both: grep and glob are search, not a view of
//! one execution world, so they mount alongside either.
```

即 `tool-search` 是**一个把 `grep` + `glob` 两个检索工具挂上来的插件 bundle 名**（同一文件 `:228` / `:246` 注册，`world_tools.rs:107` 是它的世界变体）。它与"按需拉取 MCP 工具 schema"这一 issue 诉求**毫无关系**——是检索（search）工具，不是工具检索（tool search）。

---

## 7. 唯一沾边的机制：装配期挂载列表（B-5）

真正能控制"暴露哪些工具"的，只有**装配期的 mount 列表**：

`crates/atomcode-kernel/src/tool.rs:318`（`ToolRegistry::mount`）

```rust
let snapshot = Arc::new(MountedToolsSnapshot::new(
    ToolCatalogRevision(0),
    /* 只含 names 里列出的工具 */,
));
```

- `tool.rs:548-564` 的测试 `only_mounted_tools_are_exposed_or_resolvable` 明示：**未挂载的工具不进 ToolDefs**，即"挂哪几行"决定暴露面。
- 这层是**宿主 / 插件层的装配决定**（见 `docs/tool-catalog-policy.md`：下游产品经 `PrepareOptions.host_plugins` / `HostState.plugins` 交进来），**不是用户在 `mcp.json` 里能配的东西**。
- 一旦挂上，`MountedToolsSnapshot` 到 provider 之间就是**全量**（§3），没有"挂上但按需下发 schema"的中间态。

结论：目前想缩小 MCP schema 税，**唯一手段是整台 MCP server 别挂**——这正是 issue #1664 描述的困境。

---

## 8. 对标 Claude Code

Claude Code 用 `ENABLE_TOOL_SEARCH` / MCPSearch 机制解决同一问题，其 API 依赖 Anthropic Messages API 的 beta 内容块：请求里只带工具名 + 一个搜索元工具，命中后由 `tool_reference` 块按需带回该工具的完整 schema。

| 维度 | Claude Code | atomcode（现状） |
|---|---|---|
| 初始下发的 MCP 工具面 | 仅工具名（+ 搜索元工具） | **全部工具的完整 schema** |
| 完整 schema 到达时机 | 首次命中/调用时按需 | 每轮全量重发 |
| 协议依赖 | Anthropic `tool_reference` beta（Anthropic 专有） | 无——atomcode 连任意模型，走 OpenAI Chat Completions 风格 |
| 超阈值自动切换 | 有（auto 模式） | 无 |
| 按 server 配工具子集 | 有（`enabledTools` 等） | 无 |

**atomcode 不能直接复用**：其 5,539 份请求体 dump 显示顶层键为 `model / messages / stream / stream_options / max_tokens / tools / reasoning_effort / temperature / tool_choice`，`tools[].type` 恒为 `"function"`（`function.name` 嵌套），`betas` **0 份出现**、`defer_loading` **0 次**——是 OpenAI Chat Completions 风格，**没有 `tool_reference` 这个位置**（`resume-fork-snapshot-audit.md` §5.2）。要在 atomcode 上实现等价能力，**只能由 harness 侧自行过滤后再发请求**——而 §3～§7 已证明那一层没写。

---

## 9. 与发行版二进制审计的互证（B-6）

本审计（**源码层**，`master @ 4e51fde`）与 `resume-fork-snapshot-audit.md`（**二进制层**，5.2.3 `d8918f0`，43,809,424 B）在"没有 tool search"上完全一致，证据源互补：

| 证据源 | 方法 | 结论 |
|---|---|---|
| 二进制（resume-fork-snapshot-audit §5.1） | 对 exe 扫描可打印串 | `defer_loading` / `tool_search` / `tool_reference` / `ENABLE_TOOL_SEARCH` 全 0 |
| 请求体（resume-fork-snapshot-audit §5.2） | 5,539 份 wire-dump 解析 | `defer_loading` 0 次、`betas` 0 份；OpenAI 风格 |
| **源码（本审计 §3～§5）** | 802 个 `.rs` 检索 + 链路追踪 | 关键词全 0，且**定位到全量注入的 5 个具体环节** |

二进制审计止步于"实现不存在 + 协议无位置"，本审计补上了"**代码里具体为什么全量**"的逐点证据（§3），使 issue #1664 的诉求有了可落地的改动坐标。

---

## 10. 可行方案

按 issue #1664 的三个方向，结合源码结构给落点：

**方向 1 —— 客户端 schema 延迟（改动最大，收益最高）**
改 `Tool` trait：让 `parameters_schema()` 支持"先发空对象 schema（或仅 name+description），首次调用时再补全"。落点：
- `crates/atomcode-kernel/src/tool.rs:366-370`（`MountedToolsSnapshot::new` 里选择降级 schema）
- `provider/*.rs` 的 `tools` 组装处（§3 ④，按标记决定是否带全量 `parameters`）
- 需要一个"schema 缓存 + 命中补全"的元工具或两段式协议

**方向 2 —— `mcp.json` 支持工具子集（改动最小，先落）**
给 `McpServerConfig`（`mcp/config.rs:93-106`）加 `enabled_tools` / `tool_families` 等字段，在 `registry.rs:760` `list_all_tools()` 或挂载点按名单过滤，使**未列表的工具根本不进 `ToolDef`**（复用 §7 的 mount 机制即可，几乎不动内核）。

**方向 3 —— 超阈值自动延迟（依赖方向 1）**
在 §3 ② 计算 `defs` 的 schema 总体积，超 `context_window` 某比例（如 10%）时自动切到降级模式。对应 Claude Code 的 auto 模式。

**优先级建议**：方向 2 是当天可落地的补丁（纯配置层 + 过滤），能立刻给用户 `mcp.json` 里"只暴露我常用的几个工具"的能力；方向 1/3 需要动内核 trait，属中期。

---

## 11. 影响与意义

- **MCP 生态直接受限**：没有这个能力，挂任何大型 MCP server 都不实际——每轮 schema 税会把长会话拖进压缩循环。用户被迫在"随时可用 MCP 工具"与"会话不炸"之间二选一。
- **对"连接任意大模型"的定位尤其关键**：非 Anthropic 后端没有 `tool_reference` beta 可用，**客户端自己解决是唯一出路**；这恰恰是 atomcode 相对 Claude Code 的差异化短板，值得优先补齐。
- **成本**：schema 常驻还会抬高每个请求的输入 token 计费（每轮重发）。

---

## 12. 相关 issue

| 编号 | 关系 |
|---|---|
| **#1664** | 本审计记录的原始功能请求（open / enhancement / 已 assign） |
| id `4065967` | issue #1664 正文自注：检索 "tool search" / "MCP schema" / "deferred tool" 时命中的疑似重复讨论，如重复请合并（未在本次审计中复核） |

---

## 13. 尚未验证

1. `normalize_openai_tool_schema()`（`openai_compat.rs:1448` 起）对 MCP schema 的具体归一化行为——是否可能放大而非缩小体积
2. `mcp/registry.rs` 里 `tools/list` 失败后重试/去重的完整路径（`listed_tools` 的更新时机）
3. MCP server 工具数量是否存在**上限保护**（实测 40 工具是内置面；叠加 MCP 后是否封顶未测）
4. 排除式方案（harness 侧对 `tools` 数组按体积截断）对模型工具选择准确率的实际影响——需实验，非本次静态审计范围

---

## 14. 复现方法

纪律：源码层只做检索与链路追踪，不改文件、不读会话正文。

```bash
# ① 关键词全量检索（本审计 §4）
cd <atomcode-clone>
grep -rniE 'tool_reference|ENABLE_TOOL_SEARCH|MCPSearch|enabled_tools|tool_families|toolFilter|dynamicTool|lazyTool' \
  --include='*.rs' --include='*.toml' --include='*.md' --include='*.json' \
  . --exclude-dir=target --exclude-dir=.git
# 预期：0 命中

# ② 全量注入链路（本审计 §3，逐点核对 file:line）
sed -n '2105,2106p' crates/atomcode-kernel/src/agent/engine.rs      # snapshot + defs
sed -n '362,378p'   crates/atomcode-kernel/src/tool.rs              # ToolDef{ parameters: parameters_schema() }
sed -n '1434,1447p' crates/atomcode-capabilities/src/provider/openai_compat.rs  # tools 全量组装

# ③ 配置结构（本审计 §5）
sed -n '93,106p' crates/atomcode-capabilities/src/mcp/config.rs     # McpServerConfig 字段
```

> 注意异常：本机 `E:/VSCodeSpace/Agent/atomcode/` 外层是 GitHub `hj01857655/AtomCode2api` 工作仓，真正的上游 atomcode 源码在其内层 `atomcode/` 子目录（remote `atomgit_atomcode/atomcode`）。对**外层**跑 grep 只会扫到 52 个文件（嵌套 clone 被 gitignore），会得到假 0 命中——本审计踩过并已纠正。