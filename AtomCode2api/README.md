# AtomCode2api

> AtomCode CodingPlan + OpenRouter → OpenAI / Anthropic 兼容 API 网关

把 AtomCode CodingPlan 免费额度和 OpenRouter 免费模型包装为三协议兼容接口，供任意客户端调用。

## 功能特性

- **三协议兼容**：OpenAI Chat Completions · OpenAI Responses · Anthropic Messages
- **双上游路由**：CodingPlan 模型走 `api-ai.gitcode.com`，OpenRouter 模型走 `openrouter.ai`
- **OAuth 设备流登录**：`GET /login` 引导授权，后台自动续期
- **流式 / 非流式双模式**

## 快速开始

```bash
pip install -r requirements.txt
python server.py
```

```
Base URL : http://127.0.0.1:8788/v1
API Key  : .env 的 API_KEY
Model    : /v1/models 返回的 id
```

### 首次登录

```bash
# 浏览器访问 http://127.0.0.1:8788/login 开始 OAuth 授权
```

未登录时 CodingPlan 路由不可用，OpenRouter 路由不受影响。

## API 接口

| 端点 | 方法 | 说明 |
|---|---|---|
| `/v1/chat/completions` | POST | OpenAI Chat Completions（流式/非流式） |
| `/v1/responses` | POST | OpenAI Responses API（翻译层 ⇄ Chat） |
| `/v1/messages` | POST | Anthropic Messages API（翻译层 ⇄ Chat） |
| `/v1/models` | GET | 可用模型列表（CodingPlan + OpenRouter） |
| `/health` | GET | 存活探针 |
| `/status` | GET | 登录状态 |
| `/login` | GET | OAuth 设备流登录 |
| `/login/poll` | GET | 轮询登录结果 |

### 协议翻译架构

```
客户端                 proxy 翻译层              上游（仅 Chat）
─────────            ─────────────            ─────────────
Chat Completions ──→  直通                 ──→  CodingPlan / OpenRouter
Responses        ──→  responses_to_chat   ──→  CodingPlan / OpenRouter
Anthropic        ──→  anthropic_to_chat   ──→  CodingPlan / OpenRouter
                    ↑ 响应翻回各自格式
```

Chat 是上游母语；Responses / Anthropic 均为「方言 ⇄ 母语」双向翻译层。`thinking`、`cache_control` 等 Anthropic 特有字段无 Chat 对应项，翻译时丢弃。

## 配置

| 变量 | 默认 | 说明 |
|---|---|---|
| `API_KEY` | — | 本地鉴权 Bearer token |
| `HOST` | `127.0.0.1` | 监听地址 |
| `PORT` | `8788` | 监听端口 |

## 模型路由

| 前缀 | 上游 | 说明 |
|---|---|---|
| `openrouter/` | `openrouter.ai/api/v1` | 免费模型，不走 CodingPlan 额度 |
| 其他 | `api-ai.gitcode.com/v1` | CodingPlan Lite 体验版模型 |

CodingPlan 模型：`qwen3.8-27b`、`glm5.3-flash` 等。
OpenRouter 模型：`openrouter/nvidia/nemotron-3.5-lightning:free`、`openrouter/thinkingmachines/inkling:free` 等。

## 已知限制

- **CodingPlan 额度限制**：模型用量窗口达上限时返回 quota 错误，约当日重置
- **OpenRouter 不消耗 CodingPlan 额度**：走独立 API key
- **thinking / cache_control 丢失**：Anthropic 特有字段，Chat 协议无对应项
- **凭证隔离**：只读本目录凭证，绝不碰 AtomCode 客户端本体

## 项目结构

```
AtomCode2api/
├── server.py              # Flask 反代主体
├── auth.py                # OAuth 认证
├── responses_bridge.py    # Responses ⇄ Chat 翻译层
├── anthropic_bridge.py    # Anthropic ⇄ Chat 翻译层
├── test_responses_route.py
├── test_pseudo_detect.py
└── .env                   # 本地配置
```
