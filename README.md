# AtomCode 逆向分析与 atomcode2api 网关

对 AtomCode CLI（atomcode-v5.1.0-windows-x64.exe）的逆向分析成果，以及基于它的
CodingPlan → OpenAI 兼容 API 网关（`AtomCode2api/`）。

## 目录结构

```
AtomCode/
├── README.md                  # 本文件
├── quota.sh                   # 额度查询脚本
└── AtomCode2api/
    ├── server.py              # 网关路由层（Flask：OpenAI 兼容 + /login OAuth + OpenRouter 反代）
    ├── auth.py                # 认证层（共用 ~/.atomcode/auth.toml + mtime 热加载 + RT 轮换刷新写回）
    ├── server.log             # 运行日志（2MB 轮换，[rNNNN] 关联 ID + ttft/tokens）
    └── docs/                  # 全部文档（索引见其 README.md）
```

## 核心结论速览

| 项 | 结论 |
|---|---|
| 技术栈 | Rust 原生编译（tokio + clap 4.6 + tracing），非 Electron/Go |
| 架构 | crate workspace：cli / daemon / codingplan / auth / kernel / telemetry / capabilities |
| 数据面 | `https://api-ai.gitcode.com/v1`（OpenAI 兼容；不要求签名，但不能带 `atomcode/*` UA） |
| 官方默认端点 | `https://llm-api.atomgit.com/v1`（实测任意 UA 均 403，网关不可用） |
| 控制面 | `https://api.gitcode.com/api/v5`（CodingPlan 额度查询，Bearer 直通） |
| 认证 | AtomGit OAuth，凭据存 `~/.atomcode/auth.toml`；RT 轮换刷新 |
| 额度机制 | 每 5 小时一个滑动窗口，200 次调用，窗口结束自动回满；claim-v2 领取后激活 |
| 遥测 | acs.atomgit.com/api/v1/events，可关闭 |

## 文档

全部文档在 **[AtomCode2api/docs/README.md](AtomCode2api/docs/README.md)**（阅读顺序索引）：

- **[00 二进制分析报告](AtomCode2api/docs/reverse-engineering-report.md)** — PE 结构、crate 划分、端点、环境变量清单、CLI 命令面
- **[01–05 逆向系列](AtomCode2api/docs/atomcode-01-侦察与架构.md)** — 架构 / 控制面与额度 / 数据面与 UA 门 / 认证流 / 签名历史存档
- **[额度机制详解](AtomCode2api/docs/codingplan-quota.md)** — 窗口规则、响应结构体、字段速查、查询方法
- **[网关设计](AtomCode2api/docs/网关设计.md)** — 架构、流程、配置、实施计划
