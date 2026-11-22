# DVWA 安全测试与修复验证实践

> 基于官方 DVWA 的本地授权靶场项目。重点展示 Web 漏洞的发现链、源码定位、可复现验证、补丁分析和修复副本回归。

## 项目概览

- **环境**：Docker Compose、官方 DVWA 容器、MariaDB；应用仅绑定 `127.0.0.1:4280`，数据库只连内部 Compose 网络。
- **覆盖**：17 个已有案例记录的模块，覆盖源码审查、本机页面/API 验证、隔离副本测试和修复补丁回归；每个模块的证据等级和未测项见 `study.md` 与各模块 `NOTES.md`。
- **产物**：13 个模块补丁、脱敏验证记录、17 份模块笔记，以及[全模块分析报告](reports/DVWA全模块漏洞成因定位修复与补丁分析报告.md)。
- **重要边界**：补丁只在源码副本或隔离环境验证，**没有部署到主 DVWA**。CSP Bypass 和 JavaScript Attacks 以源码审查为主；其他模块的动态覆盖范围也请以各自记录为准。

## 能力展示

| 实践环节 | 项目中的体现 |
|---|---|
| 发现与定位 | 从正常请求/帮助文档入手，追踪参数到 SQL、HTML/DOM、文件系统、shell、认证及跳转等敏感操作 |
| 验证 | 采用真假条件、正常/异常响应差异、浏览器事件、状态变化及隔离副本等判据；区分动态实测和源码推断 |
| 修复分析 | 使用参数化查询、上下文编码、服务端状态/权限校验、白名单、密码学安全随机值等修复思路 |
| 回归与边界 | 记录合法功能是否保留、攻击输入是否被拒、持久状态是否改变，以及未覆盖项；不把 lint 通过等同端到端修复 |
| 环境安全 | 本机回环绑定、数据库不发布宿主端口、有状态模块使用隔离数据库、临时探针清理并保留主数据库卷 |

## 环境拓扑

```text
浏览器 / Burp
      │
      ▼
127.0.0.1:4280  ── DVWA 容器
                         │ Compose 内部网络
                         ▼
                    MariaDB 容器
```

本项目只用于自有本机教学靶场；不要将 DVWA 暴露到公网或接入生产数据。

## 快速启动（Windows CMD，在项目根目录）

```cmd
:: 检查 Compose 配置及固定镜像引用
docker compose -f environment/compose.yaml config --images

:: 启动本地靶场
docker compose -f environment/compose.yaml up -d

:: 查看容器状态
docker compose -f environment/compose.yaml ps
```

浏览器访问：<http://127.0.0.1:4280>

实验结束后停止容器并保留数据库：

```cmd
docker compose -f environment/compose.yaml stop
```

`stop` 不删除数据。除非确实准备销毁数据库，**不要执行 `docker compose down -v`**。

## 案例索引

各案例笔记已统一为审阅结构，首页链接直达“审阅摘要”；每篇保留原始详细记录，记录未覆盖的项目标注为未验证。若存在 `fix.patch`，该补丁只代表候选修复，部署与回归状态以案例正文为准。

| 模块 | 案例 | 模块 | 案例 |
|---|---|---|---|
| SQL Injection | [审阅摘要](cases/sql-injection/NOTES.md#审阅摘要) | Reflected XSS | [审阅摘要](cases/reflected-xss/NOTES.md#审阅摘要) |
| Stored XSS | [审阅摘要](cases/stored-xss/NOTES.md#审阅摘要) | DOM XSS | [审阅摘要](cases/dom-xss/NOTES.md#审阅摘要) |
| CSP Bypass | [审阅摘要](cases/csp-bypass/NOTES.md#审阅摘要) | File Upload | [审阅摘要](cases/file-upload/NOTES.md#审阅摘要) |
| Insecure CAPTCHA | [审阅摘要](cases/insecure-captcha/NOTES.md#审阅摘要) | Blind SQL Injection | [审阅摘要](cases/sql-injection-blind/NOTES.md#审阅摘要) |
| Weak Session IDs | [审阅摘要](cases/weak-session-id/NOTES.md#审阅摘要) | Brute Force | [审阅摘要](cases/brute-force/NOTES.md#审阅摘要) |
| Command Injection | [审阅摘要](cases/command-injection/NOTES.md#审阅摘要) | CSRF | [审阅摘要](cases/csrf/NOTES.md#审阅摘要) |
| File Inclusion | [审阅摘要](cases/file-inclusion/NOTES.md#审阅摘要) | JavaScript Attacks | [审阅摘要](cases/javascript-attacks/NOTES.md#审阅摘要) |
| Open HTTP Redirect | [审阅摘要](cases/open-redirect/NOTES.md#审阅摘要) | Cryptography | [审阅摘要](cases/cryptography/NOTES.md#审阅摘要) |
| API | [审阅摘要](cases/api/NOTES.md#审阅摘要) |  |  |

### 证据阅读方式

阅读每个案例时，先看 `NOTES.md` 的结论和限制，再看 `evidence/`、脚本和补丁。报告中使用以下区分：

- **动态实测**：请求/页面/状态产生了记录中所述的可观察结果。
- **源码审查**：确认了数据流或危险调用，但未取得动态成功信号。
- **修复副本回归**：补丁在独立副本/隔离环境验证，不表示已部署。
- **未验证**：没有足够证据时明确保留，不用源码推测补齐结论。

## 目录

```text
.
├── README.md
├── study.md                         # 按阶段追加的学习与验证记录
├── environment/
│   └── compose.yaml                 # 固定镜像 digest 的本机靶场
├── cases/
│   ├── <module>/NOTES.md            # 发现链、根因、验证和限制
│   ├── <module>/fix.patch           # 部分模块的修复候选补丁（未部署）
│   ├── <module>/scripts/            # 可复跑的本地/隔离验证脚本
│   └── <module>/evidence/           # 脱敏源码与结果证据
└── reports/
    └── DVWA全模块漏洞成因定位修复与补丁分析报告.md
```

## 已知限制与公开前检查

- DVWA 是第三方教学项目。本仓库保存了部分上游源码证据；公开时保留上游归属与适用许可证，不把 DVWA 本身说成原创作品，也不将自己的许可证覆盖到上游文件。
- 本地验证使用的 Compose 配置仍需在公开前把数据库演示凭据改为环境变量，并提供只含占位符的 `.env.example`；不要把可复用或真实凭据提交到仓库。
- 本地 `README`、补丁和报告不是生产部署指南；生产系统应基于业务需求重新设计并进行独立安全评估。
- 项目目前没有声明主实例已部署修复。要把某个 patch 宣称为“已修复”，还需明确部署到目标版本并完成部署后端到端回归。

## 项目价值

> 基于 Docker 搭建本地 DVWA 安全实验环境，整理 17 个 Web 安全模块的源码审查与本机/隔离验证案例；为其中 13 个模块编写修复补丁，并在副本中进行语法检查或回归验证。保留脱敏证据并明确区分动态实测、源码发现与未覆盖项；补丁未部署到主靶场。

此表述强调实际做过的工程工作，不把教学靶场漏洞包装成原创漏洞发现或生产修复项目。
