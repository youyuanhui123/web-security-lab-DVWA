# DVWA SQL Injection (Blind)：验证与修复

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

独立隔离副本中 Low、Medium、High 的真假条件成对测试均产生 `exists/missing` 差异，确认布尔 oracle；没有导出数据。

## 2. 发现过程

### 原记录：启动与范围

用户要求先启动 Docker。发现 Docker Desktop 引擎未运行，启动 Docker Desktop 后执行主项目 `environment/compose.yaml up -d`；DVWA 与 MariaDB 均进入 Up 状态，`http://127.0.0.1:4280/login.php` 返回 HTTP 200。主实例只用于恢复服务与只读取源码，本次动态测试均在独立隔离副本完成。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/sqli_blind/source/low.php` 至 `high.php` 的输入处理和数据库查询。

### 原记录：发现链与源码分析

从 `vulnerabilities/sqli_blind/index.php` 确认入口因安全等级而使用不同方法：Low 走 GET、Medium 走 POST、High 从 `id` Cookie 取值。对照源码后发现：Low 将用户输入直接拼进带引号的 `user_id` 条件；Medium 调用 `mysqli_real_escape_string()` 后仍把值放进无引号的数值上下文；High 的 Cookie 值直接拼接，错误分支还会随机 sleep。三者最后都只把查询结果转成“exists / missing”反馈，形成布尔 oracle。Impossible 则先要求数值输入，再用参数绑定查询。

## 4. 脱敏请求与证据

### 原记录：漏洞验证（隔离副本，实测）

在独立 Docker 副本中初始化一次性数据库，使用成对真假条件，仅判断查询结果，不枚举或导出记录：

| 等级 | 真条件结果 | 假条件结果 | 结论 |
|---|---|---|---|
| Low / GET | HTTP 200，显示 `User ID exists in the database.` | HTTP 404，显示 `User ID is MISSING from the database.` | Boolean oracle 确认 |
| Medium / POST | HTTP 200，显示 exists | HTTP 200，显示 missing | Boolean oracle 确认，状态码本身不能区分真/假 |
| High / Cookie | HTTP 200，显示 exists | HTTP 404，显示 missing | Boolean oracle 确认 |

复测脚本 `scripts/verify_blind_oracle.php` 每个等级各发送一对探针；只验证 oracle，没有继续取数。原始输出摘要见 `evidence/verification-results.md`。

## 5. 漏洞根因

### 报告交叉摘要

查询虽不直接显示数据，输入仍影响 SQL 条件；应用以结果是否存在、响应差异等作为 oracle，攻击者可逐步推断数据库状态。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

参数绑定；对 ID 做严格类型校验；统一错误和响应形态，避免把查询真假泄漏为可观察 oracle；必要时使用最小权限数据库账户。

### 原记录：修复与复测（隔离副本，实测）

`fix.patch` 将 Low/Medium/High 入口统一委托给 Impossible 的安全实现：数值校验后转换为整数，以 PDO 参数绑定执行；表单统一为 GET 并在所有等级包含 CSRF token，High 不再暴露 Cookie 输入路径。补丁 dry-run、应用成功；四个改动 PHP 文件在容器 PHP CLI 中 lint 通过。

修复副本以只读挂载接入另一独立隔离栈后，先用合法 ID `1` 验证正常查询仍显示 exists，再对每个等级重放原本可让真条件成立的 payload。三种修复请求均返回 HTTP 404 / missing，且没有 exists 标记；Low、Medium、High 的 `*_PATCH_BLOCK_CONFIRMED` 检查全部通过。回归脚本为 `scripts/verify_fixed_blind.php`。

## 7. 修复前后回归

相关修复回归原记录位于第 6 节：“修复与复测（隔离副本，实测）”。该处保留原始结果，未在此重复或扩写。


## 8. 限制与未验证项

### 原记录：环境隔离与边界

- 两个测试栈使用独立 MariaDB 临时卷、Docker internal network、只读应用根文件系统、CPU/内存/PID 限额；HTTP 客户端通过应用容器内的 `127.0.0.1` 回环测试。
- 动态测试没有读取数据库记录、没有执行数据导出，也没有触碰主项目数据库。
- 补丁只在 `worktree/`、`patch-check/` 及隔离栈中使用；未应用到主 DVWA 容器。
- 测试后移除本次创建的隔离容器、网络和临时数据库卷；保留主项目容器与数据卷。

## 9. 复现环境

原笔记未单独记录复现环境。
