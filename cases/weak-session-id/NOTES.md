# DVWA Weak Session IDs：验证与修复

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

隔离副本中 Low 的连续计数、Medium 的时间值、High 的计数器 MD5 均呈可预测性。没有猜测或访问他人会话。

## 2. 发现过程

### 原记录：范围与发现链

只读检查 `index.php` 后发现 Low/Medium/High 都在 POST 时设置 `dvwaSession`，再对照各等级源码：Low 用 session 计数器递增；Medium 直接用 `time()`；High 用递增计数器再做 MD5。Impossible 改用 `random_bytes(20)`，输出 40 位十六进制值，并设置 Secure、HttpOnly 与限定路径属性。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/weak_id/source/low.php`、`medium.php`、`high.php` 的 session id 生成逻辑；Impossible 使用安全随机来源。

## 4. 脱敏请求与证据

### 原记录：动态验证（隔离副本，实测）

在独立 Docker 网络和临时数据库中，使用同一认证会话，各级别连续生成两次 cookie：

| 等级 | 实测判据 | 结果 |
|---|---|---|
| Low | cookie 值依次等于 session 计数器 `1`、`2` | 顺序可预测，确认 |
| Medium | 两次 cookie 都是 10 位 Unix 时间戳格式 | 时间可预测，确认 |
| High | 两次 cookie 分别等于计数器 `1`、`2` 的 MD5 | 只是哈希可预测计数器，确认 |
| Impossible | 40 位十六进制、两次不同，并带 Secure/HttpOnly | 安全实现对照，确认 |

只检查 cookie 生成行为，没有尝试猜测他人会话或访问他人数据。测试输出不保存实际 cookie 值，见 `evidence/verification-results.md`。

## 5. 漏洞根因

### 报告交叉摘要

会话标识由计数器、当前时间或其简单散列生成，随机性不足；攻击者可预测候选标识，威胁会话接管。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

使用密码学安全随机数生成器，确保足够熵；由框架生成/轮换会话 ID，并配置 Secure、HttpOnly、合适 SameSite 与 HTTPS。

### 原记录：修复与复测（隔离副本，实测）

`fix.patch` 让 Low/Medium/High 统一委托给 Impossible 的 `random_bytes(20)` 生成逻辑与安全属性。补丁 dry-run、应用成功；三个改动 PHP 文件 lint 通过。只读挂载修复副本后，对 Low/Medium/High 各生成两次 cookie，均为不同的 40 位十六进制值且带 Secure/HttpOnly；三项 `*_PATCH_RANDOM_COOKIE_CONFIRMED` 检查通过。

## 7. 修复前后回归

相关修复回归原记录位于第 6 节：“修复与复测（隔离副本，实测）”。该处保留原始结果，未在此重复或扩写。


## 8. 限制与未验证项

### 原记录：边界与清理

- 修复只在隔离副本验证；没有改动主 DVWA 源码或主数据库。
- 隔离栈使用 internal network、只读应用文件系统、资源限制及独立临时数据库卷。
- 测试结束后删除本阶段的隔离容器、网络和临时数据库卷；主 DVWA 与 MariaDB 保持运行。
- 实际浏览器在 HTTP 下是否接受 Secure cookie 未测试；这里只核对服务器发出的属性。

## 9. 复现环境

原笔记未单独记录复现环境。
