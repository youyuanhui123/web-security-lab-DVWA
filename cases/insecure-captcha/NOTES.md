# DVWA Insecure CAPTCHA：验证与修复

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

独立 Docker 副本中，Low 直接跳到后续步骤、Medium 伪造客户端 `passed_captcha` 状态、High 使用源码备用验证逻辑，均实际改了测试账户密码，并可用新密码登录。reCAPTCHA 公钥为空，正常外部 CAPTCHA 流程没有覆盖。

## 2. 发现过程

### 原记录：范围与发现链

目标为本地 DVWA `Insecure CAPTCHA`。先从 `index.php` 确认安全等级选择的源码，再对照 Low/Medium/High 与 Impossible。Low、Medium 都把密码修改拆成两步，后端第二步没有可信的服务端 CAPTCHA 状态；Medium 的 `passed_captcha=true` 是客户端隐藏字段。High 源码含硬编码备用条件 `g-recaptcha-response=hidd3n_valu3` 且 User-Agent 为 `reCAPTCHA`。Impossible 要求 CSRF token、当前密码和 reCAPTCHA，并用 PDO 参数化语句更新密码。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/captcha/source/low.php`、`medium.php`、`high.php` 的步骤判断和改密路径；Impossible 提供更严格的参考校验。

## 4. 脱敏请求与证据

### 原记录：漏洞验证（隔离副本，实测）

没有改当前 `web-security-lab` 的数据库。另建 `sandbox.compose.yaml` 隔离栈：Docker internal network（无外网路由）、应用只读根文件系统、显式 CPU/内存/PID 限额、数据库使用独立临时卷；HTTP 客户端在应用容器内经 `127.0.0.1` 回环访问。测试结束后移除隔离容器和该临时数据库卷。

| 等级 | 请求验证 | 验收证据 |
|---|---|---|
| Low | 登录后直接 POST `step=2`，不提交 CAPTCHA | 请求 HTTP 200；随后用新密码登录成功，`LOW_CAPTCHA_BYPASS_CONFIRMED` |
| Medium | 直接 POST `step=2` 并伪造 `passed_captcha=true` | HTTP 200；随后用新密码登录成功，`MEDIUM_CAPTCHA_BYPASS_CONFIRMED` |
| High | 提交硬编码备用响应值并设置对应 User-Agent | HTTP 200；随后用新密码登录成功，`HIGH_CAPTCHA_BYPASS_CONFIRMED` |

以上密码变更只作用于一次性隔离数据库，不影响主 DVWA 实例。详细输出见 `evidence/verification-results.md`；可复跑脚本见 `scripts/verify_low_step2.php` 与 `scripts/verify_medium_high.php`。

## 5. 漏洞根因

### 报告交叉摘要

将流程状态或验证码结果信任客户端字段、允许直接跳过步骤，或在高等级中使用可预测/硬编码备用验证信息；服务器没有在最终敏感操作前重新完成可信校验。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

验证码验证必须由服务端完成，验证结果与当前会话/操作绑定；不以 hidden field、User-Agent 或硬编码备用值代表通过；敏感改密操作还应要求当前密码和 CSRF token。

### 原记录：修复与复测（隔离副本，实测）

`fix.patch` 在源码副本应用：Low/Medium/High 入口改为委托给 DVWA Impossible 实现；页面对所有等级都显示当前密码并发送 CSRF token，同时移除 High 页面暴露的备用值说明。修复逻辑要求当前密码、CSRF token 与 CAPTCHA 通过后才执行密码更新。

补丁 dry-run 与应用成功；四个改动文件在容器 PHP CLI 中 `php -l` 全通过。将修复副本以只读 bind mount 接入隔离栈后，分别重放 Low、Medium、High 的原攻击请求：三次均为 HTTP 200，但原密码仍有效，攻击者设置的新密码均不能登录；三项 `*_PATCH_BLOCK_CONFIRMED` 检查通过。详细输出见 `evidence/verification-results.md`，回归脚本为 `scripts/verify_fixed_levels.php`。

## 7. 修复前后回归

相关修复回归原记录位于第 6 节：“修复与复测（隔离副本，实测）”。该处保留原始结果，未在此重复或扩写。


## 8. 限制与未验证项

### 原记录：边界与未验证项

- 原始 Low、Medium、High 的 CAPTCHA 绕过均已在隔离副本端到端验证；对应修复也已在隔离副本做负向回归。
- 隔离副本 `recaptcha_public_key` 为空，因此**没有验证有效 CAPTCHA 的正常密码修改成功路径**；本轮仅确认绕过被堵住、攻击密码未被写入。
- 补丁未应用到当前运行的主 DVWA 容器。主容器与其 MariaDB 数据卷未修改。
- 不记录密码或会话值；测试数据库卷已删除。

## 9. 复现环境

原笔记未单独记录复现环境。
