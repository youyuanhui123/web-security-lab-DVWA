# DVWA CSRF：验证与修复

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

独立副本中 Low 带外部 Origin/Referer 的无 token GET 实际改密；Medium 的 Referer 检查拒绝；High/Impossible 缺 token 不改密。

## 2. 发现过程

原笔记未单独记录发现过程。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/csrf/source/low.php` 至 `high.php` 的改密方法、Referer/token 校验与更新逻辑。

### 原记录：范围与源码发现

Low 将改密操作放在 GET 请求中，无 CSRF token 或来源校验；Medium 仅检查 `HTTP_REFERER` 是否包含 `SERVER_NAME`；High 要求 CSRF token，但仍用 GET；Impossible 还校验当前密码和 token。页面源码同时提醒浏览器默认 SameSite=Lax 可能影响部分传统 CSRF 请求。

## 4. 脱敏请求与证据

### 原记录：动态验证（隔离副本，实测）

每档使用独立初始化的临时数据库与已认证会话，向模块发送携带 attacker Origin/Referer 的请求，测试后通过重新登录确认账户状态：

| 等级 | 结果 |
|---|---|
| Low | 无 token 的跨站模拟 GET 更改了测试账户密码；新密码可登录，旧密码不能 |
| Medium | 外部 Referer 被拒绝，原密码仍有效 |
| High | 缺少 token 的请求未改密，原密码仍有效 |
| Impossible | 缺少 token 的请求未改密，原密码仍有效 |

该测试通过 cURL 显式携带会话 cookie，证明服务端接受/拒绝行为；**没有在真实浏览器中验证跨站时浏览器是否发送 cookie**，因此浏览器可利用性还受 SameSite 和部署策略影响。实际密码值及 session 内容未写入证据。

## 5. 漏洞根因

### 报告交叉摘要

浏览器自动携带受害者会话 Cookie；Low 的改密操作缺少不可预测 CSRF token / 强制 POST 等校验，攻击者可诱导已登录浏览器代发请求。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

对状态变更仅使用 POST/PUT/DELETE；验证服务端生成并绑定会话的 CSRF token；当前密码校验属于额外保护但不能替代 token；Cookie 设置 SameSite、Secure、HttpOnly，服务端仍需检查请求来源。

### 原记录：修复与复测（隔离副本，实测）

`fix.patch` 将 Low/Medium/High 统一委托给 Impossible 的 CSRF token、当前密码校验和参数化更新路径；改密表单统一为 POST，并在各档提供当前密码和 token。Impossible 处理器也改为只从 POST 读取改密字段。补丁 dry-run、应用及五个改动 PHP 文件 lint 通过。

修复副本的 Low/Medium/High 均验证：跨站模拟 GET 不改密；跨站模拟 POST 缺少 token 不改密；合法 token 加正确当前密码的 POST 能正常改密，新密码可登录、旧密码失效。三档回归检查通过；详细输出见 `evidence/verification-results.md`。

## 7. 修复前后回归

相关修复回归原记录位于第 6 节：“修复与复测（隔离副本，实测）”。该处保留原始结果，未在此重复或扩写。


## 8. 限制与未验证项

原笔记未单独列出限制或未验证项；未提及不等于已验证。

## 9. 复现环境

### 原记录：隔离与清理

动态验证只在独立数据库、internal network、只读应用文件系统和资源受限的隔离栈中进行。两个隔离栈、网络及临时数据库卷已清理；主 DVWA、MariaDB 和主数据库卷保留。补丁未部署到主实例。
