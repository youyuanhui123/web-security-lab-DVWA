# DVWA CSP Bypass：初步源码检查

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

页面交互转到 `about:blank`，没有取得有效脚本执行或 CSP 拒绝证据。当前结论仅是源码中存在待验证数据流，**但不能称为 CSP 绕过已成功**。

## 2. 发现过程

### 原记录：当前发现

本机 Low 模式 `vulnerabilities/csp/source/low.php` 设置：

```http
Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja;
```

随后把 POST 参数 `include` 直接拼进 `<script src='...'></script>`。因此，注入 URL 的脚本必须同时满足 CSP 的 `script-src` 来源规则；这不是任意外站脚本都能执行。该 allowlist 包含多个外部站点，需逐一评估它们是否存在可被攻击者控制的脚本托管/JSONP 等路径，不能仅凭域名在白名单内就宣称已绕过 CSP。

## 3. 核心代码位置

### 报告交叉摘要

Low 源码把 POST `include` 参数拼到脚本 `src`，同时页面配置多个 `script-src` 来源；若攻击者能影响所加载脚本资源，CSP 可能无法达到预期防护。

### 原记录明确提及的代码文件

以下仅汇总原记录中出现的路径，不增加新的源码判断：

- `vulnerabilities/csp/source/low.php`


## 4. 脱敏请求与证据

原笔记未单独列出请求或证据材料；不得据此声称完成动态验证。

## 5. 漏洞根因

### 报告交叉摘要

Low 源码把 POST `include` 参数拼到脚本 `src`，同时页面配置多个 `script-src` 来源；若攻击者能影响所加载脚本资源，CSP 可能无法达到预期防护。

## 6. Patch diff 与修复建议

### 报告交叉摘要

不要将任意请求参数拼入 script URL；用固定资源映射或 nonce/hash 策略，采用严格 CSP 并移除不必要的宽泛来源。

## 7. 修复前后回归

原笔记未提供独立的修复前后回归记录。

## 8. 限制与未验证项

### 原记录：验证状态

- ✅ 容器源码已读，确认 CSP 响应头、白名单来源及 `include` 参数进入 script `src` 的数据流。
- ⏳ 尚未完成浏览器端 CSP 绕过验证。尝试提交本机同源脚本时浏览器会话窗口变为 `about:blank`，因此没有取得有效的执行/拒绝证据。
- 未请求任何外部白名单域名，未声称已绕过 CSP。

下一步应先恢复可用的 DVWA 浏览器会话，再分别验证 CSP 允许来源与非允许来源的脚本加载结果，并记录浏览器控制台的 CSP 报告/错误；只检查响应头不能证明脚本实际执行。

## 9. 复现环境

原笔记未单独记录复现环境。
