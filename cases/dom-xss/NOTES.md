# DVWA DOM Based XSS：验证与修复方向

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

本机浏览器验证事件执行，标题变为 `1`。

## 2. 发现过程

### 原记录：结论与发现链

仅测试本机 DVWA `127.0.0.1:4280` 的 DOM XSS 页面。Low 源码直接把 URL 的 `default` 参数拼进 `document.write()`，浏览器端自行构造 HTML；输入不经过服务器端 HTML 输出编码。

1. 页面默认显示语言选择器。
2. 观察 `index.php` 中读取 `document.location.href`、提取 `default=` 后调用 `document.write()` 的代码。
3. 在 `default` 参数中提供标签闭合片段与一张失效图片：`%3C/option%3E%3C/select%3E%3Cimg%20src=x%20onerror=document.title=1%3E`。
4. 浏览器实际将页面标题改为 `1`，确认 DOM 侧事件执行。该 payload 中 `<` `>` 经过百分号编码；斜杠与等号保留为字面字符，因为本页 `decodeURI()` 不解码某些保留字符的百分号形式。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/xss_d/index.php` 中从 URL `default` 参数读取后进入 `document.write()` 的客户端数据流。

## 4. 脱敏请求与证据

原笔记未单独列出请求或证据材料；不得据此声称完成动态验证。

## 5. 漏洞根因

### 报告交叉摘要

数据虽然在服务端页面中交给客户端，但进入 `document.write()` 等 HTML 解析 sink 时仍被当成标记解析。简单编码 `<`、`>` 若被解码或未覆盖最终 sink，不能建立安全边界。

### 原记录：根因与修复方向

DOM sink 是 `document.write()`，source 是 `location.href` 中的 `default` 值。应避免把 URL 值拼接成 HTML 字符串：将语言限定到 `English/French/Spanish/German` 白名单，使用 `URLSearchParams` 读取参数，通过 `document.createElement('option')` 创建节点，并用 `textContent` 设置可见文本；不符合白名单时只显示默认选项。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

不要用 `document.write()` 渲染用户值；使用 DOM API 创建节点并通过 `textContent` 写文本；参数再做语义白名单（如语言/主题标识），不要把任意 URL 值当 HTML。

## 7. 修复前后回归

原笔记未提供独立的修复前后回归记录。

## 8. 限制与未验证项

### 原记录：验证边界

- ✅ 本机 Low 模式浏览器端到端验证，标题变为 `1`。
- ✅ 上游源码确认客户端 `location` → `document.write` 数据流。
- ✅ `fix.patch` 在 `index.php` 副本 dry-run/应用成功（工具报告 hunk at line 48, fuzz 2, offset -1）；PHP lint 通过。补丁移除动态 `document.write()` 拼接，以 `URLSearchParams` 读取并限制语言白名单，使用 DOM API 与 `textContent` 填充。
- ⏳ 补丁未部署到 DVWA 上游，修复后的浏览器端到端回归未做；仅完成副本应用及 PHP 语法检查。
- 仅使用本机靶场；没有外部请求或数据访问。

## 9. 复现环境

原笔记未单独记录复现环境。
