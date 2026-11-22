# DVWA File Inclusion：验证与修复

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

隔离沙箱中 Low/Medium 通过绝对路径、High 通过 `file://` 包含沙箱内无害标记；Impossible 白名单拒绝。未测远程文件包含和 PHP 代码执行。

## 2. 发现过程

### 原记录：范围与发现链

先对照 Low/Medium/High/Impossible 的 `source/*.php` 和模块入口。Low 直接把 `page` 交给 `include()`；Medium 只删除 `../`、`..\\` 与 `http(s)://`；High 只允许 `fnmatch("file*", $file)` 或 `include.php`，因此本地 `file://` wrapper 仍落在允许前缀内；Impossible 使用固定文件名白名单。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/fi/source/low.php`、`medium.php`、`high.php` 的 page/file 参数和包含逻辑；Impossible 用固定文件映射作对照。

## 4. 脱敏请求与证据

### 原记录：动态验证（隔离副本，实测）

在独立 Docker 副本中，以容器自己的 `/etc/hostname` 作为无害文本标记，分别请求 Low/Medium 的绝对路径 `/etc/hostname`、High 的 `file:///etc/hostname`。三档响应都包含该标记，确认本地文件可被包含。Impossible 对同一路径返回拒绝，不包含标记。测试没有读取主机文件或导出敏感文件。

## 5. 漏洞根因

### 报告交叉摘要

用户可控路径直接进入 `include`/文件读取逻辑；路径过滤不足时可以越出预期目录或使用 PHP stream wrapper。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

外部参数只接受固定 ID/文件名，再由服务器端白名单映射到路径；规范化路径并确保目标在固定目录内；关闭不需要的远程包含能力。

### 原记录：修复与复测（隔离副本，实测）

`fix.patch` 让 Low/Medium/High 委托给 Impossible 的固定白名单。补丁 dry-run、应用及三个改动 PHP 文件 lint 通过。修复副本中，三个安全等级均可包含白名单内的 `file1.php`；原始任意路径 payload 均被拒绝，响应不再包含文件标记。输出摘要见 `evidence/verification-results.md`。

## 7. 修复前后回归

相关修复回归原记录位于第 6 节：“修复与复测（隔离副本，实测）”。该处保留原始结果，未在此重复或扩写。


## 8. 限制与未验证项

### 原记录：隔离与边界

- 测试运行于独立数据库卷、Docker internal network、只读应用文件系统和资源限制下。
- 本次只验证本地文件包含读取，未测试远程文件包含，也未验证 PHP 代码执行。
- 补丁只用于源码副本和隔离栈；未修改主 DVWA 源码或主数据库。
- 两套隔离栈和临时数据库卷已删除；主 DVWA 与 MariaDB 保持运行，主数据卷保留。

## 9. 复现环境

原笔记未单独记录复现环境。
