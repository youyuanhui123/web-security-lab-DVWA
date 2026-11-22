# SQL 注入验证与修复记录

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

本机 Low 中正常 ID 返回 admin；恒真条件仍返回用户行，恒假条件不返回用户行。Impossible 中正常查询仍有效，注入输入不再返回用户行。

### 原记录：结论

DVWA Low 模式的 MySQL 分支存在可复现 SQL 注入。输入 `id` 被直接拼入带引号的 SQL 字符串，再交给 `mysqli_query()` 执行。基线 `id=1` 返回 admin；附加恒真条件仍返回 admin，恒假条件不返回用户行。页面状态码为 200 本身不是证明，判断依据是结果内容差异与源码数据流。

## 2. 发现过程

原笔记未单独记录发现过程。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/sqli/source/low.php`，`$_REQUEST['id']` → 查询字符串 → `mysqli_query()`。安全对照 `impossible.php` 先做数值验证/转换，并用 PDO 参数绑定。

### 原记录：源码证据

容器内文件：`/var/www/html/vulnerabilities/sqli/source/low.php`。

```php
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

该文件在本次运行容器中的 SHA-256：`652bb44d14a9d81c9245f05ed8440beecf7977e982e00d3ddb916126a72e85bf`。
运行环境实测为 PHP 8.5.12、mysqli 已加载、DVWA SQLi DB 为 MySQL。

## 4. 脱敏请求与证据

### 原记录：实测记录

| 状态 | 输入 | 观察结果 | 结论 |
|---|---|---|---|
| Low 基线 | `1` | `First name: admin`、`Surname: admin` | 正常业务路径可用 |
| Low 真条件 | `1' AND '1'='1` | 仍显示 admin | 输入影响 SQL 条件逻辑 |
| Low 假条件 | `1' AND '1'='2` | 页面不渲染用户行 | 与真条件形成稳定差分，确认可注入 |
| Impossible 基线 | `1` | 仍显示 admin | 修复后正常查询保留 |
| Impossible 注入输入 | `1' AND '1'='1` | 不渲染用户行 | 安全实现不把输入解析成 SQL 语法 |

用户提供的 HTTP 200 页面正文是 SQLi 页面空表单，没有查询结果；它仅证明页面加载、`security=low` 和 `SQLi DB=mysql` 等上下文，不能单独作为注入证据。

## 5. 漏洞根因

### 报告交叉摘要

Low 把 `id` 直接插入带引号的 SQL 条件，数据库收到的是由输入共同构造的 SQL 语法，而不是固定查询加独立参数。攻击者能改变 WHERE 条件。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

按字段类型做严格验证；使用参数化查询，不把输入拼入 SQL。表名、列名、排序方向等不能由普通占位符绑定的语法位置，应使用服务端白名单。

### 原记录：修复方向

参考 DVWA 自带 `impossible.php`：先验证输入为数字并转成整数，再用 PDO 参数化查询（`prepare`、`bindParam`/`bindValue`、`execute`）。项目内 `fixed_query.php` 是独立的参考实现，不会改写上游容器；它从 `DVWA_TEST_DSN`、`DVWA_TEST_USER`、`DVWA_TEST_PASSWORD` 读取临时测试连接信息，不保存凭据。

当前靶场实际配置是 MySQL。上游 `low.php` 还包含 SQLite 分支；若将补丁用于 SQLite 部署，必须同时改用 SQLite3 参数绑定，不能只修 MySQL 分支后宣称所有后端都已修复。

## 7. 修复前后回归

原笔记未提供独立的修复前后回归记录。

## 8. 限制与未验证项

### 原记录：证据边界

- ✅ 已在本机容器复现低安全等级真假条件差分，并检查源码。
- ✅ 已用 DVWA 的 Impossible 模式对照正常查询与注入输入。
- ✅ `fixed_query.php` 已通过 PHP 8.5.12 语法检查，并在本机 MariaDB 上运行：`normal ID: admin`；真假条件输入均为 `no row`。临时测试凭据来自本地 Compose 环境变量，未写入文件。
- ✅ `fix.patch` 已对运行容器中的原始 `low.php` 副本通过 dry-run、成功应用，应用后 PHP 语法检查通过；未覆盖容器内上游源文件。
- 未尝试枚举数据库、读取其他用户资料、修改或删除数据。
- 测试期间将安全等级临时切换为 Impossible，测试后已恢复 Low；容器停止后保留数据库卷。

## 9. 复现环境

### 原记录：范围与原始上下文

> 范围：只测试自建 DVWA（`127.0.0.1:4280`）的 SQL Injection 模块；不访问外部目标。
