# DVWA 存储型 XSS：验证与副本修复

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

隔离测试记录在浏览器中触发事件，标题变为 `STORED_XSS_PROOF`。随后只删除本次测试行，原有示例记录保留。

## 2. 发现过程

### 原记录：结论与发现链

仅测试本机 DVWA `127.0.0.1:4280` 的 Stored XSS guestbook。Low 模式下，输入写入 `guestbook` 表，随后由页面逐条取出并未经 HTML 编码插入 DOM。用一次性本地事件把页面标题改为 `STORED_XSS_PROOF`，实际观察到标题变化，证明存储后执行。

1. Guestbook 页面已有正常记录 `test / This is a test comment.`，作为基线。
2. 在表单提交唯一标识 `LAB_STORED` 与消息 `<img src=x onerror=document.title='STORED_XSS_PROOF'>`。
3. 页面显示该记录，并因破图触发事件将标题改成 `STORED_XSS_PROOF`。
4. 源码追踪确认：`low.php` 将表单内容插入数据库；`dvwaGuestbook()` 从数据库取出后，在非 Impossible 模式直接输出 `$row[0]` 与 `$row[1]`。
5. 删除仅由本次实验创建的 `LAB_STORED` 记录并查询确认；原有 `test` 记录保留。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/xss_s/source/low.php` 的写入路径，以及负责读取/渲染 guestbook 的公共 `dvwaGuestbook()` 输出逻辑。

### 原记录：源码证据

`xss_s/source/low.php` 用 `mysqli_real_escape_string()` 处理写库数据，但这只是 SQL 字符串层的处理，并不对 HTML 输出做编码。公共展示逻辑位于 `dvwa/includes/dvwaPage.inc.php` 的 `dvwaGuestbook()`：Impossible 模式会 `htmlspecialchars()`；其他模式原样输出。这说明存储型 XSS 的根因在**展示时缺少 HTML 上下文编码**，不是数据库存储本身。

## 4. 脱敏请求与证据

原笔记未单独列出请求或证据材料；不得据此声称完成动态验证。

## 5. 漏洞根因

### 报告交叉摘要

输入存入数据库时保留了攻击者控制的 HTML；之后 guestbook 读取并原样输出，使查看页面的用户浏览器执行内容。存储使影响跨请求、跨访问者持续存在。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

存储原始业务文本，在每个输出上下文正确编码；不要只在写入时做一次不明用途的过滤。若允许富文本，需使用白名单 sanitizer 并限制 URL/属性。

### 原记录：修复材料

- `fix.patch`：示范将 guestbook 输出统一进行 HTML 编码的补丁，适用于源码副本；不会自行改写容器。
- `fixed.php`：独立渲染示例，用于回归普通文本与恶意标记。

## 7. 修复前后回归

原笔记未提供独立的修复前后回归记录。

## 8. 限制与未验证项

### 原记录：验证状态与边界

- ✅ Low 模式浏览器实测，提交后持久化记录触发事件并改写本地页面标题。
- ✅ 容器源码确认写库与输出点，定位到输出编码缺失。
- ✅ 实验记录已从 guestbook 删除；数据库剩余原有 `test` 示例行。
- ✅ `fix.patch` 对 `dvwa/includes/dvwaPage.inc.php` 副本 dry-run 通过并应用（工具报告 hunk at line 615, fuzz 2）；补丁文件及 `fixed.php` 均通过 PHP lint。
- ✅ `fixed.php` 回归：普通评论保持正常显示，`<img ...>` 被编码为 `&lt;img ...&gt;`。
- ⏳ 未将补丁部署到容器上游源码，也未做修复后的浏览器端 HTTP 复测。
- 仅限自建回环靶场；未读取或发送会话数据，未触碰靶场外文件。

## 9. 复现环境

原笔记未单独记录复现环境。
