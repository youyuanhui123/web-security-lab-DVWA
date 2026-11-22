# DVWA 反射型 XSS：验证与副本修复

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

正常标记回显后，本机浏览器载入事件型输入，页面标题实际变为 `XSS_LAB_PROOF`，证明脚本事件执行，不是仅看见字符串回显。

## 2. 发现过程

### 原记录：范围与结论

仅测试本机 DVWA `127.0.0.1:4280` 的 Reflected XSS 模块。Low 模式下，`name` 参数未经 HTML 编码直接拼入 `<pre>`；通过本地浏览器观察到输入标签被解析，且事件处理器将页面标题改为 `XSS_LAB_PROOF`。这是反射型 XSS 的浏览器端执行证据，不只是 HTTP 200 或响应中出现字符串。

### 原记录：发现过程与证据

1. 访问 `/vulnerabilities/xss_r/`，页面提供 `name` 参数的问候表单。
2. 基线请求 `?name=LAB_MARK` 显示 `Hello LAB_MARK`。
3. 将 `<img src=x onerror=document.title='XSS_LAB_PROOF'>` 放入 `name`。页面 DOM 中形成真实 `img` 元素；破图触发 `onerror`，页面标题实际变为 `XSS_LAB_PROOF`。
4. 容器内 Low 源码为：

```php
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Feedback for end user
    $html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}
```

数据流是 `$_GET['name']` → 字符串拼接 → HTML 文本上下文，未编码。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/xss_r/source/low.php` 的 GET `name` 读取和 HTML 输出位置。

### 原记录明确提及的代码文件

以下仅汇总原记录中出现的路径，不增加新的源码判断：

- `source/low.php`


## 4. 脱敏请求与证据

原笔记未单独列出请求或证据材料；不得据此声称完成动态验证。

## 5. 漏洞根因

### 报告交叉摘要

请求参数未经与 HTML 上下文相匹配的编码，直接写入页面；浏览器将可控内容解析为标签/事件，而非纯文本。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

HTML 文本/属性上下文使用正确编码；PHP 输出建议用 `htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`。避免未经上下文处理的 HTML 拼接；若业务确需富文本，使用经过维护的 HTML sanitizer。

### 原记录：修复

参考 DVWA Impossible 实现，在输出前进行 HTML 上下文编码。`fix.patch` 仅针对 MySQL 无关的反射型 XSS 模块 `source/low.php`，采用 `htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`；补丁只在本地源码副本上预演，不覆盖容器上游文件。

- `fix.patch`：移植到目标源码副本的差异。
- `fixed.php`：独立修复示例，便于阅读/单独验证。

## 7. 修复前后回归

### 原记录：验收与边界

- ✅ Low 模式：正常标记显示；`<img src=x onerror=document.title='XSS_LAB_PROOF'>` 的事件实际执行，浏览器标题变成 `XSS_LAB_PROOF`。
- ✅ 源码：确认输入未经编码后进入 HTML。
- ✅ `fix.patch` 在容器源码副本上 dry-run 通过并应用成功；补丁后 PHP 文件 `php -l` 通过。
- ✅ 独立 `fixed.php` 语法检查通过；命令行回归显示普通文本不变，`<b>` 与 `<img ...>` 均编码成 `&lt;...&gt;`，事件处理器不会形成活动标签。
- ⏳ 未将补丁部署到 DVWA 页面，未做修复后浏览器端到端复测。
- 未访问外部目标，未读取会话数据或尝试窃取凭据。

## 8. 限制与未验证项

原笔记未单独列出限制或未验证项；未提及不等于已验证。

## 9. 复现环境

原笔记未单独记录复现环境。
