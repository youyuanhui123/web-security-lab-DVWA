# 学习记录

每阶段保留一段核心说明，必要时附数据流图；只记录真实执行结果，不把讲解等同于用户独立掌握。

## 第一阶段｜环境与范围

使用官方 DVWA 镜像及 MariaDB，在独立 Compose 项目中部署。应用仅监听宿主 127.0.0.1:4280，数据库不发布宿主端口；只在自有本地环境实验。助手已验证两容器运行及登录页 HTTP 200；用户随后提供 SQL Injection 页面截图，正常查询 ID 1 显示 First name: admin、Surname: admin，正常查询基线成立；截图未显示当前安全等级，Low 设置仍需页面另行确认。Docker 引擎冷启动曾超时，后续核实容器已正常启动，不删除重建。环境启动不等于漏洞已验证。

```text
浏览器 / Burp → 127.0.0.1:4280 → DVWA → 内部 MariaDB
                                     ↓
                         初始化 → 登录 → 正常查询基线
```

## 第二阶段｜抓取正常请求

Burp 监听和 FoxyProxy 均使用 127.0.0.1:8080；Firefox 将 network.proxy.allow_hijacking_localhost 设为 true 后，用户截图确认捕获 GET /vulnerabilities/sqli/?id=1&Submit=Submit，状态 200。根因是本地请求绕过代理，而非 Burp 地址配置错误；无需为 HTTP 导入证书。之后进入 Repeater 原样重放并核对用户信息，再做真假条件对照。

## 第三阶段｜SQL 注入验证、源码确认与修复对照

本机 DVWA Low/MySQL 中，ID=1 正常返回 admin；`1' AND '1'='1` 仍返回用户行，`1' AND '1'='2` 不返回用户行。容器源码确认 `$_REQUEST['id']` 被插入 `WHERE user_id = '$id'` 后由 `mysqli_query()` 执行。对照 DVWA Impossible：正常 ID 仍返回 admin，注入输入不返回用户行；其源码先做数值验证/转换，再用 PDO `prepare` 参数绑定。项目参考实现 `fixed_query.php` 已在 MariaDB 上测得正常 ID 返回 admin、两种条件字符串均拒绝；`fix.patch` 对原始源码副本可应用且 PHP lint 通过，未改容器原件。补丁仅覆盖当前启用的 MySQL 分支；SQLite 分支需另补绑定。已将当前实例安全等级恢复为 Low。用户给出的 HTTP 200 空表单响应只证明页面上下文，不单独证明注入。用户决定跳过 SQLi 补丁的进一步预演/部署。

## 第四阶段｜反射型 XSS 验证与副本修复

DVWA Low 的 Reflected XSS 中，`name` 参数经 GET 进入 `<pre>` 时未做 HTML 编码。基线 `LAB_MARK` 正常回显；本地浏览器提交 `<img src=x onerror=document.title='XSS_LAB_PROOF'>` 后，标题实际变成 `XSS_LAB_PROOF`，确认事件执行。容器源码证明输入直接拼接进 HTML。参考修复使用 `htmlspecialchars` 并指定 `ENT_QUOTES | ENT_SUBSTITUTE` 与 UTF-8；`fix.patch` 在源码副本 dry-run/应用成功，PHP lint 通过；独立示例的回归输出确认 HTML 被转义。补丁未部署到 DVWA 页面，修复后的浏览器端到端复测未做。

## 第五阶段｜存储型 XSS 验证与副本修复

DVWA Low guestbook 中，`low.php` 将表单字段写入数据库，公共 `dvwaGuestbook()` 在非 Impossible 模式把取出的姓名/评论原样放进 HTML。一次性 `LAB_STORED` 记录在浏览器实际执行 `onerror` 并把标题改为 `STORED_XSS_PROOF`。随后只删除本次记录，数据库原有 `test / This is a test comment.` 行保留。建议修复是对 guestbook 展示字段始终用 `htmlspecialchars`；`fix.patch` 在 helper 副本 dry-run/应用成功（hunk fuzz 2），PHP lint 通过；独立示例回归显示 HTML 标签被编码。未部署到容器上游，也未做修复后浏览器端到端复测。

## 第六阶段｜DOM 型 XSS 验证

DVWA Low 的 `xss_d/index.php` 从 URL `default` 参数取值并拼入 `document.write()`。参数 `<`、`>` 编码后仍进入 DOM sink；通过关闭 `<option>/<select>` 并生成失效 `<img>` 的 payload，浏览器页面标题实际变为 `1`，确认 DOM 事件执行。修复补丁移除了用户数据参与 `document.write()`，改用 URL 参数读取、语言白名单、DOM API 与 `textContent`；补丁已在源码副本应用，PHP lint 通过，未部署到容器上游或做修复后浏览器复测。本阶段记录于 `cases/dom-xss/NOTES.md`。

## 第七阶段｜CSP Bypass 初步源码检查

Low 源码设置多个 `script-src` 外部来源，并把 POST `include` 参数拼入 script `src`。已读源码确认数据流；但浏览器提交后会话窗口转到 `about:blank`，没有拿到有效执行或 CSP 拒绝证据，因此只记录为源码级发现，**未宣称绕过成功**。记录见 `cases/csp-bypass/NOTES.md`。

## 第八阶段｜文件上传源码检查

DVWA Low `source/low.php` 对上传名仅做 `basename()`，再直接 `move_uploaded_file()` 到 Web 可访问的 `hackable/uploads/`。最初 curl 请求缺少有效 `user_token`、返回 302，不能作为验证；随后登录取 token 后只上传一次唯一临时 PHP 探针，访问结果确认 PHP 标记和 `id` 命令输出，实测 Low 上传目录可执行 PHP 并造成命令执行。脚本自动删除探针，后续容器检查确认不存在，原有 `dvwa_email.png` 保留。修复 `fix.patch` 在源码副本 dry-run、应用和容器 PHP lint 均通过；正样本 PNG 被重新编码，文本探针被拒绝。补丁未部署，修复后的 HTTP 端到端复测未做。详见 `cases/file-upload/NOTES.md`。

## 第九阶段｜Insecure CAPTCHA 验证与修复

在独立 Docker 隔离副本中端到端验证：Low 直接提交 `step=2`、Medium 伪造客户端 `passed_captcha=true`、High 使用源码硬编码备用响应值与 User-Agent，均成功修改测试账户密码并可用新密码登录。修复补丁让 Low/Medium/High 复用 Impossible 的当前密码、CSRF token、CAPTCHA 校验与参数化更新逻辑，并为各安全等级表单加入当前密码和 token。补丁 dry-run、应用与四个 PHP 文件 lint 通过；只读挂载修复副本后，三种绕过请求都未更改密码，原密码仍有效、伪造密码不能登录。隔离网络与临时数据库已清理；reCAPTCHA 公钥为空，正常 CAPTCHA 密码修改路径未测；主 DVWA 源码和数据库未改。详见 `cases/insecure-captcha/NOTES.md`。

## 第十阶段｜SQL Injection (Blind) 验证与修复

在用户要求下先启动 Docker Desktop 和主项目 Compose；主 DVWA 登录页 HTTP 200。随后在独立隔离副本中对 Blind SQLi 的 Low/Medium/High 做真假条件成对验证，三者都能产生 exists/missing 布尔 oracle；未导出数据。修复补丁将三种入口统一委托给 Impossible 的数值校验、CSRF 与 PDO 参数绑定路径，并统一为带 token 的 GET 表单。补丁 dry-run、应用与四个 PHP 文件 lint 通过；修复副本中 `id=1` 基线仍正常，三种原真条件载荷均返回 missing，修复负测全部通过。隔离容器/临时卷已清理，主 Docker 容器与数据库卷保留；主源码和主数据库未修改。详见 `cases/sql-injection-blind/NOTES.md`。

## 第十一阶段｜Weak Session IDs 验证与修复

主 Docker 已运行；只读源码发现 Low 以 session 计数器生成连续值、Medium 用 Unix 时间戳、High 对递增计数器做 MD5。隔离副本实测三种生成规则均可预测；Impossible 使用 `random_bytes(20)` 并设置 Secure/HttpOnly 属性。修复补丁让 Low/Medium/High 统一复用 Impossible 生成逻辑；补丁 dry-run、应用与三个 PHP 文件 lint 通过。只读挂载修复副本后，三种等级连续生成的 cookie 均为不同的 40 位随机十六进制值并带 Secure/HttpOnly。没有猜测或访问他人会话；隔离栈与临时卷已清理，主项目容器和数据卷保留。详见 `cases/weak-session-id/NOTES.md`。

## 第十二阶段｜Brute Force 验证与修复

主 Docker 容器保持运行；独立隔离副本中 Low/Medium/High 各仅发送三次错误密码请求，再用正确密码做控制，均未触发锁定。修复补丁将三种入口统一委托给 Impossible 的失败计数/15 分钟锁定逻辑，并统一为 POST 与 CSRF token。补丁 dry-run、应用及四个 PHP 文件 lint 通过；修复副本中三种等级各三次错误尝试后，正确密码均被锁定逻辑拒绝。没有使用字典或持续猜测；隔离容器及临时卷已清理，主 DVWA 与数据库卷保留。详见 `cases/brute-force/NOTES.md`。

## 第十三阶段｜Command Injection 验证与修复

主 DVWA 保持运行；隔离副本中 Low/Medium/High 均以 `127.0.0.1|printf CMDI_LAB_PROOF` 显示无害标记，确认命令注入；没有读文件或访问外网。修复补丁让三档复用 Impossible 的数值 IP 校验与 CSRF token；补丁 dry-run、应用及四个 PHP 文件 lint 通过。修复副本中合法 IP 仍接受，原注入输入均作为无效 IP 被拒且不再回显标记。隔离栈和临时卷已清理，主容器和数据库卷保留；主源码未改。详见 `cases/command-injection/NOTES.md`。

## 第十四阶段｜CSRF 验证与修复

主 Docker 已运行；只读源码确认 Low 无 token 且用 GET 改密，隔离副本中带外部 Origin/Referer 的无 token GET 实际修改了测试账户密码。Medium 的 Referer 检查拒绝该模拟请求；High 与 Impossible 对缺 token 请求不改密。修复补丁让三档统一使用 token、当前密码校验和参数化更新，改为 POST；补丁 dry-run、应用与五个 PHP 文件 lint 通过。修复副本中跨站模拟 GET、缺 token POST 都不能改密；合法 token 与当前密码仍能正常改密。真实浏览器的 SameSite cookie 发送行为未测；隔离栈和临时卷已清理，主源码与主数据库未改。详见 `cases/csrf/NOTES.md`。

## 第十五阶段｜File Inclusion 验证与修复

主 Docker 保持运行；隔离副本中 Low/Medium 的绝对路径 `/etc/hostname`、High 的 `file:///etc/hostname` 均成功包含 sandbox 自身的无害文本标记；Impossible 白名单拒绝。修复补丁让 Low/Medium/High 复用固定文件名白名单；dry-run、应用和三个 PHP 文件 lint 通过。修复副本仍能包含 `file1.php`，但三个原路径载荷均被拒绝，不再包含 hostname 标记。未测试远程文件包含或 PHP 代码执行；隔离栈与临时卷已清理，主源码和主数据库未改。详见 `cases/file-inclusion/NOTES.md`。

## 第十六阶段｜JavaScript Attacks 只读源码检查

主 Docker 已确认运行。按前端 JS 审计只读边界，仅复制并检查模块源码，没有打开真实浏览器、执行脚本或提交表单。源码显示 Low/Medium/High 的 token 算法可从客户端脚本及服务端比较逻辑得知，phrase `success` 也直接显示在页面中；成功分支只生成 `Well done!` 页面提示，未发现持久化或权限变更。故结论仅为源码级：客户端派生 token 不是安全边界；没有动态绕过实测，也未对刻意设计的教学模块打补丁。真实业务应由服务端验证权限/业务规则，并将 CSRF token 与业务验证分开。记录见 `cases/javascript-attacks/NOTES.md`。

## 第十七阶段｜Open HTTP Redirect 验证与修复

主 DVWA/MariaDB 保持运行。原版和修复版均在无外网的 internal Docker 网络中测试，容器根文件系统只读，DB 为 tmpfs，未发布宿主端口。原版源码检查显示 Low 直接把 `redirect` 写入 Location；Medium 只拒绝绝对 http(s) scheme；High 只查找 `info.php` 子串。容器 loopback 的无 Cookie GET 实测：Low `https://example.invalid/redirect-proof`、Medium `//example.invalid/redirect-proof`、High `https://example.invalid/?next=info.php` 均返回 302 并回显指定 Location；未跟随跳转或访问外部域名。修复补丁让三档复用 Impossible 的固定数字 ID 映射；补丁 dry-run、应用、归一化换行比对和 PHP lint 通过。修复副本三种恶意输入均无 302/Location，ID 1、2 仍映射到本地 info.php，六项回归全部通过。两套隔离栈已清理，主卷 `web-security-lab_database` 保留，未部署主实例。详见 `cases/open-redirect/NOTES.md`。

## 第十八阶段｜Cryptography 验证

启动主 DVWA/MariaDB 后，按菜单顺序进入 Cryptography；只复制模块源码、帮助与随附攻击脚本。Low 的固定重复 XOR+Base64 解出示例密码，页面返回 `Welcome back user`；Medium 的 AES-128-ECB 演示令牌经分组重排后返回管理员身份；High 用模块自带 padding-oracle 脚本访问本地检查端点，成功恢复用户标识并获得管理员演示响应。Impossible 的 AES-256-GCM 原 token 返回普通用户，改动 token 字符后返回解密失败。High 脚本运行退出码 0；令牌和 IV 不保存在笔记。本模块未制作或部署修复补丁。安全等级已恢复 Impossible，主数据库卷未改。详见 `cases/cryptography/NOTES.md` 与 `evidence/verification-results.md`。

## 第十九阶段｜API 安全审查与本机验证

主 DVWA/MariaDB 容器保持运行，主数据库卷保留。按菜单进入 API 后从帮助页发现 v1 路由线索；只读源码确认未鉴权的 v1 用户接口输出密码哈希字段，而 v2 隐去该字段；对应请求实际 HTTP 200，返回 3 条用户记录，结果材料只记字段存在与记录数、不保存哈希。未鉴权 PUT 可在单次请求的临时对象响应中把用户 level 改为 0；后续独立 GET 仍为原值 1，确认演示控制器不持久化。health/connectivity 的 `target` 直接拼接入 `exec(ping ...)`：本机回环基线 HTTP 200；仅追加 shell 内建 `false` 的测试变为 HTTP 500，未执行任意外部程序、读文件或访问外网。未授权订单请求包含无效 token 提示，但 PHP deprecation/warning 先输出，未把它当作正确 401。API 源码证据副本中的硬编码凭据、密钥与用户密码哈希已脱敏为 `[REDACTED]`。没有创建/删除业务记录、修改安全等级、制作补丁或改动主源码。详见 `cases/api/NOTES.md`。

## 第二十阶段｜案例审阅结构统一

为方便 HR 快速审阅，17 份 `cases/<module>/NOTES.md` 已按“问题影响 → 发现过程 → 核心代码位置 → 脱敏请求/证据 → 根因 → Patch diff/修复建议 → 修复前后回归 → 限制 → 复现环境”重排。逐模块报告中的成因、代码定位、实测效果与 Patch 分析摘要已补入对应章节；原有详细证据与限定保留在“原记录”小节，补丁文件提供直链。未记录项明确标记未验证；此项工作只整理现有材料，没有重新测试漏洞，也没有将补丁部署到主 DVWA。案例模板位于 `cases/CASE_TEMPLATE.md`，README 案例索引直链至各篇审阅摘要。

