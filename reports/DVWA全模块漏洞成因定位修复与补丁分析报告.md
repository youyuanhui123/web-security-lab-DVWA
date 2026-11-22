# DVWA 漏洞成因、核心定位、修复建议与 Patch 分析报告

## 1. 报告摘要

本报告汇总本机授权 DVWA 学习项目中已有记录的漏洞模块。覆盖 SQL Injection、XSS、File Upload、认证/会话、CSRF、File Inclusion、Open Redirect、Cryptography、API 等 17 个模块。重点区分：源码审查、原版动态验证、修复副本测试、补丁部署四种不同证据，不把“补丁可应用/语法通过”写成“主站已修复”。

**总体结论**：多个教学等级通过不安全输入处理、缺失服务端授权、弱密码学或不安全状态管理暴露风险。已有 13 个模块形成 `fix.patch`；补丁只在源码副本或隔离环境中验证，**没有部署到主 DVWA**。CSP Bypass、JavaScript Attacks、Cryptography、API 没有制作修复补丁；其中 CSP 与 JavaScript 以源码观察为主，Cryptography 和 API 有本机演示/端点实测。主数据库卷保留。

### 证据状态含义

- **动态实测**：在本机 DVWA 或注明的隔离副本发送请求，并观察到能够支持结论的结果。
- **源码审查**：确认代码路径/危险调用，但没有可复核的动态成功信号。
- **修复副本回归**：只验证隔离副本或独立修复样例，不代表主站已修复。
- **未部署**：主 DVWA 上游文件未被本报告中的补丁覆盖。

## 2. 范围与测试边界

- 目标：本机自建 DVWA，应用地址 `http://127.0.0.1:4280`，MariaDB 不对宿主机发布端口。
- 文件依据：项目 `study.md`、`cases/<module>/NOTES.md`、相应 `fix.patch` 与 `evidence/`。各模块记录保存了具体请求、观察结果和未测项。
- 有状态或写操作优先在隔离 Compose / 临时数据库中验证；上传探针在本机靶场短暂使用后已删除。未执行对外扫描、外部目标攻击、数据库导出或破坏性批量操作。
- API 和 Cryptography 材料中的凭据、密码哈希、密钥、token、IV 等均不在本报告复述；相关证据副本已按项目约定脱敏。
- 本报告不覆盖未形成案例记录的 DVWA 模块；例如菜单中条件启用的 Authorization Bypass 未纳入本轮结果，不能据此推断其安全或存在漏洞。

## 3. 模块发现与修复总览

| 模块 | 核心成因 / 定位 | 实际验证 | Patch 状态 |
|---|---|---|---|
| SQL Injection | 输入拼接 SQL | Low 真假条件差异实测 | MySQL 参数化查询 patch / 副本语法检查；SQLite 未覆盖，未部署 |
| Reflected XSS | 输出上下文未编码 | 浏览器事件执行实测 | HTML 编码 patch / 副本检查；未部署，未做修复后浏览器复测 |
| Stored XSS | 存储内容展示时未编码 | 浏览器事件执行实测，测试行已清理 | 输出编码 patch / 副本 lint；未部署 |
| DOM XSS | URL 数据进入 `document.write()` | 浏览器 DOM 事件实测 | 白名单 + DOM API / `textContent` patch；未部署 |
| CSP Bypass | 用户输入进入 script URL | 源码可疑，动态结论未成立 | 无 patch |
| File Upload | 上传校验不足，落入可访问目录 | 临时 PHP 探针实测执行，已清理 | 图片重编码/随机名/非 Web 目录 patch，隔离验证；未部署 |
| Insecure CAPTCHA | 步骤、客户端状态或备用校验可伪造 | Low/Medium/High 隔离副本均实测绕过改密 | 复用严格校验逻辑 patch，隔离回归通过；正常 reCAPTCHA 流程未测，未部署 |
| SQL Injection (Blind) | 注入条件可被真假响应作为 oracle | Low/Medium/High 隔离副本实测 | 数值校验 + CSRF + PDO 参数绑定 patch，副本回归通过；未部署 |
| Weak Session IDs | 会话标识由可预测值生成 | Low/Medium/High 隔离副本实测可预测性 | 统一安全随机值 / Cookie 属性 patch，副本验证通过；未部署 |
| Brute Force | 缺少有效失败次数限制/锁定 | 三次错误后正确密码仍可登录 | 失败计数/锁定、POST、CSRF patch，副本验证通过；未部署 |
| Command Injection | 用户输入进入系统命令 | 无害标记在 Low/Medium/High 隔离副本实测 | IP 校验 + CSRF patch，合法与恶意输入回归通过；未部署 |
| CSRF | Low 缺少服务端请求来源/令牌校验 | 隔离副本跨站模拟 GET 实际改密 | POST + token + 当前密码及参数化更新 patch；未部署 |
| File Inclusion | 文件路径由用户输入决定 | 沙箱绝对路径 / file wrapper 包含标记实测 | 固定文件名白名单 patch，副本回归通过；未部署 |
| JavaScript Attacks | 客户端 token/逻辑可见 | 只读源码审查 | 无动态绕过结论，无 patch |
| Open HTTP Redirect | 不同等级对跳转目标过滤不足 | 隔离环境三档均返回外部 Location，未跟随跳转 | 固定数字 ID 映射 patch，六项回归通过；未部署 |
| Cryptography | XOR、ECB、padding oracle 等教学缺陷 | Low/Medium/High/Impossible 演示差异实测 | 无 patch；Impossible 仅作现有安全实现对照 |
| API | 旧版敏感字段、无授权写入、shell 参数拼接等 | v1/v2、PUT、connectivity 和订单拒绝响应有实测 | 无 patch；未部署 |

## 4. 逐模块分析

### 4.1 SQL Injection

**漏洞成因**：Low 把 `id` 直接插入带引号的 SQL 条件，数据库收到的是由输入共同构造的 SQL 语法，而不是固定查询加独立参数。攻击者能改变 WHERE 条件。

**核心定位**：`vulnerabilities/sqli/source/low.php`，`$_REQUEST['id']` → 查询字符串 → `mysqli_query()`。安全对照 `impossible.php` 先做数值验证/转换，并用 PDO 参数绑定。

**实际效果**：本机 Low 中正常 ID 返回 admin；恒真条件仍返回用户行，恒假条件不返回用户行。Impossible 中正常查询仍有效，注入输入不再返回用户行。

**修复建议**：按字段类型做严格验证；使用参数化查询，不把输入拼入 SQL。表名、列名、排序方向等不能由普通占位符绑定的语法位置，应使用服务端白名单。

**Patch 分析**：`cases/sql-injection/fix.patch` 以参数绑定替换 MySQL 查询中的字符串拼接；独立 `fixed_query.php` 在本机 MariaDB 上通过正常 ID 和真假输入对照。补丁对副本 dry-run/应用及 PHP lint 通过，但补丁仅覆盖当前 MySQL 分支；SQLite 需要 SQLite3 自身的参数绑定实现。暂时决定不做进一步补丁预演/部署，主实例未修改。

### 4.2 Reflected XSS

**漏洞成因**：请求参数未经与 HTML 上下文相匹配的编码，直接写入页面；浏览器将可控内容解析为标签/事件，而非纯文本。

**核心定位**：`vulnerabilities/xss_r/source/low.php` 的 GET `name` 读取和 HTML 输出位置。

**实际效果**：正常标记回显后，本机浏览器载入事件型输入，页面标题实际变为 `XSS_LAB_PROOF`，证明脚本事件执行，不是仅看见字符串回显。

**修复建议**：HTML 文本/属性上下文使用正确编码；PHP 输出建议用 `htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`。避免未经上下文处理的 HTML 拼接；若业务确需富文本，使用经过维护的 HTML sanitizer。

**Patch 分析**：`cases/reflected-xss/fix.patch` 在输出点加 HTML 编码；副本 dry-run/应用、PHP lint 和独立输出回归通过。未部署，也未在修复后的页面做浏览器端到端复测，因此不能把独立样例等同完整页面闭环。

### 4.3 Stored XSS

**漏洞成因**：输入存入数据库时保留了攻击者控制的 HTML；之后 guestbook 读取并原样输出，使查看页面的用户浏览器执行内容。存储使影响跨请求、跨访问者持续存在。

**核心定位**：`vulnerabilities/xss_s/source/low.php` 的写入路径，以及负责读取/渲染 guestbook 的公共 `dvwaGuestbook()` 输出逻辑。

**实际效果**：隔离测试记录在浏览器中触发事件，标题变为 `STORED_XSS_PROOF`。随后只删除本次测试行，原有示例记录保留。

**修复建议**：存储原始业务文本，在每个输出上下文正确编码；不要只在写入时做一次不明用途的过滤。若允许富文本，需使用白名单 sanitizer 并限制 URL/属性。

**Patch 分析**：`cases/stored-xss/fix.patch` 针对共享 guestbook 渲染出口编码姓名与评论，修复覆盖点优于只改某个输入表单。补丁在 helper 副本通过 dry-run/应用、PHP lint 和独立输出回归；未部署、没有做修复后浏览器复测。

### 4.4 DOM XSS

**漏洞成因**：数据虽然在服务端页面中交给客户端，但进入 `document.write()` 等 HTML 解析 sink 时仍被当成标记解析。简单编码 `<`、`>` 若被解码或未覆盖最终 sink，不能建立安全边界。

**核心定位**：`vulnerabilities/xss_d/index.php` 中从 URL `default` 参数读取后进入 `document.write()` 的客户端数据流。

**实际效果**：本机浏览器验证事件执行，标题变为 `1`。

**修复建议**：不要用 `document.write()` 渲染用户值；使用 DOM API 创建节点并通过 `textContent` 写文本；参数再做语义白名单（如语言/主题标识），不要把任意 URL 值当 HTML。

**Patch 分析**：`cases/dom-xss/fix.patch` 删除用户数据进入 `document.write()` 的路径，改用 URL 参数处理、白名单和 DOM API/`textContent`。源码副本 PHP lint 通过；未部署，修复后浏览器端到端回归未做。

### 4.5 CSP Bypass（仅源码级发现）

**疑似成因与定位**：Low 源码把 POST `include` 参数拼到脚本 `src`，同时页面配置多个 `script-src` 来源；若攻击者能影响所加载脚本资源，CSP 可能无法达到预期防护。

**实际效果**：页面交互转到 `about:blank`，没有取得有效脚本执行或 CSP 拒绝证据。当前结论仅是源码中存在待验证数据流，**但不能称为 CSP 绕过已成功**。

**修复建议**：不要将任意请求参数拼入 script URL；用固定资源映射或 nonce/hash 策略，采用严格 CSP 并移除不必要的宽泛来源。

**Patch 分析**：没有 `fix.patch`，没有验证可执行路径，故无补丁效果可报告。

### 4.6 File Upload

**漏洞成因**：Low 主要对文件名做路径层面的 `basename()` 处理，缺少可靠内容校验，并把文件放在 Web 可访问目录；若服务器会解析上传目录中的 PHP，上传即变成代码执行入口。

**核心定位**：`vulnerabilities/upload/source/low.php` 的上传接收、命名、移动逻辑；上传目标为 `hackable/uploads/`。

**实际效果**：第一次缺少有效表单 token 的请求返回 302，不作为漏洞证据。随后使用有效会话上传唯一临时 PHP 探针，访问结果显示 PHP 标记和无害 `id` 输出；探针已删除，容器检查确认不存在，原有 `dvwa_email.png` 保留。

**修复建议**：服务端确认内容格式，若业务只收图片则实际解码并重新编码；随机生成存储名；将上传文件放在 Web 根目录外，或以不可执行方式静态提供；限制权限、大小、类型和下载响应头。

**Patch 分析**：`cases/file-upload/fix.patch` 使用图片重编码、随机文件名、非公开存储目录等措施。隔离副本中有效图片接受、文本探针拒绝，PHP lint 通过。补丁未部署，修复后 HTTP 端到端访问回归未做。

### 4.7 Insecure CAPTCHA

**漏洞成因**：将流程状态或验证码结果信任客户端字段、允许直接跳过步骤，或在高等级中使用可预测/硬编码备用验证信息；服务器没有在最终敏感操作前重新完成可信校验。

**核心定位**：`vulnerabilities/captcha/source/low.php`、`medium.php`、`high.php` 的步骤判断和改密路径；Impossible 提供更严格的参考校验。

**实际效果**：独立 Docker 副本中，Low 直接跳到后续步骤、Medium 伪造客户端 `passed_captcha` 状态、High 使用源码备用验证逻辑，均实际改了测试账户密码，并可用新密码登录。reCAPTCHA 公钥为空，正常外部 CAPTCHA 流程没有覆盖。

**修复建议**：验证码验证必须由服务端完成，验证结果与当前会话/操作绑定；不以 hidden field、User-Agent 或硬编码备用值代表通过；敏感改密操作还应要求当前密码和 CSRF token。

**Patch 分析**：`cases/insecure-captcha/fix.patch` 让 Low/Medium/High 走严格校验路径，并补齐当前密码与 CSRF token。补丁 dry-run、应用及 PHP lint 通过；修复副本中三种绕过均不能改密，原密码仍可用、攻击者指定的新密码不可用。隔离栈已清理；未部署，正常 CAPTCHA 通过路径未验证。

### 4.8 SQL Injection (Blind)

**漏洞成因**：查询虽不直接显示数据，输入仍影响 SQL 条件；应用以结果是否存在、响应差异等作为 oracle，攻击者可逐步推断数据库状态。

**核心定位**：`vulnerabilities/sqli_blind/source/low.php` 至 `high.php` 的输入处理和数据库查询。

**实际效果**：独立隔离副本中 Low、Medium、High 的真假条件成对测试均产生 `exists/missing` 差异，确认布尔 oracle；没有导出数据。

**修复建议**：参数绑定；对 ID 做严格类型校验；统一错误和响应形态，避免把查询真假泄漏为可观察 oracle；必要时使用最小权限数据库账户。

**Patch 分析**：`cases/sql-injection-blind/fix.patch` 将低/中/高入口统一委托到 Impossible 的数值校验、CSRF 和 PDO 参数化路径。补丁 dry-run、应用、PHP lint 通过；修复副本正常 ID 保留，原真条件载荷返回 missing。隔离栈/临时卷已清理；未部署主实例。

### 4.9 Weak Session IDs

**漏洞成因**：会话标识由计数器、当前时间或其简单散列生成，随机性不足；攻击者可预测候选标识，威胁会话接管。

**核心定位**：`vulnerabilities/weak_id/source/low.php`、`medium.php`、`high.php` 的 session id 生成逻辑；Impossible 使用安全随机来源。

**实际效果**：隔离副本中 Low 的连续计数、Medium 的时间值、High 的计数器 MD5 均呈可预测性。没有猜测或访问他人会话。

**修复建议**：使用密码学安全随机数生成器，确保足够熵；由框架生成/轮换会话 ID，并配置 Secure、HttpOnly、合适 SameSite 与 HTTPS。

**Patch 分析**：`cases/weak-session-id/fix.patch` 让三档复用 Impossible 的随机生成逻辑并补齐 Cookie 安全属性。修复副本连续生成的值彼此不同，为 40 位随机十六进制并带 Secure/HttpOnly；补丁和三个 PHP 文件 lint 通过。未部署。

### 4.10 Brute Force

**漏洞成因**：认证失败后没有有效限速、账户/来源级锁定或延迟策略，正确凭据在少量错误尝试后仍可使用，无法阻止持续猜测。

**核心定位**：`vulnerabilities/brute/source/low.php`、`medium.php`、`high.php` 的登录失败处理与锁定状态。

**实际效果**：隔离副本每档仅发送三次错误密码，再以正确密码控制；Low/Medium/High 均未锁定，正确密码仍能登录。没有使用字典或长期猜测。

**修复建议**：服务端失败计数、逐步延迟、账户/来源联合限速、15 分钟等有界锁定、审计告警；避免永久锁账户导致拒绝服务；统一安全响应。

**Patch 分析**：`cases/brute-force/fix.patch` 让低/中/高复用 Impossible 的失败计数/15 分钟锁定逻辑，并统一 POST 与 CSRF token。补丁和 PHP lint 通过；修复副本三次错误后正确密码也被锁定逻辑拒绝。未进行长时间压力测试，也未部署。

### 4.11 Command Injection

**漏洞成因**：用户输入被拼接入操作系统命令；shell 元字符改变命令结构，输入不再只是 IP/业务参数。

**核心定位**：`vulnerabilities/exec/source/low.php`、`medium.php`、`high.php` 中拼接并执行 ping 的代码。

**实际效果**：隔离副本中 Low/Medium/High 使用 `printf` 无害标记验证，均显示预期标记；没有读文件或外联。

**修复建议**：首选移除 shell，改用安全网络库；若必须调用 ping，严格校验 IP，使用参数数组/无 shell 调用，并控制可访问目标范围，不能只靠字符黑名单或简单转义。

**Patch 分析**：`cases/command-injection/fix.patch` 让三档复用 Impossible 的 IP 验证与 CSRF 逻辑。修复副本合法 IP 被接受，原注入输入作为非法 IP 拒绝且不再显示标记；补丁及 PHP lint 通过。未部署。

### 4.12 CSRF

**漏洞成因**：浏览器自动携带受害者会话 Cookie；Low 的改密操作缺少不可预测 CSRF token / 强制 POST 等校验，攻击者可诱导已登录浏览器代发请求。

**核心定位**：`vulnerabilities/csrf/source/low.php` 至 `high.php` 的改密方法、Referer/token 校验与更新逻辑。

**实际效果**：独立副本中 Low 带外部 Origin/Referer 的无 token GET 实际改密；Medium 的 Referer 检查拒绝；High/Impossible 缺 token 不改密。

**修复建议**：对状态变更仅使用 POST/PUT/DELETE；验证服务端生成并绑定会话的 CSRF token；当前密码校验属于额外保护但不能替代 token；Cookie 设置 SameSite、Secure、HttpOnly，服务端仍需检查请求来源。

**Patch 分析**：`cases/csrf/fix.patch` 让低/中/高复用 Impossible 的 token、当前密码校验和参数化更新，并改为 POST。修复副本跨站模拟 GET、缺 token POST 均不改密；合法 token 和当前密码路径通过。真实浏览器 SameSite 行为未测；未部署。

### 4.13 File Inclusion

**漏洞成因**：用户可控路径直接进入 `include`/文件读取逻辑；路径过滤不足时可以越出预期目录或使用 PHP stream wrapper。

**核心定位**：`vulnerabilities/fi/source/low.php`、`medium.php`、`high.php` 的 page/file 参数和包含逻辑；Impossible 用固定文件映射作对照。

**实际效果**：隔离沙箱中 Low/Medium 通过绝对路径、High 通过 `file://` 包含沙箱内无害标记；Impossible 白名单拒绝。未测远程文件包含和 PHP 代码执行。

**修复建议**：外部参数只接受固定 ID/文件名，再由服务器端白名单映射到路径；规范化路径并确保目标在固定目录内；关闭不需要的远程包含能力。

**Patch 分析**：`cases/file-inclusion/fix.patch` 让 Low/Medium/High 统一使用 Impossible 的固定名称白名单。dry-run、应用、PHP lint 和攻击拒绝/合法文件回归通过；隔离环境已清理，未部署。

### 4.14 JavaScript Attacks

**漏洞成因与定位**：客户端脚本中的 token/验证逻辑可被查看或修改；若服务端把客户端生成结果当作授权依据，客户端控制就不是安全边界。源码显示成功提示本身不意味着后端写入或权限改变。

**实际效果**：只读审查 PHP/JS 源码；未运行脚本、未提交表单、未做动态绕过。未发现该成功分支写数据库或持久化权限变化，因此不报告为已验证的权限提升。

**修复建议**：敏感权限与业务规则在服务端重新验证；客户端 token 仅作界面流程辅助，不能充当授权；CSRF token 与业务授权分开设计。

**Patch 分析**：没有 patch。原因是该模块按刻意设计的教学前端检查审阅，且没有动态漏洞证据；不应为了给出补丁而臆造缺陷。

### 4.15 Open HTTP Redirect

**漏洞成因**：跳转目标由请求参数控制，或过滤仅检查部分 scheme/子串，未对最终目标做严格允许列表校验。

**核心定位**：`vulnerabilities/open_redirect/source/low.php`、`medium.php`、`high.php` 的 Location 生成与过滤；Impossible 采用固定 ID 映射。

**实际效果**：在无外网的隔离网络、容器内部请求中，Low 的绝对 URL、Medium 的协议相对 URL、High 的参数子串绕过均得到 302 和指定 Location。没有跟随重定向，也没有访问外部站点。

**修复建议**：跳转目标以固定数字 ID 或服务器端枚举映射；禁止直接把用户输入写入 Location；对本地相对目标也做规范化和白名单校验。

**Patch 分析**：`cases/open-redirect/fix.patch` 令 Low/Medium/High 复用 Impossible 的固定数字映射。修复副本恶意输入无 302/Location，合法 ID 1、2 仍转到本地页面；六项回归、PHP lint、补丁检查通过。两套隔离栈已清理，主卷保留，未部署。

### 4.16 Cryptography

**漏洞成因与定位**：Low 用重复 XOR 和 Base64；Medium 用 AES-ECB，密文块可重排；High 的 CBC 错误响应泄漏 padding 是否有效，形成 oracle；Impossible 使用带认证的 AES-256-GCM。

**实际效果**：Low 解出教学演示消息并通过演示页面；Medium 重排 ECB 块得到管理员演示响应；High 调用模块自带 oracle 脚本，成功恢复并改写 token 中的身份字段；Impossible 原 token正常返回普通用户，篡改后服务端拒绝。未探测外网、未执行系统命令、未持久化改动。

**修复建议**：不要自制加密/认证协议；采用成熟 AEAD（如 GCM）并验证 tag，正确使用随机 nonce；token 采用标准签名/校验和严格过期策略，避免将明文敏感信息放入可控结构；对外错误响应统一，避免 oracle。

**Patch 分析**：没有修复补丁。Impossible 是源码已存在的安全等级对照，不等于 Low/Medium/High 已修复；安全等级最终恢复为 Impossible。演示页面成功并不代表真实认证系统。

### 4.17 API

**漏洞成因与核心定位**：

- `src/UserController.php`：版本化 `toArray($version)` 在 v1 输出 password 字段，v2 隐去；未认证用户路由可直接 GET。
- 同文件 `updateUser()`：接受客户端 `level` 并直接更新对象，且用户读写路径未见授权检查。
- `src/HealthController.php`：`checkConnectivity()` 将 `target` 拼入 `exec("ping ..." . $target)`。
- `src/LoginController.php`、`src/Login.php`、`src/Token.php`：教学用硬编码认证/密钥逻辑；证据副本已脱敏。
- `src/OrderController.php`：有 Bearer token 检查；但 PHP deprecation/warning 先输出会影响实际状态头。

**实际效果**：未认证 v1 用户集合 HTTP 200、3 条均有 password 字段；v2 同样返回 3 条但无该字段。未认证 PUT 响应对象 level 变为 0，随后独立 GET 仍是 1，说明本教学控制器每请求重新建内存数据，没有持久化。Connectivity 的本机回环基线为 200/OK，增加无害 shell 内建 `false` 后变为 500/Connection failed，支持 shell 元字符被解释。未认证订单请求响应正文说明 token 缺失，但运行时 warning 导致状态不能作为可靠的 401 证据。没有调用 API POST/DELETE、没有伪造 token、没有读文件或外联。

**修复建议**：弃用或保护 v1；所有响应模型默认拒绝输出密码哈希；每个 endpoint 做身份认证与对象级授权；更新接口采用允许字段白名单并拒绝 level/role；移除 shell 或使用无 shell 参数调用；凭据与加密密钥从源码移出并经密钥管理；关闭客户端错误细节输出。

**Patch 分析**：未创建 `fix.patch`，未部署修改。测试报告中的脱敏只修改本地 evidence 副本，不是修复。用户更新、授权和命令执行路径需在独立副本设计完整回归后再补丁。

## 5. Patch 整体质量与适用边界

### 5.1 已有 patch 的共同优点

1. 修复通常落在服务端最终 sink/授权点，而不是仅增加前端提示：SQL 使用参数绑定，XSS 在输出上下文编码，文件/跳转用白名单，认证与会话使用服务端校验。
2. 多数状态变更模块在隔离环境做攻击负测和正常行为正测；例如 CAPTCHA/CSRF 检查“攻击不能改密”，Brute Force 检查锁定后正确密码也不能登录，Open Redirect 检查恶意目标失效且本地合法映射仍能用。
3. 多数 patch 做过 dry-run、应用到副本及 PHP lint；File Inclusion、Blind SQLi、Open Redirect 等还做过针对旧攻击路径的副本回归。
4. 主 DVWA 源码没有因这些 patch 被部署修改，隔离栈和临时卷按模块清理，主数据卷保留。

### 5.2 不能扩大解释的地方

- SQLi patch 只覆盖 MySQL，SQLite 分支还需相应参数绑定。
- XSS 的 PHP lint / 独立示例通过不等于浏览器页面修复后端到端通过。
- File Upload 隔离输入验证通过不等于生产静态文件服务策略、权限与反向代理解析行为已验证。
- CAPTCHA 正常 reCAPTCHA 流程未测；CSRF 真实浏览器 SameSite 行为未测。
- CSP Bypass 没有成功绕过证据；JavaScript Attacks 是源码审查；Cryptography 和 API 未制作补丁。
- API 未完整测试全部方法和对象授权；未调用增删接口，未伪造/刷新令牌。
- 所有补丁均未部署到主 DVWA，也没有在主服务上做补丁部署后页面复测。

### 5.3 部署前建议的质量门

对未来要部署的每个补丁，至少完成：

1. 锁定上游版本与文件哈希，确认补丁上下文匹配。
2. 在独立源码副本 `patch --dry-run`，再应用并核对 diff。
3. 运行 PHP lint、单元/集成测试与攻击负测、正常业务正测。
4. 以隔离 Compose 和临时 DB 做页面/HTTP 端到端复测；检查错误处理、权限和回滚方案。
5. 只有用户明确要求部署时才改主实例；部署后核验具体 endpoint 与数据状态。

## 6. 当前状态与产物索引

- 主 DVWA 与 MariaDB 容器按最近一次核验仍处运行状态；数据库卷 `web-security-lab_database` 保留。
- 各模块实际结果和限制：`study.md`。
- 每项模块笔记：`cases/<module>/NOTES.md`。
- 有补丁模块：`cases/<module>/fix.patch`（共 13 个；各自只代表待移植 diff，不代表已部署）。
- Cryptography 结果：`cases/cryptography/NOTES.md` 及 `evidence/verification-results.md`。
- API 结果及脱敏源证据：`cases/api/NOTES.md` 与 `cases/api/evidence/`。

---

**一句话结论**：本轮已对有案例记录的 DVWA 模块完成不同深度的源码审查与隔离/本机验证，并为 13 个模块准备了经相应副本检查的修复 patch；这些 patch 均未部署到主 DVWA，若要形成上线修复闭环，还需要逐项部署前复测与回滚验证。
