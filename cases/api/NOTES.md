# DVWA API 安全模块记录

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

未认证 v1 用户集合 HTTP 200、3 条均有 password 字段；v2 同样返回 3 条但无该字段。未认证 PUT 响应对象 level 变为 0，随后独立 GET 仍是 1，说明本教学控制器每请求重新建内存数据，没有持久化。Connectivity 的本机回环基线为 200/OK，增加无害 shell 内建 `false` 后变为 500/Connection failed，支持 shell 元字符被解释。未认证订单请求响应正文说明 token 缺失，但运行时 warning 导致状态不能作为可靠的 401 证据。没有调用 API POST/DELETE、没有伪造 token、没有读文件或外联。

## 2. 发现过程

### 原记录：发现过程

1. 按 DVWA 菜单进入 API 模块，先从 `help/help.php` 的版本提示找到 `/vulnerabilities/api/v1/user/`，而页面 Low 示例请求的是 v2。源码证据副本位于 `evidence/`。
2. `public/index.php` 根据路径将请求分派到控制器；`src/UserController.php` 的 `toArray($version)` 在 v1 返回 `password` 字段、v2 不返回。用户集合和单用户 GET 路由均无认证检查。
3. `src/UserController.php` 的 `updateUser()` 接受 JSON `level` 并直接改对象属性；用户 GET/PUT/DELETE 的处理路径没有鉴权。`src/HealthController.php` 将 `target` 拼接进 `exec("ping -c 4 " . $target, ...)`。
4. `src/OrderController.php` 对订单 API 检查 Bearer token；`src/Login.php`、`src/Token.php` 和 `src/LoginController.php` 存在教学用硬编码密钥/认证常量。证据副本中的密钥、凭据、密码哈希已替换为 `[REDACTED]`，证据副本因此是脱敏审阅材料，不应作为可运行原件。

## 3. 核心代码位置

### 报告交叉摘要

- `src/UserController.php`：版本化 `toArray($version)` 在 v1 输出 password 字段，v2 隐去；未认证用户路由可直接 GET。
- 同文件 `updateUser()`：接受客户端 `level` 并直接更新对象，且用户读写路径未见授权检查。
- `src/HealthController.php`：`checkConnectivity()` 将 `target` 拼入 `exec("ping ..." . $target)`。
- `src/LoginController.php`、`src/Login.php`、`src/Token.php`：教学用硬编码认证/密钥逻辑；证据副本已脱敏。
- `src/OrderController.php`：有 Bearer token 检查；但 PHP deprecation/warning 先输出会影响实际状态头。

### 原记录明确提及的代码文件

以下仅汇总原记录中出现的路径，不增加新的源码判断：

- `help/help.php`
- `public/index.php`
- `src/UserController.php`
- `src/HealthController.php`
- `src/OrderController.php`
- `src/Login.php`
- `src/Token.php`
- `src/LoginController.php`


## 4. 脱敏请求与证据

### 原记录：实测结果

| 请求 | 结果 | 结论 |
|---|---|---|
| 未带认证 `GET /vulnerabilities/api/v1/user/` | HTTP 200；3 条记录都含 `password` 字段 | 旧版 API 未授权暴露密码哈希字段。日志不保留哈希值。 |
| 未带认证 `GET /vulnerabilities/api/v2/user/` | HTTP 200；3 条记录均无 `password` 字段 | v2 隐去该字段，但端点仍公开用户资料。 |
| 未带认证 `PUT /vulnerabilities/api/v2/user/2`，JSON 仅用于临时演示 `level=0` | HTTP 200，响应对象显示 level 0；后续独立 GET 仍为 level 1 | 能在当前请求处理过程中提交越权字段；该演示 API 每个请求重建内存数据，未持久化状态。 |
| `POST /vulnerabilities/api/v2/health/connectivity`，target 为 `127.0.0.1` | HTTP 200，`{"status":"OK"}` | 本地回环连通基线。 |
| 同一端点 target 为 `127.0.0.1; false` | HTTP 500，`{"status":"Connection failed"}` | 安全的 shell 内建 `false` 作为末尾命令改变执行结果；与基线差异支持 shell 元字符被解释的结论。没有运行任意外部程序、读文件或访问网络。 |
| 未带 token `GET /vulnerabilities/api/v2/order/` | 响应包含“token 无效/缺失”；PHP deprecation/warning 先输出，导致预期状态头可能无法设置 | 订单端点有 token 检查，但此请求在当前 PHP 运行时另暴露错误输出/状态码处理问题；不把响应体误读为正确的 401。 |
| `GET /v2/health/status` 与 `/v2/health/ping` | 均 HTTP 200 | 普通健康端点基线。 |

所有 PUT 数据是控制器单次请求中的临时对象；独立 GET 确认原用户 level 未改变。未调用 POST/DELETE，不创建或删除任何业务记录。测试期间没有修改 DVWA security level。

## 5. 漏洞根因

### 报告交叉摘要

- `src/UserController.php`：版本化 `toArray($version)` 在 v1 输出 password 字段，v2 隐去；未认证用户路由可直接 GET。
- 同文件 `updateUser()`：接受客户端 `level` 并直接更新对象，且用户读写路径未见授权检查。
- `src/HealthController.php`：`checkConnectivity()` 将 `target` 拼入 `exec("ping ..." . $target)`。
- `src/LoginController.php`、`src/Login.php`、`src/Token.php`：教学用硬编码认证/密钥逻辑；证据副本已脱敏。
- `src/OrderController.php`：有 Bearer token 检查；但 PHP deprecation/warning 先输出会影响实际状态头。

## 6. Patch diff 与修复建议

### 报告交叉摘要

弃用或保护 v1；所有响应模型默认拒绝输出密码哈希；每个 endpoint 做身份认证与对象级授权；更新接口采用允许字段白名单并拒绝 level/role；移除 shell 或使用无 shell 参数调用；凭据与加密密钥从源码移出并经密钥管理；关闭客户端错误细节输出。

### 原记录：主要风险与建议

- 移除或保护 v1，避免旧版本暴露敏感字段；API 响应模型使用显式字段白名单，不按版本决定是否输出密码哈希。
- 对用户/订单路由做服务端认证与对象级授权；更新接口只允许可编辑字段，拒绝客户端提交 `level`、角色等权限字段。仅隐藏前端按钮不构成授权。
- connectivity 不应将用户输入拼接进 shell 命令。改用安全的网络探测库；若保留 ping，先严格校验目标为允许的 IP/主机，并以参数数组调用，禁止 shell 解释。
- 将客户端密钥、访问/刷新 token 秘密及加密密钥移出源码，使用足够强的密钥管理；令牌采用标准签名/验证流程并正确区分访问与刷新令牌。
- 避免向客户端输出 PHP warning/deprecation、文件路径；在生产配置中关闭 display_errors，服务端记录脱敏错误。


## 7. 修复前后回归

原笔记未提供独立的修复前后回归记录。

## 8. 限制与未验证项

### 原记录：限制与修复状态

- 以上发现仅在本机 DVWA 教学环境与当前代码版本验证；未推断为任意真实服务的漏洞。
- 未尝试破解哈希、伪造令牌、访问外部主机、读系统文件或持久化修改用户资料。
- 本模块尚未制作修复补丁，也未修改/部署主实例。版本控制、对象级授权、shell 命令移除及令牌方案需作为后续独立修复与回归范围。
- `evidence/` 的 PHP 源码中敏感硬编码已脱敏；验证结果只保留状态、字段存在与记录数，不保留哈希、凭据、Cookie 或 token 正文。

原笔记未单独列出限制或未验证项；未提及不等于已验证。

## 9. 复现环境

### 原记录：范围与原始上下文

日期：2026-11-21  
目标：本机授权靶场 `http://127.0.0.1:4280/vulnerabilities/api/`；Docker 仅本机访问。  
范围：源码审阅 + 只读 HTTP 请求及内存态 API 演示；未扫描外部地址、未读取宿主文件、未导出数据库、未部署补丁。
