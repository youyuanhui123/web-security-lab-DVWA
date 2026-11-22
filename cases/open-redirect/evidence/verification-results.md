# DVWA Open HTTP Redirect：源码、隔离验证与修复

## 发现链

1. `evidence/index.php` 按安全等级生成 `source/<level>.php?redirect=...` 链接；Low/Medium/High 传入 URL 字符串，Impossible 传数字 ID。
2. `low.php` 将 `$_GET['redirect']` 直接拼入 `Location` 响应头。
3. `medium.php` 只拒绝含 `http://` / `https://` 的值；协议相对地址 `//host/path` 不匹配该规则。
4. `high.php` 只检查输入中是否含 `info.php`，检查点可放在攻击者 URL 的 query string。
5. `impossible.php` 将数字 ID 映射到固定目标，不直接接受任意 URL；本模块页面提供的 ID 1、2 均为本地 `info.php` 页面。

## 原版隔离实测

在原版 DVWA 容器与 MariaDB 均位于 `internal` Docker 网络、应用根文件系统只读、DB 仅用 tmpfs 的临时栈中执行。模块 handler 通过容器 loopback 访问，无 Cookie、无登录；HTTP 客户端关闭自动跟随跳转。使用保留域名 `example.invalid`，未解析/访问外部站点。

| 安全等级 | 输入 `redirect` | 实际响应 | 结论 |
|---|---|---|---|
| Low | `https://example.invalid/redirect-proof` | 302，`Location` 为该绝对 URL | 任意绝对 URL 可控 |
| Medium | `//example.invalid/redirect-proof` | 302，`Location` 为该协议相对 URL | 过滤只挡绝对协议写法，可绕过 |
| High | `https://example.invalid/?next=info.php` | 302，`Location` 为该绝对 URL | 任意位置出现 `info.php` 子串即可通过 |

实际状态码与 Location 由 `scripts/verify_redirects.php` 的容器内 curl 请求确认；三项原版检查均 `pass: true`。

## 修复与回归

`fix.patch` 将 Low/Medium/High 统一委托给 Impossible 的数字 ID 白名单映射；原上游源码未改。补丁在源码副本完成 dry-run、应用和归一化换行后的逐文件比对；低、中、高三份修复文件均与补丁结果一致。隔离修复容器中 `php -l` 对 Low/Medium/High/Impossible 和验证脚本全部通过。

修复副本回归结果：

- 三个原恶意目标均不再产生 302，也没有 `Location` 头。
- 合法 ID 1、2 仍分别产生 302，目标为 `info.php?id=1`、`info.php?id=2`。
- 六项检查全部通过，见 `scripts/verify_redirects.php`。

## 隔离与边界

两套测试栈均使用 internal 网络、无宿主端口发布、只读容器根文件系统、tmpfs 临时数据库、CPU/内存/PID/文件大小限制和显式测试环境变量。只检查响应 Location，没有跟随跳转，没有向外部发送请求，没有收集凭据，也没有访问受害者或真实用户。两套临时栈已停止并移除；主 DVWA/MariaDB 仍运行，主卷 `web-security-lab_database` 保留。补丁未部署主实例。
