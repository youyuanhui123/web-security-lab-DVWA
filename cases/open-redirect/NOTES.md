# DVWA Open HTTP Redirect

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

在无外网的隔离网络、容器内部请求中，Low 的绝对 URL、Medium 的协议相对 URL、High 的参数子串绕过均得到 302 和指定 Location。没有跟随重定向，也没有访问外部站点。

### 原记录：结论

Low、Medium、High 均存在未验证跳转：原版隔离栈实际返回指向 `example.invalid` 的 302 Location。未跟随重定向，未访问外部站点。Medium 的协议相对 URL 绕过 scheme 黑名单；High 的 `info.php` 子串检查可由攻击者 URL 的 query 参数满足。模块 handler 不需要登录 Cookie，原版测试直接经容器 loopback 命中。

## 2. 发现过程

原笔记未单独记录发现过程。

## 3. 核心代码位置

### 报告交叉摘要

`vulnerabilities/open_redirect/source/low.php`、`medium.php`、`high.php` 的 Location 生成与过滤；Impossible 采用固定 ID 映射。

## 4. 脱敏请求与证据

原笔记未单独列出请求或证据材料；不得据此声称完成动态验证。

## 5. 漏洞根因

### 报告交叉摘要

跳转目标由请求参数控制，或过滤仅检查部分 scheme/子串，未对最终目标做严格允许列表校验。

## 6. Patch diff 与修复建议

- 补丁文件：[`fix.patch`](fix.patch)；完整 diff 保留在该文件，是否部署仍以本篇状态记录为准。

### 报告交叉摘要

跳转目标以固定数字 ID 或服务器端枚举映射；禁止直接把用户输入写入 Location；对本地相对目标也做规范化和白名单校验。

### 原记录：修复

`fix.patch` 将 Low/Medium/High 的处理统一交给 `impossible.php` 的固定数字 ID 映射，而不是检查或拼接用户提供的 URL。补丁只在 `worktree/` 副本应用，主 DVWA 未修改。严格维护外部跳转时应只允许业务明确批准的固定目标；不能把“包含可信字符串”当作 URL 验证。

## 7. 修复前后回归

### 原记录：验收

- 原版三档：Low 绝对 URL、Medium `//` 协议相对 URL、High query 中含 `info.php` 均返回 302 到指定外部 URL。
- 修复副本：三种恶意输入均无 302/Location；合法编号 1/2 仍跳转到对应本地 `info.php`。
- `fix.patch` dry-run、应用及归一化换行后的结果比对通过；修复文件 Low/Medium/High/Impossible 与验证脚本 PHP lint 通过；六项修复回归全通过。
- 栈配置限制为 internal 网络、容器只读根、tmpfs 数据库和资源上限；临时栈已清理。主 DVWA、MariaDB 与 `web-security-lab_database` 保留。补丁未部署主实例。

## 8. 限制与未验证项

原笔记未单独列出限制或未验证项；未提及不等于已验证。

## 9. 复现环境

### 原记录：复现

```bash
docker compose -f sandbox-vulnerable.compose.yaml up -d --pull never
docker exec -i dvwa-open-redirect-sandbox-dvwa-1 php /dev/stdin vulnerable < scripts/verify_redirects.php
docker compose -f sandbox-vulnerable.compose.yaml down

docker compose -f sandbox-fixed.compose.yaml up -d --pull never
# 在修复容器中同样运行脚本，参数改为 fixed
docker exec -i dvwa-open-redirect-fixed-dvwa-1 php /dev/stdin fixed < scripts/verify_redirects.php
docker compose -f sandbox-fixed.compose.yaml down
```

验证脚本不跟随跳转；`example.invalid` 仅用于响应头证明，不会连接外部站点。详细实际输出与边界记录见 `evidence/verification-results.md`。
