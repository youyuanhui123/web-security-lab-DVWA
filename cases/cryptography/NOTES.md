# DVWA Cryptography 模块

## 审阅摘要

> 快速阅读：先看“问题影响”和“脱敏请求与证据”，再核对 Patch、回归及限制。
> 证据等级、实际结果和补丁部署状态以本篇对应章节记录为准；未记录项不作推断。

本篇按统一审阅结构重排，详细事实保留在各节“原记录”小节中。

> 以下按统一审阅顺序重排既有记录。分组依据是原笔记章节标题；原始文字和测试边界保留，未覆盖项目明确标注，不将源码审查当作动态验证。

## 1. 问题影响

### 报告交叉摘要

Low 解出教学演示消息并通过演示页面；Medium 重排 ECB 块得到管理员演示响应；High 调用模块自带 oracle 脚本，成功恢复并改写 token 中的身份字段；Impossible 原 token正常返回普通用户，篡改后服务端拒绝。未探测外网、未执行系统命令、未持久化改动。

## 2. 发现过程

### 原记录：发现链

1. 主菜单中 Open HTTP Redirect 后一项是 Cryptography；运行中的 DVWA 源码 `dvwa/includes/dvwaPage.inc.php` 的菜单顺序也确认其后才是 API。本阶段只推进 Cryptography。
2. 复制模块 `index.php`、Low–Impossible 实现、token 库、服务端检查端点、ECB/Oracle 辅助脚本与 help 文档到 `evidence/`，先看说明和源码，再按等级验证。
3. help 明确指出三类缺陷：Low 把 XOR/Base64 编码误当加密；Medium 用 AES-128-ECB 使独立密文块可互换；High 的 CBC 解密错误可形成 padding oracle；Impossible 改为带认证的 AES-256-GCM。

## 3. 核心代码位置

### 原记录明确提及的代码文件

以下仅汇总原记录中出现的路径，不增加新的源码判断：

- `dvwa/includes/dvwaPage.inc.php`
- `source/check_token_impossible.php`


## 4. 脱敏请求与证据

### 原记录：实测

详见 `evidence/verification-results.md`。Low 解出示例消息中的密码并在页面得到 `Welcome back user`；Medium 按 ECB 分组重排演示令牌，页面返回 `Welcome administrator Sweep`；High 运行模块自带 oracle 脚本，实际从响应中恢复 `userid:2`，再将 IV 改写对应明文为 `userid:1`，端点返回管理员 `Geoffery`；Impossible 原始 token 返回普通用户，改动一个 token 字符后服务端拒绝并报认证/解密失败。

## 5. 漏洞根因

### 报告交叉摘要

Low 用重复 XOR 和 Base64；Medium 用 AES-ECB，密文块可重排；High 的 CBC 错误响应泄漏 padding 是否有效，形成 oracle；Impossible 使用带认证的 AES-256-GCM。

### 原记录：关键机制

- **Low**：Base64 只是二进制到文本的编码，XOR 以重复密钥逐字节异或；`C XOR K = P`。由题目 source 中固定 key 和帮助文档中的已知明文例子得到 key，再解截获串。页面源码还存在比较输入密码字面量的实现，故此级别的“登录成功”只证明本演示页面分支可达，不代表真实身份认证系统。
- **Medium**：AES-ECB 对相同明文块产生相同密文块，且没有将块绑定到整体 token。题面将用户名、过期时间、权限字段安排在易识别的块边界，故可从三份 token 取块拼出用户 `sweep`、有效过期时间及 `admin` 权限字段。
- **High**：CBC 首块满足 `P1 = D_K(C1) XOR IV`。服务端暴露 padding 是否有效的差异（状态 526 代表解密失败），脚本以逐字节查询恢复中间值，再构造新 IV 修改首块明文。此处没有恢复 AES 密钥；利用的是错误响应 oracle 与未认证 IV。
- **Impossible**：GCM 将密文与认证 tag 绑定；随机 nonce 并非单独的修复，核心是服务端验证 tag。单字符改动破坏认证，服务端不返回修改后身份。

## 6. Patch diff 与修复建议

### 报告交叉摘要

不要自制加密/认证协议；采用成熟 AEAD（如 GCM）并验证 tag，正确使用随机 nonce；token 采用标准签名/校验和严格过期策略，避免将明文敏感信息放入可控结构；对外错误响应统一，避免 oracle。

## 7. 修复前后回归

原笔记未提供独立的修复前后回归记录。

## 8. 限制与未验证项

### 原记录：边界与当前状态

- 所有请求都在用户指定的回环 DVWA 上，High helper 访问的是容器内 `127.0.0.1` 服务；未探测外网或其他系统。
- High 仅调用靶场自带脚本与模块测试端点，没有访问文件、执行 shell 命令或持久化更改。日志保留了脱敏运行结果；token/IV 不写入报告。
- 本阶段完成了源码归档和各级演示验证，**未制作或部署修复补丁**。Impossible 仅作为源码已有的安全实现参考，不等价于 Low/Medium/High 已被修复。
- DVWA 已恢复 Impossible 安全等级；主栈保持运行，数据库卷未触碰。
- 当前实例的 High helper 使用了 PHP 8.5，输出 `curl_close()` 弃用提示，但进程退出码为 0 且管理员响应实测成功。

## 9. 复现环境

### 原记录：复现提示

- Low：`evidence/source/low.php` 中 key 为 `wachtwoord`；以 Base64 解码后，与重复 key 循环 XOR。模块截获串在源码 85 行，解密结果是一条演示密码提示（具体密码已脱敏）。不要把该示例密码当作真实系统凭据。
- Medium：查看 `evidence/help/help.php` 的分组说明及 `evidence/source/ecb_attack.php`。AES-128 的 block size 是 16 bytes，即 32 个十六进制字符；将三个给定 token 切成区块，再按题面字段布局置换。
- High：进入 High 等级页面取得当次 token 和 IV，在容器内运行 `evidence/source/oracle_attack.php`（或已归档的一次性运行日志 `evidence/high-oracle-run.log`）。应确认服务端回显的管理员身份，而不只看本地明文输出。动态 token/IV 只在运行时使用，禁止存进证据。
- Impossible：模块 UI 提交原样 JSON token 应识别为普通用户；修改 `token` 后重放到 `source/check_token_impossible.php`，预期状态字段为 526。
