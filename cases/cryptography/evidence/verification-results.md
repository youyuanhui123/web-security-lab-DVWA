# Cryptography 模块验证结果

范围：本机 DVWA `127.0.0.1:4280`；只使用模块自带的演示令牌和测试端点。会话/令牌正文已脱敏，不记录 Cookie。验证期间将 DVWA security level 切换为各等级，结束时恢复 Impossible。

| 等级 | 源码/题面线索 | 实测结果 | 判定 |
|---|---|---|---|
| Low | `low.php` 用固定 XOR 密钥 `wachtwoord`，再 Base64 编码；截获值外层 Base64 可解 | 用 Python Base64 解码后循环 XOR，输出 `Your new password is: [REDACTED]`；在页面提交该值，页面返回 `Welcome back user` | 弱编码可逆；登录成功实测 |
| Medium | `medium.php` 使用 AES-128-ECB，JSON 字段跨固定 16-byte 分组；页面给三份 token | 依照题目分组重排构造 token，提交后页面返回 `Welcome administrator Sweep` | ECB 分组可移植导致权限字段可篡改；管理员结果实测 |
| High | `token_library_high.php` 使用 AES-128-CBC，无认证标签；`check_token_high.php` 对解密失败返回状态 526 | 隔离在本地 DVWA 容器中运行随附 `oracle_attack.php`。脚本输出解得明文 `userid:2`，随后通过 IV 位翻转构造 `userid:1`；服务端 JSON 返回 `status=200, user=Geoffery, level=admin`，并报告 `Hack success!`。总运行约 1 秒，退出码 0 | 可利用 padding oracle 并篡改第一明文块；实测 |
| Impossible | `token_library_impossible.php` 使用 AES-256-GCM、12-byte nonce 与认证 tag | 原样 token 返回 `{"status":200,"user":"Bungle","level":"user"}`；仅修改 token 首字符后返回 `status=526`、`Decryption failed` | 正常 token 可用，篡改因认证失败而拒绝；对照实测 |

## 可复核信号

- Low：页面出现 `Welcome back user`。
- Medium：页面出现 `Welcome administrator Sweep`。
- High：`high-oracle-run.log` 中出现 `Decrypted string as text: userid:2`、最终 `status=200` / `level=admin` 和 `Hack success!`。日志中的 token/IV 已替换为 `[REDACTED]`。
- Impossible：容器内对 `check_token_impossible.php` 发送 JSON 的原始响应分别为 `status=200` 普通用户、篡改后 `status=526` 解密失败；请求不含会话 Cookie。

High 随附脚本在 PHP 8.5 上会提示 `curl_close()` 已弃用；不影响本次运行或成功判据。未对主源码进行修改或部署修复。