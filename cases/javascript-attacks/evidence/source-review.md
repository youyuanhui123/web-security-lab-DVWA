# JavaScript Attacks 静态源码证据摘要

证据来源：`index.php`、`low.php`、`medium.php`、`high.php`、`impossible.php`、`medium.js`、`high.js`、`high_unobfuscated.js`（均为本机 DVWA 容器源码只读副本）。

- `index.php`：仅接受 POST；`phrase` 必须等于明文展示的 `success`。各安全等级用固定算法/常量比较 `token`。成功时只构造 `Well done!` 页面提示。
- Low：服务端期望值为 `md5(str_rot13("success"))`；`low.php` 内联脚本按 phrase 计算 MD5/ROT13 token。
- Medium：服务端期望值为 `strrev("XXsuccessXX")`；`medium.js` 对 `XX` + phrase + `XX` 反转生成 token。
- High：服务端期望值为 `hash("sha256", hash("sha256", "XX" . strrev("success")) . "ZZ")`；算法本身不是秘密。
- Impossible：`index.php` 不呈现可提交的挑战表单，并明确写明客户端内容不可阻止用户篡改。

执行边界：仅进行文件复制和源码阅读。没有向 `http://127.0.0.1:4280` 发起模块请求；没有浏览器运行、表单 POST、token 提交或动态绕过测试。因此不把静态推断写成实测。
