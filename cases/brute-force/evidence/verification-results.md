# 实测输出摘要：Brute Force

## 漏洞副本

```text
LOW invalid_attempts=3/3; correct_password_still_accepted=true
LOW_NO_LOCKOUT_CONFIRMED
MEDIUM invalid_attempts=3/3; correct_password_still_accepted=true
MEDIUM_NO_LOCKOUT_CONFIRMED
HIGH invalid_attempts=3/3; correct_password_still_accepted=true
HIGH_NO_LOCKOUT_CONFIRMED
```

High 每次请求都先从表单取得当前 token；各级别都只发送 3 次错误密码，再用正确密码做一次控制。

## 修复副本

```text
LOW failed_attempts=3/3; valid_password_blocked=true
LOW_LOCKOUT_CONFIRMED
MEDIUM failed_attempts=3/3; valid_password_blocked=true
MEDIUM_LOCKOUT_CONFIRMED
HIGH failed_attempts=3/3; valid_password_blocked=true
HIGH_LOCKOUT_CONFIRMED
```

## 补丁检查

```text
patch --dry-run: index.php、low.php、medium.php、high.php 均成功
patch apply: 四个文件均成功
PHP lint: 四个改动文件均无语法错误
```
