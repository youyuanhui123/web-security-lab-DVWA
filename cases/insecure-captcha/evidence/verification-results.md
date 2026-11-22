# 实测输出摘要：Insecure CAPTCHA

## 原始源码（隔离副本）

```text
sandbox database setup: HTTP 200
Low direct step=2 POST: HTTP 200; CAPTCHA fields omitted
LOW_CAPTCHA_BYPASS_CONFIRMED: password changed without submitting CAPTCHA

MEDIUM request: HTTP 200
MEDIUM_CAPTCHA_BYPASS_CONFIRMED by login with changed password

HIGH request: HTTP 200
HIGH_CAPTCHA_BYPASS_CONFIRMED by login with changed password
```

判据是变更后的临时密码能重新登录，不是只看页面成功提示。

## 修复副本

```text
isolated DB initialized
LOW forged request HTTP 200
LOW original password=valid; forged password=invalid
LOW_PATCH_BLOCK_CONFIRMED
MEDIUM forged request HTTP 200
MEDIUM original password=valid; forged password=invalid
MEDIUM_PATCH_BLOCK_CONFIRMED
HIGH forged request HTTP 200
HIGH original password=valid; forged password=invalid
HIGH_PATCH_BLOCK_CONFIRMED
```

## 修复文件检查

```text
patch --dry-run: index.php、low.php、medium.php、high.php 均成功
patch apply: 四个文件均成功
PHP lint: 四个改动文件均无语法错误
```

## 隔离条件

```text
readonly=true
mem_bytes=402653184
nano_cpus=500000000
pids=96
network_internal=true
recaptcha_public_key=EMPTY
```

数据库只存在于 `dvwa-captcha-sandbox_database` 临时卷；测试期间没有挂载或修改主项目的 `web-security-lab_database`。
