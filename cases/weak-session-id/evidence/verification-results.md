# 实测输出摘要：Weak Session IDs

## 原始源码（隔离副本）

```text
isolated database initialized
LOW sequential counter=confirmed
LOW_COOKIE_BEHAVIOR_CONFIRMED
MEDIUM Unix-timestamp format=confirmed
MEDIUM_COOKIE_BEHAVIOR_CONFIRMED
HIGH md5-of-counter=confirmed
HIGH_COOKIE_BEHAVIOR_CONFIRMED
IMPOSSIBLE random 160-bit format, distinct pair, Secure/HttpOnly=confirmed
IMPOSSIBLE_COOKIE_BEHAVIOR_CONFIRMED
```

## 修复副本

```text
isolated database initialized
LOW randomized 160-bit value, distinct pair, Secure/HttpOnly=confirmed
LOW_PATCH_RANDOM_COOKIE_CONFIRMED
MEDIUM randomized 160-bit value, distinct pair, Secure/HttpOnly=confirmed
MEDIUM_PATCH_RANDOM_COOKIE_CONFIRMED
HIGH randomized 160-bit value, distinct pair, Secure/HttpOnly=confirmed
HIGH_PATCH_RANDOM_COOKIE_CONFIRMED
```

## 修复检查

```text
patch --dry-run: low.php、medium.php、high.php 均成功
patch apply: 三个文件均成功
PHP lint: 三个改动文件均无语法错误
```
