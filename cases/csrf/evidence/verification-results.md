# 实测输出摘要：CSRF

## 漏洞副本

```text
LOW external-origin GET: new_password_login=true; original_password_login=false
LOW_CSRF_CONFIRMED
MEDIUM external-origin GET: new_password_login=false; original_password_login=true
MEDIUM_REFERER_CHECK_CONFIRMED
HIGH external-origin GET without token: new_password_login=false; original_password_login=true
HIGH_TOKEN_REQUIRED_CONFIRMED
IMPOSSIBLE external-origin GET without token: new_password_login=false; original_password_login=true
IMPOSSIBLE_TOKEN_REQUIRED_CONFIRMED
```

## 修复副本

```text
LOW cross-site GET changed=false; missing-token POST changed=false; original_password_valid=true
LOW valid_token_and_current_password=accepted; new_password_login=true; old_password_login=false
LOW_PATCH_CSRF_AND_LEGIT_FLOW_CONFIRMED

MEDIUM cross-site GET changed=false; missing-token POST changed=false; original_password_valid=true
MEDIUM valid_token_and_current_password=accepted; new_password_login=true; old_password_login=false
MEDIUM_PATCH_CSRF_AND_LEGIT_FLOW_CONFIRMED

HIGH cross-site GET changed=false; missing-token POST changed=false; original_password_valid=true
HIGH valid_token_and_current_password=accepted; new_password_login=true; old_password_login=false
HIGH_PATCH_CSRF_AND_LEGIT_FLOW_CONFIRMED
```

## 补丁检查

```text
patch --dry-run: index.php、low.php、medium.php、high.php、impossible.php 均成功
patch apply: 五个文件均成功
PHP lint: 五个改动文件均无语法错误
```
