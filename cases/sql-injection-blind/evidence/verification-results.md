# 实测输出摘要：SQL Injection (Blind)

## 漏洞副本

```text
isolated database initialized
LOW true=200/exists false=404/missing
LOW_BOOLEAN_ORACLE_CONFIRMED
MEDIUM true=200/exists false=200/missing
MEDIUM_BOOLEAN_ORACLE_CONFIRMED
HIGH true=200/exists false=404/missing
HIGH_BOOLEAN_ORACLE_CONFIRMED
```

Medium 的真/假响应状态码相同，必须看页面中的 exists/missing 标记。

## 修复副本

```text
isolated database initialized
LOW control=exists attack_http=404 attack_exists=false attack_missing=true
LOW_PATCH_BLOCK_CONFIRMED
MEDIUM control=exists attack_http=404 attack_exists=false attack_missing=true
MEDIUM_PATCH_BLOCK_CONFIRMED
HIGH control=exists attack_http=404 attack_exists=false attack_missing=true
HIGH_PATCH_BLOCK_CONFIRMED
```

每个等级先用 `id=1` 做正常查询控制，再以新 token 发送原真条件载荷。没有执行记录导出。

## 补丁与运行环境检查

```text
patch --dry-run: index.php、low.php、medium.php、high.php 均成功
patch apply: 四个文件均成功
PHP lint: 四个改动文件均无语法错误
Docker sandbox: readonly=true; mem=402653184 bytes; cpus=0.5; pids=96; internal network=true
```
