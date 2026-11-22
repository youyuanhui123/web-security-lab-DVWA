# 实测输出摘要：Command Injection

## 漏洞副本

```text
isolated database initialized
LOW baseline_marker=absent; injected_marker=present; HTTP=200
LOW_COMMAND_INJECTION_CONFIRMED
MEDIUM baseline_marker=absent; injected_marker=present; HTTP=200
MEDIUM_COMMAND_INJECTION_CONFIRMED
HIGH baseline_marker=absent; injected_marker=present; HTTP=200
HIGH_COMMAND_INJECTION_CONFIRMED
```

唯一执行的额外命令是打印固定标记 `CMDI_LAB_PROOF`；没有读文件、改系统状态或访问外网。

## 修复副本

```text
isolated database initialized
LOW valid_ip_accepted=true; injected_marker=absent; invalid_ip_rejected=true
LOW_COMMAND_INJECTION_BLOCKED
MEDIUM valid_ip_accepted=true; injected_marker=absent; invalid_ip_rejected=true
MEDIUM_COMMAND_INJECTION_BLOCKED
HIGH valid_ip_accepted=true; injected_marker=absent; invalid_ip_rejected=true
HIGH_COMMAND_INJECTION_BLOCKED
```

## 补丁检查

```text
patch --dry-run: index.php、low.php、medium.php、high.php 均成功
patch apply: 四个文件均成功
PHP lint: 四个改动文件均无语法错误
```
