# 实测输出摘要：File Inclusion

## 漏洞副本

```text
isolated database initialized
LOW local-file-marker=present
LOW_LOCAL_FILE_INCLUSION_CONFIRMED
MEDIUM local-file-marker=present
MEDIUM_LOCAL_FILE_INCLUSION_CONFIRMED
HIGH local-file-marker=present
HIGH_LOCAL_FILE_INCLUSION_CONFIRMED
IMPOSSIBLE_ARBITRARY_PATH_REJECTED
```

Low/Medium 使用本地绝对路径；High 使用本地 `file://` wrapper。只核对 sandbox 自身 `/etc/hostname` 标记是否被包含，不记录标记内容。

## 修复副本

```text
isolated database initialized
LOW allowed_page=works; hostname_marker=absent; allowlist_rejection=true
LOW_ARBITRARY_FILE_BLOCKED
MEDIUM allowed_page=works; hostname_marker=absent; allowlist_rejection=true
MEDIUM_ARBITRARY_FILE_BLOCKED
HIGH allowed_page=works; hostname_marker=absent; allowlist_rejection=true
HIGH_ARBITRARY_FILE_BLOCKED
```

## 补丁检查

```text
patch --dry-run: low.php、medium.php、high.php 均成功
patch apply: 三个文件均成功
PHP lint: 三个改动文件均无语法错误
```
