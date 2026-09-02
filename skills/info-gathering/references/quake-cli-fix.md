# Quake CLI 工具修复记录

**CLI：** `~/.hermes/tools/quake_query.py`

## Bug 修复（2026-06-23）

`--domain` 参数使用了错误的 Quake 查询字段。

**修复前（不工作）：**
```python
def build_domain_query(domain):
    return f'hostname:\"{domain}\"'
```

**修复后：**
```python
def build_domain_query(domain):
    return f'domain:\"{domain}\"'
```

`hostname:` 不是 Quake 的有效查询字段，`domain:` 才是。

## 其他参数参考

```bash
python3 ~/.hermes/tools/quake_query.py --domain example.com    # 域名搜索（已修复）
python3 ~/.hermes/tools/quake_query.py --ip 1.2.3.4            # IP 反查
python3 ~/.hermes/tools/quake_query.py --icp "京ICP备xxx号"    # ICP 备案搜索
python3 ~/.hermes/tools/quake_query.py --org "公司名"           # 组织搜索
python3 ~/.hermes/tools/quake_query.py --search 'app:"nginx"'  # 原始查询
python3 ~/.hermes/tools/quake_query.py --cve "CVE-2024-xxx"   # CVE 关联资产
```
