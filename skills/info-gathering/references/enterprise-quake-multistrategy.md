# 中国企业集团 Quake 多策略资产发现

中国企业集团旗下有几十家子公司，各自有独立域名和 IP 段。单一 Quake 查询无法覆盖全量资产，需要多策略交叉。

## 五策略交叉法

### 策略一：组织名称搜索（精准度最高但覆盖最差）

Quake 的 `org` 字段标注的是云厂商/IDC，很少标注企业全名。中国企业的资产在 Quake 中大多只标注了"Alibaba Cloud"而非企业名，此策略命中率低。

```bash
python3 ~/.hermes/tools/quake_query.py --search 'org:"浙能"' --size 100
python3 ~/.hermes/tools/quake_query.py --search 'org:"浙江浙能"' --size 100
```

### 策略二：域名直接搜索（可靠）

```bash
python3 ~/.hermes/tools/quake_query.py --domain "zjenergy.com"
python3 ~/.hermes/tools/quake_query.py --domain "zheneng.net"
python3 ~/.hermes/tools/quake_query.py --domain "zjenergy.cn"
```

**注意：** 中国企业常同持多个主域（.com / .cn / .net），必须全部搜索。

### 策略三：ICP 备案号反查（最强关联手段）

中国网站的 ICP 备案号（工信部备案）是**将同一主体下的所有域名关联起来的最强手段**。一个集团公司可能有多个独立域名，但通常挂在同一 ICP 备案号下。

```bash
# 从官网 footer 提取 ICP 号
curl -skL https://target.com | grep -iP 'icp|备案|beian'

# Quake 搜索同 ICP 所有域名
python3 ~/.hermes/tools/quake_query.py --icp "浙B2-xxxxxx号"
```

**限制：** Quake 按 ICP 返回的条目常缺失 `hostname` 字段（仅显示 IP 和端口），需结合 crt.sh 补全域名。

### 策略四：子公司逐一搜索（最彻底）

需要提前知道子公司全名。来源：企查查/天眼查/天眼查/ENScan_GO。

```bash
# 先查子公司列表
enscan -n "浙江省能源集团" -invest

# 逐个搜索
for org in "浙能电力" "浙能数科" "浙能燃气" "浙能煤炭"; do
  python3 ~/.hermes/tools/quake_query.py --search "org:${org}" --size 50
done
```

### 策略五：交叉推断

- 同一 IP 在不同查询中出现 → 大概率属于目标
- 不同 IP 但在同一 /24 段 + 相同云厂商 → 可能同属一个集团
- Quake 对中文企业的 org 字段常缺失（仅显示"Alibaba Cloud"），不要仅靠 org 判断归属

## CSV 导出去重

合并多次查询结果后去重（key = IP:端口），写入 CSV：

```python
import csv
# key: "IP:PORT"
# columns: IP, 端口, 主机名, 所属机构, 来源查询
# 编码必须用 utf-8-sig（带 BOM），Excel 才能正确显示中文
```

## 子公司批量清单

对于大型国企（能源/电力/烟草等），子公司数量可能达几十家。建议用 ENScan_GO 先拉清单：

```bash
go install github.com/wgpsec/ENScan_GO@latest
enscan -n "集团名称" -invest -o json > subsidiaries.json
```

然后逐条子公司名称走策略四。

## 已知限制

| 限制 | 说明 |
|------|------|
| Quake `org` 字段失效 | 中国企业资产在 Quake 中大多标为云厂商名，非企业名 |
| ICP 反查缺域名 | 返回条目常缺 `hostname`，需结合 crt.sh 补齐 |
| 子公司独立域名 | 子公司域名不一定挂在集团主域下，需要逐家搜索 |
| 干扰项多 | 关键词匹配会带出大量非目标资产，需要人工过滤 |
