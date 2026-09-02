# 企业集团资产批量发现（多策略交叉）

中国大型企业集团旗下有几十家子公司，各自有独立域名和 IP 段。仅靠单一 Quake 查询无法覆盖完整攻击面，需多策略交叉。

## 策略清单

| 策略 | 查询语法 | 覆盖范围 |
|------|---------|---------|
| 组织名称 | `org:"浙能"` | 匹配指纹库中标注了该组织的资产 |
| 主域名 | `domain:"zheneng.com"` | 该域名下的所有子域名+IP |
| 子公司逐一搜索 | `org:"浙能电力"` | 逐一搜每家子公司 |
| ICP 备案 | `icp:"浙B2-xxxx"` | 同一备案号下的所有域名 |
| SSL 证书组织 | `cert.subject_org:"浙江省能源集团"` | 证书字段反查 |

## 完整流程

```bash
# 0. 先查清楚子公司列表
# 企查查/天眼查 → ENScan_GO
enscan -n "浙江能源集团" -invest

# 1. 批量搜集团+子公司
for org in "浙江省能源集团" "浙能电力" "浙能数科" "浙能燃气"; do
  python3 ~/.hermes/tools/quake_query.py --search "org:${org}" --size 100 --format compact
done

# 2. 搜主域名
for domain in "zheneng.com" "zjenergy.com" "zjenergy.cn"; do
  python3 ~/.hermes/tools/quake_query.py --domain "${domain}" --format compact
done

# 3. 去重合并 → CSV 导出
# 合并 key=IP:端口，utf-8-sig 编码，Excel 可直接打开
```

## CSV 导出格式

```csv
IP,端口,主机名,所属公司,Quake机构,位置,来源查询
47.96.122.15,443,,浙能集团,Alibaba Cloud,?,domain:zjenergy.com
42.121.103.112,80,,浙能集团,Alibaba Cloud,?,domain:zjenergy.com
```

## 注意事项

- Quake 对中文企业的 `org` 字段常缺失，仅显示云厂商名（如"Alibaba Cloud"），不要仅靠 org 判断归属
- 同一 IP 在不同查询中出现 → 大概率属于目标集团
- 不同 IP 在同一 /24 段 + 相同云厂商 → 可能同属一个集团
- crt.sh 证书透明度日志可补充 Quake 未覆盖的域名
