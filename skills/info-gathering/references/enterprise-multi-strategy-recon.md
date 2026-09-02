# 中国企业集团多策略资产发现

中文企业（尤其是国企/大型集团）在 Quake 等空间搜索引擎中的 org 字段经常缺失（仅显示云厂商名如"Alibaba Cloud"而非"浙能集团"），单一策略无法覆盖全部资产。

## 多策略交叉搜索流程

### 策略一：组织名称搜索

```bash
python3 ~/.hermes/tools/quake_query.py --search 'org:"浙能"'
python3 ~/.hermes/tools/quake_query.py --search 'org:"浙江浙能"'
```

**局限性：** 中文企业的 org 字段在 Quake 中常为空白或只显示云厂商名，此策略仅覆盖被 Quake 明确标注的资产。

### 策略二：主域名搜索

```bash
python3 ~/.hermes/tools/quake_query.py --domain "zheneng.com"
python3 ~/.hermes/tools/quake_query.py --domain "zjenergy.com.cn"
python3 ~/.hermes/tools/quake_query.py --domain "zjenergy.cn"
python3 ~/.hermes/tools/quake_query.py --domain "zheneng.net"
```

**注意：** 子公司的域名不一定挂在集团主域下，很多子公司使用独立域名。

### 策略三：ICP 备案号反查

找到目标公司的 ICP 备案号后，Quake 反查所有同备案号的域名：

```bash
python3 ~/.hermes/tools/quake_query.py --icp "浙B2-xxxxxx"
```

**注意：** Quake 按 ICP 检索返回的条目中 hostname 字段经常为空（仅显示 IP 和端口），需结合 crt.sh 补齐域名。

### 策略四：ENScan_GO 获取子公司列表

先获取子公司全名，再逐一搜索：

```bash
# ENScan_GO 深度查询（获取子公司、ICP、APP、公众号）
enscan -n "浙江省能源集团" -deep -o json

# 子公司逐一搜
for org in "浙能电力" "浙能数科" "浙能燃气" "浙能煤炭" "浙能环保"; do
  python3 ~/.hermes/tools/quake_query.py --search "org:${org}" --size 50
done
```

### 策略五：SSL 证书组织字段

通过 Quake 的证书字段搜索：

```
cert.subject_org:"浙江省能源集团"
```

### 策略六：交叉推断

- 同一 IP 在不同策略中重复出现 → 大概率属于目标
- 不同 IP 但在同一 /24 段 + 同云厂商 → 可能同属一个集团
- 不要仅靠 Quake 的 org 字段判断归属（大量中文企业的 org 字段缺失或为"Alibaba Cloud"）

## 导出与去重

```csv
IP,端口,主机名,所属公司/机构,来源查询
1.2.3.4,80,www.example.com,浙能集团,domain搜索
```

- 合并多次查询结果，去重 key = `IP:端口`
- CSV 用 `utf-8-sig` 编码（带 BOM），Excel 可直接打开中文
- 列：IP、端口、主机名、所属机构、来源查询

## 实战案例：浙能集团

| 策略 | 结果数 | 有效资产 |
|------|--------|---------|
| org:"浙能" | 14 | 部分相关（有干扰项） |
| domain:"zjenergy.com" | 24 | 核心资产（47.96.122.15 阿里云主站） |
| domain:"zjenergy.cn" | 4 | 辅助节点 |
| 合计（去重后） | 83 | 含 IP:端口 唯一记录 |

核心 IP 分布：
- 47.96.122.15（阿里云）— zjenergy.com 主站
- 42.121.103.112（阿里云）— zjenergy.com 多端口
- 170.33.12.185（阿里云）— zjenergy.cn
- 172.67.198.115（Cloudflare）— zheneng.net CDN
