# 免费威胁情报源整合

从安全平台调用威胁情报做告警富化时，优先使用零 Key 源。有 Key 源按是否配置自动启用。

## 零 Key 源（始终可用）

### Shodan InternetDB

URL: `https://internetdb.shodan.io/{ip}`

返回 JSON：ip、ports、hostnames、cpes、tags、vulns。

评分规则：有 vulns → score=70（malicious），有 tags → score=30（suspicious），空记录 → score=0（benign）。

优点：零注册、零 Key、实时。缺点：数据不如完整 Shodan API 丰富，只覆盖公网已扫描的 IP。

### AlienVault OTX

URL: `https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general`

返回 JSON：reputation、pulse_info.count、country_name、asn。reputation 归一化到 0-100。

优点：无需 Key，有 rate limit 但宽松。
缺点：数据更新不及时，部分 IP 返回 404（无记录，算 benign）。

## 有 Key 源（按 Key 配置自动启用）

### AbuseIPDB

URL: `https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`

需要环境变量 `ABUSEIPDB_API_KEY`。免费 1000 次/天。

评分：直接返回 `abuseConfidenceScore` 0-100。

### Quake 360

已有平台内置集成。查 IP 归属、开放端口、服务指纹。可同时做测绘和情报。

## 聚合模式

所有源并行查询（goroutine + errgroup）→ 取最高分作为综合评分 → 各源明细存入 sources 数组 → 30 分钟 TTL 缓存（避免重复查询同一 IP）。

```go
// 伪代码
for _, source := range enabledSources {
    wg.Add(1)
    go func() {
        defer wg.Done()
        result := source.Query(ip)
        // 收集结果
    }()
}
wg.Wait()
// 综合判定
verdict = DetermineVerdict(maxScore)
```

有 Key 的源通过 `os.Getenv("KEY")` 检查，有值才加入并行队列。没 Key 不报错，直接跳过。
