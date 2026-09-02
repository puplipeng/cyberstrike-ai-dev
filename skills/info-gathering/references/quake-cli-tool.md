# CyberStrikeAI Quake 查询参考

> CyberStrikeAI 已原生接入 Quake。优先从“资产管理 → 信息收集”选择 Quake；密钥在系统设置中保存并由后端读取，不写入 Skill、命令或导出文件。

## 基本用法

在 Quake 查询框中输入 DSL：

```text
domain:"target.com"
ip:"1.2.3.4"
icp:"京ICP备010000号"
org:"公司名称"
cve:"CVE-2024-XXXXX"
service.http.title:"nginx" AND port:80
```

执行查询后可以在结果表格中勾选记录，点击“入库所选”写入资产管理。平台按“目标 + 端口 + 协议”去重，重复记录会安全合并。

## 查询参数

| 页面字段 | 默认值 | 说明 |
|---------|--------|------|
| 返回数量 | 100 | 当前页结果数，受 Quake 账户限制 |
| 页码 | 1 | 后端换算为 Quake `start` 偏移量 |
| 返回字段 | 平台默认值 | 对应 Quake `include` |
| 最新数据 | 关闭 | 对应 Quake `latest` |

## 鉴权方式

1. 系统设置中的 `quake.api_key`
2. 服务进程环境变量 `QUAKE_API_KEY`（优先级更高）

前端只能获得脱敏占位值，真实 Token 不随查询结果或资产数据返回。

## 已知坑位

1. 域名检索使用 `domain:"target.com"`，不要使用旧 CLI 的参数格式。
2. Quake API 域名已迁移到 `quake.360.net`，旧域名 `quake.360.cn` 返回 308 重定向。
3. `quake_service` 端点不支持 `service.port` 等细粒度过滤字段，只用 `query` 参数即可。
4. Quake 数据属于测绘快照，不等于当前实时可访问。入库时保留 `source=quake` 和查询条件，主动验证需另行确认范围。
