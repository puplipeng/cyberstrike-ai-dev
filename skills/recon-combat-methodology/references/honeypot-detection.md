# 蜜罐检测实战案例

## 案例一：目标公网IP — InsightFlow 蜜罐

### 基本信息
- IP: 目标公网IP (阿里云)
- 声称应用: InsightFlow（安全运营平台）
- 开放端口: 22, 8080-8083, 7000-7001, 9200

### 蜜罐实锤指标

| 指标 | 发现 |
|------|------|
| **ES build_date 伪造** | ES 8.11.0 真实发布于 2023-11，但声称 `build_date: 2026-03-15` |
| **ES build_hash 占位符** | `"build_hash": "abc123"` — 真实 ES 从未使用此值 |
| **Favicon 是文本** | `/favicon.jpg` 实际内容是 ASCII 文本 `404 page not found` |
| **多端口统一阻断** | 8081/8082/8083/7001/9200 全部返回相同 `403 Retry-After: 120` |
| **端口沙拉模式** | 22 + 8080 + 8081/2/3 + 7001 + 9200 — 人工堆叠 |

### 反方证据（可能为真实系统）

| 指标 | 说明 |
|------|------|
| 1.1MB JS 包 | Vue 3 + Element Plus 完整组件（Alerts/Assets/Users/Roles） |
| 中文 API 响应 | `用户名或密码错误`、`未登录或token已过期` |
| ES 响应结构完整 | 字段齐全的 JSON |

### 判定：蜜罐（置信度 80%）

**最可能平台：** HFish 或 T-Pot。`build_hash: abc123` 是 HFish 中伪造 ES 服务的已知特征。1.1MB JS 包可能是从真实 InsightFlow 产品扒下来的前端静态资源。

### 探测命令

```bash
# ES 蜜罐检测
curl -sk "http://目标公网IP:9200/"
# → build_hash: abc123, build_date: 2026-03-15 (ES 8.11.0 was 2023!)

# Favicon 检测
file /tmp/insightflow_favicon.jpg
# → ASCII text (不是图片!)

# 多端口一致性检测
for port in 8081 8082 8083 9200; do
  curl -skI "http://目标公网IP:$port/" 2>/dev/null | head -1
done
# → 全部 HTTP/1.1 403 Forbidden + Retry-After: 120

# JS bundle 大小
curl -sk "http://目标公网IP:8080/assets/index-D10HDksq.js" | wc -c
# → 1,101,869 bytes (1.1MB)
```

---

## 案例二：115.198.202.226 — 真实中国电信 CPE 路由器

### 基本信息
- IP: 115.198.202.226 (CHINANET-ZJ-HZ, 杭州电信)
- ISP: 中国电信浙江
- 类型: 家庭/企业宽带 CPE + Hikvision 摄像头

### Quake 确认 13 个服务

| 端口 | 协议 | 服务 | 说明 |
|------|------|------|------|
| 22 | TCP | SSH (Linux) | CPE 管理 |
| 2222 | TCP | SSH (Ubuntu) | 备用 SSH |
| 23 | TCP | Telnet | CPE 管理 |
| 21 | TCP | FTP | CPE 管理 |
| 161 | UDP | SNMP | 设备管理 |
| 500 | UDP | ISAKMP (IPSec) | VPN 透传 |
| 1701 | UDP | L2TPv2 | VPN 透传 |
| 7547 | TCP | HTTP (TR-069) | 电信 ACS 管理 |
| 7000 | TCP | HTTP | CPE Web 管理 |
| 30010 | TCP | HTTP | CPE 功能页 |
| **8000** | TCP | **Hikvision** | **海康摄像头** |
| 1688 | TCP | unknown | 端口映射 |
| 20002 | TCP | unknown/SSL | 未知 |

### 判定：真实设备（置信度 95%）

**判断依据：**
- 端口分布符合 CPE 路由器标准模式
- 7547 TR-069 + 500/1701 VPN 是 ISP CPE 标配
- 8000 Hikvision 是内网设备端口映射
- Quake org 字段确认 China Telecom
- 无蜜罐特征（无 ES、无假版本号）

### 攻击面

| 风险 | 端口 | 说明 |
|------|------|------|
| 🔴 高 | 8000 Hikvision | 默认口令 admin/12345，历史 RCE |
| 🔴 高 | 23 Telnet | 明文协议，弱口令 |
| 🔴 高 | 21 FTP | 明文协议，弱口令 |
| 🟡 中 | 22/2222 SSH | 可爆破 |
| 🟡 中 | 161 SNMP | public 字符串泄露 |
| 🟡 中 | 7547 TR-069 | 历史漏洞 |
