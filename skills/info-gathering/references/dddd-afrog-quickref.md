# dddd & afrog 工具快速参考

## 工具路径
```bash
/home/c1ay/.local/bin/dddd    # v2.0.1 批量信息收集
/home/c1ay/.local/bin/afrog   # v3.5.3 PoC漏洞扫描
```

## dddd 常用命令

### 域名扫描（自动 CDN 识别 + 真实IP提取）
```bash
dddd -t example.com -p top200
```
输出会包含 `[RealIP]` 行，直接暴露真实IP。

### 指定端口扫描
```bash
dddd -t 1.2.3.4 -p 21,22,80,443,3306,8080,8443
```

### IP 段扫描
```bash
dddd -t 192.168.1.0/24
```

### 扫描结果解读
- `[Alive]` - 主机存活
- `[PortScan]` - 开放端口
- `[Nmap]` - 服务协议识别
- `[Web]` - Web服务标题
- `[Finger]` - 指纹识别结果（技术栈）
- `[shiro-detect]` - Shiro框架检测

## afrog 常用命令

### 单目标扫描
```bash
afrog -t https://example.com
```

### 多目标扫描
```bash
afrog -t https://target1.com,https://target2.com
```

### 从文件加载目标
```bash
afrog -T targets.txt
```

### 按严重级别过滤
```bash
afrog -t target.com -S high,critical
```

### 搜索特定PoC
```bash
afrog -t target.com -s shiro,log4j,spring
```

### 输出HTML报告
```bash
afrog -t target.com -o report.html
```

## 空间搜索引擎配置

配置文件: `/home/c1ay/.config/afrog/afrog-config.yaml`

```yaml
quake:
  api_key: "YOUR_KEY"
fofa:
  email: ""
  api_key: ""
zoomeye:
  api_key: ""
shodan:
  api_key: ""
```

使用: `afrog -cs quake -q "app:'tomcat'" -qc 1000`

## 实战经验

1. **dddd 自动探测真实IP** — 绕过CDN，直接输出 `[RealIP]`
2. **dddd 指纹识别很全面** — 一次扫描可获取技术栈、框架、CMS等信息
3. **afrog 的 Shiro 检测** — 即使不指定PoC，默认也会检测常见框架
4. **afrog 指定 `-S info` 可只看信息级别** — 减少噪音
5. **扫描超时** — 大范围扫描建议后台运行：`dddd -t target -p 1-65535 &`
6. **两个工具配合** — dddd 做信息收集+端口扫描，afrog 做漏洞验证

## 全端口扫描避坑

| 工具 | 问题 | 替代方案 |
|------|------|---------|
| `dddd -p 1-65535` | TCP connect 扫描极慢（65535 端口逐个连接），300s+ 无输出 | 不用于全端口扫描，仅用于 top 端口 + 指纹识别 |
| `nmap -sS` | 需要 root 权限 | 用 `nmap -sT -T4 -Pn --top-ports 100`（非 root 用户首选） |
| `nmap -sT -p-` | 同样慢，且目标可能过滤 ICMP → 必须加 `-Pn` | 仅当 top-100 有收获时才扩大到全端口 |

**推荐流程（非 root 用户）：**
```bash
# Step 1: 快速 top 100 扫一波（3-5秒）
nmap -sT -T4 -Pn --top-ports 100 <target>

# Step 2: 结合 Quake/Shodan 历史数据交叉验证
python3 ~/.hermes/tools/quake_query.py --ip <target>

# Step 3: 仅当 top 100 有多端口开放 + 非标端口出现才加扫
nmap -sT -T4 -Pn -p- <target> --min-rate=3000
```
