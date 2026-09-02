# 批量域名信息收集：并行 delegate_task 模式

适用场景：用户提供 30+ 域名清单，要求纯被动收集（禁止打点），需输出每个域名的 DNS、端口、Web 指纹。

## 工作流

### 1. 域名分组

按根域去重后分 2-3 组，每组约 15-20 个子域名：

```python
groups = {
    "group1": ["iprcc.cn", "www.iprcc.cn", ...],  # ~15
    "group2": ["zysy.org.cn", "www.zysy.org.cn", ...],  # ~16
    "group3": ["globaltimes.cn", "www.globaltimes.cn", ...],  # ~22
}
```

### 2. 并行 dispatch

```python
delegate_task(tasks=[
    {"goal": "信息收集：域名组A（约15个子域名），纯被动探活+指纹", "toolsets": ["terminal","web"]},
    {"goal": "信息收集：域名组B（约16个子域名），纯被动探活+指纹", "toolsets": ["terminal","web"]},
    {"goal": "信息收集：域名组C（约22个子域名），纯被动探活+指纹", "toolsets": ["terminal","web"]},
])
```

每组 agent 执行：`dig A/CNAME` → `curl -skI 80/443` → 提取 Server/Title/状态码。

### 3. 汇总

各组完成后，合并 DNS 解析表、端口状态、Web 指纹，输出综合报告。

## 输出格式（每个域名组）

```markdown
| 域名 | 解析IP | 80 | 443 | HTTP状态 | 网页标题 | Server头 | CDN/CNAME链 |
```

## 关键注意事项

1. **禁止打点**：用户明确说"禁止打点"时，仅做 DNS + 80/443 curl -I，不做路径探测、不做 afrog/nuclei 扫描
2. **crt.sh 兜底**：crt.sh 不可达时改用 certspotter API 或 `openssl s_client` 提取 SAN
3. **SSL 证书 SAN 跨域关联**：对 HTTPS 可达域执行 `openssl s_client -connect` 提取证书 SAN，可发现隐藏子域名和跨域基础设施关联
4. **超时控制**：每个 curl 设 `--connect-timeout 5 --max-time 10`，10 秒内无响应标记为不可达
5. **IP 复用发现**：跨域共享同一 IP 是高价值信号，说明共用 CDN/云平台
