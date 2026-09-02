# xawl.edu.cn 信息收集案例

> 西安文理学院 | 70+ 子域名 | 15+ IP | 8个IP段 | 40+活跃Web服务

## 分阶段策略（避免delegate_task超时）

### 阶段一：被动收集（主会话）
```bash
# crt.sh 子域名
curl -s "https://crt.sh/?q=%25.xawl.edu.cn&output=json" | python3 -c "
import sys,json
d=json.load(sys.stdin)
[print(n) for n in sorted({e for i in d for e in i['name_value'].split('\n') if '*' not in e and e.strip()})]
"

# Quake API
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: <TOKEN>" \
  -d '{"query": "domain: xawl.edu.cn", "start": 0, "size": 500}'
```

### 阶段二：DNS + IP段归类
- 核心段：112.46.132.0/24（约15个活IP）
- 教育网：140.210.88.45/44（图书馆）
- 教育网DNS：59.75.121.202
- 腾讯云：129.226.106.19（邮件系统）

### 阶段三：按IP段分批扫描
每批3-5个IP，用delegate_task并行

### 阶段四：汇总
合并去重，按标准格式输出

## 核心系统清单
| 系统 | 域名 | 技术栈 |
|------|------|--------|
| 主站 | www.xawl.edu.cn | Visual SiteBuilder 9 + Vue.js + WEngine WAF |
| OA | oa.xawl.edu.cn | nginx |
| 统一认证CAS | cas.xawl.edu.cn | nginx |
| 统一认证平台 | auth.xawl.edu.cn | openresty |
| 教务系统 | jwgl.xawl.edu.cn | Tengine/2.1.2 |
| 综合服务大厅 | ehall.xawl.edu.cn | nginx |
| 运维安全网关 | ssa/sas.xawl.edu.cn | 天玥V6.0 堡垒机 |
| 人脸识别 | faced.xawl.edu.cn:9520/9526 | nginx/1.22.1 + VUE SPA + Spring Boot |
| 收费平台 | sfxt.xawl.edu.cn | 博思高校教育收费云平台 |
| 跨校认证 | idp.xawl.edu.cn | Apache + Shibboleth IDP |
| 微信平台 | wxpt.xawl.edu.cn | Microsoft-IIS/10.0 |
| 学生事务 | fresh.xawl.edu.cn | nginx/1.21.1 |
| 科研管理 | kygl.xawl.edu.cn | nginx |
| 智慧报销 | bzxt.xawl.edu.cn | nginx |
| VPN | vpn.xawl.edu.cn | SSL VPN |
| WebVPN | webvpn.xawl.edu.cn | - |
| 邮件系统 | mail.xawl.edu.cn | 腾讯企业邮 |
| 图书馆 | lib.xawl.edu.cn / lib1.xawl.edu.cn | - |
| 人事系统 | rsxt.xawl.edu.cn | openresty |
| 招生系统 | zsb.xawl.edu.cn | - |

## 安全发现
- WEngine WAF: 敏感路径(.svn/.git/.env)返回302重定向非404
- SPA fallback: Vue.js返回index.html掩盖真实endpoint状态
- 人脸识别: 荣邦科技bio_platform, 硬编码apiKey+secret
- 天玥堡垒机: V6.0公网暴露
- IIS服务器: Windows系统暴露
