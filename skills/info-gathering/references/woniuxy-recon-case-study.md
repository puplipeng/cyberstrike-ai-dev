---
title: "蜗牛学苑信息收集案例"
target: woniuxy.com
icp: 蜀ICP备15014130号-2
author: Saber
date: 2026-06-17
---

# 蜗牛学苑信息收集案例

## 背景

目标：蜗牛学苑（IT 培训机构），官网 woniuxy.com。
方法论：官网提取 ICP → Quake 搜 ICP → 发现 40+ 关联域名。

## 覆盖资产

从单一域名 woniuxy.com 扩展到 64 个独立域名/子域名，包括：

| 系统 | 域名 | 技术栈 |
|------|------|--------|
| 官网 | woniuxy.com | nginx |
| BOSS 系统 | woniuboss.com | Apache/2.4.39 PHP/7.3.4 |
| 网安实验室 | woniusec.com | — |
| 蜗牛笔记 | woniunote.com | Apache/2.4.41 PHP/7.3.11 |
| 文件云(KodExplorer) | woniuboss.com:8088 | Apache/2.4.39 PHP/7.3.4 |
| Nacos 配置中心 | woniulab.com:28080 | Nacos |
| 模拟面试 | survey.woniuxy.com:5000 | Werkzeug/3.1.3 Python/3.10.10 |
| 基金监管系统 | survey.woniuxy.com:8082 | nginx/1.24.0 |
| Java-WebSocket | survey.woniuxy.com:8989 | TooTallNate |
| 蜗牛问卷 | survey.woniuxy.com:8888 | — |
| 邮箱系统 | mail/pop/smtp/imap.woniuxy.com | nginx/Apache/Tomcat |
| Tengine 视频 | video.woniuxy.com | Tengine |
| WinRM | woniumovie.com:5985/5986 | Microsoft-HTTPAPI/2.0 |
| GoFrame | woniuqa.com:9100 | GoFrame HTTP Server |
| 实验环境 | web.woniulab.com (5 ports) | nginx, Apache, React |

## 关键高危发现

1. Nacos 配置中心公网可达（woniulab.com:28080）— 默认密钥
2. KodExplorer 文件云（woniuboss.com:8088）— 弱口令
3. Tomcat 8.0.47（多处:8080）— 多个已知 CVE
4. WinRM 端口公网暴露（woniumovie.com）
5. PHP 7.1/7.3 已停止安全更新

## 方法论总结

对于中国目标，ICP 反查是效率最高的资产发现手段——一次 Quake 查询即可发现同一公司名下的全部域名，远超 crt.sh 或子域暴力枚举的覆盖面。
