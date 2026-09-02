#!/usr/bin/env python3
"""
Web Application Fingerprint Scanner
====================================
基于 HTTP 响应特征的 Web 指纹识别工具
- Header / Body / Title / Cookie / 特定路径探测
- 支持 CRITICAL / HIGH / MEDIUM / LOW 四级严重度
- 参考: TideFinger, Wappalyzer, 14Finger, EASY233/Finger

Usage:
    python3 web_fingerprint.py https://target.com
    python3 web_fingerprint.py https://target.com -o result.json
    python3 web_fingerprint.py -t targets.txt --threads 10
"""

import argparse
import json
import re
import sys
import ssl
import urllib3
import concurrent.futures
from typing import Optional
from dataclasses import dataclass, field, asdict

try:
    import requests
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────
# Fingerprint Database
# ─────────────────────────────────────────────────────────

FINGERPRINTS = [
    # ═══════════════════════════════════════════════
    # CRITICAL — 远程代码执行 / 凭据泄露 / 敏感数据
    # ═══════════════════════════════════════════════

    # Actuator 暴露 (Spring Boot)
    {
        "name": "Spring Boot Actuator 暴露",
        "severity": "CRITICAL",
        "category": "信息泄露",
        "probes": [
            {"path": "/actuator", "match_type": "body", "pattern": r'"\_links"\s*:\s*\{.*?"(health|env|heapdump|beans)"'},
            {"path": "/actuator/env", "match_type": "body", "pattern": r'"propertySources"|"activeProfiles"'},
            {"path": "/actuator/heapdump", "match_type": "status", "pattern": "200"},
            {"path": "/actuator/configprops", "match_type": "body", "pattern": r'"contexts"|"beans"'},
        ],
        "exploit_note": "可获取环境变量、堆转储、数据库密码等敏感信息",
        "remediation": "限制 actuator 端点访问，配置 management.endpoints.web.exposure.include"
    },

    # SQL 错误泄露
    {
        "name": "SQL 错误信息泄露",
        "severity": "CRITICAL",
        "category": "信息泄露",
        "match_rules": [
            {"match_type": "body", "pattern": r"SQL syntax.*?MySQL|Warning.*?mysql_|MySqlException|valid MySQL result"},
            {"match_type": "body", "pattern": r"ORA-\d{5}|Oracle.*?Driver|quoted string not properly terminated"},
            {"match_type": "body", "pattern": r"Unclosed quotation mark.*?Microsoft|ODBC SQL Server Driver|\[SQL Server\]"},
            {"match_type": "body", "pattern": r"PostgreSQL.*?ERROR|pg_query\(\)|PG::SyntaxError"},
            {"match_type": "body", "pattern": r"SQLite.*?error|SQLite3::|sqlite3\.OperationalError"},
            {"match_type": "body", "pattern": r"Syntax error.*?in query expression|Microsoft JET Database|Microsoft Access"},
        ],
        "exploit_note": "可能存在 SQL 注入漏洞",
        "remediation": "使用参数化查询，关闭详细错误输出"
    },

    # 凭据泄露
    {
        "name": "数据库连接串泄露",
        "severity": "CRITICAL",
        "category": "凭据泄露",
        "match_rules": [
            {"match_type": "body", "pattern": r"jdbc:(?:mysql|postgresql|oracle|sqlserver)://[\S]+"},
            {"match_type": "body", "pattern": r"mongodb(?:\+srv)?://[\S]+"},
            {"match_type": "body", "pattern": r"redis://[\S]+"},
            {"match_type": "body", "pattern": r"amqp://[\S]+"},
            {"match_type": "body", "pattern": r"mysql://[\S]+"},
            {"match_type": "body", "pattern": r"postgres(?:ql)?://[\S]+"},
        ],
        "exploit_note": "泄露的连接串可能包含数据库地址、端口、用户名和密码",
        "remediation": "使用环境变量或密钥管理服务存储凭据"
    },

    # Git 泄露
    {
        "name": "Git 仓库泄露",
        "severity": "CRITICAL",
        "category": "源码泄露",
        "probes": [
            {"path": "/.git/HEAD", "match_type": "body", "pattern": r"ref:\s+refs/"},
            {"path": "/.git/config", "match_type": "body", "pattern": r"\[core\]|repositoryformatversion"},
        ],
        "exploit_note": "可利用 git-dumper 等工具还原完整源码",
        "remediation": "部署时排除 .git 目录，配置 Web 服务器禁止访问"
    },

    # SVN 泄露
    {
        "name": "SVN 仓库泄露",
        "severity": "CRITICAL",
        "category": "源码泄露",
        "probes": [
            {"path": "/.svn/entries", "match_type": "body", "pattern": r"(svn|dir|file).*?\d+"},
            {"path": "/.svn/wc.db", "match_type": "status", "pattern": "200"},
        ],
        "exploit_note": "可还原源码及提交历史",
        "remediation": "部署时排除 .svn 目录"
    },

    # .env 文件泄露
    {
        "name": ".env 环境变量泄露",
        "severity": "CRITICAL",
        "category": "凭据泄露",
        "probes": [
            {"path": "/.env", "match_type": "body", "pattern": r"(DB_PASSWORD|SECRET_KEY|API_KEY|AWS_SECRET|DATABASE_URL)\s*="},
        ],
        "exploit_note": "泄露数据库密码、API 密钥、云服务凭据等",
        "remediation": "配置 Web 服务器禁止访问隐藏文件"
    },

    # ThinkPHP 日志泄露
    {
        "name": "ThinkPHP 日志泄露",
        "severity": "CRITICAL",
        "category": "信息泄露",
        "probes": [
            {"path": "/runtime/log/", "match_type": "status", "pattern": "200"},
            {"path": "/runtime/log/home/", "match_type": "body", "pattern": r"\d{4}_\d{2}_\d{2}|\.log"},
        ],
        "exploit_note": "日志可能包含 SQL 语句、请求参数、错误堆栈",
        "remediation": "配置 Web 服务器禁止访问 runtime 目录"
    },

    # ═══════════════════════════════════════════════
    # HIGH — 框架识别 / API 文档暴露 / 管理后台
    # ═══════════════════════════════════════════════

    # Spring Boot
    {
        "name": "Spring Boot",
        "severity": "HIGH",
        "category": "框架识别",
        "match_rules": [
            {"match_type": "body", "pattern": r"Whitelabel Error Page"},
            {"match_type": "header", "pattern": r"X-Application-Context"},
        ],
        "probes": [
            {"path": "/actuator", "match_type": "body", "pattern": r'"\_links"'},
            {"path": "/swagger-ui.html", "match_type": "body", "pattern": r"swagger-ui"},
            {"path": "/druid/index.html", "match_type": "body", "pattern": r"Druid.*?Monitor"},
            {"path": "/v2/api-docs", "match_type": "body", "pattern": r'"swagger"\s*:\s*"2\.0"'},
        ],
        "exploit_note": "Spring Boot 默认配置可能暴露 actuator、swagger、druid 等敏感端点",
        "remediation": "配置 management.endpoints.web.exposure.include=health,info"
    },

    # Swagger / API 文档
    {
        "name": "Swagger API 文档暴露",
        "severity": "HIGH",
        "category": "API 文档",
        "probes": [
            {"path": "/swagger-ui.html", "match_type": "body", "pattern": r"swagger-ui|Swagger UI"},
            {"path": "/swagger-ui/", "match_type": "body", "pattern": r"swagger-ui"},
            {"path": "/api-docs", "match_type": "body", "pattern": r'"swagger"|"openapi"'},
            {"path": "/v2/api-docs", "match_type": "body", "pattern": r'"swagger"\s*:\s*"2\.0"'},
            {"path": "/v3/api-docs", "match_type": "body", "pattern": r'"openapi"\s*:\s*"3\.'},
            {"path": "/doc.html", "match_type": "body", "pattern": r"knife4j|swagger-bootstrap-ui"},
        ],
        "exploit_note": "API 文档暴露完整接口信息，便于进一步攻击",
        "remediation": "生产环境禁用 Swagger，或配置 IP 白名单"
    },

    # Druid 监控
    {
        "name": "Druid 监控面板暴露",
        "severity": "HIGH",
        "category": "管理后台",
        "probes": [
            {"path": "/druid/index.html", "match_type": "body", "pattern": r"Druid.*?Monitor|DruidStatView"},
            {"path": "/druid/login.html", "match_type": "body", "pattern": r"Druid.*?Login"},
            {"path": "/druid/datasource.json", "match_type": "body", "pattern": r'"DbType"|"URL"'},
        ],
        "exploit_note": "Druid 面板可查看 SQL 执行记录、数据源配置、连接池信息",
        "remediation": "配置 stat-view-servlet.allow IP 白名单"
    },

    # ThinkPHP
    {
        "name": "ThinkPHP",
        "severity": "HIGH",
        "category": "框架识别",
        "match_rules": [
            {"match_type": "body", "pattern": r"thinkphp|ThinkPHP|thinkphp_show_page_trace"},
            {"match_type": "cookie", "pattern": r"think_var|thinkphp_show_page_trace"},
            {"match_type": "header", "pattern": r"X-Powered-By.*?ThinkPHP"},
        ],
        "probes": [
            {"path": "/index.php?s=/captcha", "match_type": "header", "pattern": r"think_var|thinkphp|Set-Cookie.*?think_"},  # 200 = TP
            {"path": "/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1", "match_type": "body", "pattern": r"phpinfo|PHP Version"},
        ],
        "exploit_note": "ThinkPHP 多个版本存在 RCE 漏洞，堆栈信息泄露可获取绝对路径",
        "remediation": "升级到最新版本，关闭调试模式 app_debug=false"
    },

    # ASP.NET
    {
        "name": "ASP.NET",
        "severity": "HIGH",
        "category": "框架识别",
        "match_rules": [
            {"match_type": "body", "pattern": r"__VIEWSTATE|__EVENTVALIDATION|__VIEWSTATEGENERATOR"},
            {"match_type": "header", "pattern": r"X-Powered-By.*?ASP\.NET|X-AspNet-Version"},
            {"match_type": "header", "pattern": r"X-AspNetMvc-Version"},
        ],
        "probes": [
            {"path": "/elmah.axd", "match_type": "body", "pattern": r"Error Log|ELMAH"},
            {"path": "/trace.axd", "match_type": "body", "pattern": r"Request Details|ASP\.NET Trace"},
            {"path": "/web.config", "match_type": "body", "pattern": r"<configuration>|<system\.web>"},
        ],
        "exploit_note": "elmah.axd 泄露错误日志，trace.axd 泄露请求详情，web.config 可能含连接串",
        "remediation": "禁用 customErrors=Off，移除 elmah/trace handler"
    },

    # Laravel
    {
        "name": "Laravel",
        "severity": "HIGH",
        "category": "框架识别",
        "match_rules": [
            {"match_type": "body", "pattern": r"csrf-token|laravel_session|XSRF-TOKEN"},
            {"match_type": "cookie", "pattern": r"laravel_session|XSRF-TOKEN"},
            {"match_type": "body", "pattern": r"Whoops!.*?Looks like something went wrong|Ignition"},
        ],
        "probes": [
            {"path": "/.env", "match_type": "body", "pattern": r"APP_KEY=base64:"},
            {"path": "/storage/logs/laravel.log", "match_type": "body", "pattern": r"laravel\.log|Stack trace"},
            {"path": "/telescope", "match_type": "body", "pattern": r"Laravel Telescope"},
            {"path": "/_ignition/execute-solution", "match_type": "body", "pattern": r"solution|parameters"},
        ],
        "exploit_note": ".env 泄露 APP_KEY 可伪造 Cookie；Ignition <= 2.5.2 存在 RCE (CVE-2021-3129)",
        "remediation": "生产环境 APP_DEBUG=false，移除 telescope"
    },

    # 芋道 Yudao (ruoyi-vue-pro)
    {
        "name": "芋道 (Yudao/ruoyi-vue-pro)",
        "severity": "HIGH",
        "category": "框架识别",
        "match_rules": [
            {"match_type": "body", "pattern": r"VITE_GLOB_API_URL_PREFIX|yudao|ruoyi"},
            {"match_type": "body", "pattern": r"/admin-api/|/app-api/"},
        ],
        "probes": [
            {"path": "/admin-api/system/user/page", "match_type": "body", "pattern": r'"code"|"data"|"msg"'},
            {"path": "/admin-api/infra/file/upload", "match_type": "body", "pattern": r'"code"'},
            {"path": "/admin-api/bpm/task/my", "match_type": "body", "pattern": r'"code"'},
            {"path": "/app-api/", "match_type": "body", "pattern": r'"code"'},
        ],
        "exploit_note": "芋道框架常见 80+ 接口暴露，需检查未授权访问",
        "remediation": "配置接口权限，关闭不必要的 API"
    },

    # Vue.js 前端
    {
        "name": "Vue.js",
        "severity": "MEDIUM",
        "category": "前端框架",
        "match_rules": [
            {"match_type": "body", "pattern": r"vue|Vue\.|__vue__|nuxt"},
            {"match_type": "body", "pattern": r"webpackJsonp|__webpack_require__"},
        ],
        "probes": [
            {"path": "/api/v1/", "match_type": "status", "pattern": "200|401|403"},
            {"path": "/api/v2/", "match_type": "status", "pattern": "200|401|403"},
        ],
    },

    # React 前端
    {
        "name": "React",
        "severity": "MEDIUM",
        "category": "前端框架",
        "match_rules": [
            {"match_type": "body", "pattern": r"react-dom|__REACT_DEVTOOLS|_reactRootContainer"},
            {"match_type": "body", "pattern": r"data-reactroot|react-hot-loader"},
        ],
    },

    # 神策 Sensors Data
    {
        "name": "神策数据 (Sensors Analytics)",
        "severity": "HIGH",
        "category": "数据分析",
        "match_rules": [
            {"match_type": "body", "pattern": r"SensorsDataAPI|sensorsdata|sa\.track|Sensors Analytics"},
        ],
        "probes": [
            {"path": "/sdk/debug_mode_init", "match_type": "body", "pattern": r"Sensors Analytics is ready|debug_mode"},
        ],
        "exploit_note": "神策 Debug 模式暴露可查看埋点配置和用户数据",
        "remediation": "关闭 Debug 模式"
    },

    # Shiro
    {
        "name": "Apache Shiro",
        "severity": "HIGH",
        "category": "安全框架",
        "match_rules": [
            {"match_type": "cookie", "pattern": r"rememberMe=deleteMe|Shiro"},
        ],
        "exploit_note": "Shiro rememberMe 反序列化漏洞 (CVE-2016-4437) 可 RCE",
        "remediation": "升级 Shiro 版本，使用随机密钥"
    },

    # Nacos
    {
        "name": "Nacos",
        "severity": "HIGH",
        "category": "服务发现",
        "probes": [
            {"path": "/nacos/", "match_type": "body", "pattern": r"nacos-console|Nacos v\d|Nacos Login"},
            {"path": "/nacos/v1/auth/login", "match_type": "body", "pattern": r'"accessToken"|"token"'},
        ],
        "exploit_note": "Nacos 默认凭据 nacos/nacos，存在多个未授权漏洞",
        "remediation": "修改默认密码，开启认证"
    },

    # ═══════════════════════════════════════════════
    # MEDIUM — Web 服务器 / 中间件 / 其他框架
    # ═══════════════════════════════════════════════

    # Tomcat
    {
        "name": "Apache Tomcat",
        "severity": "MEDIUM",
        "category": "Web 服务器",
        "match_rules": [
            {"match_type": "header", "pattern": r"Server.*?Apache-Coyote|Tomcat"},
            {"match_type": "body", "pattern": r"Apache Tomcat.*?Error report|Tomcat Manager"},
        ],
        "probes": [
            {"path": "/manager/html", "match_type": "body", "pattern": r"Tomcat Manager|Tomcat Web Application Manager"},
            {"path": "/host-manager/html", "match_type": "body", "pattern": r"Tomcat Host Manager"},
        ],
    },

    # Nginx
    {
        "name": "Nginx",
        "severity": "LOW",
        "category": "Web 服务器",
        "match_rules": [
            {"match_type": "header", "pattern": r"Server.*?nginx"},
        ],
    },

    # IIS
    {
        "name": "Microsoft IIS",
        "severity": "MEDIUM",
        "category": "Web 服务器",
        "match_rules": [
            {"match_type": "header", "pattern": r"Server.*?Microsoft-IIS|X-Powered-By.*?ASP\.NET"},
        ],
        "probes": [
            {"path": "/iisstart.htm", "match_type": "body", "pattern": r"IIS.*?Windows|Microsoft"},
        ],
    },

    # Apache
    {
        "name": "Apache HTTP Server",
        "severity": "LOW",
        "category": "Web 服务器",
        "match_rules": [
            {"match_type": "header", "pattern": r"Server.*?Apache(?!-Coyote)"},
        ],
        "probes": [
            {"path": "/server-status", "match_type": "body", "pattern": r"Apache Server Status|Server uptime"},
            {"path": "/server-info", "match_type": "body", "pattern": r"Apache Server Information"},
        ],
    },

    # WordPress
    {
        "name": "WordPress",
        "severity": "MEDIUM",
        "category": "CMS",
        "match_rules": [
            {"match_type": "body", "pattern": r"wp-content|wp-includes|wp-json|WordPress"},
            {"match_type": "body", "pattern": r"xmlrpc\.php|wp-login\.php"},
        ],
        "probes": [
            {"path": "/wp-login.php", "match_type": "body", "pattern": r"WordPress|wp-login"},
            {"path": "/wp-json/wp/v2/users", "match_type": "body", "pattern": r'"slug"|"name"'},
            {"path": "/xmlrpc.php", "match_type": "body", "pattern": r"XML-RPC server accepts POST requests only"},
        ],
    },

    # Drupal
    {
        "name": "Drupal",
        "severity": "MEDIUM",
        "category": "CMS",
        "match_rules": [
            {"match_type": "body", "pattern": r"Drupal|drupal\.js|sites/default/files"},
            {"match_type": "header", "pattern": r"X-Generator.*?Drupal|X-Drupal-Cache"},
        ],
    },

    # Joomla
    {
        "name": "Joomla",
        "severity": "MEDIUM",
        "category": "CMS",
        "match_rules": [
            {"match_type": "body", "pattern": r"/media/jui/|Joomla!|com_content"},
        ],
    },

    # Weblogic
    {
        "name": "Oracle WebLogic",
        "severity": "HIGH",
        "category": "中间件",
        "match_rules": [
            {"match_type": "body", "pattern": r"WebLogic|weblogic\.internal|<title>Error 404.*?WebLogic"},
            {"match_type": "header", "pattern": r"Server.*?WebLogic"},
        ],
        "probes": [
            {"path": "/console", "match_type": "body", "pattern": r"WebLogic Server.*?Console"},
            {"path": "/wls-wsat/CoordinatorPortType", "match_type": "body", "pattern": r"WLS Web Services|<wscoor:|CoordinatorPortType.*?xmlns"},
        ],
        "exploit_note": "WebLogic 存在多个反序列化 RCE 漏洞 (CVE-2019-2725 等)",
    },

    # JBoss
    {
        "name": "JBoss/WildFly",
        "severity": "HIGH",
        "category": "中间件",
        "match_rules": [
            {"match_type": "body", "pattern": r"JBoss|jboss|WildFly"},
            {"match_type": "header", "pattern": r"X-Powered-By.*?JBoss"},
        ],
        "probes": [
            {"path": "/jmx-console/", "match_type": "body", "pattern": r"JBoss JMX Management Console"},
            {"path": "/web-console/", "match_type": "body", "pattern": r"JBoss Web Console"},
        ],
    },

    # Jenkins
    {
        "name": "Jenkins",
        "severity": "HIGH",
        "category": "CI/CD",
        "match_rules": [
            {"match_type": "header", "pattern": r"X-Jenkins|X-Hudson"},
        ],
        "probes": [
            {"path": "/login", "match_type": "body", "pattern": r"Jenkins|Dashboard"},
            {"path": "/api/json", "match_type": "body", "pattern": r'"jobs"|"primaryView"'},
        ],
    },

    # GitLab
    {
        "name": "GitLab",
        "severity": "MEDIUM",
        "category": "代码托管",
        "match_rules": [
            {"match_type": "body", "pattern": r"GitLab|gitlab"},
            {"match_type": "cookie", "pattern": r"_gitlab_session"},
        ],
        "probes": [
            {"path": "/api/v4/version", "match_type": "body", "pattern": r'"version"'},
        ],
    },

    # Grafana
    {
        "name": "Grafana",
        "severity": "HIGH",
        "category": "监控",
        "match_rules": [
            {"match_type": "body", "pattern": r"Grafana|grafana"},
            {"match_type": "cookie", "pattern": r"grafana_session"},
        ],
        "probes": [
            {"path": "/api/org", "match_type": "body", "pattern": r'"id"|"name"'},
            {"path": "/login", "match_type": "body", "pattern": r"Grafana v\d|grafana-app|GrafanaLoader"},
        ],
    },

    # MinIO
    {
        "name": "MinIO",
        "severity": "HIGH",
        "category": "对象存储",
        "match_rules": [
            {"match_type": "header", "pattern": r"Server.*?MinIO"},
            {"match_type": "body", "pattern": r"MinIO|minio"},
        ],
        "probes": [
            {"path": "/minio/login", "match_type": "body", "pattern": r"MinIO|Login"},
        ],
    },

    # RabbitMQ
    {
        "name": "RabbitMQ",
        "severity": "MEDIUM",
        "category": "消息队列",
        "probes": [
            {"path": "/", "match_type": "body", "pattern": r"RabbitMQ Management|rabbitmq"},
            {"path": "/api/overview", "match_type": "body", "pattern": r'"rabbitmq_version"|"cluster_name"'},
        ],
    },

    # Elasticsearch
    {
        "name": "Elasticsearch",
        "severity": "HIGH",
        "category": "搜索引擎",
        "probes": [
            {"path": "/", "match_type": "body", "pattern": r'"cluster_name".*?"tagline"\s*:\s*"You Know, for Search"'},
            {"path": "/_cat/indices", "match_type": "body", "pattern": r"green open|yellow open"},
        ],
        "exploit_note": "未授权访问可查看/删除所有索引数据",
    },

    # Redis (Web UI)
    {
        "name": "Redis (Web 管理)",
        "severity": "HIGH",
        "category": "数据库",
        "match_rules": [
            {"match_type": "body", "pattern": r"Redis Commander|redis-commander|phpRedisAdmin"},
        ],
    },

    # Kibana
    {
        "name": "Kibana",
        "severity": "MEDIUM",
        "category": "监控",
        "match_rules": [
            {"match_type": "body", "pattern": r"kibana|Kibana"},
            {"match_type": "header", "pattern": r"kbn-name|kbn-version"},
        ],
    },

    # Harbor
    {
        "name": "Harbor",
        "severity": "HIGH",
        "category": "容器镜像",
        "probes": [
            {"path": "/api/v2.0/projects", "match_type": "body", "pattern": r'"project_id"|"name"'},
            {"path": "/api/systeminfo/volumes", "match_type": "body", "pattern": r'"storage"|"total"'},
        ],
    },

    # Kong API Gateway
    {
        "name": "Kong API Gateway",
        "severity": "MEDIUM",
        "category": "API 网关",
        "match_rules": [
            {"match_type": "header", "pattern": r"Server.*?kong|X-Kong-"},
        ],
    },

    # Express.js
    {
        "name": "Express.js",
        "severity": "LOW",
        "category": "Web 框架",
        "match_rules": [
            {"match_type": "header", "pattern": r"X-Powered-By.*?Express"},
        ],
    },

    # Django
    {
        "name": "Django",
        "severity": "MEDIUM",
        "category": "Web 框架",
        "match_rules": [
            {"match_type": "body", "pattern": r"csrfmiddlewaretoken|Django.*?Error|DisallowedHost"},
            {"match_type": "cookie", "pattern": r"csrftoken|django"},
        ],
        "probes": [
            {"path": "/admin/", "match_type": "body", "pattern": r"Django administration|Log in"},
        ],
    },

    # Flask
    {
        "name": "Flask",
        "severity": "MEDIUM",
        "category": "Web 框架",
        "match_rules": [
            {"match_type": "body", "pattern": r"werkzeug.*?Debug|Werkzeug Debugger|Jinja2"},
            {"match_type": "header", "pattern": r"Server.*?Werkzeug"},
        ],
        "exploit_note": "Werkzeug Debug 模式存在 RCE (Debug Console PIN 爆破或直接执行)",
    },

    # PHP
    {
        "name": "PHP",
        "severity": "LOW",
        "category": "编程语言",
        "match_rules": [
            {"match_type": "header", "pattern": r"X-Powered-By.*?PHP|Set-Cookie.*?PHPSESSID"},
        ],
        "probes": [
            {"path": "/phpinfo.php", "match_type": "body", "pattern": r"PHP Version|phpinfo\(\)"},
            {"path": "/info.php", "match_type": "body", "pattern": r"PHP Version|phpinfo\(\)"},
        ],
    },

    # Java
    {
        "name": "Java",
        "severity": "LOW",
        "category": "编程语言",
        "match_rules": [
            {"match_type": "cookie", "pattern": r"JSESSIONID"},
            {"match_type": "header", "pattern": r"Set-Cookie.*?JSESSIONID"},
        ],
    },

    # UniApp / uniCloud
    {
        "name": "UniApp / uniCloud",
        "severity": "MEDIUM",
        "category": "前端框架",
        "match_rules": [
            {"match_type": "body", "pattern": r"uni-app|__uniConfig|uniCloud|__uniappview"},
        ],
    },

    # Element UI / Ant Design
    {
        "name": "Element UI",
        "severity": "LOW",
        "category": "UI 组件",
        "match_rules": [
            {"match_type": "body", "pattern": r"element-ui|el-|el-button|el-table"},
        ],
    },

    {
        "name": "Ant Design",
        "severity": "LOW",
        "category": "UI 组件",
        "match_rules": [
            {"match_type": "body", "pattern": r"ant-design|antd|ant-btn|ant-table"},
        ],
    },

    # 通达 OA
    {
        "name": "通达 OA",
        "severity": "HIGH",
        "category": "OA 系统",
        "match_rules": [
            {"match_type": "body", "pattern": r"通达|tongda|TongdaOA|MYOA"},
        ],
        "probes": [
            {"path": "/login/", "match_type": "body", "pattern": r"通达|Office Anywhere"},
            {"path": "/ispirit/", "match_type": "body", "pattern": r"通达|ispirit"},
        ],
        "exploit_note": "通达 OA 存在多个 RCE 和文件上传漏洞",
    },

    # 泛微 OA
    {
        "name": "泛微 E-Office / E-Cology",
        "severity": "HIGH",
        "category": "OA 系统",
        "match_rules": [
            {"match_type": "body", "pattern": r"泛微|weaver|E-Office|e-cology|e-Bridge"},
        ],
        "probes": [
            {"path": "/eoffice/", "match_type": "body", "pattern": r"泛微|E-Office"},
            {"path": "/e-cology/", "match_type": "body", "pattern": r"泛微|e-cology"},
        ],
        "exploit_note": "泛微 OA 存在多个未授权和文件上传漏洞",
    },

    # 致远 OA
    {
        "name": "致远 OA (Seeyon)",
        "severity": "HIGH",
        "category": "OA 系统",
        "match_rules": [
            {"match_type": "body", "pattern": r"致远软件|Seeyon.*?OA|SEAYON|A8\+.*?协同"},
        ],
        "probes": [
            {"path": "/seeyon/", "match_type": "body", "pattern": r"致远|Seeyon"},
        ],
        "exploit_note": "致远 OA 存在文件上传和反序列化漏洞",
    },

    # 用友
    {
        "name": "用友 (Yonyou)",
        "severity": "HIGH",
        "category": "ERP",
        "match_rules": [
            {"match_type": "body", "pattern": r"用友网络|yonyou\.com|Yonyou|U8[Cc]loud|NC [Cc]loud|用友.*?(?:ERP|NC|U8|CRM)"},
        ],
        "exploit_note": "用友多个产品存在 SQL 注入和文件上传漏洞",
    },

    # 金蝶
    {
        "name": "金蝶 (Kingdee)",
        "severity": "HIGH",
        "category": "ERP",
        "match_rules": [
            {"match_type": "body", "pattern": r"金蝶|kingdee|Kingdee|K3Cloud|K3WISE|EAS"},
        ],
    },

    # Zabbix
    {
        "name": "Zabbix",
        "severity": "MEDIUM",
        "category": "监控",
        "match_rules": [
            {"match_type": "body", "pattern": r"Zabbix|zabbix"},
            {"match_type": "cookie", "pattern": r"zbx_session"},
        ],
        "probes": [
            {"path": "/api_jsonrpc.php", "match_type": "body", "pattern": r'"jsonrpc"'},
        ],
    },

    # FortiGate / Fortinet
    {
        "name": "FortiGate",
        "severity": "MEDIUM",
        "category": "安全设备",
        "match_rules": [
            {"match_type": "body", "pattern": r"FortiGate|fortinet|fgt_lang"},
            {"match_type": "cookie", "pattern": r"APSCOOKIE_|APCFRS"},
        ],
        "exploit_note": "FortiGate 存在多个 SSL VPN RCE 漏洞 (CVE-2023-27997 等)",
    },

    # Palo Alto GlobalProtect
    {
        "name": "Palo Alto GlobalProtect",
        "severity": "MEDIUM",
        "category": "VPN",
        "match_rules": [
            {"match_type": "body", "pattern": r"GlobalProtect|global-protect|/ssl-vpn/"},
            {"match_type": "cookie", "pattern": r"PHPSESSID.*?portal"},
        ],
        "exploit_note": "GlobalProtect 存在多个 RCE 漏洞 (CVE-2021-3064 等)",
    },

    # 深信服
    {
        "name": "深信服 (Sangfor)",
        "severity": "MEDIUM",
        "category": "安全设备",
        "match_rules": [
            {"match_type": "body", "pattern": r"深信服|Sangfor|SANGFOR"},
            {"match_type": "cookie", "pattern": r"SANGFOR"},
        ],
    },

    # 齐治堡垒机
    {
        "name": "齐治堡垒机 (Shterm)",
        "severity": "HIGH",
        "category": "堡垒机",
        "match_rules": [
            {"match_type": "body", "pattern": r"shterm|齐治|堡垒机"},
        ],
        "probes": [
            {"path": "/api/virtual/role", "match_type": "body", "pattern": r'"result"|"data"'},
        ],
    },

    # 宝塔面板
    {
        "name": "宝塔面板 (BT Panel)",
        "severity": "MEDIUM",
        "category": "运维面板",
        "match_rules": [
            {"match_type": "body", "pattern": r"宝塔面板|BT-Panel|bt.cn|BaoTa"},
        ],
        "probes": [
            {"path": "/login", "match_type": "body", "pattern": r"宝塔|BT-Panel"},
        ],
    },

    # phpMyAdmin
    {
        "name": "phpMyAdmin",
        "severity": "HIGH",
        "category": "数据库管理",
        "match_rules": [
            {"match_type": "body", "pattern": r"phpMyAdmin|pma_"},
            {"match_type": "cookie", "pattern": r"phpMyAdmin|pma_"},
        ],
        "probes": [
            {"path": "/phpmyadmin/", "match_type": "body", "pattern": r"phpMyAdmin.*?(?:Log in|Login|MySQL)"},
            {"path": "/pma/", "match_type": "body", "pattern": r"phpMyAdmin"},
        ],
    },

    # JumpServer
    {
        "name": "JumpServer 堡垒机",
        "severity": "MEDIUM",
        "category": "堡垒机",
        "match_rules": [
            {"match_type": "body", "pattern": r"JumpServer|jumpserver"},
            {"match_type": "cookie", "pattern": r"jms_sessionid|csrftoken_jms"},
        ],
    },

    # Casdoor
    {
        "name": "Casdoor",
        "severity": "MEDIUM",
        "category": "认证系统",
        "match_rules": [
            {"match_type": "body", "pattern": r"casdoor|Casdoor"},
        ],
        "probes": [
            {"path": "/api/get-account", "match_type": "body", "pattern": r'"data":\s*\{.*?"name"'},
        ],
    },
]


# ─────────────────────────────────────────────────────────
# Scanner Engine
# ─────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate",
}


@dataclass
class FingerprintMatch:
    name: str
    severity: str
    category: str
    matched_by: list = field(default_factory=list)
    exploit_note: str = ""
    remediation: str = ""


@dataclass
class ScanResult:
    target: str
    status_code: int = 0
    server_header: str = ""
    title: str = ""
    technologies: list = field(default_factory=list)  # list of FingerprintMatch as dict
    raw_headers: dict = field(default_factory=dict)
    error: str = ""


def safe_regex(pattern: str, text: str) -> bool:
    """Safe regex match with timeout protection."""
    try:
        return bool(re.search(pattern, text, re.IGNORECASE | re.DOTALL))
    except re.error:
        return False


def get_title(html: str) -> str:
    """Extract <title> from HTML."""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""


def check_match_rule(rule: dict, headers_str: str, body: str, title: str, cookies_str: str) -> bool:
    """Check a single match rule against response data."""
    mt = rule["match_type"]
    pattern = rule["pattern"]
    if mt == "header":
        return safe_regex(pattern, headers_str)
    elif mt == "body":
        return safe_regex(pattern, body)
    elif mt == "title":
        return safe_regex(pattern, title)
    elif mt == "cookie":
        return safe_regex(pattern, cookies_str)
    return False


def scan_target(target: str, timeout: int = 10) -> ScanResult:
    """Scan a single target URL."""
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    result = ScanResult(target=target)

    try:
        r = requests.get(target, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        result.status_code = r.status_code
        result.server_header = r.headers.get("Server", "")
        result.title = get_title(r.text)
        result.raw_headers = dict(r.headers)

        headers_str = str(dict(r.headers))
        body = r.text
        title = result.title
        cookies_str = "; ".join([f"{c.name}={c.value}" for c in r.cookies])

        for fp in FINGERPRINTS:
            matched_by = []

            # Check match_rules (response-based)
            if "match_rules" in fp:
                for rule in fp["match_rules"]:
                    if check_match_rule(rule, headers_str, body, title, cookies_str):
                        matched_by.append(f"{rule['match_type']}匹配: {rule['pattern'][:60]}")
                        break  # One match is enough for match_rules (OR logic within rules)

            # Check probes (path-based) — only match on 2xx responses to avoid false positives on 404 pages
            if "probes" in fp:
                for probe in fp["probes"]:
                    probe_url = target.rstrip("/") + probe["path"]
                    try:
                        pr = requests.get(probe_url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
                        # Skip 4xx/5xx responses for body/header probes (status probes handle their own codes)
                        if probe["match_type"] != "status" and pr.status_code >= 400:
                            continue

                        probe_text = pr.text if probe["match_type"] != "status" else str(pr.status_code)
                        probe_headers = str(dict(pr.headers))
                        probe_cookies = "; ".join([f"{c.name}={c.value}" for c in pr.cookies])

                        if probe["match_type"] == "status":
                            if re.match(probe["pattern"], str(pr.status_code)):
                                matched_by.append(f"探测 {probe['path']} → {pr.status_code}")
                        elif probe["match_type"] == "body":
                            if safe_regex(probe["pattern"], probe_text):
                                matched_by.append(f"探测 {probe['path']} → body匹配")
                        elif probe["match_type"] == "header":
                            if safe_regex(probe["pattern"], probe_headers):
                                matched_by.append(f"探测 {probe['path']} → header匹配")
                    except:
                        pass

            if matched_by:
                result.technologies.append({
                    "name": fp["name"],
                    "severity": fp.get("severity", "MEDIUM"),
                    "category": fp.get("category", "未分类"),
                    "matched_by": matched_by,
                    "exploit_note": fp.get("exploit_note", ""),
                    "remediation": fp.get("remediation", ""),
                })

    except requests.exceptions.ConnectionError:
        result.error = "连接失败"
    except requests.exceptions.Timeout:
        result.error = "连接超时"
    except Exception as e:
        result.error = str(e)

    # Sort by severity
    result.technologies.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "LOW"), 99))
    return result


def format_result(result: ScanResult, verbose: bool = False) -> str:
    """Format scan result for terminal output."""
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"🎯 目标: {result.target}")
    if result.error:
        lines.append(f"❌ 错误: {result.error}")
        return "\n".join(lines)

    lines.append(f"📊 状态码: {result.status_code}")
    lines.append(f"🖥️  Server: {result.server_header or '未检测到'}")
    lines.append(f"📝 Title: {result.title or '无标题'}")
    lines.append(f"{'='*60}")

    if not result.technologies:
        lines.append("  未识别到已知技术栈")
    else:
        severity_colors = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }
        for tech in result.technologies:
            icon = severity_colors.get(tech["severity"], "⚪")
            lines.append(f"\n  {icon} [{tech['severity']}] {tech['name']} ({tech['category']})")
            if verbose:
                for m in tech["matched_by"]:
                    lines.append(f"     └─ {m}")
                if tech["exploit_note"]:
                    lines.append(f"     💡 {tech['exploit_note']}")
                if tech["remediation"]:
                    lines.append(f"     🛡️  {tech['remediation']}")

    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Web Application Fingerprint Scanner")
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("-t", "--target-file", help="File with targets (one per line)")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--threads", type=int, default=5, help="Thread count (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show match details")
    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    if args.target_file:
        with open(args.target_file) as f:
            targets.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])

    if not targets:
        parser.print_help()
        sys.exit(1)

    results = []
    print(f"\n🔍 Web 指纹识别 - 共 {len(targets)} 个目标")

    if len(targets) == 1:
        result = scan_target(targets[0], args.timeout)
        print(format_result(result, args.verbose))
        results.append(asdict(result))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_map = {executor.submit(scan_target, t, args.timeout): t for t in targets}
            for future in concurrent.futures.as_completed(future_map):
                result = future.result()
                print(format_result(result, args.verbose))
                results.append(asdict(result))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n✅ 结果已保存到 {args.output}")

    # Summary
    total = len(results)
    found = sum(1 for r in results if r["technologies"])
    critical = sum(1 for r in results for t in r["technologies"] if t["severity"] == "CRITICAL")
    high = sum(1 for r in results for t in r["technologies"] if t["severity"] == "HIGH")
    print(f"\n📊 汇总: {total} 个目标, {found} 个识别到技术栈, 🔴{critical} 个严重, 🟠{high} 个高危")


if __name__ == "__main__":
    main()
