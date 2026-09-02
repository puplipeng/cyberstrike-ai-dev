# Enterprise Reconnaissance Tools Reference

Tools and techniques for collecting enterprise/company information during reconnaissance.

## ENScan_GO (推荐)

基于国内企业信息查询API的工具，可以收集企业关联信息。

### 安装
```bash
go install github.com/wgpsec/ENScan_GO@latest
# 或下载Release
wget https://github.com/wgpsec/ENScan_GO/releases/latest/download/ENScan_GO_linux_amd64
chmod +x ENScan_GO_linux_amd64
mv ENScan_GO_linux_amd64 /usr/local/bin/enscan
```

### 基本用法
```bash
# 查询企业基本信息
enscan -n 公司名称

# 查询子公司（对外投资）
enscan -n 公司名称 -invest

# 查询ICP备案
enscan -n 公司名称 -icp

# 查询APP
enscan -n 公司名称 -app

# 查询微信公众号
enscan -n 公司名称 -wechat

# 查询招聘岗位
enscan -n 公司名称 -job

# 查询域名
enscan -n 公司名称 -domain

# 深度查询（包含子公司信息）
enscan -n 公司名称 -deep

# 输出JSON格式
enscan -n 公司名称 -o json
```

### 数据源
- 天眼查
- 企查查
- 爱企查
- ICP备案查询

## ICP备案查询

### 工信部备案查询
https://beian.miit.gov.cn/

### 第三方备案查询
```bash
# API查询
curl -s 'https://api.vvhan.com/api/icp?url=example.com'

# 在线工具
# https://www.beianx.cn/
# https://icplishi.com/
```

### 查询方法
1. 搜索目标公司名称
2. 获取该公司名下所有备案域名
3. 搜索子公司名称
4. 获取子公司备案域名

## WHOIS反查

```bash
# 基础WHOIS
whois example.com

# 关键字段
whois example.com | grep -E "Registrant Organization|Registrant Email|Registrant Phone"

# API查询
curl -s 'https://api.vvhan.com/api/whois?url=example.com'
```

### 反查方法
- 搜索同一邮箱注册的其他域名
- 搜索同一组织注册的其他域名
- 搜索同一电话注册的其他域名

## APP和公众号收集

### APP应用
- 苹果App Store搜索公司名称
- 安卓应用市场搜索
- 查看APP隐私政策中的公司信息
- 抓包分析APP请求获取API域名

### 微信公众号
- 搜索公司名称相关的公众号
- 查看公众号主体信息
- 关联其他公司和域名

### 小程序
- 搜索公司相关小程序
- 查看小程序开发者信息
- 抓包获取后端API域名

## 社交媒体和招聘平台

### 招聘信息
- 搜索目标公司招聘信息
- 查看技术栈描述
- 获取内部系统域名

### 代码仓库
- GitHub组织：https://github.com/orgs/xxx
- GitLab：搜索公司名称
- Gitee：搜索公司名称
- 查看README和配置文件中的域名

## 工商信息查询

### 天眼查
https://www.tianyancha.com/
- 搜索目标公司名称
- 查看「对外投资」获取子公司列表
- 查看「股东信息」获取关联公司
- 查看「实际控制人」获取同一控制下的其他公司

### 企查查
https://www.qcc.com/
- 搜索目标公司
- 查看「股权穿透图」获取完整股权关系
- 查看「企业族谱」获取关联企业

### 爱企查
https://aiqicha.baidu.com/
- 免费查询工商信息
- 查看「子公司」和「投资」关系
