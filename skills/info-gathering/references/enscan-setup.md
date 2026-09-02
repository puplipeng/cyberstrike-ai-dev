# ENScan_GO 安装与配置

## 安装

```bash
# 从 GitHub 克隆编译（推荐 — go install 路径有问题）
git clone --depth 1 https://github.com/wgpsec/ENScan_GO.git /tmp/enscan_go
cd /tmp/enscan_go
go build -o ~/.local/bin/enscan .
```

**注意：** `go install github.com/wgpsec/ENScan_GO@latest` 会因模块路径声明（ENScan vs ENScan_GO）失败。必须 git clone 手动编译。

## 配置

```bash
# 首次运行生成配置文件
mkdir -p ~/.config/ENScan
enscan -v   # 生成 ~/.config/ENScan/config.yaml
```

配置文件需填入 API Key 才能使用对应数据源：

| 数据源 | 用途 | 需要 Key |
|--------|------|---------|
| AQC | 爱企查（企业信息/子公司/ICP） | 是 |
| TYC | 天眼查 | 是 |
| QCC | 企查查 | 是 |

**注意：** AQC（爱企查）是默认查询渠道。没有 API Key 时查询返回「没有查询到关键词」，跳过该任务。需自行获取 API Key 填入 config.yaml。

## 常用命令

```bash
enscan -n "浙江省能源集团" -invest 100 -field icp -deep 2 -is-group
enscan -n "小米" -invest -deep 1               # 子公司
enscan -n "百度" -field icp                     # ICP备案
enscan -n "公司名" -type tyc                     # 切换数据源
```

## 分类失败兜底

ENScan 无 Key 不可用时，子公司发现改用：
1. **web_search**：「浙能集团 子公司」「浙江能源 旗下」
2. **企业官网**：首页抓取「关于我们→组织架构」链接
3. **ICP 反查**：拿主站 ICP 备案号 → Quake 搜同备案主体域名
