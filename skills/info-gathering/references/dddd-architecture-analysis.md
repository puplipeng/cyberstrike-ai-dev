# dddd Project Architecture Analysis

Source: `github.com/SleepingBag945/dddd` (⭐1,903, Go)

## Why This Matters

The user wants to fork and 二开 dddd. Understanding the original design patterns is critical before modifying.

## Directory Structure

```
dddd/
├── main.go                 # 入口 + workflow() 主流程
├── structs/type.go         # 全局数据类型（Config/HostInfo/URLEntity等）
├── common/                 # 核心功能模块
│   ├── flag.go             # CLI 参数解析 → GlobalConfig
│   ├── portscan.go         # 端口扫描
│   ├── subdomain.go        # 子域名发现
│   ├── hostbind.go         # Host 绑定
│   ├── icmp.go             # ICMP 探活
│   ├── net.go              # 网络工具
│   ├── protocol.go         # 协议识别
│   ├── callnuclei/         # nuclei 调用封装
│   ├── http/               # Web 探测 + 截图
│   ├── report/             # 报告生成
│   └── uncover/            # 搜索引擎集成
├── lib/                    # 第三方库封装
│   ├── ddfinger/           # Web 指纹规则引擎
│   ├── dnsx/               # DNS 查询
│   ├── gologger/           # 日志
│   ├── gonmap/             # Nmap 风格的端口指纹识别
│   ├── httpx/              # HTTP 探测（projectdiscovery）
│   ├── masscan/            # masscan 封装
│   ├── nuclei/             # nuclei 引擎封装
│   └── subfinder/          # 子域名收集
├── gopocs/                 # Go 实现 PoC 引擎（最核心）
│   ├── base.go             # PluginList 注册 + 工具函数
│   ├── scanner.go          # GoPocsDispatcher 调度器
│   ├── dict/               # 爆破字典
│   └── *.go                # 各协议爆破/检测（ssh/ftp/mysql/redis等）
├── utils/                  # 工具类
│   ├── input.go            # 输入解析（域名/IP/URL/CIDR自动判断）
│   ├── uri.go              # URL 解析
│   └── cdn/                # CDN 检测
└── structs/type.go         # 数据模型定义
```

## Core Design Patterns

### 1. Input Type Auto-Detection

`structs/type.go` defines 8 input types:

```go
const (
    TypeDomain     = 1  // example.com
    TypeDomainPort = 2  // example.com:80
    TypeIPRange    = 3  // 192.168.1.1-100
    TypeCIDR       = 4  // 192.168.1.0/24
    TypeIP         = 5  // 1.2.3.4
    TypeIPPort     = 6  // 1.2.3.4:80
    TypeURL        = 7  // https://example.com
    TypeUnSupport  = 0
)
```

`utils.GetInputType()` 自动判断输入类型，统一入口。

### 2. Plugin Registration System

`gopocs/base.go` 的注册制是扩展 PoC 的标准方式：

```go
var PluginList = map[string]interface{}{
    "SSH-Crack":    SshScan,
    "FTP-Crack":    FtpScan,
    "Mysql-Crack":  MysqlScan,
    "Mssql-Crack":  MssqlScan,
    // ... 20+ 插件
}
```

**加一个 PoC 的标准步骤：**

1. 在 `gopocs/` 下新建 `.go` 文件，函数签名：`func XxxScan(info *structs.HostInfo)`
2. 在 `PluginList` 中注册：`"协议-Crack": XxxScan`
3. 在 `scanner.go` 的 `GoPocsDispatcher()` 中加 protocol 判断
4. 字典文件放 `gopocs/dict/xxx.txt`
5. 结果通过 `GoPocWriteResult()` 输出

### 3. Global Config Singleton

所有配置集中管理：

```go
var GlobalConfig Config  // structs/type.go 中的全局变量
```

通过 `common.Flag()` 解析 CLI 参数填充。各模块直接读 `structs.GlobalConfig.XXX`。

### 4. Concurrent Scan Control

`AddScan()` 统一管理协程调度：

```go
func AddScan(scantype string, info structs.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
    *ch <- struct{}{}   // 信号量
    wg.Add(1)
    go func() {
        ScanFunc(&scantype, &info)
        wg.Done()
        <-*ch
    }()
}
```

- 并发数：`structs.GlobalConfig.GoPocThreads`
- 使用 chan 做信号量 + WaitGroup 等待完成

### 5. Reflection-based Plugin Invocation

```go
func ScanFunc(name *string, info *structs.HostInfo) {
    f := reflect.ValueOf(PluginList[*name])
    in := []reflect.Value{reflect.ValueOf(info)}
    f.Call(in)
}
```

通过反射调用 PluginList 中注册的函数，所有 PoC 函数签名必须统一为 `func(info *structs.HostInfo)`。

### 6. Unified Error Filtering

```go
func CheckErrs(err error) bool {
    errs := []string{
        "closed by the remote host", "too many connections",
        "i/o timeout", "EOF", "A connection attempt failed",
        // ...
    }
    for _, key := range errs {
        if strings.Contains(err.Error(), key) {
            return true  // 可忽略的错误
        }
    }
    return false
}
```

### 7. Password Dictionary with Variable Expansion

支持 `{{key}}` 模板变量——用扫描到的服务信息（域名/主机名）动态生成密码：

```go
if strings.Contains(oriPass, "{{key}}") {
    for _, sKey := range info.InfoStr {
        newKeys := generateKeys(sKey)
        for _, nKey := range newKeys {
            newPass := strings.Replace(oriPass, "{{key}}", nKey, -1)
            userPasswdList = append(...)
        }
    }
}
```

## Key Platform Dependencies

| 功能 | 依赖 | 来源 |
|------|------|------|
| 端口扫描 | masscan (SYN) / TCP 直连 | `lib/masscan/` + `common/portscan.go` |
| Web 指纹 | httpx | `projectdiscovery/httpx` |
| 子域名 | subfinder | `projectdiscovery/subfinder` |
| 漏洞扫描 | nuclei | `projectdiscovery/nuclei/v3` |
| 服务指纹 | gonmap | `lcvvvv/gonmap` |
| 搜索引擎 | 自定义 | `common/uncover/` |
| 报告生成 | 自定义 | `common/report/` |

## 二开建议方向

| 方向 | 改动范围 | 难度 |
|------|---------|------|
| 新增协议爆破 | `gopocs/` + `PluginList` 注册 | 低 |
| 新增指纹规则 | `lib/ddfinger/` + `FingerprintDB` | 低 |
| 集成新搜索引擎 | `common/uncover/` | 中 |
| 优化扫描性能 | `common/portscan.go` + masscan 参数 | 中 |
| 自定义报告格式 | `common/report/` | 低 |
