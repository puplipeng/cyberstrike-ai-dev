# APK 整包反编译与代码审计

入口：左侧“反编译与代码审计”。上传 APK 后可浏览 Manifest、类、字节码和引用；“整包规则初审”不依赖选中类，遍历全部支持的 DEX 和方法。

## 审核与导出

- 8 类启发式规则：外部输入进入命令、SQL 文本、WebView 脚本、动态代码加载、文件写入，以及证书错误继续、空证书校验和主机名校验恒真。
- 每个候选含 DEX/类/方法/方法源码行号、证据、成立条件与修复建议。所有命中都需复核，不自动认定漏洞。
- 显示完整审计类、成功/失败/未处理方法、无方法体数量和截断计数。JNI、服务端和动态下载代码不在覆盖范围，规则也不做完整的跨方法污点分析。
- 导出 Markdown 报告，或包含报告与 JSONL 源码的 ZIP。手动查看单类不会覆盖整包报告。
- AI 草稿按源码批次包括未命中规则的方法；先选择通道再手动发送。生成草稿不代表完成 AI 审计，需完成所有批次后汇总去重。代码可能含敏感信息，发送外部模型前应确认允许披露。

## 引擎配置

引擎作为独立进程运行；未配置时平台仍可启动，此模块显示禁用。

环境变量均使用本机绝对路径：

| 变量 | 用途 |
| --- | --- |
| CYBERSTRIKE_APK_DATA | 私有 APK/报告存储目录 |
| CYBERSTRIKE_APK_PYTHON | APK 专用 Python 解释器 |
| CYBERSTRIKE_APK_WORKER | 仓库 scripts/apk_audit/worker.py |
| CYBERSTRIKE_ASC_ROOT | 经过校验的外部 ASC 源码目录 |

已验证环境：Windows、Python 3.12、Androguard 4.1.4、mutf8 1.1.0、[ASC](https://github.com/MG1937/ASC) 提交 `6bd94926c700d4254723efb137753d965a6151ac`。ASC 不随本仓库分发；请自行确认上游许可和使用条件。

安装与校验步骤：

1. 获取固定 ASC 提交，并在其目录应用本仓库 `scripts/apk_audit/asc-index-zero-fix.patch`。它修正类索引为 0 被误判的问题。
2. 为引擎创建 Python 3.12 虚拟环境，运行 `python -m pip install --require-hashes -r scripts/apk_audit/requirements.windows-py312.lock`。此锁文件仅面向已验证的 Windows wheel 环境，不保证适用于其他系统。
3. 配置以上变量。工作进程会按照 `asc-lock.json` 核对 ASC Python 文件哈希与关键依赖版本，不匹配则拒绝启动。升级依赖前应重新审核和测试，不要简单删除校验。
4. Windows 启动脚本默认从仓库父目录的 `apk-engine/venv/Scripts/python.exe` 和 `apk-engine/ASC` 寻找引擎；私有数据在同级 `apk-audit-data/`。调整脚本可适配自己的目录。

限制：256 MiB APK、1 GiB 工作进程内存、单任务并发；单类最长 3 分钟，整包最长 30 分钟。源码保留最多 64 MiB，规则结果与错误样例有明确上限。超限显示覆盖缺口。

不安装或运行 APK。工作进程阻断 Python 网络操作和子进程，但不是完整操作系统沙箱；高度不可信或恶意 APK 应在专用虚拟机中处理。

## 测试

```text
go test ./internal/apkaudit ./internal/security
python scripts/apk_audit/test_worker.py
node --test web/static/js/apk-audit.test.cjs
```

完整 ASC 集成测试需要设置 APK_TEST_BASE，布局为 ASC/、venv/Scripts/python.exe、platform/scripts/apk_audit/ 和 fixtures/sample.apk。仓库中的 sample.dex 为最小合成测试数据，不含用户 APK。默认测试会跳过未配置的引擎集成；规则、ZIP/DEX 边界及报告测试可独立运行。
