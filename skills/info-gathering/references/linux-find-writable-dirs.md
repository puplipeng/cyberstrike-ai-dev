# Linux 可写目录查找技巧（RedTail 实战技术）

## 来源

从 RedTail 挖矿僵尸网络 `/sh` 加载器脚本中提取（C2: 217.60.195.113, SWISSNET）。

## 攻击者视角：找可写目录落文件

```bash
find / -type d -user $(whoami) -perm -u=rwx
```

• `/` — 全盘搜索，不漏任何挂载点
• `-type d` — 只找目录
• `-user $(whoami)` — 只搜当前用户所有的目录
• `-perm -u=rwx` — 要求用户位同时有 r/w/x 三个权限

### 进化版：排除 noexec 挂载点

```bash
NOEXEC_DIRS=$(cat /proc/mounts | grep 'noexec' | awk '{print $2}')
EXCLUDE=""
for dir in $NOEXEC_DIRS; do
  EXCLUDE="${EXCLUDE} -not -path \"$dir\" -not -path \"$dir/*\""
done
FOLDERS=$(eval find / -type d -user $(whoami) -perm -u=rwx \
  -not -path \"/tmp/*\" -not -path \"/proc/*\" $EXCLUDE 2>/dev/null)
```

• `cat /proc/mounts` 比 `df`/`mount` 更底层，不受 shell 环境限制
• 用 `-not -path` 排除 noexec 目录
• 额外排除 `/proc/*` 和 `/tmp/*`

### 空间验证

```bash
for i in $FOLDERS /tmp /var/tmp /dev/shm; do
  if cd "$i" && touch .testfile && \
     (dd if=/dev/zero of=.testfile2 bs=2M count=1 >/dev/null 2>&1 || \
      truncate -s 2M .testfile2 >/dev/null 2>&1); then
    rm -rf .testfile .testfile2
    break
  fi
done
```

• `touch` 确认写权限
• `dd bs=2M` 确认 ≥ 2MB 可用空间
• `|| truncate` 兜底（某些系统 dd 受限）

### 兜底

当 find 结果为空时，回退到三个经典路径：`/tmp /var/tmp /dev/shm`

## 防御/应急视角

| 目的 | 命令 |
|------|------|
| 排查未知可执行文件 | `find / -type f -user $(whoami) -perm -u=x -newer /tmp` |
| 定位 WebShell | `find / -type f -name "*.jsp" -o -name "*.php"` 结合 `-perm -u=rwx` |
| 发现隐藏挖矿木马 | 搭配 `-size +1M` 过滤，重点关注 2MB 左右随机名文件 |
| 权限维持排查 | `find / -type d -user $(whoami) -perm -u=rwx -mtime -1` |

## 参考

此命令来源于 RedTail 挖矿僵尸网络的 `/sh` 加载器脚本，经实战验证的 Linux 后渗透信息收集技巧。文档已写入飞书知识库 1.2-内网渗透技巧。
