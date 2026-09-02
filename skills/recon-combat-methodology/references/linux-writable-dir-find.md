# Linux 可写目录搜索：Find 技巧

来源：RedTail 挖矿僵尸网络加载器（C2: 217.60.195.113, SWISSNET 托管）

## 核心命令

```bash
find / -type d -user $(whoami) -perm -u=rwx
```

- `/` — 全盘搜索，不漏挂载点
- `-type d` — 只找目录
- `-user $(whoami)` — 只匹配当前用户所有的目录
- `-perm -u=rwx` — 用户位同时有 r/w/x 三个权限

## 进化版：排除 noexec

```bash
NOEXEC_DIRS=$(cat /proc/mounts | grep 'noexec' | awk '{print $2}')
EXCLUDE=""
for dir in $NOEXEC_DIRS; do
  EXCLUDE="${EXCLUDE} -not -path \"$dir\" -not -path \"$dir/*\""
done
FOLDERS=$(eval find / -type d -user $(whoami) -perm -u=rwx \
  -not -path \"/tmp/*\" -not -path \"/proc/*\" $EXCLUDE 2>/dev/null)
```

`cat /proc/mounts` 比 `df`/`mount` 更底层，不受 shell 环境限制。

## 可用性验证

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

## 攻防双视角

| 视角 | 目的 | 命令 |
|------|------|------|
| 攻击者 | 找可写目录落文件 | `find / -type d -user $(whoami) -perm -u=rwx` |
| 防御者 | 查可疑可执行文件 | `find / -type f -user $(whoami) -perm -u=x -newer /tmp` |
| 防御者 | 定位 WebShell | `find / -type f -name "*.jsp" -o -name "*.php"` 结合 `-perm -u=rwx` |
| 防御者 | 发现隐藏挖矿木马 | `find / -type f -size +1M` 过滤，重点关注 2MB 随机名文件 |
| 防御者 | 权限维持排查 | `find / -type d -user $(whoami) -perm -u=rwx -mtime -1` 找 24h 内新建可写目录 |
