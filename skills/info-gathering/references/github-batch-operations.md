# GitHub 批量操作工作流

## 认证

使用 Personal Access Token (PAT) 认证：
```bash
# 验证 Token
curl -s "https://api.github.com/user" \
  -H "Authorization: token <TOKEN>" \
  -H "Accept: application/vnd.github.v3+json"

# 检查权限
curl -sI "https://api.github.com/user" \
  -H "Authorization: token <TOKEN>" | grep -i "x-oauth-scopes"
```

## Fork 仓库

```bash
# 单个 Fork
curl -s -X POST "https://api.github.com/repos/<owner>/<repo>/forks" \
  -H "Authorization: token <TOKEN>" \
  -H "Accept: application/vnd.github.v3+json" \
  -H "Content-Type: application/json" \
  -d '{"default_branch_only": false}'

# 批量 Fork
REPOS=("owner1/repo1" "owner2/repo2" "owner3/repo3")
for repo in "${REPOS[@]}"; do
  echo -n "Forking ${repo}... "
  RESULT=$(curl -s -X POST "https://api.github.com/repos/${repo}/forks" \
    -H "Authorization: token <TOKEN>" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    -d '{"default_branch_only": false}')
  FULL_NAME=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('full_name',''))")
  ERROR=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('message',''))")
  [ -n "$FULL_NAME" ] && echo "✅ https://github.com/${FULL_NAME}" || echo "❌ ${ERROR}"
  sleep 1  # 避免限流
done
```

## Star 仓库

```bash
# Star 单个仓库
curl -s -X PUT "https://api.github.com/user/starred/<owner>/<repo>" \
  -H "Authorization: token <TOKEN>" \
  -H "Accept: application/vnd.github.v3+json"

# 批量 Star
for repo in "${REPOS[@]}"; do
  curl -s -X PUT "https://api.github.com/user/starred/${repo}" \
    -H "Authorization: token <TOKEN>" \
    -H "Accept: application/vnd.github.v3+json"
  echo "⭐ Starred: ${repo}"
  sleep 0.5
done
```

## 创建仓库

```bash
curl -s -X POST "https://api.github.com/user/repos" \
  -H "Authorization: token <TOKEN>" \
  -H "Accept: application/vnd.github.v3+json" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "repo-name",
    "description": "仓库描述",
    "private": false,
    "auto_init": true,
    "has_issues": true,
    "has_projects": true,
    "has_wiki": true
  }'
```

## 查询用户仓库

```bash
# 获取用户所有公开仓库
curl -s "https://api.github.com/users/<username>/repos?per_page=100&sort=updated&type=public"

# 获取认证用户的仓库（含私有）
curl -s "https://api.github.com/user/repos?per_page=100&sort=updated" \
  -H "Authorization: token <TOKEN>"
```

## Token 权限要求

| 操作 | 所需权限 |
|------|----------|
| 查看公开仓库 | 无需认证 |
| Fork 仓库 | `repo` scope |
| Star 仓库 | 无需认证（公开仓库） |
| 创建仓库 | `repo` scope |
| 查看私有仓库 | `repo` scope |

## 常见错误

- `Bad credentials` - Token 无效或已过期
- `Resource not accessible by personal access token` - Token 权限不足，需要 `repo` scope
- `422 Validation Failed` - 仓库名已存在或参数错误
- `403 API rate limit exceeded` - 超出 API 限流，等待重置

## 批量操作脚本模板

```bash
#!/bin/bash
TOKEN="ghp_xxxxx"
REPOS=(
  "owner1/repo1"
  "owner2/repo2"
  "owner3/repo3"
)

echo "========== 批量 Fork 开始 =========="
SUCCESS=0
FAIL=0

for repo in "${REPOS[@]}"; do
  echo -n "Forking ${repo}... "
  RESULT=$(curl -s -X POST "https://api.github.com/repos/${repo}/forks" \
    -H "Authorization: token ${TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    -d '{"default_branch_only": false}')
  
  FULL_NAME=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('full_name',''))" 2>/dev/null)
  ERROR=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('message',''))" 2>/dev/null)
  
  if [ -n "$FULL_NAME" ] && [ "$FULL_NAME" != "" ]; then
    echo "✅ https://github.com/${FULL_NAME}"
    SUCCESS=$((SUCCESS+1))
  else
    echo "❌ ${ERROR}"
    FAIL=$((FAIL+1))
  fi
  
  sleep 1
done

echo ""
echo "========== 完成 =========="
echo "成功: ${SUCCESS}"
echo "失败: ${FAIL}"
```
