# Feishu Wiki API Quick Reference

## Block Types

| Type | Description | Format |
|------|-------------|--------|
| 1 | root | Document root (don't create) |
| 2 | text | `{"block_type": 2, "text": {"elements": [{"text_run": {"content": "..."}}]}}` |
| 3 | heading1 | `{"block_type": 3, "heading1": {"elements": [{"text_run": {"content": "..."}}]}}` |
| 4 | heading2 | `{"block_type": 4, "heading2": {"elements": [{"text_run": {"content": "..."}}]}}` |
| 15 | bullet | `{"block_type": 15, "bullet": {"elements": [{"text_run": {"content": "..."}}]}}` |
| 22 | divider | `{"block_type": 22, "divider": {}}` |

## API Endpoints

```
# List wiki spaces
GET /open-apis/wiki/v2/spaces

# Create wiki space
POST /open-apis/wiki/v2/spaces

# List nodes
GET /open-apis/wiki/v2/spaces/{space_id}/nodes

# Create node (document)
POST /open-apis/wiki/v2/spaces/{space_id}/nodes
Body: {"obj_type": "docx", "title": "...", "parent_node_token": "..."}

# Write content blocks
POST /open-apis/docx/v1/documents/{doc_token}/blocks/{doc_token}/children
Body: {"children": [...blocks...], "index": -1}

# Update block content
PATCH /open-apis/docx/v1/documents/{doc_token}/blocks/{block_id}
Body: {"update_text_elements": {"elements": [{"text_run": {"content": "..."}}], "style": {}}}

# Set permissions (group)
POST /open-apis/drive/v1/permissions/{doc_token}/members?type=docx
Body: {"member_type": "openchat", "member_id": chat_id, "perm": "view"}
```

## Key Pitfalls

- `obj_type` must be `"docx"`, NOT `"doc"`
- `member_type` must be `"openchat"`, NOT `"chat"`
- Max 50 blocks per write request
- DELETE block API returns 404; use PATCH to clear content
- user_access_token expires in 2 hours; refresh_token lasts 30 days

## Wiki URL Format

```
https://kcn9ct1s0p1x.feishu.cn/wiki/{node_token}
```
