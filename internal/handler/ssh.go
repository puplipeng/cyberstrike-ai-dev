package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/sshclient"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type sshOperation struct {
	connection, user string
	cancel           context.CancelFunc
}
type sshTicket struct {
	connection, token string
	expires           time.Time
}
type SSHHandler struct {
	store   *sshclient.Store
	auth    *security.AuthManager
	audit   *audit.Service
	mu      sync.Mutex
	active  map[string]sshOperation
	tickets map[string]sshTicket
	closed  bool
}

func NewSSHHandler(store *sshclient.Store, auth *security.AuthManager, log *audit.Service) *SSHHandler {
	return &SSHHandler{store: store, auth: auth, audit: log, active: map[string]sshOperation{}, tickets: map[string]sshTicket{}}
}
func (h *SSHHandler) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for _, op := range h.active {
		op.cancel()
	}
	clear(h.tickets)
}
func (h *SSHHandler) cancelConnection(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, op := range h.active {
		if op.connection == id {
			op.cancel()
		}
	}
	for key, ticket := range h.tickets {
		if ticket.connection == id {
			delete(h.tickets, key)
		}
	}
}
func (h *SSHHandler) authorize(c *gin.Context, permission string) (security.Session, bool) {
	s, ok := security.CurrentSession(c)
	if !ok || s.UserID == "" {
		c.JSON(401, gin.H{"error": "请先登录"})
		return s, false
	}
	if !s.Permissions["webshell:read"] || !s.Permissions[permission] {
		c.JSON(403, gin.H{"error": "需要 WebShell 连接管理权限"})
		return s, false
	}
	if h.store == nil {
		c.JSON(503, gin.H{"error": "SSH 凭据库不可用，请检查服务日志和本机密钥"})
		return s, false
	}
	return s, true
}
func sshAll(s security.Session, permission string) bool {
	return s.ScopeFor(permission) == database.RBACScopeAll && s.ScopeFor("webshell:read") == database.RBACScopeAll
}
func (h *SSHHandler) connection(c *gin.Context, permission string) (sshclient.Connection, security.Session, bool) {
	s, ok := h.authorize(c, permission)
	if !ok {
		return sshclient.Connection{}, s, false
	}
	item, err := h.store.Get(c.Request.Context(), c.Param("id"), s.UserID, sshAll(s, permission))
	if err != nil {
		h.fail(c, err)
		return item, s, false
	}
	return item, s, true
}
func (h *SSHHandler) fail(c *gin.Context, err error) {
	code, message := 500, "SSH 操作失败"
	switch {
	case errors.Is(err, sql.ErrNoRows):
		code, message = 404, "连接不存在或无权访问"
	case errors.Is(err, sshclient.ErrInvalid):
		code, message = 400, "连接参数、凭据或文件路径无效"
	case errors.Is(err, sshclient.ErrConflict):
		code, message = 409, "连接已修改，请刷新后重试"
	case errors.Is(err, sshclient.ErrTrust):
		code, message = 409, "服务器指纹未确认或已变化；请先核验指纹"
	case errors.Is(err, sshclient.ErrCredential):
		code, message = 502, "SSH 连接或认证失败，请检查地址、凭据及服务器配置"
	case errors.Is(err, sshclient.ErrBusy):
		code, message = 429, "SSH 操作数量达到上限，请先断开闲置会话"
	case errors.Is(err, context.DeadlineExceeded):
		code, message = 504, "SSH 操作超时"
	case errors.Is(err, context.Canceled):
		code, message = 409, "SSH 操作已取消"
	}
	c.JSON(code, gin.H{"error": message})
}
func sshBody(c *gin.Context, out any) bool {
	if c.ContentType() != "application/json" {
		c.JSON(415, gin.H{"error": "需要 application/json"})
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 128<<10)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		c.JSON(400, gin.H{"error": "无效的 JSON 请求"})
		return false
	}
	return true
}
func (h *SSHHandler) record(c *gin.Context, action, id string, err error, detail map[string]interface{}) {
	if h.audit == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "failure"
	}
	h.audit.Record(c, audit.Entry{Category: "webshell", Action: "ssh_" + action, Result: result, ResourceType: "ssh_connection", ResourceID: id, Message: "SSH " + action, Detail: detail})
}
func (h *SSHHandler) List(c *gin.Context) {
	s, ok := h.authorize(c, "webshell:read")
	if !ok {
		return
	}
	items, err := h.store.List(c.Request.Context(), s.UserID, sshAll(s, "webshell:read"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"items": items})
}
func (h *SSHHandler) Save(c *gin.Context) {
	s, ok := h.authorize(c, "webshell:write")
	if !ok {
		return
	}
	var input sshclient.Input
	if !sshBody(c, &input) {
		return
	}
	item, err := h.store.Save(c.Request.Context(), c.Param("id"), s.UserID, sshAll(s, "webshell:write"), input)
	h.record(c, "save", item.ID, err, nil)
	if err != nil {
		h.fail(c, err)
		return
	}
	h.cancelConnection(item.ID)
	c.Header("Cache-Control", "no-store")
	c.JSON(200, item)
}
func (h *SSHHandler) Delete(c *gin.Context) {
	item, _, ok := h.connection(c, "webshell:delete")
	if !ok {
		return
	}
	var input struct {
		Revision int64 `json:"revision"`
	}
	if !sshBody(c, &input) {
		return
	}
	if item.Revision != input.Revision {
		h.fail(c, sshclient.ErrConflict)
		return
	}
	err := h.store.Delete(c.Request.Context(), item)
	h.record(c, "delete", item.ID, err, nil)
	if err != nil {
		h.fail(c, err)
		return
	}
	h.cancelConnection(item.ID)
	c.JSON(200, gin.H{"ok": true})
}
func (h *SSHHandler) begin(c *gin.Context, item sshclient.Connection, s security.Session, timeout time.Duration) (context.Context, func(), bool) {
	h.mu.Lock()
	perUser := 0
	for _, op := range h.active {
		if op.user == s.UserID {
			perUser++
		}
	}
	if h.closed || len(h.active) >= 16 || perUser >= 4 {
		h.mu.Unlock()
		h.fail(c, sshclient.ErrBusy)
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
	key := uuid.NewString()
	h.active[key] = sshOperation{item.ID, s.UserID, cancel}
	h.mu.Unlock()
	return ctx, func() { cancel(); h.mu.Lock(); delete(h.active, key); h.mu.Unlock() }, true
}
func (h *SSHHandler) Probe(c *gin.Context) {
	item, s, ok := h.connection(c, "webshell:write")
	if !ok {
		return
	}
	ctx, done, ok := h.begin(c, item, s, 20*time.Second)
	if !ok {
		return
	}
	defer done()
	fingerprint, err := sshclient.Probe(ctx, item)
	h.record(c, "probe", item.ID, err, nil)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(200, gin.H{"fingerprint": fingerprint, "trusted": fingerprint == item.Fingerprint, "revision": item.Revision})
}
func (h *SSHHandler) Trust(c *gin.Context) {
	item, s, ok := h.connection(c, "webshell:write")
	if !ok {
		return
	}
	var input struct {
		Fingerprint string `json:"fingerprint"`
		Revision    int64  `json:"revision"`
	}
	if !sshBody(c, &input) {
		return
	}
	if input.Revision != item.Revision {
		h.fail(c, sshclient.ErrConflict)
		return
	}
	if !sshclient.ValidFingerprint(input.Fingerprint) {
		h.fail(c, sshclient.ErrInvalid)
		return
	}
	ctx, done, ok := h.begin(c, item, s, 20*time.Second)
	if !ok {
		return
	}
	defer done()
	actual, err := sshclient.Probe(ctx, item)
	if err == nil && actual != input.Fingerprint {
		err = sshclient.ErrTrust
	}
	if err == nil {
		err = h.store.Trust(ctx, item, actual)
	}
	h.record(c, "trust", item.ID, err, map[string]interface{}{"fingerprint": input.Fingerprint})
	if err != nil {
		h.fail(c, err)
		return
	}
	h.cancelConnection(item.ID)
	c.JSON(200, gin.H{"ok": true})
}
func (h *SSHHandler) dial(ctx context.Context, item sshclient.Connection) (*ssh.Client, func(), error) {
	if err := h.store.Check(ctx, item); err != nil {
		return nil, nil, err
	}
	credential, err := h.store.Credential(item)
	if err != nil {
		return nil, nil, err
	}
	client, err := sshclient.Dial(ctx, item, credential)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { client.Close() })
	return client, func() { stop(); client.Close() }, nil
}
func (h *SSHHandler) Test(c *gin.Context) {
	item, s, ok := h.connection(c, "webshell:write")
	if !ok {
		return
	}
	ctx, done, ok := h.begin(c, item, s, 20*time.Second)
	if !ok {
		return
	}
	defer done()
	_, closeClient, err := h.dial(ctx, item)
	if err == nil {
		closeClient()
	}
	h.record(c, "test", item.ID, err, nil)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
