package handler

import (
	"bytes"
	"context"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/testutil/testpostgres"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func withTempWorkingDir(t *testing.T) string {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(old)
	})
	return dir
}

func TestDetachedAgentContextRetainsPrincipalWithoutParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	parent = authctx.WithPrincipal(parent, authctx.NewPrincipal("u1", "user", database.RBACScopeAssigned, map[string]bool{"agent:execute": true}))
	detached := detachedAgentContext(parent)
	cancel()
	if err := detached.Err(); err != nil {
		t.Fatalf("detached context inherited cancellation: %v", err)
	}
	principal, ok := authctx.PrincipalFromContext(detached)
	if !ok || principal.UserID != "u1" || !principal.HasPermission("agent:execute") {
		t.Fatalf("detached context lost principal: %#v, ok=%v", principal, ok)
	}
}

func TestPromoteAttackChainRequiresSourceConversationAccess(t *testing.T) {
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	project, _ := db.CreateProject(&database.Project{Name: "owned"})
	conversation, _ := db.CreateConversation("foreign", database.ConversationCreateMeta{})
	_ = db.SetResourceOwner("project", project.ID, "u1")
	_ = db.SetResourceOwner("conversation", conversation.ID, "u2")
	h := NewProjectHandler(db, zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "u1", Scope: database.RBACScopeOwn})
		c.Next()
	})
	router.POST("/api/projects/:id/promote-attack-chain/:conversationId", h.PromoteAttackChain)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/projects/"+project.ID+"/promote-attack-chain/"+conversation.ID, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestVulnerabilityCannotBeReparentedToForeignProject(t *testing.T) {
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	owned, _ := db.CreateProject(&database.Project{Name: "owned"})
	foreign, _ := db.CreateProject(&database.Project{Name: "foreign"})
	_ = db.SetResourceOwner("project", owned.ID, "u1")
	_ = db.SetResourceOwner("project", foreign.ID, "u2")
	vulnerability, err := db.CreateVulnerability(&database.Vulnerability{Title: "v", Severity: "high", ProjectID: owned.ID})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.SetResourceOwner("vulnerability", vulnerability.ID, "u1")
	h := NewVulnerabilityHandler(db, zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "u1", Scope: database.RBACScopeOwn})
		c.Next()
	})
	router.PUT("/api/vulnerabilities/:id", h.UpdateVulnerability)
	body, _ := json.Marshal(map[string]interface{}{"project_id": foreign.ID})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/vulnerabilities/"+vulnerability.ID, bytes.NewReader(body)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestAgentTaskEndpointsFilterAndRejectForeignConversations(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	allowed, _ := db.CreateConversation("allowed", database.ConversationCreateMeta{})
	hidden, _ := db.CreateConversation("hidden", database.ConversationCreateMeta{})
	if err := db.AssignResourceToUser(user.ID, "conversation", allowed.ID); err != nil {
		t.Fatal(err)
	}
	tasks := NewAgentTaskManager()
	if _, err := tasks.StartTask(allowed.ID, "visible", func(error) {}); err != nil {
		t.Fatal(err)
	}
	if _, err := tasks.StartTask(hidden.ID, "secret", func(error) {}); err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{db: db, tasks: tasks, logger: zap.NewNop()}

	w := performAssignedHandler(user, http.MethodGet, "/api/agent-loop/tasks", nil, h.ListAgentTasks)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", w.Code, w.Body.String())
	}
	var response struct {
		Tasks []*AgentTask `json:"tasks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Tasks) != 1 || response.Tasks[0].ConversationID != allowed.ID {
		t.Fatalf("tasks = %#v, want only %s", response.Tasks, allowed.ID)
	}

	w = performAssignedHandler(user, http.MethodPost, "/api/agent-loop/cancel", map[string]string{"conversationId": hidden.ID}, h.CancelAgentLoop)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cancel status = %d, want %d: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestChatUploadPathAuthorizationFollowsConversationAccess(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	allowed, _ := db.CreateConversation("allowed", database.ConversationCreateMeta{})
	hidden, _ := db.CreateConversation("hidden", database.ConversationCreateMeta{})
	if err := db.AssignResourceToUser(user.ID, "conversation", allowed.ID); err != nil {
		t.Fatal(err)
	}
	h := NewChatUploadsHandler(zap.NewNop(), db)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAssigned, Permissions: map[string]bool{"chat:write": true}})

	if !h.pathAllowed(c, filepath.ToSlash(filepath.Join("2026-07-10", allowed.ID, "a.txt"))) {
		t.Fatal("assigned conversation attachment should be accessible")
	}
	if h.pathAllowed(c, filepath.ToSlash(filepath.Join("2026-07-10", hidden.ID, "secret.txt"))) {
		t.Fatal("foreign conversation attachment should be denied")
	}
	if h.pathAllowed(c, "2026-07-10/_manual/secret.txt") {
		t.Fatal("unowned manual attachment should fail closed")
	}
}

func TestChatUploadsListIncludesAuthorizedProjectWorkspaceFiles(t *testing.T) {
	withTempWorkingDir(t)
	db, user := setupConversationRBACTest(t)
	fsBase := t.TempDir()
	workspaceBase := filepath.Join(fsBase, "workspace")
	reductionBase := filepath.Join(fsBase, "reduction")
	db.SetEinoConversationDirs("", "", reductionBase, workspaceBase)
	allowedProject, _ := db.CreateProject(&database.Project{Name: "allowed"})
	hiddenProject, _ := db.CreateProject(&database.Project{Name: "hidden"})
	conversation, _ := db.CreateConversation("project conversation", database.ConversationCreateMeta{ProjectID: allowedProject.ID})
	if err := db.AssignResourceToUser(user.ID, "project", allowedProject.ID); err != nil {
		t.Fatal(err)
	}
	allowedFile := filepath.Join(workspaceBase, "projects", allowedProject.ID, "csv", "assets.csv")
	hiddenFile := filepath.Join(workspaceBase, "projects", hiddenProject.ID, "csv", "secret.csv")
	for _, path := range []string{allowedFile, hiddenFile} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("name\nexample\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	h := NewChatUploadsHandler(zap.NewNop(), db)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/chat-uploads?source=workspace&pageSize=all&conversation="+conversation.ID, nil)
	c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAssigned})
	h.List(c)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var response struct {
		Files []ChatUploadFileItem `json:"files"`
		Total int                  `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 1 || len(response.Files) != 1 {
		t.Fatalf("files = %#v, total = %d, want only authorized workspace file", response.Files, response.Total)
	}
	got := response.Files[0]
	if got.Source != chatUploadSourceWorkspace || got.Name != "assets.csv" || got.ProjectID != allowedProject.ID {
		t.Fatalf("workspace file = %#v", got)
	}
	if got.ProjectName != allowedProject.Name {
		t.Fatalf("projectName = %q, want %q", got.ProjectName, allowedProject.Name)
	}
	if got.ConversationID != conversation.ID {
		t.Fatalf("conversationId = %q, want %q", got.ConversationID, conversation.ID)
	}
	if got.ConversationTitle != conversation.Title {
		t.Fatalf("conversationTitle = %q, want %q", got.ConversationTitle, conversation.Title)
	}
	if got.AbsolutePath != allowedFile {
		t.Fatalf("absolutePath = %q, want %q", got.AbsolutePath, allowedFile)
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	resolveURL := "/api/chat-uploads/path?kind=directory&path=__workspace__%2Fprojects%2F" + allowedProject.ID
	c.Request = httptest.NewRequest(http.MethodGet, resolveURL, nil)
	c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAssigned})
	h.ResolvePath(c)
	if w.Code != http.StatusOK {
		t.Fatalf("resolve status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var resolved struct {
		AbsolutePath string `json:"absolutePath"`
		IsDir        bool   `json:"isDir"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resolved); err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(workspaceBase, "projects", allowedProject.ID)
	if !resolved.IsDir || resolved.AbsolutePath != wantDir {
		t.Fatalf("resolved = %#v, want dir %q", resolved, wantDir)
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/chat-uploads/path?kind=directory&path=__workspace__%2Fprojects", nil)
	c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAssigned})
	h.ResolvePath(c)
	if w.Code != http.StatusOK {
		t.Fatalf("resolve projects container status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resolved); err != nil {
		t.Fatal(err)
	}
	wantContainer := filepath.Join(workspaceBase, "projects")
	if !resolved.IsDir || resolved.AbsolutePath != wantContainer {
		t.Fatalf("resolved container = %#v, want dir %q", resolved, wantContainer)
	}

	for _, tc := range []struct {
		path string
		want string
	}{
		{"__workspace__/", workspaceBase},
		{"__reduction__/", reductionBase},
		{"__conversation_artifact__/", db.ConversationArtifactsBaseDir()},
	} {
		if err := os.MkdirAll(tc.want, 0o755); err != nil {
			t.Fatal(err)
		}
		w = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/chat-uploads/path?kind=directory&path="+url.QueryEscape(tc.path), nil)
		c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAssigned})
		h.ResolvePath(c)
		if w.Code != http.StatusOK {
			t.Fatalf("resolve root %q status = %d, want 200: %s", tc.path, w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resolved); err != nil {
			t.Fatal(err)
		}
		wantAbs, _ := filepath.Abs(tc.want)
		if !resolved.IsDir || resolved.AbsolutePath != wantAbs {
			t.Fatalf("resolved root %q = %#v, want dir %q", tc.path, resolved, wantAbs)
		}
	}
}

func TestPrepareMultiAgentSessionRejectsForeignConversation(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	hidden, _ := db.CreateConversation("hidden", database.ConversationCreateMeta{})
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAssigned, Permissions: map[string]bool{"chat:write": true}})

	_, err := h.prepareMultiAgentSession(&ChatRequest{ConversationID: hidden.ID, Message: "write"}, c, "test")
	if err == nil || err.Error() != "无权访问该对话" {
		t.Fatalf("err = %v, want unauthorized conversation", err)
	}
}

func TestMonitorExecutionDetailRejectsForeignOwner(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	for _, exec := range []*mcp.ToolExecution{
		{ID: "exec-allowed", ToolName: "allowed", Status: "completed", StartTime: time.Now(), OwnerUserID: user.ID},
		{ID: "exec-hidden", ToolName: "hidden", Status: "completed", StartTime: time.Now(), OwnerUserID: "another-user"},
	} {
		if err := db.SaveToolExecution(exec); err != nil {
			t.Fatal(err)
		}
	}
	h := NewMonitorHandler(mcp.NewServerWithStorage(zap.NewNop(), db), nil, db, zap.NewNop())

	request := func(id string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/monitor/execution/"+id, nil)
		c.Params = gin.Params{{Key: "id", Value: id}}
		c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAssigned})
		h.GetExecution(c)
		return w
	}
	if w := request("exec-hidden"); w.Code != http.StatusForbidden {
		t.Fatalf("hidden status = %d, want %d: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
	if w := request("exec-allowed"); w.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func performAssignedHandler(user *database.RBACUser, method, path string, body interface{}, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		payload, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
	}
	c.Request = req
	c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAssigned})
	handler(c)
	return w
}

func securityFixDB(t *testing.T) (*database.DB, *security.AuthManager) {
	t.Helper()
	t.Chdir(t.TempDir())
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	auth := security.NewAuthManager(1)
	if _, err := auth.AttachRBACStore(db); err != nil {
		t.Fatal(err)
	}
	return db, auth
}

func securityFixUser(t *testing.T, db *database.DB, auth *security.AuthManager, name string, roles ...string) (*database.RBACUser, string) {
	t.Helper()
	const password = "isolated-audit-fixture-only-29"
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateRBACUser(name, name, hash, true, roles)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := auth.Authenticate(name, password)
	if err != nil {
		t.Fatal(err)
	}
	return user, token
}

func securityFixRouter(db *database.DB, auth *security.AuthManager) *gin.Engine {
	r := gin.New()
	r.Use(security.AuthMiddleware(auth), security.RBACMiddleware(db))
	return r
}

func securityFixHTTP(t *testing.T, s *httptest.Server, token, method, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, s.URL+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, body
}

func TestSecurityArtifactScopeBoundary(t *testing.T) {
	db, auth := securityFixDB(t)
	viewer, token := securityFixUser(t, db, auth, "artifact_viewer", database.RBACSystemRoleViewer)
	other, _ := securityFixUser(t, db, auth, "artifact_other")
	_, noPermission := securityFixUser(t, db, auth, "artifact_no_permission")
	allowed, err := db.CreateConversation("allowed fixture", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	hidden, err := db.CreateConversation("foreign fixture", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", allowed.ID, viewer.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", hidden.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(viewer.ID, "conversation", allowed.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{allowed.ID, hidden.ID} {
		dir := filepath.Join(db.ConversationArtifactsBaseDir(), id)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "audit-canary.txt"), []byte("canary-"+id), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h := NewChatUploadsHandler(zap.NewNop(), db)
	r := securityFixRouter(db, auth)
	r.GET("/api/chat-uploads/download", h.Download)
	r.GET("/api/chat-uploads/path", h.ResolvePath)
	s := httptest.NewServer(r)
	defer s.Close()
	direct := artifactVirtualPrefix + hidden.ID + "/audit-canary.txt"
	traversed := artifactVirtualPrefix + allowed.ID + "/../" + hidden.ID + "/audit-canary.txt"
	for _, tc := range []struct {
		name, token, path string
		status            int
		canary            bool
	}{
		{"anonymous", "", traversed, 401, false},
		{"no_files_permission", noPermission, traversed, 403, false},
		{"assigned_file", token, artifactVirtualPrefix + allowed.ID + "/audit-canary.txt", 200, false},
		{"direct_foreign_denied", token, direct, 403, false},
		{"foreign_via_assigned_prefix", token, traversed, 403, false},
		{"windows_separator", token, artifactVirtualPrefix + allowed.ID + "\\..\\" + hidden.ID + "\\audit-canary.txt", 403, false},
		{"outside_global_root_denied", token, artifactVirtualPrefix + allowed.ID + "/../../../outside.txt", 403, false},
	} {
		status, body := securityFixHTTP(t, s, tc.token, http.MethodGet, "/api/chat-uploads/download?path="+url.QueryEscape(tc.path))
		if status != tc.status {
			t.Fatalf("%s status=%d want=%d", tc.name, status, tc.status)
		}
		if tc.canary && string(body) != "canary-"+hidden.ID {
			t.Fatal("did not receive the foreign fixture canary")
		}
		t.Logf("%s status=%d foreign_canary=%t", tc.name, status, tc.canary)
	}
	status, _ := securityFixHTTP(t, s, token, http.MethodGet, "/api/chat-uploads/path?path="+url.QueryEscape(traversed))
	if status != 403 {
		t.Fatalf("foreign resolve path status=%d", status)
	}

}

func TestSecurityReadonlyWebshellSecret(t *testing.T) {
	db, auth := securityFixDB(t)
	viewer, token := securityFixUser(t, db, auth, "webshell_viewer", database.RBACSystemRoleViewer)
	const fakeSecret = "canary-webshell-password-not-a-real-secret"
	conn := &database.WebShellConnection{ID: "ws_audit_allowed", URL: "http://127.0.0.1:1/fixture", Password: fakeSecret, Type: "php", Method: "post", CmdParam: "cmd", CreatedAt: time.Now()}
	if err := db.CreateWebshellConnection(conn); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(viewer.ID, "webshell", conn.ID); err != nil {
		t.Fatal(err)
	}
	hidden := *conn
	hidden.ID = "ws_audit_hidden"
	hidden.Password = "hidden-canary"
	if err := db.CreateWebshellConnection(&hidden); err != nil {
		t.Fatal(err)
	}
	h := NewWebShellHandler(zap.NewNop(), db)
	r := securityFixRouter(db, auth)
	r.GET("/api/webshell/connections", h.ListConnections)
	r.POST("/api/webshell/exec", h.Exec)
	s := httptest.NewServer(r)
	defer s.Close()
	status, body := securityFixHTTP(t, s, token, http.MethodGet, "/api/webshell/connections")
	var got []database.WebShellConnection
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if status != 200 || len(got) != 1 || got[0].Password != "" || bytes.Contains(body, []byte(fakeSecret)) || !bytes.Contains(body, []byte(`"has_password":true`)) || got[0].ID != conn.ID {
		t.Fatal("readonly list exposed a secret or lost assignment filtering")
	}
	t.Log("builtin_viewer GET list=200 assigned_only=true cleartext_password=false")
	status, _ = securityFixHTTP(t, s, token, http.MethodPost, "/api/webshell/exec")
	if status != 403 {
		t.Fatalf("readonly execute status=%d want=403", status)
	}
	t.Log("same_viewer POST exec=403; no remote target contacted")
	status, _ = securityFixHTTP(t, s, "", http.MethodGet, "/api/webshell/connections")
	if status != 401 {
		t.Fatal("anonymous list must be denied")
	}
}

func TestSecurityConfigReaderSecrets(t *testing.T) {
	db, auth := securityFixDB(t)
	role, err := db.UpsertRBACRole("", "Config read audit fixture", "test only", database.RBACScopeOwn, []string{"config:read"})
	if err != nil {
		t.Fatal(err)
	}
	_, token := securityFixUser(t, db, auth, "config_reader", role.ID)
	_, viewerToken := securityFixUser(t, db, auth, "config_viewer_control", database.RBACSystemRoleViewer)
	cfg := &config.Config{}
	cfg.OpenAI.APIKey = "canary-model-api-key"
	cfg.Knowledge.Embedding.APIKey = "canary-embedding-api-key"
	h := NewConfigHandler(filepath.Join(t.TempDir(), "config.yaml"), cfg, nil, nil, nil, nil, nil, zap.NewNop())
	r := securityFixRouter(db, auth)
	r.GET("/api/config", h.GetConfig)
	r.PUT("/api/config", func(c *gin.Context) { t.Error("read-only user reached config mutation"); c.Status(500) })
	s := httptest.NewServer(r)
	defer s.Close()
	status, body := securityFixHTTP(t, s, token, http.MethodGet, "/api/config")
	if status != 200 || bytes.Contains(body, []byte(cfg.OpenAI.APIKey)) || bytes.Contains(body, []byte(cfg.Knowledge.Embedding.APIKey)) || !bytes.Contains(body, []byte(config.SecretMask)) {
		t.Fatal("config response must mask secrets")
	}
	t.Log("custom_config_read_own GET=200 model_key=false embedding_key=false")
	status, _ = securityFixHTTP(t, s, token, http.MethodPut, "/api/config")
	if status != 403 {
		t.Fatalf("read-only PUT status=%d want=403", status)
	}
	status, _ = securityFixHTTP(t, s, viewerToken, http.MethodGet, "/api/config")
	if status != 403 {
		t.Fatalf("builtin viewer GET config status=%d want=403", status)
	}
	status, _ = securityFixHTTP(t, s, "", http.MethodGet, "/api/config")
	if status != 401 {
		t.Fatal("anonymous config must be denied")
	}
	t.Log("controls: config_write=403 builtin_viewer=403 anonymous=401")
}

func TestConfigMaskedSaveAndEndpointBinding(t *testing.T) {
	cfg := &config.Config{}
	cfg.AI = config.AIConfig{DefaultChannel: "primary", Channels: map[string]config.AIChannelConfig{"primary": {Provider: "openai", BaseURL: "https://saved.invalid/v1", Model: "m1", APIKey: "fixture-key"}}}
	cfg.ApplyDefaultAIChannel()
	cfg.Knowledge.Embedding.APIKey = "fixture-embedding"
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("server:\n  host: 127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h := NewConfigHandler(file, cfg, nil, nil, nil, nil, nil, zap.NewNop())
	for _, tc := range []struct {
		key, endpoint string
		allowed       bool
	}{
		{config.SecretMask, "https://saved.invalid/v1", true},
		{config.SecretMask, "https://other.invalid/v1", false},
		{"fresh-key", "https://other.invalid/v1", true},
	} {
		got, err := h.resolveTestAPIKey("/ai/channels/primary/api_key", tc.key, "openai", tc.endpoint)
		if (err == nil) != tc.allowed {
			t.Fatal("saved key endpoint authorization incorrect")
		}
		if tc.allowed && got == config.SecretMask {
			t.Fatal("placeholder would be sent to provider")
		}
	}
	public, err := config.RedactedCopy(cfg.AI)
	if err != nil {
		t.Fatal(err)
	}
	ch := public.Channels["primary"]
	ch.Model = "m2"
	public.Channels["primary"] = ch
	body, _ := json.Marshal(map[string]any{"ai": public, "knowledge": map[string]any{"embedding": map[string]any{"api_key": ""}}})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPatch, "/api/config", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.UpdateConfig(c)
	if w.Code != 200 {
		t.Fatalf("masked save status=%d", w.Code)
	}
	if cfg.AI.Channels["primary"].APIKey != "fixture-key" || cfg.AI.Channels["primary"].Model != "m2" || cfg.Knowledge.Embedding.APIKey != "" {
		t.Fatal("masked save lost update/secret or did not clear explicit secret")
	}
	if err := h.saveConfig(); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stored, []byte("fixture-key")) || bytes.Contains(stored, []byte("fixture-embedding")) || bytes.Contains(stored, []byte(config.SecretMask)) {
		t.Fatal("persisted configuration contains wrong secret state")
	}
}
