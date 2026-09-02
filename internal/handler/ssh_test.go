package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/sshclient"
	"cyberstrike-ai/internal/testutil/sshtest"
	"cyberstrike-ai/internal/testutil/testpostgres"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"go.uber.org/zap"
)

type sshHarness struct {
	db         *database.DB
	auth       *security.AuthManager
	h          *SSHHandler
	server     *httptest.Server
	remote     *sshtest.Server
	token      string
	connection sshclient.Connection
}

type sshHarnessOptions struct {
	uploadTimeout time.Duration
	fileLister    sftp.FileLister
}

func newSSHHarness(t *testing.T, options ...sshHarnessOptions) *sshHarness {
	t.Helper()
	var option sshHarnessOptions
	if len(options) > 0 {
		option = options[0]
	}
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	auth := security.NewAuthManager(1)
	password, err := auth.AttachRBACStore(db)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := auth.Authenticate("admin", password)
	if err != nil {
		t.Fatal(err)
	}
	store, err := sshclient.NewStore(context.Background(), db.DB, filepath.Join(t.TempDir(), "vault", "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	h := NewSSHHandler(store, auth, audit.NewService(db, &config.Config{}, zap.NewNop()))
	t.Cleanup(h.Close)
	r := gin.New()
	if option.uploadTimeout > 0 {
		r.Use(func(c *gin.Context) {
			if strings.HasSuffix(c.Request.URL.Path, "/files/upload") {
				ctx, cancel := context.WithTimeout(c.Request.Context(), option.uploadTimeout)
				defer cancel()
				c.Request = c.Request.WithContext(ctx)
			}
			c.Next()
		})
	}
	r.GET("/api/ssh/connections/:id/terminal", h.AuthenticateSocket, security.AuthMiddleware(auth), security.RBACMiddleware(db), h.Terminal)
	p := r.Group("/api/ssh", security.AuthMiddleware(auth), security.RBACMiddleware(db))
	p.GET("/connections", h.List)
	p.POST("/connections", h.Save)
	p.PUT("/connections/:id", h.Save)
	p.DELETE("/connections/:id", h.Delete)
	p.POST("/connections/:id/probe", h.Probe)
	p.POST("/connections/:id/trust", h.Trust)
	p.POST("/connections/:id/test", h.Test)
	p.POST("/connections/:id/terminal-ticket", h.Ticket)
	p.GET("/connections/:id/files/:action", h.Files)
	p.POST("/connections/:id/files/:action", h.Files)
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	f := sshtest.Start(t, sshtest.WithFileLister(option.fileLister))
	x := &sshHarness{db: db, auth: auth, h: h, server: server, remote: f, token: token}
	host, port, _ := net.SplitHostPort(f.Address)
	number, _ := strconv.Atoi(port)
	_, body := x.call(t, "POST", "/connections", sshclient.Input{Name: "fixture", Host: host, Port: number, Username: "fixture", AuthType: "password", Credential: &sshclient.Credential{Password: f.Password}}, 200)
	if err = json.Unmarshal(body, &x.connection); err != nil {
		t.Fatal(err)
	}
	if _, err = store.List(context.Background(), "", true); err != nil {
		t.Fatal("store list:", err)
	}
	return x
}
func (x *sshHarness) call(t *testing.T, method, path string, body any, want int) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, x.server.URL+"/api/ssh"+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+x.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, resp.StatusCode, want, raw)
	}
	return resp, raw
}
func (x *sshHarness) trust(t *testing.T) {
	t.Helper()
	x.call(t, "POST", "/connections/"+x.connection.ID+"/trust", map[string]any{"fingerprint": x.remote.Fingerprint, "revision": x.connection.Revision}, 200)
	x.connection, _ = x.h.store.Get(context.Background(), x.connection.ID, "", true)
}
func TestSSHPermissionsTrustSFTPAndAudit(t *testing.T) {
	x := newSSHHarness(t)
	id := x.connection.ID
	_, raw := x.call(t, "GET", "/connections", nil, 200)
	if bytes.Contains(raw, []byte(x.remote.Password)) || bytes.Contains(raw, []byte("secret")) {
		t.Fatal("credential leaked")
	}
	x.call(t, "POST", "/connections/"+id+"/test", nil, 409)
	_, raw = x.call(t, "POST", "/connections/"+id+"/probe", nil, 200)
	if !bytes.Contains(raw, []byte(x.remote.Fingerprint)) || x.remote.AuthCalls.Load() != 0 {
		t.Fatal("probe authenticated")
	}
	x.trust(t)
	x.call(t, "POST", "/connections/"+id+"/test", nil, 200)
	req, _ := http.NewRequest("POST", x.server.URL+"/api/ssh/connections/"+id+"/files/upload?path=fixture.txt", strings.NewReader("roundtrip 中文\n"))
	req.Header.Set("Authorization", "Bearer "+x.token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatal("upload failed", resp.StatusCode)
	}
	_, raw = x.call(t, "GET", "/connections/"+id+"/files/list?path=.", nil, 200)
	if !bytes.Contains(raw, []byte("fixture.txt")) {
		t.Fatal("uploaded file missing", string(raw))
	}
	_, raw = x.call(t, "GET", "/connections/"+id+"/files/download?path=fixture.txt", nil, 200)
	if string(raw) != "roundtrip 中文\n" {
		t.Fatal("download differs")
	}
	x.call(t, "POST", "/connections/"+id+"/files/upload?path=fixture.txt", map[string]string{"x": "overwrite"}, 409)
	_, raw = x.call(t, "GET", "/connections/"+id+"/files/download?path=fixture.txt", nil, 200)
	if string(raw) != "roundtrip 中文\n" {
		t.Fatal("existing file overwritten")
	}
	x.call(t, "GET", "/connections/"+id+"/files/upload?path=bad", nil, 405)
	var count int
	if err = x.db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action='ssh_file_upload' AND result='success'").Scan(&count); err != nil || count != 1 {
		t.Fatal("upload audit missing", count, err)
	}
	x.call(t, "DELETE", "/connections/"+id, map[string]int64{"revision": x.connection.Revision}, 200)
	x.call(t, "POST", "/connections/"+id+"/test", nil, 404)
}
func TestSSHOwnerAndPermissionScopeCannotBeBypassed(t *testing.T) {
	x := newSSHHarness(t)
	session := security.Session{UserID: "other", Scope: database.RBACScopeOwn, Permissions: map[string]bool{"webshell:read": true, "webshell:write": true, "webshell:delete": true}}
	check := func(s security.Session, handler gin.HandlerFunc, method, path string, want int) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Set(security.ContextSessionKey, s) })
		r.Handle(method, path, handler)
		w := httptest.NewRecorder()
		requestPath := strings.ReplaceAll(path, ":id", x.connection.ID)
		req := httptest.NewRequest(method, requestPath, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("scope status=%d want=%d body=%s", w.Code, want, w.Body.String())
		}
	}
	check(session, x.h.Probe, "POST", "/connections/:id/probe", 404)
	session.PermissionScopes = map[string]string{"webshell:read": database.RBACScopeAll, "webshell:write": database.RBACScopeOwn}
	check(session, x.h.Test, "POST", "/connections/:id/test", 404)
	session.Permissions["webshell:write"] = false
	check(session, x.h.Probe, "POST", "/connections/:id/probe", 403)
	if x.remote.AuthCalls.Load() != 0 {
		t.Fatal("denied request reached authentication")
	}
}
func TestSSHTerminalTicketOriginReplayAndCleanup(t *testing.T) {
	x := newSSHHarness(t)
	x.trust(t)
	path := "/connections/" + x.connection.ID
	resp, raw := x.call(t, "POST", path+"/terminal-ticket", nil, 200)
	var ticketResponse struct {
		ExpiresIn int `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &ticketResponse); err != nil {
		t.Fatal(err)
	}
	if ticketResponse.ExpiresIn != int(sshTerminalTicketTTL/time.Second) {
		t.Fatalf("unexpected ticket lifetime: got %d, want %d", ticketResponse.ExpiresIn, int(sshTerminalTicketTTL/time.Second))
	}
	var cookie *http.Cookie
	for _, candidate := range resp.Cookies() {
		if candidate.Name == sshCookie {
			cookie = candidate
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != ticketResponse.ExpiresIn {
		t.Fatal("unsafe ticket cookie")
	}
	wsURL := "ws" + strings.TrimPrefix(x.server.URL, "http") + "/api/ssh" + path + "/terminal"
	headers := http.Header{"Origin": []string{x.server.URL}, "Cookie": []string{cookie.String()}}
	bad := headers.Clone()
	bad.Set("Origin", "http://attacker.invalid")
	if conn, response, err := websocket.DefaultDialer.Dial(wsURL, bad); err == nil {
		conn.Close()
		t.Fatal("cross-origin accepted")
	} else if response.StatusCode != 403 {
		t.Fatal(response.StatusCode)
	}
	conn, response, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatal("terminal upgrade failed", response, err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, raw, err = conn.ReadMessage()
	if err != nil || !bytes.Contains(raw, []byte("fixture-ready")) {
		t.Fatal("terminal greeting missing", err)
	}
	if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":100,"rows":30}`)); err != nil {
		t.Fatal(err)
	}
	if err = conn.WriteMessage(websocket.BinaryMessage, []byte("echo-canary\r")); err != nil {
		t.Fatal(err)
	}
	_, raw, err = conn.ReadMessage()
	if err != nil || !bytes.Contains(raw, []byte("echo-canary")) {
		t.Fatal("terminal input/output failed", err)
	}
	if x.remote.Resizes.Load() == 0 {
		t.Fatal("PTY resize missing")
	}
	if duplicate, response, err := websocket.DefaultDialer.Dial(wsURL, headers); err == nil {
		duplicate.Close()
		t.Fatal("ticket replay accepted")
	} else if response.StatusCode != 401 {
		t.Fatal(response.StatusCode)
	}
	d := x.connection
	x.call(t, "PUT", "/connections/"+d.ID, sshclient.Input{Name: "renamed", Host: d.Host, Port: d.Port, Username: d.Username, AuthType: d.AuthType, Revision: d.Revision}, 200)
	if _, _, err = conn.ReadMessage(); err == nil {
		t.Fatal("connection mutation did not disconnect terminal")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		x.h.mu.Lock()
		active := len(x.h.active)
		x.h.mu.Unlock()
		if active == 0 && x.remote.Active.Load() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SSH session leaked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A ticket is not a replacement for a valid platform login.
	resp, _ = x.call(t, "POST", path+"/terminal-ticket", nil, 200)
	for _, candidate := range resp.Cookies() {
		if candidate.Name == sshCookie {
			headers.Set("Cookie", candidate.String())
		}
	}
	x.auth.RevokeToken(x.token)
	if unauthorized, response, err := websocket.DefaultDialer.Dial(wsURL, headers); err == nil {
		unauthorized.Close()
		t.Fatal("revoked login accepted")
	} else if response.StatusCode != 401 {
		t.Fatal(response.StatusCode)
	}
}

func TestSSHConcurrentOperationBudgetAndShutdown(t *testing.T) {
	x := newSSHHarness(t)
	session, _ := x.auth.ValidateToken(x.token)
	ctx := []context.Context{}
	cleanup := []func(){}
	for i := 0; i < 4; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/", nil)
		active, done, ok := x.h.begin(c, x.connection, session, time.Minute)
		if !ok {
			t.Fatal("valid operation rejected")
		}
		ctx = append(ctx, active)
		cleanup = append(cleanup, done)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	if _, _, ok := x.h.begin(c, x.connection, session, time.Minute); ok || w.Code != 429 {
		t.Fatal("per-user operation limit missing")
	}
	x.h.Close()
	for i, active := range ctx {
		if active.Err() == nil {
			t.Fatal("shutdown did not cancel operation")
		}
		cleanup[i]()
	}
}

func sshRawUpload(t *testing.T, x *sshHarness, name string, declared int, data string) *net.TCPConn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(x.server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	tcp := conn.(*net.TCPConn)
	t.Cleanup(func() { tcp.Close() })
	_, err = fmt.Fprintf(tcp, "POST /api/ssh/connections/%s/files/upload?path=%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", x.connection.ID, name, strings.TrimPrefix(x.server.URL, "http://"), x.token, declared, data)
	if err != nil {
		t.Fatal(err)
	}
	return tcp
}

func sshActiveOperations(x *sshHarness) int {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	return len(x.h.active)
}

func waitSSHCondition(t *testing.T, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !predicate() {
		select {
		case <-deadline.C:
			t.Fatal("SSH operation did not release its resources before the deadline")
		case <-ticker.C:
		}
	}
}

func TestSSHUploadDeadlineAndCancellationReleaseOperations(t *testing.T) {
	for _, reason := range []string{"deadline", "delete", "shutdown"} {
		t.Run(reason, func(t *testing.T) {
			option := sshHarnessOptions{}
			if reason == "deadline" {
				option.uploadTimeout = time.Second
			}
			x := newSSHHarness(t, option)
			x.trust(t)
			conn := sshRawUpload(t, x, "stalled.txt", 1024, "a")
			waitSSHCondition(t, 3*time.Second, func() bool { return sshActiveOperations(x) == 1 && x.remote.Active.Load() == 1 })
			switch reason {
			case "delete":
				x.call(t, "DELETE", "/connections/"+x.connection.ID, map[string]int64{"revision": x.connection.Revision}, 200)
			case "shutdown":
				x.h.Close()
			}
			// The client socket is deliberately still open with an incomplete body.
			waitSSHCondition(t, 3*time.Second, func() bool { return sshActiveOperations(x) == 0 && x.remote.Active.Load() == 0 })
			conn.Close()
			if reason == "deadline" {
				x.call(t, "POST", "/connections/"+x.connection.ID+"/test", nil, 200)
			}
		})
	}
}

func TestSSHUploadRequiresTransportDeadline(t *testing.T) {
	w := httptest.NewRecorder() // deliberately lacks SetReadDeadline
	c, _ := gin.CreateTestContext(w)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if finish, err := sshUploadDeadline(c, ctx); err == nil {
		finish()
		t.Fatal("unsupported response writer accepted without a read deadline")
	}
}

func TestSSHUploadTruncationIsNotSuccess(t *testing.T) {
	x := newSSHHarness(t)
	x.trust(t)
	for _, tc := range []struct {
		name     string
		declared int
		complete bool
	}{{"complete.txt", 3, true}, {"truncated.txt", 12, false}} {
		t.Run(tc.name, func(t *testing.T) {
			conn := sshRawUpload(t, x, tc.name, tc.declared, "abc")
			if !tc.complete {
				waitSSHCondition(t, 3*time.Second, func() bool { return x.remote.Active.Load() == 1 })
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if tc.complete && resp.StatusCode != 201 {
				t.Fatal("complete upload failed", resp.StatusCode)
			}
			if !tc.complete && resp.StatusCode < 400 {
				t.Fatal("truncated upload reported success", resp.StatusCode)
			}
			waitSSHCondition(t, 3*time.Second, func() bool { return sshActiveOperations(x) == 0 && x.remote.Active.Load() == 0 })
		})
	}
}

func TestSSHDirectoryEnumerationStopsAtBudget(t *testing.T) {
	directory := &sshtest.Directory{Count: 2500}
	x := newSSHHarness(t, sshHarnessOptions{fileLister: directory})
	x.trust(t)
	_, raw := x.call(t, "GET", "/connections/"+x.connection.ID+"/files/list?path=.", nil, 200)
	var result struct {
		Items     []sshFile `json:"items"`
		Truncated bool      `json:"truncated"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Truncated || len(result.Items) != 1000 {
		t.Fatalf("unexpected bounded listing: count=%d truncated=%v", len(result.Items), result.Truncated)
	}
	if got := directory.Emitted.Load(); got > 1100 {
		t.Fatalf("enumerated %d entries although only 1000 can be shown", got)
	}
	waitSSHCondition(t, 3*time.Second, func() bool { return directory.Closed.Load() > 0 && x.remote.Active.Load() == 0 })
}

// Opt-in smoke check for this local deployment; it creates and removes only its own fixture connection.
func TestSSHLiveDeployment(t *testing.T) {
	base := os.Getenv("CYBERSTRIKE_SSH_LIVE_URL")
	if base == "" {
		t.Skip("opt-in local deployment smoke test")
	}
	if base != "http://127.0.0.1:8080" {
		t.Fatal("live smoke test is restricted to this local application")
	}
	password := os.Getenv("CYBERSTRIKE_SSH_LIVE_PASSWORD")
	if password == "" {
		t.Fatal("live test password not supplied")
	}
	payload, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	resp, err := http.Post(base+"/api/auth/login", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	var login struct {
		Token string `json:"token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&login)
	resp.Body.Close()
	if err != nil || login.Token == "" {
		t.Fatal("live login failed")
	}
	t.Cleanup(func() {
		req, _ := http.NewRequest("POST", base+"/api/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+login.Token)
		if response, e := http.DefaultClient.Do(req); e == nil {
			response.Body.Close()
		}
	})
	f := sshtest.Start(t)
	x := &sshHarness{server: &httptest.Server{URL: base}, remote: f, token: login.Token}
	host, port, _ := net.SplitHostPort(f.Address)
	p, _ := strconv.Atoi(port)
	_, raw := x.call(t, "POST", "/connections", sshclient.Input{Name: "Temporary SSH deployment verification", Host: host, Port: p, Username: "fixture", AuthType: "password", Credential: &sshclient.Credential{Password: f.Password}}, 200)
	var item sshclient.Connection
	if err = json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, listRaw := x.call(t, "GET", "/connections", nil, 200)
		var list struct {
			Items []sshclient.Connection `json:"items"`
		}
		if json.Unmarshal(listRaw, &list) != nil {
			t.Error("cannot clean fixture")
			return
		}
		for _, c := range list.Items {
			if c.ID == item.ID {
				x.call(t, "DELETE", "/connections/"+item.ID, map[string]int64{"revision": c.Revision}, 200)
			}
		}
	})
	root := "/connections/" + item.ID
	x.call(t, "POST", root+"/test", nil, 409)
	x.call(t, "POST", root+"/probe", nil, 200)
	if f.AuthCalls.Load() != 0 {
		t.Fatal("live probe sent credentials")
	}
	x.call(t, "POST", root+"/trust", map[string]any{"revision": item.Revision, "fingerprint": f.Fingerprint}, 200)
	x.call(t, "POST", root+"/test", nil, 200)
	// Transfer through the deployed backend and its real SFTP transport.
	x.call(t, "POST", root+"/files/upload?path=live-canary.json", map[string]string{"canary": "SSH deployment verified"}, 201)
	_, raw = x.call(t, "GET", root+"/files/download?path=live-canary.json", nil, 200)
	if !bytes.Contains(raw, []byte("SSH deployment verified")) {
		t.Fatal("live SFTP roundtrip failed")
	}
	x.call(t, "POST", root+"/files/upload?path=live-canary.json", map[string]string{"canary": "must not overwrite"}, 409)
	response, _ := x.call(t, "POST", root+"/terminal-ticket", nil, 200)
	var cookie string
	for _, c := range response.Cookies() {
		if c.Name == sshCookie {
			cookie = c.String()
		}
	}
	ws, _, err := websocket.DefaultDialer.Dial("ws://127.0.0.1:8080/api/ssh"+root+"/terminal", http.Header{"Origin": []string{base}, "Cookie": []string{cookie}})
	if err != nil {
		t.Fatal("live terminal failed", err)
	}
	defer ws.Close()
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, raw, err = ws.ReadMessage()
	if err != nil || !bytes.Contains(raw, []byte("fixture-ready")) {
		t.Fatal("live terminal greeting missing", err)
	}
	if err = ws.WriteMessage(websocket.BinaryMessage, []byte("live-echo\r")); err != nil {
		t.Fatal(err)
	}
	_, raw, err = ws.ReadMessage()
	if err != nil || !bytes.Contains(raw, []byte("live-echo")) {
		t.Fatal("live terminal echo failed", err)
	}
	t.Log("Deployed SSH: trust gate, login, SFTP, no-overwrite and terminal echo passed; fixture connection cleaned on exit.")
}
