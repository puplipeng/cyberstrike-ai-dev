package app

import (
	"bytes"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/handler"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/testutil/testpostgres"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCORSMiddlewareAllowsSameOriginAndRejectsForeignOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(corsMiddleware(nil))
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	same := httptest.NewRequest(http.MethodGet, "http://app.example/test", nil)
	same.Host = "app.example"
	same.Header.Set("Origin", "http://app.example")
	sameW := httptest.NewRecorder()
	router.ServeHTTP(sameW, same)
	if sameW.Code != http.StatusNoContent || sameW.Header().Get("Access-Control-Allow-Origin") != "http://app.example" {
		t.Fatalf("same-origin response = %d, allow-origin=%q", sameW.Code, sameW.Header().Get("Access-Control-Allow-Origin"))
	}

	foreign := httptest.NewRequest(http.MethodGet, "http://app.example/test", nil)
	foreign.Host = "app.example"
	foreign.Header.Set("Origin", "https://evil.example")
	foreignW := httptest.NewRecorder()
	router.ServeHTTP(foreignW, foreign)
	if foreignW.Code != http.StatusForbidden {
		t.Fatalf("foreign-origin response = %d, want %d", foreignW.Code, http.StatusForbidden)
	}
}

func TestCORSMiddlewareAllowsBrowserExtensionWithoutConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(corsMiddleware(nil))
	router.POST("/api/auth/login", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	req := httptest.NewRequest(http.MethodOptions, "https://server.example/api/auth/login", nil)
	req.Host = "server.example"
	req.Header.Set("Origin", "chrome-extension://abcdefghijklmnopabcdefghijklmnop")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight response = %d, want %d", w.Code, http.StatusNoContent)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "chrome-extension://abcdefghijklmnopabcdefghijklmnop" {
		t.Fatalf("allow-origin = %q", got)
	}
}

func TestCORSMiddlewareRejectsInvalidExtensionOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, origin := range []string{
		"chrome-extension://too-short",
		"chrome-extension://qrstuvwxyzabcdefqrstuvwxyzabcdef",
		"chrome-extension://abcdefghijklmnopabcdefghijklmnop:8443",
		"moz-extension://abcdefghijklmnopabcdefghijklmnop",
	} {
		t.Run(origin, func(t *testing.T) {
			router := gin.New()
			router.Use(corsMiddleware(nil))
			router.GET("/test", func(c *gin.Context) { c.Status(http.StatusNoContent) })

			req := httptest.NewRequest(http.MethodGet, "https://server.example/test", nil)
			req.Host = "server.example"
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("response = %d, want %d", w.Code, http.StatusForbidden)
			}
		})
	}
}

func TestCORSMiddlewareRejectsUnsafeConfiguredEntries(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, configured := range []string{
		"*",
		"null",
		"https://trusted.example/extra",
		"https://trusted.example?trusted=true",
	} {
		t.Run(configured, func(t *testing.T) {
			router := gin.New()
			router.Use(corsMiddleware([]string{configured}))
			router.GET("/test", func(c *gin.Context) { c.Status(http.StatusNoContent) })

			req := httptest.NewRequest(http.MethodGet, "https://server.example/test", nil)
			req.Host = "server.example"
			req.Header.Set("Origin", "https://trusted.example")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("response = %d, want %d", w.Code, http.StatusForbidden)
			}
		})
	}
}

func TestSecurityQueryTokenAccessLog(t *testing.T) {
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
	const password = "isolated-query-token-audit-only"
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateRBACUser("log_fixture", "fixture", hash, true, []string{database.RBACSystemRoleViewer}); err != nil {
		t.Fatal(err)
	}
	token, _, err := auth.Authenticate("log_fixture", password)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := gin.DefaultWriter
	gin.DefaultWriter = &logs
	t.Cleanup(func() { gin.DefaultWriter = previous })
	r, err := newHTTPRouter(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := handler.NewAuthHandler(auth, &config.Config{}, "", zap.NewNop())
	r.GET("/api/auth/validate", security.AuthMiddleware(auth), h.Validate)
	request := httptest.NewRequest(http.MethodGet, "/api/auth/validate?token="+url.QueryEscape(token), nil)
	request.Header.Set("Accept", "text/event-stream")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, request)
	if w.Code != 401 || bytes.Contains(logs.Bytes(), []byte(token)) {
		t.Fatalf("query-token behavior not reproduced: status=%d", w.Code)
	}
	t.Log("ordinary_JSON_route_with_SSE_header=401 full_session_token_in_access_log=false (fixture token not printed)")
	logs.Reset()
	request = httptest.NewRequest(http.MethodGet, "/api/auth/validate", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, request)
	if w.Code != 200 || bytes.Contains(logs.Bytes(), []byte(token)) {
		t.Fatal("Authorization-header negative control failed")
	}
	t.Log("Authorization_header_control=200 token_in_access_log=false")
}
