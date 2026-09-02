package security

import (
	"cyberstrike-ai/internal/testutil/testpostgres"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestAuthManagerAuthenticatesCreatedRBACUser(t *testing.T) {
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewAuthManager(12)
	if _, err := manager.AttachRBACStore(db); err != nil {
		t.Fatalf("AttachRBACStore: %v", err)
	}
	hash, err := HashPassword("operator-secret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user, err := db.CreateRBACUser("operator1", "Operator One", hash, true, []string{database.RBACSystemRoleViewer})
	if err != nil {
		t.Fatalf("CreateRBACUser: %v", err)
	}

	token, _, err := manager.Authenticate("operator1", "operator-secret")
	if err != nil {
		t.Fatalf("Authenticate created user: %v", err)
	}
	session, ok := manager.ValidateToken(token)
	if !ok {
		t.Fatalf("expected created user session to validate")
	}
	if session.UserID != user.ID || session.Username != "operator1" {
		t.Fatalf("session user = %s/%s, want %s/operator1", session.UserID, session.Username, user.ID)
	}
	if !session.Permissions["auth:self"] || !session.Permissions["chat:read"] {
		t.Fatalf("expected viewer permissions in session, got %#v", session.Permissions)
	}

	if _, _, err := manager.Authenticate("", "operator-secret"); err == nil {
		t.Fatalf("empty username must not authenticate non-admin user")
	}

	router := gin.New()
	router.Use(AuthMiddleware(manager))
	router.GET("/principal", func(c *gin.Context) {
		principal, ok := authctx.PrincipalFromContext(c.Request.Context())
		if !ok || principal.UserID != user.ID || !principal.HasPermission("chat:read") || principal.ScopeFor("chat:read") != database.RBACScopeAssigned {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusNoContent)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/principal", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("principal propagation status = %d", w.Code)
	}
}

func TestQueryTokenRejectedForSSEAndWebSocketGET(t *testing.T) {
	requestToken := func(method, accept, upgrade string) string {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(method, "/api/test?token=secret", nil)
		c.Request.Header.Set("Accept", accept)
		c.Request.Header.Set("Upgrade", upgrade)
		return extractTokenFromRequest(c)
	}
	if got := requestToken(http.MethodGet, "application/json", ""); got != "" {
		t.Fatalf("ordinary GET accepted query token %q", got)
	}
	if got := requestToken(http.MethodPost, "text/event-stream", ""); got != "" {
		t.Fatalf("POST accepted query token %q", got)
	}
	if got := requestToken(http.MethodGet, "text/event-stream", ""); got != "" {
		t.Fatalf("SSE token = %q", got)
	}
	if got := requestToken(http.MethodGet, "", "websocket"); got != "" {
		t.Fatalf("WebSocket token = %q", got)
	}
}

func TestTerminalTicketsBoundToLiveSessionAndSocket(t *testing.T) {
	auth := NewAuthManager(1)
	auth.sessions["fixture-session"] = Session{Token: "fixture-session", ExpiresAt: time.Now().Add(time.Hour), Permissions: map[string]bool{"terminal:execute": true}}
	r := gin.New()
	r.Use(AuthMiddleware(auth))
	r.GET(TerminalSocketPath, func(c *gin.Context) { c.Status(204) })
	r.GET("/api/other", func(c *gin.Context) { c.Status(204) })
	request := func(path, ticket string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Protocol", "csai-terminal, "+TerminalTicketProtocol+ticket)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	ticket, err := auth.IssueTerminalTicket("fixture-session")
	if err != nil {
		t.Fatal(err)
	}
	if request("/api/other", ticket) != 401 {
		t.Fatal("ticket accepted on wrong route")
	}
	if request(TerminalSocketPath, ticket) != 204 {
		t.Fatal("valid ticket rejected")
	}
	if request(TerminalSocketPath, ticket) != 401 {
		t.Fatal("ticket replay accepted")
	}
	ticket, _ = auth.IssueTerminalTicket("fixture-session")
	entry := auth.terminalTickets[ticket]
	entry.expires = time.Now().Add(-time.Second)
	auth.terminalTickets[ticket] = entry
	if request(TerminalSocketPath, ticket) != 401 {
		t.Fatal("expired ticket accepted")
	}
	ticket, _ = auth.IssueTerminalTicket("fixture-session")
	auth.RevokeToken("fixture-session")
	if request(TerminalSocketPath, ticket) != 401 {
		t.Fatal("revoked session accepted")
	}
	if _, err := auth.IssueTerminalTicket("fixture-session"); err == nil {
		t.Fatal("revoked session minted ticket")
	}
}

func TestTerminalTicketPendingLimit(t *testing.T) {
	auth := NewAuthManager(1)
	auth.sessions["fixture"] = Session{Token: "fixture", ExpiresAt: time.Now().Add(time.Hour), Permissions: map[string]bool{"terminal:execute": true}}
	for i := 0; i < 8; i++ {
		if _, err := auth.IssueTerminalTicket("fixture"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := auth.IssueTerminalTicket("fixture"); err == nil {
		t.Fatal("pending ticket limit ignored")
	}
}
