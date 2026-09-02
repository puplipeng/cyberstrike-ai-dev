package app

import (
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPRouterForwardedHeadersCannotBypassRateLimit(t *testing.T) {
	router, err := newHTTPRouter(nil)
	if err != nil {
		t.Fatal(err)
	}
	router.POST("/login", security.RateLimitMiddleware(security.NewRateLimiter(1, time.Minute)), func(c *gin.Context) { c.Status(http.StatusUnauthorized) })
	for i, headers := range []map[string]string{nil, {"X-Forwarded-For": "203.0.113.8"}, {"X-Real-IP": "203.0.113.9"}} {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "192.0.2.10:2345"
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		want := http.StatusTooManyRequests
		if i == 0 {
			want = http.StatusUnauthorized
		}
		if response.Code != want {
			t.Fatalf("request %d: got %d, want %d", i, response.Code, want)
		}
	}
}

func TestHTTPRouterTrustsOnlyConfiguredProxy(t *testing.T) {
	router, err := newHTTPRouter([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	router.GET("/ip", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })
	for _, tc := range []struct{ remote, want string }{{"192.0.2.10:1234", "203.0.113.8"}, {"198.51.100.2:1234", "198.51.100.2"}} {
		req := httptest.NewRequest(http.MethodGet, "/ip", nil)
		req.RemoteAddr = tc.remote
		req.Header.Set("X-Forwarded-For", "203.0.113.8")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		if response.Body.String() != tc.want {
			t.Fatalf("%s: got %s", tc.remote, response.Body.String())
		}
	}
	if _, err := newHTTPRouter([]string{"invalid-proxy"}); err == nil {
		t.Fatal("invalid proxy CIDR must fail startup")
	}
}
