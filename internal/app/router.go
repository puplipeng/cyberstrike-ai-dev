package app

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"runtime/debug"
	"strings"
)

func newHTTPRouter(trustedProxies []string) (*gin.Engine, error) {
	router := gin.New()
	router.Use(gin.LoggerWithFormatter(func(p gin.LogFormatterParams) string {
		// Query strings are unnecessary for access auditing and can contain
		// credentials even on rejected or malformed requests.
		path, _, _ := strings.Cut(p.Path, "?")
		return fmt.Sprintf("[GIN] %s | %d | %v | %s | %s %q\n", p.TimeStamp.Format("2006/01/02 - 15:04:05"), p.StatusCode, p.Latency, p.ClientIP, p.Method, path)
	}))
	router.Use(gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) {
		// The default recovery logger dumps request headers and the raw URL.
		fmt.Fprintf(gin.DefaultErrorWriter, "HTTP handler panic\n%s", debug.Stack())
		c.AbortWithStatus(500)
	}))
	if err := router.SetTrustedProxies(trustedProxies); err != nil {
		return nil, fmt.Errorf("invalid server.trusted_proxies: %w", err)
	}
	return router, nil
}
