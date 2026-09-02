package security

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// rateLimitEntry 记录某个 IP 的请求窗口信息
type rateLimitEntry struct {
	count    int
	windowAt time.Time
}

// RateLimiter 基于 IP 的固定窗口速率限制器
type RateLimiter struct {
	mu          sync.Mutex
	entries     map[string]*rateLimitEntry
	limit       int           // 窗口内允许的最大请求数
	window      time.Duration // 窗口时长
	nextCleanup time.Time
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		entries: make(map[string]*rateLimitEntry),
		limit:   limit,
		window:  window,
	}
	return rl
}

// cleanup runs under mu as traffic arrives, avoiding a permanent goroutine.
func (rl *RateLimiter) cleanup(now time.Time) {
	if !now.Before(rl.nextCleanup) {
		for ip, entry := range rl.entries {
			if now.Sub(entry.windowAt) >= rl.window {
				delete(rl.entries, ip)
			}
		}
		rl.nextCleanup = now.Add(time.Minute)
	}
}

// allow 检查指定 IP 是否允许通过
func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.cleanup(now)
	entry, ok := rl.entries[ip]
	if !ok || now.Sub(entry.windowAt) >= rl.window {
		rl.entries[ip] = &rateLimitEntry{count: 1, windowAt: now}
		return true
	}

	if entry.count >= rl.limit {
		return false
	}
	entry.count++
	return true
}

// RateLimitMiddleware 返回 Gin 中间件，对超限请求返回 429
func RateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !rl.allow(ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded, please try again later",
			})
			return
		}
		c.Next()
	}
}
