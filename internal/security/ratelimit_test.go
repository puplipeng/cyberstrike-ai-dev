package security

import (
	"testing"
	"time"
)

func TestRateLimiterExpiresWindowsAndCleansIdleEntries(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	if !rl.allow("a") || !rl.allow("a") || rl.allow("a") {
		t.Fatal("request limit not enforced")
	}
	if !rl.allow("b") {
		t.Fatal("independent source was blocked")
	}
	rl.entries["a"].windowAt = time.Now().Add(-2 * time.Minute)
	rl.entries["b"].windowAt = time.Now().Add(-2 * time.Minute)
	rl.nextCleanup = time.Time{}
	if !rl.allow("a") {
		t.Fatal("expired window did not reset")
	}
	if _, exists := rl.entries["b"]; exists {
		t.Fatal("idle entry was not removed")
	}
}
