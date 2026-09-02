package handler

import (
	"context"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/llm"
	"github.com/cloudwego/eino/schema"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

// Uses the current Codex ChatGPT session. No caller-provided URL or credential is
// passed to Codex, and the tiny test cannot execute host tools.
func (h *ConfigHandler) testCodexAccount(c *gin.Context, req TestOpenAIRequest) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 90*time.Second)
	defer cancel()
	started := time.Now()
	native, err := llm.NewCodexAgenticModel(config.OpenAIConfig{Provider: "codex_account", Model: req.Model})
	if err == nil {
		_, err = native.Generate(ctx, []*schema.AgenticMessage{schema.UserAgenticMessage("Reply with exactly OK. Do not use any tools.")})
	}
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "model": req.Model, "latency_ms": time.Since(started).Milliseconds(), "account_type": "chatgpt"})
}
