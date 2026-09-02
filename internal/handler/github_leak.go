package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/githubleak"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type githubLeakService interface {
	List(context.Context, githubleak.ListFilter) (githubleak.ListResult, error)
	Get(context.Context, string) (githubleak.Finding, error)
	Stats(context.Context) (githubleak.Stats, error)
	RuntimeStatus(context.Context) (githubleak.RuntimeStatus, error)
	Trigger(context.Context) error
	UpdateStatus(context.Context, string, string) (githubleak.Finding, error)
}

// GitHubLeakHandler exposes only sanitized GitHub credential-leak evidence.
type GitHubLeakHandler struct {
	service githubLeakService
	audit   *audit.Service
	logger  *zap.Logger
}

func NewGitHubLeakHandler(service githubLeakService, logger *zap.Logger) *GitHubLeakHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &GitHubLeakHandler{service: service, logger: logger}
}

func (h *GitHubLeakHandler) SetAudit(service *audit.Service) { h.audit = service }

func (h *GitHubLeakHandler) List(c *gin.Context) {
	page, err := positiveQueryInt(c, "page", 1, 100000)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pageSize, err := positiveQueryInt(c, "page_size", 25, 100)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	filter := githubleak.ListFilter{
		Page: page, PageSize: pageSize,
		Status: c.Query("status"), Keyword: c.Query("keyword"), Query: c.Query("q"),
	}
	if err := filter.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid GitHub leak monitor filters"})
		return
	}
	result, err := h.service.List(c.Request.Context(), filter)
	if err != nil {
		h.logger.Warn("读取 GitHub 泄露监控列表失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load GitHub leak findings"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, result)
}

func positiveQueryInt(c *gin.Context, key string, fallback, maximum int) (int, error) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > maximum {
		return 0, errors.New(key + " is out of range")
	}
	return value, nil
}

func (h *GitHubLeakHandler) Get(c *gin.Context) {
	finding, err := h.service.Get(c.Request.Context(), c.Param("id"))
	if errors.Is(err, githubleak.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "GitHub leak finding not found"})
		return
	}
	if err != nil {
		h.logger.Warn("读取 GitHub 泄露监控记录失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load GitHub leak finding"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, finding)
}

func (h *GitHubLeakHandler) Stats(c *gin.Context) {
	stats, err := h.service.Stats(c.Request.Context())
	if err != nil {
		h.logger.Warn("统计 GitHub 泄露监控记录失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to summarize GitHub leak findings"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, stats)
}

func (h *GitHubLeakHandler) Runtime(c *gin.Context) {
	status, err := h.service.RuntimeStatus(c.Request.Context())
	if err != nil {
		h.logger.Warn("读取 GitHub 泄露监控运行状态失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load GitHub leak monitor status"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, status)
}

func (h *GitHubLeakHandler) Run(c *gin.Context) {
	err := h.service.Trigger(c.Request.Context())
	if err != nil {
		switch {
		case errors.Is(err, githubleak.ErrBusy):
			c.JSON(http.StatusConflict, gin.H{"error": "GitHub leak monitor is already running"})
		case errors.Is(err, githubleak.ErrUnconfigured):
			c.JSON(http.StatusBadRequest, gin.H{"error": "GitHub token and at least one enabled rule are required"})
		default:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "GitHub leak monitor is unavailable"})
		}
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "github_leak", "run", "手工启动 GitHub 泄露检索", "github_leak_monitor", "", nil)
	}
	c.JSON(http.StatusAccepted, gin.H{"accepted": true})
}

type githubLeakStatusRequest struct {
	Status string `json:"status"`
}

func (h *GitHubLeakHandler) UpdateStatus(c *gin.Context) {
	var request githubLeakStatusRequest
	if err := c.ShouldBindJSON(&request); err != nil || !githubleak.ValidStatus(request.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid finding status"})
		return
	}
	finding, err := h.service.UpdateStatus(c.Request.Context(), c.Param("id"), request.Status)
	if errors.Is(err, githubleak.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "GitHub leak finding not found"})
		return
	}
	if err != nil {
		h.logger.Warn("更新 GitHub 泄露监控记录状态失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update GitHub leak finding"})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "github_leak", "status_update", "更新 GitHub 泄露记录状态", "github_leak_finding", finding.ID, map[string]interface{}{"status": finding.Status})
	}
	c.JSON(http.StatusOK, finding)
}
