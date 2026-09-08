package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/assetmonitor"
	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type assetMonitorService interface {
	CreateMonitor(context.Context, assetmonitor.CreateMonitorInput) (assetmonitor.Monitor, error)
	ListMonitors(context.Context, string) ([]assetmonitor.Monitor, error)
	GetMonitor(context.Context, string, string) (assetmonitor.Monitor, error)
	UpdateMonitor(context.Context, string, string, assetmonitor.UpdateMonitorInput) (assetmonitor.Monitor, error)
	DeleteMonitor(context.Context, string, string) error
	Trigger(context.Context, string, string, string) (assetmonitor.Run, error)
	ListRuns(context.Context, string, string, assetmonitor.RunListOptions) (assetmonitor.RunListResult, error)
	GetRun(context.Context, string, string, string) (assetmonitor.Run, error)
	ListRunAssets(context.Context, string, string, string, assetmonitor.RunAssetListOptions) (assetmonitor.RunAssetListResult, error)
}

type assetMonitorProjectStore interface {
	UserCanAccessResource(userID, scope, resourceType, resourceID string) bool
	GetProject(id string) (*database.Project, error)
}

// AssetMonitorHandler manages project-scoped passive asset discovery monitors.
// Every monitor lookup is followed by an explicit project access check because
// the public API is intentionally flat (/asset-monitors/:id).
type AssetMonitorHandler struct {
	service assetMonitorService
	db      assetMonitorProjectStore
	audit   *audit.Service
	logger  *zap.Logger
}

func NewAssetMonitorHandler(service assetMonitorService, db *database.DB, logger *zap.Logger) *AssetMonitorHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AssetMonitorHandler{service: service, db: db, logger: logger}
}

func (h *AssetMonitorHandler) SetAudit(service *audit.Service) { h.audit = service }

func (h *AssetMonitorHandler) Create(c *gin.Context) {
	var input assetmonitor.CreateMonitorInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的资产监控参数"})
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if !h.requireProjectAccess(c, input.ProjectID, "project:write") {
		return
	}
	session, _ := security.CurrentSession(c)
	input.OwnerUserID = session.UserID
	monitor, err := h.service.CreateMonitor(c.Request.Context(), input)
	if err != nil {
		h.writeError(c, "创建资产监控失败", err)
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "asset_monitor", "create", "创建项目资产监控", "asset_monitor", monitor.ID, map[string]interface{}{
			"project_id": monitor.ProjectID, "root_domain": monitor.RootDomain, "provider": monitor.Provider,
		})
	}
	c.JSON(http.StatusCreated, monitor)
}

func (h *AssetMonitorHandler) List(c *gin.Context) {
	projectID := strings.TrimSpace(c.Query("project_id"))
	if projectID != "" && !h.requireProjectAccess(c, projectID, "project:read") {
		return
	}
	limit, offset, ok := assetMonitorPagination(c)
	if !ok {
		return
	}
	monitors, err := h.service.ListMonitors(c.Request.Context(), projectID)
	if err != nil {
		h.writeError(c, "读取资产监控失败", err)
		return
	}
	if projectID == "" {
		monitors = h.filterReadableProjects(c, monitors)
	}
	if rawEnabled := strings.TrimSpace(c.Query("enabled")); rawEnabled != "" {
		enabled, parseErr := strconv.ParseBool(rawEnabled)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "enabled 必须为 true 或 false"})
			return
		}
		filtered := make([]assetmonitor.Monitor, 0, len(monitors))
		for _, monitor := range monitors {
			if monitor.Enabled == enabled {
				filtered = append(filtered, monitor)
			}
		}
		monitors = filtered
	}
	total := len(monitors)
	if offset >= total {
		monitors = []assetmonitor.Monitor{}
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		monitors = monitors[offset:end]
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"items": monitors, "total": total})
}

func (h *AssetMonitorHandler) Get(c *gin.Context) {
	monitor, ok := h.monitorForAccess(c, "project:read")
	if !ok {
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, monitor)
}

func (h *AssetMonitorHandler) Update(c *gin.Context) {
	monitor, ok := h.monitorForAccess(c, "project:write")
	if !ok {
		return
	}
	var input assetmonitor.UpdateMonitorInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的资产监控参数"})
		return
	}
	updated, err := h.service.UpdateMonitor(c.Request.Context(), monitor.ProjectID, monitor.ID, input)
	if err != nil {
		h.writeError(c, "更新资产监控失败", err)
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "asset_monitor", "update", "更新项目资产监控", "asset_monitor", updated.ID, map[string]interface{}{"project_id": updated.ProjectID})
	}
	c.JSON(http.StatusOK, updated)
}

func (h *AssetMonitorHandler) Delete(c *gin.Context) {
	monitor, ok := h.monitorForAccess(c, "project:write")
	if !ok {
		return
	}
	if err := h.service.DeleteMonitor(c.Request.Context(), monitor.ProjectID, monitor.ID); err != nil {
		h.writeError(c, "删除资产监控失败", err)
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "asset_monitor", "delete", "删除项目资产监控", "asset_monitor", monitor.ID, map[string]interface{}{"project_id": monitor.ProjectID})
	}
	c.Status(http.StatusNoContent)
}

func (h *AssetMonitorHandler) Run(c *gin.Context) {
	monitor, ok := h.monitorForAccess(c, "project:write")
	if !ok {
		return
	}
	session, _ := security.CurrentSession(c)
	run, err := h.service.Trigger(c.Request.Context(), monitor.ProjectID, monitor.ID, session.UserID)
	if err != nil {
		h.writeError(c, "启动资产监控失败", err)
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "asset_monitor", "run", "手工启动项目资产监控", "asset_monitor", monitor.ID, map[string]interface{}{
			"project_id": monitor.ProjectID, "run_id": run.ID,
		})
	}
	c.JSON(http.StatusAccepted, run)
}

func (h *AssetMonitorHandler) Runs(c *gin.Context) {
	monitor, ok := h.monitorForAccess(c, "project:read")
	if !ok {
		return
	}
	limit, offset, ok := assetMonitorPagination(c)
	if !ok {
		return
	}
	result, err := h.service.ListRuns(c.Request.Context(), monitor.ProjectID, monitor.ID, assetmonitor.RunListOptions{Limit: limit, Offset: offset})
	if err != nil {
		h.writeError(c, "读取资产监控运行记录失败", err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, result)
}

func (h *AssetMonitorHandler) RunAssets(c *gin.Context) {
	monitor, ok := h.monitorForAccess(c, "project:read")
	if !ok {
		return
	}
	limit, offset, ok := assetMonitorPagination(c)
	if !ok {
		return
	}
	state := strings.ToLower(strings.TrimSpace(c.Query("state")))
	result, err := h.service.ListRunAssets(c.Request.Context(), monitor.ProjectID, monitor.ID, strings.TrimSpace(c.Param("runId")), assetmonitor.RunAssetListOptions{
		State: state, Limit: limit, Offset: offset,
	})
	if err != nil {
		h.writeError(c, "读取资产监控发现记录失败", err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, result)
}

func assetMonitorPagination(c *gin.Context) (int, int, bool) {
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if err != nil || limit < 1 || limit > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "limit 必须在 1-100 之间"})
		return 0, 0, false
	}
	offset, err := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err != nil || offset < 0 || offset > 10_000_000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "offset 超出范围"})
		return 0, 0, false
	}
	return limit, offset, true
}

func (h *AssetMonitorHandler) monitorForAccess(c *gin.Context, permission string) (assetmonitor.Monitor, bool) {
	if h.service == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "资产监控服务不可用"})
		return assetmonitor.Monitor{}, false
	}
	monitor, err := h.service.GetMonitor(c.Request.Context(), "", strings.TrimSpace(c.Param("id")))
	if err != nil {
		h.writeError(c, "读取资产监控失败", err)
		return assetmonitor.Monitor{}, false
	}
	if !h.requireProjectAccess(c, monitor.ProjectID, permission) {
		return assetmonitor.Monitor{}, false
	}
	return monitor, true
}

func (h *AssetMonitorHandler) requireProjectAccess(c *gin.Context, projectID, permission string) bool {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id 不能为空"})
		return false
	}
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权访问"})
		return false
	}
	if !session.Permissions[permission] {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足", "permission": permission})
		return false
	}
	if h.db == nil || !h.db.UserCanAccessResource(session.UserID, session.ScopeFor(permission), "project", projectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该项目"})
		return false
	}
	if _, err := h.db.GetProject(projectID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "项目不存在"})
		return false
	}
	return true
}

func (h *AssetMonitorHandler) filterReadableProjects(c *gin.Context, monitors []assetmonitor.Monitor) []assetmonitor.Monitor {
	session, ok := security.CurrentSession(c)
	if !ok || !session.Permissions["project:read"] || h.db == nil {
		return []assetmonitor.Monitor{}
	}
	scope := session.ScopeFor("project:read")
	filtered := make([]assetmonitor.Monitor, 0, len(monitors))
	for _, monitor := range monitors {
		if h.db.UserCanAccessResource(session.UserID, scope, "project", monitor.ProjectID) {
			filtered = append(filtered, monitor)
		}
	}
	return filtered
}

func (h *AssetMonitorHandler) writeError(c *gin.Context, action string, err error) {
	switch {
	case errors.Is(err, assetmonitor.ErrValidation):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, assetmonitor.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "资产监控或运行记录不存在"})
	case errors.Is(err, assetmonitor.ErrBusy), errors.Is(err, assetmonitor.ErrConflict):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, assetmonitor.ErrUnconfigured):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Quake 凭据未配置，无法执行资产发现"})
	case errors.Is(err, assetmonitor.ErrUnavailable):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "资产监控服务不可用"})
	default:
		h.logger.Warn(action, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": action})
	}
}
