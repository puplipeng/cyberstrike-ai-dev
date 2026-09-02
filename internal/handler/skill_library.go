package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/skilllibrary"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type SkillLibraryHandler struct {
	service *skilllibrary.Service
	logger  *zap.Logger
}

func NewSkillLibraryHandler(service *skilllibrary.Service, logger *zap.Logger) *SkillLibraryHandler {
	return &SkillLibraryHandler{service, logger}
}
func (h *SkillLibraryHandler) authorize(c *gin.Context, write bool) (string, bool) {
	s, ok := security.CurrentSession(c)
	if !ok || s.UserID == "" {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return "", false
	}
	permission := "skills:read"
	if write {
		permission = "skills:write"
	}
	// This catalog contains shared package files, not project-owned records.
	if !security.SessionHasPermission(c, "skills:read") || !security.SessionHasPermission(c, permission) || s.ScopeFor("skills:read") != database.RBACScopeAll || s.ScopeFor(permission) != database.RBACScopeAll {
		c.JSON(403, gin.H{"error": "共享资料库需要全局技能读取/管理权限"})
		return "", false
	}
	if h.service == nil {
		c.JSON(503, gin.H{"error": "技能资料库未启用，请先配置本地向量服务和 pgvector。"})
		return "", false
	}
	return s.UserID, true
}
func (h *SkillLibraryHandler) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		c.JSON(404, gin.H{"error": "记录或可删除的手动关联不存在"})
	case errors.Is(err, skilllibrary.ErrInvalid):
		c.JSON(400, gin.H{"error": "参数无效；请检查类型、CVE、长度和来源链接"})
	case errors.Is(err, skilllibrary.ErrConflict):
		c.JSON(409, gin.H{"error": "原文件或元数据已变化，请扫描并重新打开详情后保存"})
	case errors.Is(err, skilllibrary.ErrBusy):
		c.JSON(409, gin.H{"error": "索引任务正在运行"})
	default:
		h.logger.Warn("skill library API failed", zap.Error(err))
		c.JSON(500, gin.H{"error": "资料库操作失败，请查看服务日志"})
	}
}
func libraryBody(c *gin.Context, out any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		c.JSON(400, gin.H{"error": "无效的 JSON 请求"})
		return false
	}
	return true
}
func (h *SkillLibraryHandler) Search(c *gin.Context) {
	if _, ok := h.authorize(c, false); !ok {
		return
	}
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil {
		h.fail(c, skilllibrary.ErrInvalid)
		return
	}
	r, err := h.service.Search(c.Request.Context(), skilllibrary.Search{Query: c.Query("q"), Kind: c.Query("kind"), Review: c.Query("review"), CVE: c.Query("cve"), Product: c.Query("product"), Page: page})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(200, r)
}
func (h *SkillLibraryHandler) Status(c *gin.Context) {
	if _, ok := h.authorize(c, false); !ok {
		return
	}
	r, err := h.service.Status(c.Request.Context())
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(200, r)
}
func (h *SkillLibraryHandler) Index(c *gin.Context) {
	if _, ok := h.authorize(c, true); !ok {
		return
	}
	var b struct {
		Full bool `json:"full"`
	}
	if !libraryBody(c, &b) {
		return
	}
	if err := h.service.Trigger(c.Request.Context(), b.Full); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(202, gin.H{"status": "queued"})
}
func (h *SkillLibraryHandler) Detail(c *gin.Context) {
	if _, ok := h.authorize(c, false); !ok {
		return
	}
	d, err := h.service.Store().Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	links, err := h.service.Store().Links(c.Request.Context(), d.ID)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(200, gin.H{"document": d, "links": links, "source_current": h.service.SourceCurrent(d)})
}
func (h *SkillLibraryHandler) Edit(c *gin.Context) {
	actor, ok := h.authorize(c, true)
	if !ok {
		return
	}
	var edit skilllibrary.Edit
	if !libraryBody(c, &edit) {
		return
	}
	if err := h.service.Edit(c.Request.Context(), c.Param("id"), actor, edit); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(200, gin.H{"status": "saved"})
}
func (h *SkillLibraryHandler) Link(c *gin.Context) {
	actor, ok := h.authorize(c, true)
	if !ok {
		return
	}
	var body struct {
		SkillID    string `json:"skill_id"`
		ResourceID string `json:"resource_id"`
		Note       string `json:"note"`
	}
	if !libraryBody(c, &body) {
		return
	}
	err := h.service.Store().Link(c.Request.Context(), skilllibrary.Link{SkillID: body.SkillID, ResourceID: body.ResourceID, Note: body.Note}, actor, c.Request.Method == http.MethodDelete)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(200, gin.H{"status": "saved"})
}
