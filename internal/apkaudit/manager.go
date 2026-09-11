package apkaudit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const MaxAPK = 256 << 20

var validID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Identity func(*gin.Context) string
type Config struct {
	Root, Python, Worker, ASCRoot string
	Timeout                       time.Duration
	AuditTimeout                  time.Duration
}
type Action struct {
	Mode  string `json:"mode"`
	Query string `json:"query"`
	Kind  string `json:"kind"`
}
type Record struct {
	ID          string          `json:"id"`
	Owner       string          `json:"-"`
	Name        string          `json:"name"`
	SHA256      string          `json:"sha256"`
	Size        int64           `json:"size"`
	Created     string          `json:"created"`
	Status      string          `json:"status"`
	Error       string          `json:"error,omitempty"`
	Action      Action          `json:"action"`
	Inspection  json.RawMessage `json:"inspection,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	AuditReport json.RawMessage `json:"audit_report,omitempty"`
}
type storedRecord struct {
	Record
	User string `json:"owner"`
}
type Manager struct {
	cfg      Config
	mu       sync.Mutex
	records  map[string]*Record
	cancels  map[string]context.CancelFunc
	slot     chan struct{}
	identity Identity
}

func New(cfg Config, identity Identity) (*Manager, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Minute
	}
	if cfg.AuditTimeout <= 0 {
		cfg.AuditTimeout = 30 * time.Minute
	}
	m := &Manager{cfg: cfg, records: map[string]*Record{}, cancels: map[string]context.CancelFunc{}, slot: make(chan struct{}, 1), identity: identity}
	if cfg.Root == "" {
		return m, nil
	}
	if !filepath.IsAbs(cfg.Root) {
		return nil, errors.New("APK storage must be an absolute private path")
	}
	if err := os.MkdirAll(cfg.Root, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(cfg.Root)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || !validID.MatchString(e.Name()) {
			continue
		}
		p := filepath.Join(cfg.Root, e.Name(), "record.json")
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var r storedRecord
		if json.Unmarshal(b, &r) != nil || r.ID != e.Name() {
			continue
		}
		r.Owner = r.User
		if r.Status == "running" {
			r.Status = "interrupted"
			r.Error = "Service restarted; rerun explicitly"
		}
		m.records[r.ID] = &r.Record
	}
	return m, nil
}
func (m *Manager) ready() bool {
	for _, p := range []string{m.cfg.Root, m.cfg.Python, m.cfg.Worker, m.cfg.ASCRoot} {
		if !filepath.IsAbs(p) {
			return false
		}
		if _, e := os.Stat(p); e != nil {
			return false
		}
	}
	return true
}
func (m *Manager) Register(g *gin.RouterGroup) {
	g.GET("/status", m.status)
	g.GET("/cases", m.list)
	g.POST("/cases", m.upload)
	g.GET("/cases/:id", m.get)
	g.POST("/cases/:id/actions", m.action)
	g.POST("/cases/:id/cancel", m.cancel)
	g.GET("/cases/:id/audit-source", m.auditSource)
	g.GET("/cases/:id/export", m.exportAudit)
}
func (m *Manager) user(c *gin.Context) string {
	if m.identity == nil {
		return ""
	}
	return m.identity(c)
}
func (m *Manager) authorized(c *gin.Context) string {
	u := m.user(c)
	if u == "" {
		c.AbortWithStatusJSON(401, gin.H{"error": "Authentication required"})
	}
	return u
}
func (m *Manager) status(c *gin.Context) {
	if m.authorized(c) == "" {
		return
	}
	c.JSON(200, gin.H{"enabled": m.ready(), "engine": "ASC 6bd9492 + local index-zero fix / Androguard 4.1.4", "max_apk_bytes": MaxAPK, "concurrency": 1, "timeout_seconds": m.cfg.Timeout.Seconds(), "audit_timeout_seconds": m.cfg.AuditTimeout.Seconds(), "note": "Offline static analysis. Review candidates are not confirmed vulnerabilities. No automatic AI submission."})
}
func clone(r *Record) *Record { v := *r; return &v }
func (m *Manager) list(c *gin.Context) {
	u := m.authorized(c)
	if u == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*Record{}
	for _, r := range m.records {
		if r.Owner == u {
			v := clone(r)
			v.Inspection = nil
			v.Result = nil
			v.AuditReport = nil
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	c.JSON(200, gin.H{"cases": out})
}
func (m *Manager) get(c *gin.Context) {
	u := m.authorized(c)
	if u == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[c.Param("id")]
	if r == nil || r.Owner != u {
		c.JSON(404, gin.H{"error": "Case not found"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, clone(r))
}
func (m *Manager) persist(r *Record) error {
	b, e := json.Marshal(storedRecord{Record: *r, User: r.Owner})
	if e != nil {
		return e
	}
	p := filepath.Join(m.cfg.Root, r.ID, "record.json")
	t := p + ".tmp"
	if e = os.WriteFile(t, b, 0600); e != nil {
		return e
	}
	return os.Rename(t, p)
}
func id() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func (m *Manager) upload(c *gin.Context) {
	u := m.authorized(c)
	if u == "" {
		return
	}
	if !m.ready() {
		c.JSON(503, gin.H{"error": "APK engine not configured"})
		return
	}
	select {
	case m.slot <- struct{}{}:
	default:
		c.JSON(409, gin.H{"error": "Another APK operation is running"})
		return
	}
	handed := false
	defer func() {
		if !handed {
			<-m.slot
		}
	}()
	m.mu.Lock()
	full := len(m.records) >= 100
	m.mu.Unlock()
	if full {
		c.JSON(409, gin.H{"error": "100 case limit reached"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxAPK+(1<<20))
	if e := c.Request.ParseMultipartForm(8 << 20); e != nil {
		c.JSON(413, gin.H{"error": "Invalid or oversized upload"})
		return
	}
	if c.Request.MultipartForm != nil {
		defer c.Request.MultipartForm.RemoveAll()
	}
	f, h, e := c.Request.FormFile("file")
	if e != nil {
		c.JSON(400, gin.H{"error": "APK file required"})
		return
	}
	defer f.Close()
	if !strings.EqualFold(filepath.Ext(h.Filename), ".apk") {
		c.JSON(400, gin.H{"error": "Only .apk files are accepted"})
		return
	}
	r := &Record{ID: id(), Owner: u, Name: filepath.Base(strings.ReplaceAll(h.Filename, "\\", "/")), Created: time.Now().UTC().Format(time.RFC3339Nano), Status: "running", Action: Action{Mode: "inspect"}}
	dir := filepath.Join(m.cfg.Root, r.ID)
	if e = os.Mkdir(dir, 0700); e != nil {
		c.JSON(500, gin.H{"error": "Unable to create private case storage"})
		return
	}
	success := false
	defer func() {
		if !success {
			os.RemoveAll(dir)
		}
	}() // UUID child created by this upload only.
	out, e := os.OpenFile(filepath.Join(dir, "input.apk"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		c.JSON(500, gin.H{"error": "Upload storage failed"})
		return
	}
	hash := sha256.New()
	n, e := io.Copy(io.MultiWriter(out, hash), io.LimitReader(f, MaxAPK+1))
	ce := out.Close()
	if e != nil || ce != nil || n > MaxAPK || n == 0 {
		c.JSON(413, gin.H{"error": "Empty, invalid or oversized APK"})
		return
	}
	r.Size = n
	r.SHA256 = hex.EncodeToString(hash.Sum(nil))
	m.mu.Lock()
	e = m.persist(r)
	if e == nil {
		m.records[r.ID] = r
	}
	m.mu.Unlock()
	if e != nil {
		c.JSON(500, gin.H{"error": "Unable to persist case"})
		return
	}
	success = true
	handed = true
	v := clone(r)
	m.start(r)
	c.JSON(202, v)
}
func validateAction(a Action) bool {
	switch a.Mode {
	case "inspect", "audit_apk":
		return a.Query == ""
	case "refs":
		return len(a.Query) > 0 && len(a.Query) <= 256 && (a.Kind == "string" || a.Kind == "type" || a.Kind == "method" || a.Kind == "field")
	case "decompile", "disassemble":
		return len(a.Query) > 0 && len(a.Query) <= 256
	}
	return false
}
func (m *Manager) action(c *gin.Context) {
	u := m.authorized(c)
	if u == "" {
		return
	}
	var a Action
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	if c.ShouldBindJSON(&a) != nil || !validateAction(a) {
		c.JSON(400, gin.H{"error": "Invalid operation"})
		return
	}
	m.mu.Lock()
	r := m.records[c.Param("id")]
	if r == nil || r.Owner != u {
		m.mu.Unlock()
		c.JSON(404, gin.H{"error": "Case not found"})
		return
	}
	if !m.ready() {
		m.mu.Unlock()
		c.JSON(503, gin.H{"error": "Engine unavailable"})
		return
	}
	select {
	case m.slot <- struct{}{}:
	default:
		m.mu.Unlock()
		c.JSON(409, gin.H{"error": "Another APK operation is running"})
		return
	}
	r.Status = "running"
	r.Error = ""
	r.Action = a
	r.Result = nil
	if e := m.persist(r); e != nil {
		r.Status = "failed"
		m.mu.Unlock()
		<-m.slot
		c.JSON(500, gin.H{"error": "Case state could not be saved"})
		return
	}
	v := clone(r)
	m.mu.Unlock()
	m.start(r)
	c.JSON(202, v)
}
func (m *Manager) cancel(c *gin.Context) {
	u := m.authorized(c)
	if u == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[c.Param("id")]
	if r == nil || r.Owner != u {
		c.JSON(404, gin.H{"error": "Case not found"})
		return
	}
	if cancel := m.cancels[r.ID]; cancel != nil {
		cancel()
	}
	c.JSON(200, gin.H{"ok": true})
}

type limitedBuffer struct {
	data     []byte
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	room := b.limit - len(b.data)
	if room < len(p) {
		b.exceeded = true
		p = p[:room]
	}
	b.data = append(b.data, p...)
	return n, nil
}
func (m *Manager) start(r *Record) {
	m.mu.Lock()
	a := r.Action
	timeout := m.cfg.Timeout
	if a.Mode == "audit_apk" {
		timeout = m.cfg.AuditTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	m.cancels[r.ID] = cancel
	m.mu.Unlock()
	go func() {
		defer cancel()
		defer func() { <-m.slot }()
		runID := id()
		input, _ := json.Marshal(map[string]interface{}{"apk": filepath.Join(m.cfg.Root, r.ID, "input.apk"), "mode": a.Mode, "query": a.Query, "kind": a.Kind, "run_id": runID, "budget_seconds": timeout.Seconds() * 0.85})
		cmd := exec.CommandContext(ctx, m.cfg.Python, "-I", "-X", "utf8", m.cfg.Worker, "--asc-root", m.cfg.ASCRoot)
		cmd.Dir = filepath.Join(m.cfg.Root, r.ID)
		cmd.Stdin = strings.NewReader(string(input))
		cmd.Env = []string{"PYTHONIOENCODING=utf-8", "PYTHONDONTWRITEBYTECODE=1"}
		for _, key := range []string{"SYSTEMROOT", "WINDIR"} {
			if v := os.Getenv(key); v != "" {
				cmd.Env = append(cmd.Env, key+"="+v)
			}
		}
		cmd.Env = append(cmd.Env, "TEMP="+cmd.Dir, "TMP="+cmd.Dir, "TMPDIR="+cmd.Dir)
		stdout := &limitedBuffer{limit: 4 << 20}
		stderr := &limitedBuffer{limit: 8192}
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		err := cmd.Run()
		message := ""
		var result struct {
			Error string `json:"error"`
		}
		parseErr := json.Unmarshal(stdout.data, &result)
		switch {
		case ctx.Err() != nil:
			message = "Operation cancelled or timed out"
		case stdout.exceeded:
			message = "Engine output exceeds limit"
		case result.Error != "":
			message = result.Error
		case err != nil:
			message = fmt.Sprintf("Engine failed (%v); inspect isolated worker runtime", err)
		case parseErr != nil:
			message = "Engine returned invalid JSON"
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		previousReport := r.AuditReport
		delete(m.cancels, r.ID)
		r.Status = "completed"
		r.Error = message
		if message != "" {
			r.Status = "failed"
		} else {
			r.Result = append(json.RawMessage{}, stdout.data...)
			if a.Mode == "inspect" {
				r.Inspection = r.Result
			}
			if a.Mode == "audit_apk" {
				r.AuditReport = r.Result
				r.Result = json.RawMessage(`{"mode":"audit_apk","note":"Whole-APK report saved separately; inspect audit_report."}`)
			}
		}
		if e := m.persist(r); e != nil {
			r.Status = "failed"
			r.Error = "Analysis finished but result could not be saved"
			r.AuditReport = previousReport
		}
		if a.Mode == "audit_apk" {
			if r.Status == "failed" {
				os.Remove(filepath.Join(m.cfg.Root, r.ID, "audit-source-"+runID+".jsonl"))
			} else {
				var old struct {
					RunID string `json:"run_id"`
				}
				if json.Unmarshal(previousReport, &old) == nil && validID.MatchString(old.RunID) && old.RunID != runID {
					os.Remove(filepath.Join(m.cfg.Root, r.ID, "audit-source-"+old.RunID+".jsonl"))
				}
			}
		}
	}()
}
