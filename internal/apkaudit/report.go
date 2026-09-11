package apkaudit

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Snapshot the owned report. Never accept a source path or run ID from the client.
func (m *Manager) reportFile(c *gin.Context) (*Record, *os.File) {
	user := m.authorized(c)
	if user == "" {
		return nil, nil
	}
	m.mu.Lock()
	r := m.records[c.Param("id")]
	if r != nil && r.Owner == user {
		r = clone(r)
	} else {
		r = nil
	}
	m.mu.Unlock()
	if r == nil {
		c.JSON(404, gin.H{"error": "Case not found"})
		return nil, nil
	}
	var report struct {
		RunID string `json:"run_id"`
	}
	if json.Unmarshal(r.AuditReport, &report) != nil || !validID.MatchString(report.RunID) {
		c.JSON(409, gin.H{"error": "Run a whole-APK audit first"})
		return nil, nil
	}
	f, err := os.Open(filepath.Join(m.cfg.Root, r.ID, "audit-source-"+report.RunID+".jsonl"))
	if err != nil {
		c.JSON(409, gin.H{"error": "Audit source bundle unavailable; rerun audit"})
		return nil, nil
	}
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 64<<20 {
		f.Close()
		c.JSON(409, gin.H{"error": "Invalid audit source bundle"})
		return nil, nil
	}
	c.Header("Cache-Control", "no-store")
	return r, f
}

func (m *Manager) auditSource(c *gin.Context) {
	offset, err := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err != nil || offset < 0 || offset > 1000000 {
		c.JSON(400, gin.H{"error": "Invalid source offset"})
		return
	}
	r, f := m.reportFile(c)
	if f == nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	chunks := []json.RawMessage{}
	index, size := 0, 0
	more := false
	for scanner.Scan() {
		if index < offset {
			index++
			continue
		}
		line := scanner.Bytes()
		if len(chunks) > 0 && (size+len(line) > 60000 || len(chunks) >= 200) {
			more = true
			break
		}
		if !json.Valid(line) {
			c.JSON(500, gin.H{"error": "Corrupt source bundle"})
			return
		}
		chunks = append(chunks, append(json.RawMessage{}, line...))
		size += len(line)
		index++
	}
	if scanner.Err() != nil {
		c.JSON(500, gin.H{"error": "Unable to read source bundle"})
		return
	}
	c.JSON(200, gin.H{"case_id": r.ID, "offset": offset, "next_offset": index, "has_more": more, "chunks": chunks})
}

func (m *Manager) exportAudit(c *gin.Context) {
	r, f := m.reportFile(c)
	if f == nil {
		return
	}
	defer f.Close()
	// Export the entire report and all retained source, not just visible findings.
	c.Header("Content-Disposition", `attachment; filename="apk-audit-`+r.ID+`.zip"`)
	c.Header("Content-Type", "application/zip")
	z := zip.NewWriter(c.Writer)
	report, err := z.Create("report.json")
	if err != nil {
		c.Error(err)
		return
	}
	payload := struct {
		Name   string          `json:"name"`
		SHA256 string          `json:"sha256"`
		Audit  json.RawMessage `json:"audit_report"`
	}{r.Name, r.SHA256, r.AuditReport}
	if err = json.NewEncoder(report).Encode(payload); err != nil {
		c.Error(err)
		return
	}
	source, err := z.Create("decompiled-source.jsonl")
	if err != nil {
		c.Error(err)
		return
	}
	if _, err = io.Copy(source, f); err != nil {
		c.Error(err)
		return
	}
	if err = z.Close(); err != nil {
		c.Error(err)
	}
}
