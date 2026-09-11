package apkaudit

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testRouter(t *testing.T) (*Manager, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	base := os.Getenv("APK_TEST_BASE")
	cfg := Config{Root: t.TempDir(), Timeout: 20 * time.Second}
	if base != "" {
		cfg.Python = filepath.Join(base, "venv", "Scripts", "python.exe")
		cfg.Worker = filepath.Join(base, "platform", "scripts", "apk_audit", "worker.py")
		cfg.ASCRoot = filepath.Join(base, "ASC")
	}
	m, e := New(cfg, func(c *gin.Context) string { return c.GetHeader("X-Test-User") })
	if e != nil {
		t.Fatal(e)
	}
	r := gin.New()
	m.Register(r.Group("/api/apk-audit"))
	return m, r
}
func req(r *gin.Engine, method, path, user, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	q := httptest.NewRequest(method, "/api/apk-audit"+path, strings.NewReader(body))
	q.Header.Set("X-Test-User", user)
	q.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, q)
	return w
}
func uploadTest(r *gin.Engine, name string, data []byte) *httptest.ResponseRecorder {
	var b bytes.Buffer
	mp := multipart.NewWriter(&b)
	f, _ := mp.CreateFormFile("file", name)
	f.Write(data)
	mp.Close()
	q := httptest.NewRequest("POST", "/api/apk-audit/cases", &b)
	q.Header.Set("Content-Type", mp.FormDataContentType())
	q.Header.Set("X-Test-User", "alice")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	return w
}
func waitRecord(t *testing.T, r *gin.Engine, id string) Record {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		w := req(r, "GET", "/cases/"+id, "alice", "")
		var record Record
		if json.Unmarshal(w.Body.Bytes(), &record) != nil {
			t.Fatal(w.Body.String())
		}
		if record.Status != "running" {
			return record
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timeout waiting for worker")
	return Record{}
}
func TestAuthAndOwnership(t *testing.T) {
	m, r := testRouter(t)
	if w := req(r, "GET", "/cases", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	i := id()
	m.records[i] = &Record{ID: i, Owner: "alice", Name: "private.apk"}
	for _, p := range []string{"/cases/" + i, "/cases/" + i + "/cancel"} {
		method := "GET"
		if strings.HasSuffix(p, "cancel") {
			method = "POST"
		}
		if w := req(r, method, p, "bob", "{}"); w.Code != 404 {
			t.Fatal(w.Code)
		}
	}
	w := req(r, "GET", "/cases", "bob", "")
	if strings.Contains(w.Body.String(), "private.apk") {
		t.Fatal("cross-user leak")
	}
	if w := req(r, "GET", "/cases/../../config.local.yaml", "alice", ""); w.Code == 200 {
		t.Fatal("path traversal")
	}
}
func TestValidationAndLimits(t *testing.T) {
	_, r := testRouter(t)
	if w := req(r, "POST", "/cases/no/actions", "alice", `{"mode":"shell","query":"calc"}`); w.Code != 400 {
		t.Fatal(w.Code)
	}
	b := limitedBuffer{limit: 4}
	n, e := b.Write([]byte("secret-long"))
	if n != 11 || e != nil || string(b.data) != "secr" || !b.exceeded {
		t.Fatal("output cap")
	}
	for _, a := range []Action{{Mode: "refs", Kind: "bad", Query: "x"}, {Mode: "audit", Query: strings.Repeat("x", 257)}, {Mode: "inspect", Query: "x"}} {
		if validateAction(a) {
			t.Fatal(a)
		}
	}
}
func TestEngineLifecycle(t *testing.T) {
	base := os.Getenv("APK_TEST_BASE")
	if base == "" {
		t.Skip("set APK_TEST_BASE for real isolated-engine integration")
	}
	m, r := testRouter(t)
	data, e := os.ReadFile(filepath.Join(base, "fixtures", "sample.apk"))
	if e != nil {
		t.Fatal(e)
	}
	if w := uploadTest(r, "bad.exe", data); w.Code != 400 {
		t.Fatal(w.Code)
	}
	w := uploadTest(r, "<script>.apk", data)
	if w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	var record Record
	json.Unmarshal(w.Body.Bytes(), &record)
	record = waitRecord(t, r, record.ID)
	if record.Status != "completed" || !bytes.Contains(record.Inspection, []byte("Laudit/Sample;")) {
		t.Fatal(record.Error)
	}
	for _, mode := range []string{"refs", "decompile", "disassemble"} {
		q := "audit.Sample"
		if mode == "refs" {
			q = "audit-marker"
		}
		body, _ := json.Marshal(Action{Mode: mode, Query: q, Kind: "string"})
		w = req(r, "POST", "/cases/"+record.ID+"/actions", "alice", string(body))
		if w.Code != 202 {
			t.Fatal(w.Body.String())
		}
		record = waitRecord(t, r, record.ID)
		if record.Status != "completed" || !bytes.Contains(record.Result, []byte("audit-marker")) {
			t.Fatalf("%s: %s", mode, record.Error)
		}
	}
	w = req(r, "POST", "/cases/"+record.ID+"/actions", "alice", `{"mode":"audit_apk"}`)
	if w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	record = waitRecord(t, r, record.ID)
	if record.Status != "completed" || !bytes.Contains(record.AuditReport, []byte(`"methods_audited":1`)) {
		t.Fatal(record.Error, string(record.AuditReport))
	}
	for _, suffix := range []string{"/audit-source", "/export"} {
		if w = req(r, "GET", "/cases/"+record.ID+suffix, "bob", ""); w.Code != 404 {
			t.Fatal("source ownership", w.Code)
		}
	}
	w = req(r, "GET", "/cases/"+record.ID+"/audit-source", "alice", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "audit-marker") {
		t.Fatal(w.Body.String())
	}
	w = req(r, "GET", "/cases/"+record.ID+"/export", "alice", "")
	z, e := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if e != nil || len(z.File) != 2 {
		t.Fatal("export", e)
	}
	for _, entry := range z.File {
		reader, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name == "report.json" && (!json.Valid(content) || !bytes.Contains(content, []byte("audit_report"))) {
			t.Fatal("invalid exported report")
		}
		if entry.Name == "decompiled-source.jsonl" && !bytes.Contains(content, []byte("audit-marker")) {
			t.Fatal("export lost source")
		}
	}
	oldReport := append([]byte{}, record.AuditReport...)
	w = req(r, "POST", "/cases/"+record.ID+"/actions", "alice", `{"mode":"decompile","query":"audit.Sample"}`)
	if w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	record = waitRecord(t, r, record.ID)
	if !bytes.Equal(oldReport, record.AuditReport) {
		t.Fatal("class browsing overwrote whole report")
	}
	m2, e := New(m.cfg, m.identity)
	if e != nil {
		t.Fatal(e)
	}
	if m2.records[record.ID].Owner != "alice" {
		t.Fatal("owner not persisted")
	}
	if !bytes.Equal(m2.records[record.ID].AuditReport, oldReport) {
		t.Fatal("whole report not persisted")
	}
	if w = req(r, "GET", "/cases", "alice", ""); strings.Contains(w.Body.String(), "audit_report") {
		t.Fatal("list exposes heavy report")
	}
	if w = req(r, "GET", "/cases/"+record.ID, "alice", ""); strings.Contains(w.Body.String(), `"owner"`) {
		t.Fatal("owner exposed")
	}
	w = uploadTest(r, "corrupt.apk", []byte("PK-not-a-zip"))
	if w.Code != 202 {
		t.Fatal(w.Code)
	}
	json.Unmarshal(w.Body.Bytes(), &record)
	record = waitRecord(t, r, record.ID)
	if record.Status != "failed" {
		t.Fatal("bad input reported success")
	}
}
func TestCancelledProcessAndBusy(t *testing.T) {
	base := os.Getenv("APK_TEST_BASE")
	if base == "" {
		t.Skip("requires isolated Python")
	}
	m, r := testRouter(t)
	worker := filepath.Join(t.TempDir(), "wait.py")
	os.WriteFile(worker, []byte("import time\ntime.sleep(30)\n"), 0600)
	m.cfg.Worker = worker
	i := id()
	os.Mkdir(filepath.Join(m.cfg.Root, i), 0700)
	m.records[i] = &Record{ID: i, Owner: "alice", Status: "completed"}
	w := req(r, "POST", "/cases/"+i+"/actions", "alice", `{"mode":"inspect"}`)
	if w.Code != 202 {
		t.Fatal(w.Code)
	}
	if w = req(r, "POST", "/cases/"+i+"/actions", "alice", `{"mode":"inspect"}`); w.Code != 409 {
		t.Fatal(w.Code)
	}
	req(r, "POST", "/cases/"+i+"/cancel", "alice", "{}")
	record := waitRecord(t, r, i)
	if record.Status != "failed" || !strings.Contains(record.Error, "cancelled") {
		t.Fatal(record)
	}
	// The same sleeping worker must also be terminated without a cancel request.
	m.cfg.Timeout = 100 * time.Millisecond
	w = req(r, "POST", "/cases/"+i+"/actions", "alice", `{"mode":"inspect"}`)
	if w.Code != 202 {
		t.Fatal(w.Code)
	}
	record = waitRecord(t, r, i)
	if record.Status != "failed" || !strings.Contains(record.Error, "timed out") {
		t.Fatal("deadline did not terminate worker", record)
	}
	_, _ = io.Discard.Write(nil)
}

func TestSourcePaginationAndRunValidation(t *testing.T) {
	m, r := testRouter(t)
	i, runID := id(), id()
	os.Mkdir(filepath.Join(m.cfg.Root, i), 0700)
	report, _ := json.Marshal(map[string]string{"run_id": runID})
	m.records[i] = &Record{ID: i, Owner: "alice", AuditReport: report}
	var data bytes.Buffer
	for n := 0; n < 5; n++ {
		json.NewEncoder(&data).Encode(map[string]interface{}{"index": n, "source": strings.Repeat("a", 20000)})
	}
	os.WriteFile(filepath.Join(m.cfg.Root, i, "audit-source-"+runID+".jsonl"), data.Bytes(), 0600)
	offset := 0
	seen := 0
	for {
		w := req(r, "GET", "/cases/"+i+"/audit-source?offset="+strconv.Itoa(offset), "alice", "")
		var page struct {
			Chunks []struct {
				Index int `json:"index"`
			} `json:"chunks"`
			Next int  `json:"next_offset"`
			More bool `json:"has_more"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil {
			t.Fatal(w.Body.String())
		}
		for _, chunk := range page.Chunks {
			if chunk.Index != seen {
				t.Fatal("lost or duplicate source chunk")
			}
			seen++
		}
		if !page.More {
			break
		}
		if page.Next <= offset {
			t.Fatal("pagination stalled")
		}
		offset = page.Next
	}
	if seen != 5 {
		t.Fatal("incomplete source pagination", seen)
	}
	if w := req(r, "GET", "/cases/"+i+"/audit-source?offset=-1", "alice", ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	m.records[i].AuditReport = json.RawMessage(`{"run_id":"../../secret"}`)
	if w := req(r, "GET", "/cases/"+i+"/export", "alice", ""); w.Code != 409 {
		t.Fatal("unsafe run ID accepted")
	}
}
