package handler

import (
	"context"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/skilllibrary"
	"cyberstrike-ai/internal/testutil/testpostgres"
	"database/sql"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSkillLibraryPermissionsAndRealRoutes(t *testing.T) {
	db, err := sql.Open("pgx", testpostgres.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE EXTENSION vector`); err != nil {
		t.Fatal(err)
	}
	store, err := skilllibrary.NewStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "sample.py"), []byte("# reference only"), 0600)
	embeddings := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := make([]float32, 1024)
		v[0] = 1
		json.NewEncoder(w).Encode(map[string]any{"embeddings": [][]float32{v}})
	}))
	defer embeddings.Close()
	embed, err := skilllibrary.NewLocalEmbedder(embeddings.URL, "fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	service := skilllibrary.NewService(store, embed, []skilllibrary.Source{{Name: "pocs", Path: root, Kind: "poc"}}, zap.NewNop())
	defer service.Close()
	if err = service.Trigger(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, e := service.Status(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if !status.Running {
			if status.Ready != 1 {
				t.Fatalf("index %+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("index timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	items, err := service.Search(context.Background(), skilllibrary.Search{Review: "all", Page: 1})
	if err != nil || len(items.Items) != 1 {
		t.Fatalf("items %v", err)
	}
	id := items.Items[0].ID
	h := NewSkillLibraryHandler(service, zap.NewNop())
	session := security.Session{UserID: "test-admin", Scope: database.RBACScopeAll, Permissions: map[string]bool{"skills:read": true, "skills:write": true}}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if c.GetHeader("X-Test-Auth") != "none" {
			c.Set(security.ContextSessionKey, session)
		}
		c.Next()
	})
	r.GET("/status", h.Status)
	r.GET("/search", h.Search)
	r.GET("/documents/:id", h.Detail)
	r.PUT("/documents/:id", h.Edit)
	r.POST("/index", h.Index)
	r.POST("/links", h.Link)
	call := func(method, path, body, auth string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Test-Auth", auth)
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := call("GET", "/status", "", "none"); code != 401 {
		t.Fatal("missing auth", code)
	}
	session.Scope = database.RBACScopeOwn
	if code := call("GET", "/status", "", ""); code != 403 {
		t.Fatal("own scope exposed shared files", code)
	}
	session.Scope = database.RBACScopeAll
	session.PermissionScopes = map[string]string{"skills:read": database.RBACScopeOwn, "skills:write": database.RBACScopeAll}
	if code := call("POST", "/index", `{}`, ""); code != 403 {
		t.Fatal("global write bypassed limited read scope", code)
	}
	session.PermissionScopes = nil
	if code := call("GET", "/documents/"+id, "", ""); code != 200 {
		t.Fatal("detail", code)
	}
	if code := call("GET", "/search?page=-1", "", ""); code != 400 {
		t.Fatal("page validation", code)
	}
	session.Permissions["skills:write"] = false
	if code := call("POST", "/index", `{}`, ""); code != 403 {
		t.Fatal("read could index", code)
	}
	session.Permissions["skills:write"] = true
	if code := call("POST", "/links", `{"user_id":"other","skill_id":"x","resource_id":"y"}`, ""); code != 400 {
		t.Fatal("unknown fields accepted", code)
	}
	if code := call("POST", "/index", `{} {}`, ""); code != 400 {
		t.Fatal("trailing JSON accepted", code)
	}
	d, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(skilllibrary.Edit{Title: "Reviewed source", Kind: "poc", Review: "reviewed", Metadata: d.Metadata, Revision: d.Revision})
	if code := call("PUT", "/documents/"+id, string(body), ""); code != 200 {
		t.Fatal("metadata save", code)
	}
	if code := call("PUT", "/documents/"+id, string(body), ""); code != 409 {
		t.Fatal("stale revision", code)
	}
	os.WriteFile(filepath.Join(root, "sample.py"), []byte("# changed original"), 0600)
	d, _ = store.Get(context.Background(), id)
	body, _ = json.Marshal(skilllibrary.Edit{Title: d.Title, Kind: d.Kind, Review: "reviewed", Metadata: d.Metadata, Revision: d.Revision})
	if code := call("PUT", "/documents/"+id, string(body), ""); code != 409 {
		t.Fatal("changed original approved", code)
	}
}

func TestSkillsRejectTraversalBeforeDiskMutation(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "skills")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "canary")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	h := NewSkillsHandler(&config.Config{SkillsDir: root}, filepath.Join(base, "config.yaml"), zap.NewNop())
	r := gin.New()
	r.DELETE("/skills/:name", h.DeleteSkill)
	r.PUT("/skills/:name", h.UpdateSkill)
	r.GET("/skills/:name", h.GetSkill)
	for _, name := range []string{"..", ".", "..\\canary", "../canary", "C:\\canary", "%2e%2e", "bad/name"} {
		for _, method := range []string{http.MethodDelete, http.MethodPut, http.MethodGet} {
			req := httptest.NewRequest(method, "/skills/"+url.PathEscape(name), strings.NewReader(`{"content":"changed"}`))
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			r.ServeHTTP(response, req)
			if response.Code != http.StatusBadRequest && response.Code != http.StatusNotFound {
				t.Fatalf("%s %q: got %d", method, name, response.Code)
			}
		}
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "keep" {
		t.Fatalf("outside canary changed: %v", err)
	}
}

func TestSkillsCreateReadUpdateDelete(t *testing.T) {
	base := t.TempDir()
	h := NewSkillsHandler(&config.Config{SkillsDir: filepath.Join(base, "skills")}, filepath.Join(base, "config.yaml"), zap.NewNop())
	r := gin.New()
	r.POST("/skills", h.CreateSkill)
	r.GET("/skills/:name", h.GetSkill)
	r.PUT("/skills/:name", h.UpdateSkill)
	r.DELETE("/skills/:name", h.DeleteSkill)
	for _, tc := range []struct {
		method, path, body string
		code               int
	}{
		{"POST", "/skills", `{"name":"sample","description":"test","content":"original"}`, 200},
		{"POST", "/skills", `{"name":"sample","description":"test","content":"duplicate"}`, 400},
		{"GET", "/skills/sample", "", 200},
		{"PUT", "/skills/sample", `{"content":"updated"}`, 200},
		{"DELETE", "/skills/sample", "", 200},
		{"DELETE", "/skills/sample", "", 404},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		r.ServeHTTP(response, req)
		if response.Code != tc.code {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, response.Code, response.Body.String())
		}
	}
}
