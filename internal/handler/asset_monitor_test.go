package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/assetmonitor"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	assetMonitorAllowedProject = "project-allowed"
	assetMonitorForeignProject = "project-foreign"
	assetMonitorAllowedID      = "monitor-allowed"
	assetMonitorForeignID      = "monitor-foreign"
)

type fakeAssetMonitorService struct {
	monitors []assetmonitor.Monitor

	createCalls        int
	listCalls          int
	getCalls           int
	updateCalls        int
	deleteCalls        int
	triggerCalls       int
	listRunsCalls      int
	getRunCalls        int
	listRunAssetsCalls int
	lastListProjectID  string
}

func (f *fakeAssetMonitorService) CreateMonitor(_ context.Context, input assetmonitor.CreateMonitorInput) (assetmonitor.Monitor, error) {
	f.createCalls++
	return assetmonitor.Monitor{ID: "created", ProjectID: input.ProjectID, OwnerUserID: input.OwnerUserID}, nil
}

func (f *fakeAssetMonitorService) ListMonitors(_ context.Context, projectID string) ([]assetmonitor.Monitor, error) {
	f.listCalls++
	f.lastListProjectID = projectID
	if projectID == "" {
		return append([]assetmonitor.Monitor(nil), f.monitors...), nil
	}
	items := make([]assetmonitor.Monitor, 0, len(f.monitors))
	for _, monitor := range f.monitors {
		if monitor.ProjectID == projectID {
			items = append(items, monitor)
		}
	}
	return items, nil
}

func (f *fakeAssetMonitorService) GetMonitor(_ context.Context, projectID, monitorID string) (assetmonitor.Monitor, error) {
	f.getCalls++
	for _, monitor := range f.monitors {
		if monitor.ID == monitorID && (projectID == "" || monitor.ProjectID == projectID) {
			return monitor, nil
		}
	}
	return assetmonitor.Monitor{}, assetmonitor.ErrNotFound
}

func (f *fakeAssetMonitorService) UpdateMonitor(_ context.Context, _, _ string, _ assetmonitor.UpdateMonitorInput) (assetmonitor.Monitor, error) {
	f.updateCalls++
	return assetmonitor.Monitor{}, nil
}

func (f *fakeAssetMonitorService) DeleteMonitor(_ context.Context, _, _ string) error {
	f.deleteCalls++
	return nil
}

func (f *fakeAssetMonitorService) Trigger(_ context.Context, _, _, _ string) (assetmonitor.Run, error) {
	f.triggerCalls++
	return assetmonitor.Run{ID: "run-created"}, nil
}

func (f *fakeAssetMonitorService) ListRuns(_ context.Context, _, _ string, _ assetmonitor.RunListOptions) (assetmonitor.RunListResult, error) {
	f.listRunsCalls++
	return assetmonitor.RunListResult{}, nil
}

func (f *fakeAssetMonitorService) GetRun(_ context.Context, _, _, _ string) (assetmonitor.Run, error) {
	f.getRunCalls++
	return assetmonitor.Run{}, nil
}

func (f *fakeAssetMonitorService) ListRunAssets(_ context.Context, _, _, _ string, _ assetmonitor.RunAssetListOptions) (assetmonitor.RunAssetListResult, error) {
	f.listRunAssetsCalls++
	return assetmonitor.RunAssetListResult{}, nil
}

func (f *fakeAssetMonitorService) downstreamCalls() int {
	return f.createCalls + f.listCalls + f.updateCalls + f.deleteCalls + f.triggerCalls + f.listRunsCalls + f.getRunCalls + f.listRunAssetsCalls
}

type fakeAssetMonitorProjectStore struct {
	accessible map[string]bool
	projects   map[string]*database.Project
	scopes     []string
}

func (f *fakeAssetMonitorProjectStore) UserCanAccessResource(userID, scope, resourceType, resourceID string) bool {
	f.scopes = append(f.scopes, scope)
	if userID != "operator" || resourceType != "project" {
		return false
	}
	// An all-scoped lookup intentionally sees both projects. Tests with a broad
	// session scope therefore fail if the handler ignores project:read/write's
	// narrower permission-specific scope.
	if scope == database.RBACScopeAll {
		return true
	}
	return f.accessible[resourceID]
}

func (f *fakeAssetMonitorProjectStore) GetProject(id string) (*database.Project, error) {
	project, ok := f.projects[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	copy := *project
	return &copy, nil
}

func newAssetMonitorTestHandler(service *fakeAssetMonitorService, projects *fakeAssetMonitorProjectStore) *AssetMonitorHandler {
	return &AssetMonitorHandler{service: service, db: projects, logger: zap.NewNop()}
}

func assetMonitorTestSession() security.Session {
	return security.Session{
		UserID:   "operator",
		Username: "operator",
		// Scope models the broader permission that admitted the route. Project
		// access must still use the narrower per-permission scopes below.
		Scope: database.RBACScopeAll,
		Permissions: map[string]bool{
			"asset:read": true, "asset:write": true, "asset:delete": true,
			"project:read": true, "project:write": true, "fofa:execute": true,
		},
		PermissionScopes: map[string]string{
			"project:read":  database.RBACScopeAssigned,
			"project:write": database.RBACScopeAssigned,
		},
	}
}

func newAssetMonitorTestRouter(handler *AssetMonitorHandler, session security.Session) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, session)
		c.Next()
	})
	router.GET("/api/asset-monitors", handler.List)
	router.POST("/api/asset-monitors", handler.Create)
	router.GET("/api/asset-monitors/:id", handler.Get)
	router.PATCH("/api/asset-monitors/:id", handler.Update)
	router.DELETE("/api/asset-monitors/:id", handler.Delete)
	router.POST("/api/asset-monitors/:id/run", handler.Run)
	router.GET("/api/asset-monitors/:id/runs", handler.Runs)
	router.GET("/api/asset-monitors/:id/runs/:runId/assets", handler.RunAssets)
	return router
}

func newAssetMonitorTestFixtures() (*fakeAssetMonitorService, *fakeAssetMonitorProjectStore) {
	service := &fakeAssetMonitorService{monitors: []assetmonitor.Monitor{
		{ID: assetMonitorAllowedID, ProjectID: assetMonitorAllowedProject, Name: "allowed-monitor", RootDomain: "allowed.example.com"},
		{ID: assetMonitorForeignID, ProjectID: assetMonitorForeignProject, Name: "foreign-monitor-secret", RootDomain: "foreign-secret.example.com"},
	}}
	projects := &fakeAssetMonitorProjectStore{
		accessible: map[string]bool{assetMonitorAllowedProject: true},
		projects: map[string]*database.Project{
			assetMonitorAllowedProject: {ID: assetMonitorAllowedProject, Name: "Allowed"},
			assetMonitorForeignProject: {ID: assetMonitorForeignProject, Name: "Foreign"},
		},
	}
	return service, projects
}

func TestAssetMonitorForeignProjectRequestsAreDeniedBeforeServiceAction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "get", method: http.MethodGet, path: "/api/asset-monitors/" + assetMonitorForeignID},
		{name: "patch", method: http.MethodPatch, path: "/api/asset-monitors/" + assetMonitorForeignID, body: `{"name":"changed"}`},
		{name: "delete", method: http.MethodDelete, path: "/api/asset-monitors/" + assetMonitorForeignID},
		{name: "run", method: http.MethodPost, path: "/api/asset-monitors/" + assetMonitorForeignID + "/run"},
		{name: "runs", method: http.MethodGet, path: "/api/asset-monitors/" + assetMonitorForeignID + "/runs"},
		{name: "run assets", method: http.MethodGet, path: "/api/asset-monitors/" + assetMonitorForeignID + "/runs/run-foreign/assets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, projects := newAssetMonitorTestFixtures()
			router := newAssetMonitorTestRouter(newAssetMonitorTestHandler(service, projects), assetMonitorTestSession())
			request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusForbidden, response.Body.String())
			}
			if service.getCalls != 1 {
				t.Fatalf("monitor lookup calls = %d, want 1", service.getCalls)
			}
			if calls := service.downstreamCalls(); calls != 0 {
				t.Fatalf("unauthorized request reached a downstream service method: %d calls", calls)
			}
			if strings.Contains(response.Body.String(), "foreign-monitor-secret") || strings.Contains(response.Body.String(), "foreign-secret.example.com") {
				t.Fatalf("foreign monitor details leaked in denial: %s", response.Body.String())
			}
			if len(projects.scopes) != 1 || projects.scopes[0] != database.RBACScopeAssigned {
				t.Fatalf("project access scopes = %#v, want assigned", projects.scopes)
			}
		})
	}
}

func TestAssetMonitorCreateRejectsInaccessibleProjectBeforeService(t *testing.T) {
	service, projects := newAssetMonitorTestFixtures()
	router := newAssetMonitorTestRouter(newAssetMonitorTestHandler(service, projects), assetMonitorTestSession())
	body := []byte(`{"project_id":"project-foreign","name":"blocked","root_domain":"example.com"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/asset-monitors", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusForbidden, response.Body.String())
	}
	if service.createCalls != 0 || service.downstreamCalls() != 0 || service.getCalls != 0 {
		t.Fatalf("inaccessible create reached service: %#v", service)
	}
	if len(projects.scopes) != 1 || projects.scopes[0] != database.RBACScopeAssigned {
		t.Fatalf("project write scope = %#v, want assigned", projects.scopes)
	}
}

func TestAssetMonitorListFiltersProjectsUsingProjectReadScope(t *testing.T) {
	service, projects := newAssetMonitorTestFixtures()
	router := newAssetMonitorTestRouter(newAssetMonitorTestHandler(service, projects), assetMonitorTestSession())
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/asset-monitors", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var payload struct {
		Items []assetmonitor.Monitor `json:"items"`
		Total int                    `json:"total"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Total != 1 || len(payload.Items) != 1 || payload.Items[0].ID != assetMonitorAllowedID {
		t.Fatalf("filtered response = %#v, want only %s", payload, assetMonitorAllowedID)
	}
	if service.listCalls != 1 || service.lastListProjectID != "" {
		t.Fatalf("list calls/project = %d/%q, want 1/empty", service.listCalls, service.lastListProjectID)
	}
	if strings.Contains(response.Body.String(), "foreign-monitor-secret") || strings.Contains(response.Body.String(), "foreign-secret.example.com") {
		t.Fatalf("foreign monitor leaked in list: %s", response.Body.String())
	}
	if len(projects.scopes) != 2 {
		t.Fatalf("project access checks = %d, want 2", len(projects.scopes))
	}
	for _, scope := range projects.scopes {
		if scope != database.RBACScopeAssigned {
			t.Fatalf("project read scope = %q, want assigned", scope)
		}
	}
}

func TestAssetMonitorListRejectsExplicitInaccessibleProjectBeforeService(t *testing.T) {
	service, projects := newAssetMonitorTestFixtures()
	router := newAssetMonitorTestRouter(newAssetMonitorTestHandler(service, projects), assetMonitorTestSession())
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/asset-monitors?project_id="+assetMonitorForeignProject, nil))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusForbidden, response.Body.String())
	}
	if service.listCalls != 0 || service.downstreamCalls() != 0 || service.getCalls != 0 {
		t.Fatalf("inaccessible project filter reached service: %#v", service)
	}
	if len(projects.scopes) != 1 || projects.scopes[0] != database.RBACScopeAssigned {
		t.Fatalf("project read scope = %#v, want assigned", projects.scopes)
	}
}
