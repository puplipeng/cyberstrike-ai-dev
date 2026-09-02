package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/githubleak"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type fakeGitHubLeakService struct {
	list       githubleak.ListResult
	runtime    githubleak.RuntimeStatus
	triggerErr error
	finding    githubleak.Finding
}

func (f *fakeGitHubLeakService) List(_ context.Context, _ githubleak.ListFilter) (githubleak.ListResult, error) {
	return f.list, nil
}
func (f *fakeGitHubLeakService) Get(_ context.Context, _ string) (githubleak.Finding, error) {
	if f.finding.ID == "" {
		return githubleak.Finding{}, githubleak.ErrNotFound
	}
	return f.finding, nil
}
func (f *fakeGitHubLeakService) Stats(context.Context) (githubleak.Stats, error) {
	return githubleak.Stats{Total: len(f.list.Items)}, nil
}
func (f *fakeGitHubLeakService) RuntimeStatus(context.Context) (githubleak.RuntimeStatus, error) {
	return f.runtime, nil
}
func (f *fakeGitHubLeakService) Trigger(context.Context) error { return f.triggerErr }
func (f *fakeGitHubLeakService) UpdateStatus(_ context.Context, id, status string) (githubleak.Finding, error) {
	if id == "" {
		return githubleak.Finding{}, githubleak.ErrNotFound
	}
	f.finding.ID, f.finding.Status = id, status
	return f.finding, nil
}

func newGitHubLeakTestRouter(service *fakeGitHubLeakService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	h := NewGitHubLeakHandler(service, zap.NewNop())
	router.GET("/findings", h.List)
	router.GET("/runtime", h.Runtime)
	router.POST("/run", h.Run)
	router.PATCH("/findings/:id/status", h.UpdateStatus)
	return router
}

func TestGitHubLeakHandlerRuntimeHasNoTokenField(t *testing.T) {
	router := newGitHubLeakTestRouter(&fakeGitHubLeakService{runtime: githubleak.RuntimeStatus{
		Configured: true, Keywords: []string{"storage-service"}, LastStatus: "partial", LastWarning: "coverage limited",
	}})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/runtime", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(strings.ToLower(recorder.Body.String()), "token") {
		t.Fatalf("runtime response exposed a token field: %s", recorder.Body.String())
	}
	var runtime githubleak.RuntimeStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.LastStatus != "partial" || runtime.LastWarning != "coverage limited" || runtime.LastError != "" {
		t.Fatalf("partial runtime classification lost at handler boundary: %+v", runtime)
	}
}

func TestGitHubLeakHandlerRejectsFastInvalidPagination(t *testing.T) {
	router := newGitHubLeakTestRouter(&fakeGitHubLeakService{})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/findings?page_size=101", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestGitHubLeakHandlerRunResponses(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{name: "accepted", want: http.StatusAccepted},
		{name: "busy", err: githubleak.ErrBusy, want: http.StatusConflict},
		{name: "unconfigured", err: githubleak.ErrUnconfigured, want: http.StatusBadRequest},
		{name: "unavailable", err: errors.New("offline"), want: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := newGitHubLeakTestRouter(&fakeGitHubLeakService{triggerErr: test.err})
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/run", nil))
			if recorder.Code != test.want {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestGitHubLeakHandlerUpdatesOnlyValidStatus(t *testing.T) {
	service := &fakeGitHubLeakService{}
	router := newGitHubLeakTestRouter(service)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/findings/finding-1/status", strings.NewReader(`{"status":"triaged"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var finding githubleak.Finding
	if err := json.Unmarshal(recorder.Body.Bytes(), &finding); err != nil {
		t.Fatal(err)
	}
	if finding.ID != "finding-1" || finding.Status != githubleak.StatusTriaged {
		t.Fatalf("unexpected finding: %+v", finding)
	}
}
