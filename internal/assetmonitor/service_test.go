package assetmonitor

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"
)

type serviceTestStore struct {
	mu           sync.Mutex
	monitor      Monitor
	run          Run
	observations []Observation
	finished     []Run
	due          []Monitor
	nextDue      time.Time
}

func (s *serviceTestStore) createMonitor(_ context.Context, monitor Monitor) (Monitor, error) {
	s.monitor = monitor
	return monitor, nil
}
func (s *serviceTestStore) listMonitors(context.Context, string) ([]Monitor, error) {
	return []Monitor{s.monitor}, nil
}
func (s *serviceTestStore) getMonitor(_ context.Context, projectID, monitorID string) (Monitor, error) {
	if s.monitor.ID != monitorID || (projectID != "" && s.monitor.ProjectID != projectID) {
		return Monitor{}, ErrNotFound
	}
	return s.monitor, nil
}
func (s *serviceTestStore) replaceMonitor(_ context.Context, _ string, monitor Monitor, _ bool) (Monitor, error) {
	s.monitor = monitor
	return monitor, nil
}
func (s *serviceTestStore) deleteMonitor(context.Context, string, string) error { return nil }
func (s *serviceTestStore) monitorBusy(context.Context, string) (bool, error)   { return false, nil }
func (s *serviceTestStore) enqueueRun(_ context.Context, monitor Monitor, trigger, actor string) (Run, error) {
	s.run = Run{ID: "run-1", MonitorID: monitor.ID, ProjectID: monitor.ProjectID, Trigger: trigger, TriggeredBy: actor, Status: RunStatusQueued}
	return s.run, nil
}
func (s *serviceTestStore) listDueMonitors(context.Context, time.Time, int) ([]Monitor, error) {
	return append([]Monitor(nil), s.due...), nil
}
func (s *serviceTestStore) enqueueDueRun(_ context.Context, _ Monitor, _, next time.Time) (bool, error) {
	s.nextDue = next
	return true, nil
}
func (s *serviceTestStore) claimNextRun(context.Context, time.Time) (Run, Monitor, error) {
	return Run{}, Monitor{}, sql.ErrNoRows
}
func (s *serviceTestStore) finishRun(_ context.Context, run Run) error {
	s.finished = append(s.finished, run)
	return nil
}
func (s *serviceTestStore) reconcileStaleRuns(context.Context, time.Time) error { return nil }
func (s *serviceTestStore) listRuns(context.Context, string, string, RunListOptions) (RunListResult, error) {
	return RunListResult{}, nil
}
func (s *serviceTestStore) getRun(context.Context, string, string, string) (Run, error) {
	return s.run, nil
}
func (s *serviceTestStore) persistObservations(_ context.Context, _ Monitor, _ Run, observations []Observation, _ time.Time) (persistenceResult, error) {
	s.mu.Lock()
	s.observations = append([]Observation(nil), observations...)
	s.mu.Unlock()
	return persistenceResult{Seen: len(observations), New: len(observations), Created: len(observations)}, nil
}
func (s *serviceTestStore) listRunAssets(context.Context, string, string, string, RunAssetListOptions) (RunAssetListResult, error) {
	return RunAssetListResult{}, nil
}

type serviceTestProvider struct {
	configured bool
	page       SearchPage
	err        error
}

func (p *serviceTestProvider) Name() string     { return ProviderQuake }
func (p *serviceTestProvider) Configured() bool { return p.configured }
func (p *serviceTestProvider) Search(context.Context, SearchRequest) (SearchPage, error) {
	return p.page, p.err
}

func TestServiceCreateDefaultsAndValidatesLimits(t *testing.T) {
	store := &serviceTestStore{}
	service := newService(store, nil, nil, nil)
	fixed := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return fixed }
	monitor, err := service.CreateMonitor(context.Background(), CreateMonitorInput{
		ProjectID: "project-1", OwnerUserID: "user-1", RootDomain: "KUAISHOU.COM.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if monitor.RootDomain != "kuaishou.com" || monitor.Query != `domain:"kuaishou.com"` ||
		monitor.IntervalMinutes != DefaultIntervalMinutes || monitor.MaxResults != DefaultMaxResults || !monitor.Enabled {
		t.Fatalf("default monitor = %+v", monitor)
	}
	if monitor.NextRunAt == nil || !monitor.NextRunAt.Equal(fixed.Add(DefaultIntervalMinutes*time.Minute)) {
		t.Fatalf("next run = %v", monitor.NextRunAt)
	}
	_, err = service.CreateMonitor(context.Background(), CreateMonitorInput{
		ProjectID: "project-1", OwnerUserID: "user-1", RootDomain: "example.com", IntervalMinutes: 59,
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("short interval error = %v", err)
	}
}

func TestServiceTriggerReturnsQueuedRunAndRejectsUnconfigured(t *testing.T) {
	store := &serviceTestStore{monitor: Monitor{ID: "monitor-1", ProjectID: "project-1", Provider: ProviderQuake}}
	provider := &serviceTestProvider{}
	service := newService(store, nil, provider, nil)
	service.started = true
	service.ctx = context.Background()
	if _, err := service.Trigger(context.Background(), "", "monitor-1", "user-2"); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("unconfigured Trigger() error = %v", err)
	}
	provider.configured = true
	run, err := service.Trigger(context.Background(), "", "monitor-1", "user-2")
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == "" || run.Status != RunStatusQueued || run.ProjectID != "project-1" || run.TriggeredBy != "user-2" {
		t.Fatalf("queued run = %+v", run)
	}
}

func TestSearchAndPersistRevalidatesScopeDeduplicatesAndCapsResults(t *testing.T) {
	store := &serviceTestStore{}
	provider := &serviceTestProvider{configured: true, page: SearchPage{
		RawCount: 5,
		Observations: []Observation{
			{Domain: "api.example.com", Port: 443},
			{Domain: "notexample.com", Port: 443},
			{IP: "1.2.3.4", Port: 443},
			{Domain: "api.example.com", Port: 443},
			{Domain: "cdn.example.com", Port: 443},
			{Domain: "third.example.com", Port: 443},
		},
	}}
	service := newService(store, nil, provider, nil)
	monitor := Monitor{ID: "m", ProjectID: "p", RootDomain: "example.com", Query: generatedQuery("example.com"), MaxResults: 2}
	status := RunStatusSuccess
	var runErr error
	run := service.searchAndPersist(context.Background(), provider, monitor, Run{ID: "r"}, &status, &runErr)
	if runErr != nil {
		t.Fatal(runErr)
	}
	if status != RunStatusPartial || run.SeenCount != 2 || run.NewCount != 2 || run.CreatedCount != 2 {
		t.Fatalf("run/status = %+v / %s", run, status)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.observations) != 2 {
		t.Fatalf("persisted observations = %+v", store.observations)
	}
	for _, observation := range store.observations {
		if !withinRoot(observation.Domain, "example.com") {
			t.Fatalf("out-of-scope observation persisted: %+v", observation)
		}
	}
}

func TestNextIntervalRunAdvancesFromPreviousAndCoalescesMissedTicks(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 35, 0, 0, time.UTC)
	previous := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	got := nextIntervalRun(&previous, now, 60)
	want := time.Date(2026, 9, 4, 13, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("nextIntervalRun() = %v, want %v", got, want)
	}
}
