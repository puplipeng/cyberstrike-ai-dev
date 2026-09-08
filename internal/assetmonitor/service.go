package assetmonitor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

const (
	defaultSchedulerPoll = 15 * time.Second
	defaultRunTimeout    = 3 * time.Minute
	defaultStaleRunAfter = 15 * time.Minute
	providerPageSize     = 100
)

type persistence interface {
	createMonitor(context.Context, Monitor) (Monitor, error)
	listMonitors(context.Context, string) ([]Monitor, error)
	getMonitor(context.Context, string, string) (Monitor, error)
	replaceMonitor(context.Context, string, Monitor, bool) (Monitor, error)
	deleteMonitor(context.Context, string, string) error
	monitorBusy(context.Context, string) (bool, error)
	enqueueRun(context.Context, Monitor, string, string) (Run, error)
	listDueMonitors(context.Context, time.Time, int) ([]Monitor, error)
	enqueueDueRun(context.Context, Monitor, time.Time, time.Time) (bool, error)
	claimNextRun(context.Context, time.Time) (Run, Monitor, error)
	finishRun(context.Context, Run) error
	reconcileStaleRuns(context.Context, time.Time) error
	listRuns(context.Context, string, string, RunListOptions) (RunListResult, error)
	getRun(context.Context, string, string, string) (Run, error)
	persistObservations(context.Context, Monitor, Run, []Observation, time.Time) (persistenceResult, error)
	listRunAssets(context.Context, string, string, string, RunAssetListOptions) (RunAssetListResult, error)
}

type Service struct {
	store    persistence
	db       *database.DB
	provider Provider
	logger   *zap.Logger

	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	wake    chan struct{}
	wg      sync.WaitGroup
	started bool
	closed  bool

	pollInterval time.Duration
	runTimeout   time.Duration
	staleAfter   time.Duration
	now          func() time.Time
}

func NewService(store *Store, db *database.DB, provider Provider, logger *zap.Logger) (*Service, error) {
	if store == nil || store.db == nil {
		return nil, errors.New("asset monitor store is required")
	}
	if db == nil || db.DB == nil {
		return nil, errors.New("asset database is required")
	}
	return newService(store, db, provider, logger), nil
}

func newService(store persistence, db *database.DB, provider Provider, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{
		store: store, db: db, provider: provider, logger: logger, wake: make(chan struct{}, 1),
		pollInterval: defaultSchedulerPoll, runTimeout: defaultRunTimeout, staleAfter: defaultStaleRunAfter,
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Start(parent context.Context) {
	if parent == nil {
		parent = context.Background()
	}
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return
	}
	s.ctx, s.cancel = context.WithCancel(parent)
	s.started = true
	s.wg.Add(1)
	ctx := s.ctx
	s.mu.Unlock()
	go s.loop(ctx)
}

func (s *Service) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Service) CreateMonitor(ctx context.Context, input CreateMonitorInput) (Monitor, error) {
	monitor, err := s.normalizeCreate(input)
	if err != nil {
		return Monitor{}, err
	}
	created, err := s.store.createMonitor(ctx, monitor)
	return s.decorateMonitor(created), err
}

func (s *Service) ListMonitors(ctx context.Context, projectID string) ([]Monitor, error) {
	monitors, err := s.store.listMonitors(ctx, strings.TrimSpace(projectID))
	if err != nil {
		return nil, err
	}
	for index := range monitors {
		monitors[index] = s.decorateMonitor(monitors[index])
	}
	return monitors, nil
}

func (s *Service) GetMonitor(ctx context.Context, projectID, monitorID string) (Monitor, error) {
	if strings.TrimSpace(monitorID) == "" {
		return Monitor{}, ErrNotFound
	}
	monitor, err := s.store.getMonitor(ctx, strings.TrimSpace(projectID), strings.TrimSpace(monitorID))
	return s.decorateMonitor(monitor), err
}

func (s *Service) UpdateMonitor(ctx context.Context, projectID, monitorID string, input UpdateMonitorInput) (Monitor, error) {
	monitor, err := s.GetMonitor(ctx, projectID, monitorID)
	if err != nil {
		return Monitor{}, err
	}
	busy, err := s.store.monitorBusy(ctx, monitor.ID)
	if err != nil {
		return Monitor{}, err
	}
	if busy {
		return Monitor{}, ErrBusy
	}
	rootChanged := false
	reschedule := false
	if input.Name != nil {
		monitor.Name = cleanProviderText(*input.Name, 120)
		if monitor.Name == "" {
			return Monitor{}, validationErrorf("name is required")
		}
	}
	if input.RootDomain != nil {
		root, normalizeErr := NormalizeRootDomain(*input.RootDomain)
		if normalizeErr != nil {
			return Monitor{}, normalizeErr
		}
		rootChanged = root != monitor.RootDomain
		monitor.RootDomain = root
		monitor.Query = generatedQuery(root)
		reschedule = reschedule || rootChanged
	}
	if input.Provider != nil {
		provider := strings.ToLower(strings.TrimSpace(*input.Provider))
		if provider != ProviderQuake {
			return Monitor{}, validationErrorf("unsupported provider %q", provider)
		}
		monitor.Provider = provider
	}
	if input.CronExpr != nil {
		monitor.CronExpr = strings.TrimSpace(*input.CronExpr)
		if len(monitor.CronExpr) > 100 {
			return Monitor{}, validationErrorf("cron_expr is too long")
		}
	}
	if input.IntervalMinutes != nil {
		if err = validateInterval(*input.IntervalMinutes); err != nil {
			return Monitor{}, err
		}
		reschedule = reschedule || monitor.IntervalMinutes != *input.IntervalMinutes
		monitor.IntervalMinutes = *input.IntervalMinutes
	}
	if input.MaxResults != nil {
		if err = validateMaxResults(*input.MaxResults); err != nil {
			return Monitor{}, err
		}
		monitor.MaxResults = *input.MaxResults
	}
	if input.Enabled != nil {
		if monitor.Enabled != *input.Enabled {
			reschedule = true
		}
		monitor.Enabled = *input.Enabled
	}
	now := s.now().UTC()
	if !monitor.Enabled {
		monitor.NextRunAt = nil
		monitor.LastStatus = MonitorStatusDisabled
		monitor.LastError = ""
	} else if reschedule || monitor.NextRunAt == nil {
		next := now.Add(time.Duration(monitor.IntervalMinutes) * time.Minute)
		monitor.NextRunAt = &next
		monitor.LastStatus = MonitorStatusIdle
		monitor.LastError = ""
	}
	updated, err := s.store.replaceMonitor(ctx, strings.TrimSpace(projectID), monitor, rootChanged)
	return s.decorateMonitor(updated), err
}

// Configured reports whether the active provider can execute searches. It does
// not expose credentials and remains usable before Start.
func (s *Service) Configured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return providerConfigured(s.provider)
}

func (s *Service) decorateMonitor(monitor Monitor) Monitor {
	s.mu.Lock()
	provider := s.provider
	s.mu.Unlock()
	monitor.ProviderConfigured = provider != nil && provider.Name() == monitor.Provider && providerConfigured(provider)
	return monitor
}

func (s *Service) DeleteMonitor(ctx context.Context, projectID, monitorID string) error {
	if strings.TrimSpace(monitorID) == "" {
		return ErrNotFound
	}
	return s.store.deleteMonitor(ctx, strings.TrimSpace(projectID), strings.TrimSpace(monitorID))
}

func (s *Service) Trigger(ctx context.Context, projectID, monitorID, triggeredBy string) (Run, error) {
	s.mu.Lock()
	available := s.started && !s.closed && s.ctx != nil && s.ctx.Err() == nil
	provider := s.provider
	s.mu.Unlock()
	if !available {
		return Run{}, ErrUnavailable
	}
	monitor, err := s.GetMonitor(ctx, projectID, monitorID)
	if err != nil {
		return Run{}, err
	}
	if provider == nil || provider.Name() != monitor.Provider || !providerConfigured(provider) {
		return Run{}, ErrUnconfigured
	}
	run, err := s.store.enqueueRun(ctx, monitor, RunTriggerManual, triggeredBy)
	if err != nil {
		return Run{}, err
	}
	s.notify()
	return run, nil
}

func (s *Service) ListRuns(ctx context.Context, projectID, monitorID string, options RunListOptions) (RunListResult, error) {
	if _, err := s.GetMonitor(ctx, projectID, monitorID); err != nil {
		return RunListResult{}, err
	}
	return s.store.listRuns(ctx, strings.TrimSpace(projectID), strings.TrimSpace(monitorID), options)
}

func (s *Service) GetRun(ctx context.Context, projectID, monitorID, runID string) (Run, error) {
	if strings.TrimSpace(monitorID) == "" || strings.TrimSpace(runID) == "" {
		return Run{}, ErrNotFound
	}
	return s.store.getRun(ctx, strings.TrimSpace(projectID), strings.TrimSpace(monitorID), strings.TrimSpace(runID))
}

func (s *Service) ListRunAssets(ctx context.Context, projectID, monitorID, runID string, options RunAssetListOptions) (RunAssetListResult, error) {
	if _, err := s.GetRun(ctx, projectID, monitorID, runID); err != nil {
		return RunAssetListResult{}, err
	}
	return s.store.listRunAssets(ctx, strings.TrimSpace(projectID), strings.TrimSpace(monitorID), strings.TrimSpace(runID), options)
}

func (s *Service) normalizeCreate(input CreateMonitorInput) (Monitor, error) {
	projectID := strings.TrimSpace(input.ProjectID)
	ownerUserID := strings.TrimSpace(input.OwnerUserID)
	if projectID == "" || len(projectID) > 100 {
		return Monitor{}, validationErrorf("project_id is required")
	}
	if ownerUserID == "" || len(ownerUserID) > 100 {
		return Monitor{}, validationErrorf("owner_user_id is required")
	}
	root, err := NormalizeRootDomain(input.RootDomain)
	if err != nil {
		return Monitor{}, err
	}
	name := cleanProviderText(input.Name, 120)
	if name == "" {
		name = root
	}
	provider := strings.ToLower(strings.TrimSpace(input.Provider))
	if provider == "" {
		provider = ProviderQuake
	}
	if provider != ProviderQuake {
		return Monitor{}, validationErrorf("unsupported provider %q", provider)
	}
	interval := input.IntervalMinutes
	if interval == 0 {
		interval = DefaultIntervalMinutes
	}
	if err = validateInterval(interval); err != nil {
		return Monitor{}, err
	}
	maxResults := input.MaxResults
	if maxResults == 0 {
		maxResults = DefaultMaxResults
	}
	if err = validateMaxResults(maxResults); err != nil {
		return Monitor{}, err
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	status := MonitorStatusDisabled
	var nextRun *time.Time
	if enabled {
		status = MonitorStatusIdle
		next := s.now().UTC().Add(time.Duration(interval) * time.Minute)
		nextRun = &next
	}
	cronExpr := strings.TrimSpace(input.CronExpr)
	if len(cronExpr) > 100 {
		return Monitor{}, validationErrorf("cron_expr is too long")
	}
	return Monitor{
		ProjectID: projectID, OwnerUserID: ownerUserID, Name: name, RootDomain: root,
		Provider: provider, Query: generatedQuery(root), CronExpr: cronExpr, IntervalMinutes: interval,
		MaxResults: maxResults, Enabled: enabled, NextRunAt: nextRun, LastStatus: status,
	}, nil
}

func validateInterval(value int) error {
	if value < MinIntervalMinutes || value > MaxIntervalMinutes {
		return validationErrorf("interval_minutes must be between %d and %d", MinIntervalMinutes, MaxIntervalMinutes)
	}
	return nil
}

func validateMaxResults(value int) error {
	if value < MinMaxResults || value > MaxMaxResults {
		return validationErrorf("max_results must be between %d and %d", MinMaxResults, MaxMaxResults)
	}
	return nil
}

func (s *Service) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) loop(ctx context.Context) {
	defer s.wg.Done()
	if err := s.store.reconcileStaleRuns(ctx, s.now().Add(-s.staleAfter)); err != nil && !errors.Is(err, context.Canceled) {
		s.logger.Warn("reconcile stale asset monitor runs failed", zap.Error(err))
	}
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	for {
		if err := s.cycle(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.logger.Warn("asset monitor scheduler cycle failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
	}
}

func (s *Service) cycle(ctx context.Context) error {
	now := s.now().UTC()
	due, err := s.store.listDueMonitors(ctx, now, 50)
	if err != nil {
		return err
	}
	for _, monitor := range due {
		next := nextIntervalRun(monitor.NextRunAt, now, monitor.IntervalMinutes)
		if _, err = s.store.enqueueDueRun(ctx, monitor, now, next); err != nil {
			return err
		}
	}
	for {
		run, monitor, claimErr := s.store.claimNextRun(ctx, s.now().UTC())
		if errors.Is(claimErr, sql.ErrNoRows) {
			return nil
		}
		if claimErr != nil {
			return claimErr
		}
		s.execute(ctx, run, monitor)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func nextIntervalRun(previous *time.Time, now time.Time, intervalMinutes int) time.Time {
	interval := time.Duration(intervalMinutes) * time.Minute
	if interval <= 0 {
		interval = time.Duration(DefaultIntervalMinutes) * time.Minute
	}
	next := now.Add(interval)
	if previous != nil {
		next = previous.UTC().Add(interval)
		for !next.After(now) {
			next = next.Add(interval)
		}
	}
	return next
}

func (s *Service) execute(parent context.Context, run Run, monitor Monitor) {
	started := s.now().UTC()
	run.StartedAt = &started
	status := RunStatusSuccess
	var runErr error
	ctx, cancel := context.WithTimeout(parent, s.runTimeout)
	defer cancel()

	if err := s.authorizeMonitor(monitor); err != nil {
		runErr = err
	} else {
		s.mu.Lock()
		provider := s.provider
		s.mu.Unlock()
		if provider == nil || provider.Name() != monitor.Provider || !providerConfigured(provider) {
			runErr = ErrUnconfigured
		} else {
			run = s.searchAndPersist(ctx, provider, monitor, run, &status, &runErr)
		}
	}
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			status = RunStatusCancelled
		} else if run.SeenCount > 0 {
			status = RunStatusPartial
		} else {
			status = RunStatusError
		}
		run.Error = safeRunError(runErr)
	}
	run.Status = status
	finished := s.now().UTC()
	run.FinishedAt = &finished
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer finishCancel()
	if err := s.store.finishRun(finishCtx, run); err != nil {
		s.logger.Error("finish asset monitor run failed", zap.String("run_id", run.ID), zap.Error(err))
	}
}

func (s *Service) searchAndPersist(ctx context.Context, provider Provider, monitor Monitor, run Run, status *string, runErr *error) Run {
	observations := make(map[string]Observation, monitor.MaxResults)
	pageNumber := 1
	processed := 0
	truncated := false
	for processed < monitor.MaxResults {
		pageSize := providerPageSize
		if remaining := monitor.MaxResults - processed; remaining < pageSize {
			pageSize = remaining
		}
		page, err := provider.Search(ctx, SearchRequest{RootDomain: monitor.RootDomain, Query: monitor.Query, Page: pageNumber, PageSize: pageSize})
		if err != nil {
			*runErr = err
			break
		}
		if page.RawCount < 0 {
			page.RawCount = 0
		}
		processed += page.RawCount
		run.TotalCount += page.RawCount
		run.SkippedCount += page.Skipped
		for _, raw := range page.Observations {
			observation, ok := NormalizeObservationForRoot(monitor.RootDomain, raw)
			if !ok {
				run.SkippedCount++
				continue
			}
			key := observationDedupKey(observation)
			if _, exists := observations[key]; exists {
				run.SkippedCount++
				continue
			}
			if len(observations) >= monitor.MaxResults {
				truncated = true
				break
			}
			observations[key] = observation
		}
		if truncated || !page.HasMore || page.RawCount == 0 {
			break
		}
		if processed >= monitor.MaxResults {
			truncated = page.HasMore || page.Total > processed
			break
		}
		pageNumber++
	}
	if len(observations) > 0 {
		items := make([]Observation, 0, len(observations))
		for _, observation := range observations {
			items = append(items, observation)
		}
		persisted, err := s.store.persistObservations(ctx, monitor, run, items, s.now().UTC())
		if err != nil {
			*runErr = err
			return run
		}
		run.SeenCount = persisted.Seen
		run.NewCount = persisted.New
		run.CreatedCount = persisted.Created
		run.UpdatedCount = persisted.Updated
		run.ConflictCount = persisted.Conflicts
		if persisted.Conflicts > 0 && *runErr == nil {
			*status = RunStatusPartial
			run.Error = "one or more assets belong to another project"
		}
	}
	if truncated && *runErr == nil {
		*status = RunStatusPartial
		run.Error = "results truncated at max_results"
	}
	return run
}

func (s *Service) authorizeMonitor(monitor Monitor) error {
	if s.db == nil {
		return nil
	}
	access, err := s.db.ResolveRBACAccess(monitor.OwnerUserID)
	if err != nil || access == nil || !access.User.Enabled {
		return errors.New("monitor owner is unavailable")
	}
	for _, permission := range []string{"project:write", "asset:write", "fofa:execute"} {
		if !access.Permissions[permission] {
			return fmt.Errorf("monitor owner lacks %s", permission)
		}
	}
	scope := access.PermissionScopes["project:write"]
	if scope == "" {
		scope = database.RBACScopeOwn
	}
	if !s.db.UserCanAccessResource(monitor.OwnerUserID, scope, "project", monitor.ProjectID) {
		return errors.New("monitor owner cannot access project")
	}
	return nil
}

func safeRunError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if errors.Is(err, context.Canceled) {
		message = "run cancelled"
	} else if errors.Is(err, context.DeadlineExceeded) {
		message = "run timed out"
	}
	message = cleanProviderText(message, 500)
	if !utf8.ValidString(message) {
		return "run failed"
	}
	return message
}
