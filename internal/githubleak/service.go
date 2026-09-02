package githubleak

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type persistence interface {
	AcquireRunLock(context.Context) (func(), bool, error)
	UpsertCandidates(context.Context, []Candidate, time.Time) (int, int, error)
	List(context.Context, ListFilter) (ListResult, error)
	Get(context.Context, string) (Finding, error)
	UpdateStatus(context.Context, string, string) (Finding, error)
	Stats(context.Context) (Stats, error)
	KeywordState(context.Context, string) (KeywordState, error)
	SaveKeywordState(context.Context, KeywordState) error
	BeginRun(context.Context, time.Time) (RunRecord, error)
	FinishRun(context.Context, RunRecord) error
	LatestRun(context.Context) (RunRecord, error)
}

type searchProvider interface {
	SearchKeywords(context.Context, []string, string, int) (SearchResult, error)
}

type secretDetector interface {
	Detect(string, SearchItem) []Candidate
}

type runtimeConfig struct {
	settings Settings
	client   searchProvider
	detector secretDetector
}

type Service struct {
	store  persistence
	logger *zap.Logger

	mu       sync.Mutex
	settings Settings
	client   searchProvider
	detector secretDetector
	ctx      context.Context
	cancel   context.CancelFunc
	queue    chan struct{}
	wake     chan struct{}
	wg       sync.WaitGroup
	started  bool
	closed   bool
	running  bool
	queued   bool
	nextRun  *time.Time
	pending  *runtimeConfig
}

func NewService(store *Store, settings Settings, logger *zap.Logger) (*Service, error) {
	if store == nil {
		return nil, errors.New("github leak store is required")
	}
	return newService(store, settings, nil, nil, logger)
}

func newService(store persistence, settings Settings, provider searchProvider, detector secretDetector, logger *zap.Logger) (*Service, error) {
	if store == nil {
		return nil, errors.New("github leak persistence is required")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	normalized, err := settings.Normalize()
	if err != nil {
		return nil, err
	}
	if provider == nil {
		provider, err = NewClient(normalized)
		if err != nil {
			return nil, err
		}
	}
	if detector == nil && normalized.Configured() {
		detector, err = NewDetector(normalized)
		if err != nil {
			return nil, err
		}
	}
	return &Service{
		store: store, settings: normalized, client: provider, detector: detector, logger: logger,
		queue: make(chan struct{}, 1), wake: make(chan struct{}, 1),
	}, nil
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
	if s.settings.Enabled && s.settings.Configured() && s.detector != nil {
		now := time.Now().UTC()
		s.nextRun = &now
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go s.loop()
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

func (s *Service) Trigger(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.closed || s.ctx == nil || s.ctx.Err() != nil {
		return ErrUnavailable
	}
	if !s.settings.Configured() || s.detector == nil {
		return ErrUnconfigured
	}
	if s.running || s.queued {
		return ErrBusy
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	s.queued = true
	select {
	case s.queue <- struct{}{}:
		return nil
	default:
		s.queued = false
		return ErrBusy
	}
}

// UpdateSettings applies a validated snapshot. During an active run the latest
// snapshot is queued and atomically applied after that run, preserving the
// client's hard inter-request spacing boundary.
func (s *Service) UpdateSettings(settings Settings) error {
	normalized, err := settings.Normalize()
	if err != nil {
		return err
	}
	client, err := NewClient(normalized)
	if err != nil {
		return err
	}
	var detector secretDetector
	if normalized.Configured() {
		detector, err = NewDetector(normalized)
		if err != nil {
			return err
		}
	}
	next := &runtimeConfig{settings: normalized, client: client, detector: detector}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrUnavailable
	}
	if s.running {
		s.pending = next
		s.mu.Unlock()
		return nil
	}
	s.applyRuntimeLocked(next, s.client)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

func (s *Service) applyRuntimeLocked(next *runtimeConfig, previous searchProvider) {
	if next == nil {
		return
	}
	inheritRequestBoundary(previous, next.client)
	s.settings = next.settings
	s.client = next.client
	s.detector = next.detector
	s.pending = nil
	if s.settings.Enabled && s.settings.Configured() && s.detector != nil {
		now := time.Now().UTC()
		s.nextRun = &now
	} else {
		s.nextRun = nil
	}
}

func inheritRequestBoundary(previous, next searchProvider) {
	oldClient, oldOK := previous.(*Client)
	newClient, newOK := next.(*Client)
	if !oldOK || !newOK || oldClient == newClient {
		return
	}
	oldClient.requestMu.Lock()
	lastRequest := oldClient.lastRequest
	oldClient.requestMu.Unlock()
	newClient.lastRequest = lastRequest
}

func (s *Service) List(ctx context.Context, filter ListFilter) (ListResult, error) {
	return s.store.List(ctx, filter)
}

func (s *Service) Get(ctx context.Context, id string) (Finding, error) {
	return s.store.Get(ctx, id)
}

func (s *Service) UpdateStatus(ctx context.Context, id, status string) (Finding, error) {
	return s.store.UpdateStatus(ctx, id, status)
}

func (s *Service) Stats(ctx context.Context) (Stats, error) {
	return s.store.Stats(ctx)
}

func (s *Service) RuntimeStatus(ctx context.Context) (RuntimeStatus, error) {
	s.mu.Lock()
	settings := s.settings
	if s.pending != nil {
		settings = s.pending.settings
	}
	running := s.running
	next := copyTime(s.nextRun)
	s.mu.Unlock()
	status := RuntimeStatus{
		Enabled: settings.Enabled, Configured: settings.Configured(), Running: running,
		NextRunAt: next, RateRemaining: -1, IntervalSeconds: settings.PollIntervalSeconds,
		RequestIntervalSeconds: settings.IntervalSeconds,
		RequestTimeoutSeconds:  settings.RequestTimeoutSeconds,
		Keywords:               append([]string(nil), settings.Keywords...), Rules: []RuleStatus{},
	}
	if rule, ruleErr := newKeywordRule(settings.Keywords); ruleErr == nil {
		status.Query = rule.Query
	}
	compiled, compileErr := compiledRules(settings, true)
	if compileErr != nil {
		return status, compileErr
	}
	for _, rule := range compiled {
		ruleStatus := RuleStatus{
			Enabled: rule.Enabled, Name: rule.Name,
			Keywords: append([]string(nil), rule.Keywords...), Query: rule.Query,
		}
		state, stateErr := s.store.KeywordState(ctx, rule.Query)
		if stateErr != nil {
			return status, stateErr
		}
		ruleStatus.LastAttemptAt = copyTime(state.LastAttemptAt)
		ruleStatus.LastSuccessAt = copyTime(state.LastSuccessAt)
		ruleStatus.LastStatus = strings.TrimSpace(state.LastStatus)
		ruleStatus.LastError = safeError(state.LastError)
		ruleStatus.Incomplete = state.Incomplete
		ruleStatus.Truncated = state.Truncated
		status.Rules = append(status.Rules, ruleStatus)
		if status.Query == "" && rule.Enabled {
			status.Keywords = append([]string(nil), rule.Keywords...)
			status.Query = rule.Query
		}
	}
	latest, err := s.store.LatestRun(ctx)
	if err != nil {
		return status, err
	}
	if latest.ID != "" {
		last := latest.StartedAt.UTC()
		status.LastRunAt = &last
		status.LastStatus = latest.Status
		message := safeError(latest.Error)
		if latest.Status == "partial" {
			status.LastWarning = message
		} else {
			status.LastError = message
		}
		status.RateRemaining = latest.RateRemaining
		status.RateResetAt = copyTime(latest.RateResetAt)
		status.LastRequests = latest.Requests
		status.LastProcessed = latest.Processed
		status.LastDetected = latest.Detected
	}
	return status, nil
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func (s *Service) loop() {
	defer s.wg.Done()
	for {
		s.mu.Lock()
		ctx := s.ctx
		settings := s.settings
		next := copyTime(s.nextRun)
		s.mu.Unlock()
		if ctx == nil {
			return
		}
		delay := time.Hour
		if settings.Enabled && settings.Configured() && next != nil {
			delay = time.Until(*next)
			if delay < 0 {
				delay = 0
			}
		}
		timer := time.NewTimer(delay)
		manual := false
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-s.wake:
			if !timer.Stop() {
				<-timer.C
			}
			continue
		case <-s.queue:
			manual = true
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
		s.mu.Lock()
		manual = s.claimQueuedRunLocked(manual)
		if s.closed || !s.settings.Configured() || s.detector == nil || s.running || (!manual && !s.settings.Enabled) {
			s.mu.Unlock()
			continue
		}
		s.running = true
		settings = s.settings
		provider := s.client
		detector := s.detector
		s.mu.Unlock()

		rateReset := s.execute(ctx, settings, provider, detector)

		s.mu.Lock()
		s.running = false
		pendingApplied := s.pending != nil
		if pendingApplied {
			s.applyRuntimeLocked(s.pending, provider)
		}
		now := time.Now().UTC()
		if s.settings.Enabled && s.settings.Configured() && s.detector != nil {
			nextAt := now.Add(s.settings.pollInterval())
			if pendingApplied {
				nextAt = now
			} else if rateReset != nil && rateReset.After(now) {
				nextAt = rateReset.UTC()
			}
			s.nextRun = &nextAt
		} else {
			s.nextRun = nil
		}
		s.mu.Unlock()
	}
}

// claimQueuedRunLocked coalesces a manual trigger with a scheduled run that is
// already due. Without draining the queued marker when the timer wins select,
// startup can consume the same intent twice and immediately repeat every rule.
func (s *Service) claimQueuedRunLocked(manual bool) bool {
	if manual {
		s.queued = false
		return true
	}
	if !s.queued {
		return false
	}
	select {
	case <-s.queue:
	default:
	}
	s.queued = false
	return true
}

func (s *Service) execute(parent context.Context, settings Settings, provider searchProvider, detector secretDetector) *time.Time {
	rules, err := compiledRules(settings, false)
	if err != nil || len(rules) == 0 {
		s.logger.Warn("GitHub leak monitor rule unavailable")
		return nil
	}
	unlock, locked, err := s.store.AcquireRunLock(parent)
	if err != nil || !locked {
		if err != nil {
			s.logger.Warn("GitHub leak monitor lock unavailable", zap.Error(err))
		}
		return nil
	}
	defer unlock()

	runTimeout := runTimeoutForRules(settings, len(rules))
	ctx, cancel := context.WithTimeout(parent, runTimeout)
	defer cancel()
	now := time.Now().UTC()
	run, err := s.store.BeginRun(ctx, now)
	if err != nil {
		s.logger.Warn("GitHub leak monitor could not create run", zap.Error(err))
		return nil
	}
	run.Status = "success"
	run.RateRemaining = -1
	completedRules := 0
	failedRules := 0
	incompleteRules := 0
	permanentSearchFailure := false
	for _, rule := range rules {
		if ctx.Err() != nil {
			run.Status = "cancelled"
			run.Error = "run cancelled"
			break
		}
		state, stateErr := s.store.KeywordState(ctx, rule.Query)
		if stateErr != nil {
			failedRules++
			continue
		}
		attemptAt := time.Now().UTC()
		state.LastAttemptAt = &attemptAt
		run.Requests++
		result, searchErr := provider.SearchKeywords(ctx, rule.Keywords, state.ETag, settings.MaxResultsPerKeyword)
		if searchErr != nil {
			state.LastStatus = "error"
			state.LastError = classifySearchError(searchErr)
			_ = s.saveKeywordState(ctx, state)
			var httpErr *HTTPStatusError
			if errors.As(searchErr, &httpErr) && httpErr.RateLimited {
				run.Status = "rate_limited"
				run.Error = state.LastError
				run.RateResetAt = copyTime(httpErr.RateReset)
				break
			}
			if errors.As(searchErr, &httpErr) && isPermanentSearchFailure(httpErr) {
				failedRules++
				permanentSearchFailure = true
				break
			}
			if errors.Is(searchErr, context.Canceled) || errors.Is(searchErr, context.DeadlineExceeded) {
				run.Status = "cancelled"
				run.Error = "run cancelled"
				break
			}
			failedRules++
			continue
		}
		if result.RateRemaining >= 0 || run.RateRemaining < 0 {
			run.RateRemaining = result.RateRemaining
		}
		if result.RateResetAt != nil {
			run.RateResetAt = copyTime(result.RateResetAt)
		}
		state.LastError = ""
		state.Incomplete = result.Incomplete
		state.Truncated = result.Truncated
		completedAt := time.Now().UTC()
		state.LastSuccessAt = &completedAt
		if result.NotModified {
			state.LastStatus = "not_modified"
			if result.ETag != "" {
				state.ETag = result.ETag
			}
			if err = s.saveKeywordState(ctx, state); err != nil {
				s.logger.Warn("GitHub leak monitor state write failed", zap.String("error_type", fmt.Sprintf("%T", err)), zap.Bool("run_context_done", ctx.Err() != nil))
				failedRules++
				continue
			}
			completedRules++
			continue
		}
		candidates := make([]Candidate, 0)
		for _, item := range result.Items {
			detected := detector.Detect(rule.Query, item)
			for i := range detected {
				detected[i].RuleName = rule.Name
			}
			candidates = append(candidates, detected...)
		}
		run.Processed += len(result.Items)
		run.Detected += len(candidates)
		if _, _, err = s.store.UpsertCandidates(ctx, candidates, completedAt); err != nil {
			state.LastStatus = "error"
			state.LastError = "finding storage failed"
			_ = s.saveKeywordState(ctx, state)
			failedRules++
			continue
		}
		if result.Incomplete || result.Truncated {
			state.LastStatus = "partial"
			// Do not save an ETag for an incomplete snapshot; otherwise a later
			// 304 could turn a partial result into a permanent high-water mark.
			state.ETag = ""
			incompleteRules++
		} else {
			state.LastStatus = "success"
			state.ETag = result.ETag
		}
		if err = s.saveKeywordState(ctx, state); err != nil {
			s.logger.Warn("GitHub leak monitor state write failed", zap.String("error_type", fmt.Sprintf("%T", err)), zap.Bool("run_context_done", ctx.Err() != nil))
			failedRules++
			continue
		}
		completedRules++
	}
	if run.Status != "rate_limited" && run.Status != "cancelled" {
		switch {
		case permanentSearchFailure && completedRules == 0:
			run.Status = "error"
			run.Error = "GitHub authentication or authorization failed; remaining rules were skipped"
		case permanentSearchFailure:
			run.Status = "partial"
			run.Error = "GitHub authentication or authorization failed; remaining rules were skipped"
		case failedRules > 0 && completedRules == 0:
			run.Status = "error"
			run.Error = fmt.Sprintf("%d of %d rule searches failed", failedRules, len(rules))
		case failedRules > 0:
			run.Status = "partial"
			run.Error = fmt.Sprintf("%d of %d rule searches failed", failedRules, len(rules))
		case incompleteRules > 0:
			run.Status = "partial"
			run.Error = fmt.Sprintf("%d of %d rule searches were incomplete or truncated", incompleteRules, len(rules))
		default:
			run.Status = "success"
		}
	}
	finished := time.Now().UTC()
	run.FinishedAt = &finished
	finishCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err = s.store.FinishRun(finishCtx, run); err != nil {
		s.logger.Warn("GitHub leak monitor run status write failed", zap.Error(err))
	}
	s.logger.Info("GitHub leak monitor run completed", zap.String("status", run.Status), zap.Int("requests", run.Requests), zap.Int("processed", run.Processed), zap.Int("detected", run.Detected))
	if run.Status == "rate_limited" {
		return copyTime(run.RateResetAt)
	}
	return nil
}

func runTimeoutForRules(settings Settings, enabledRules int) time.Duration {
	runTimeout := 30 * time.Minute
	if enabledRules < 1 {
		return runTimeout
	}
	// Search calls are serialized and spacing starts after the previous call
	// finishes, so both the timeout and the quiet interval scale per rule.
	minimum := time.Duration(enabledRules)*(settings.interval()+settings.timeout()) + 5*time.Minute
	if minimum > runTimeout {
		runTimeout = minimum
	}
	if runTimeout > 6*time.Hour {
		runTimeout = 6 * time.Hour
	}
	return runTimeout
}

func isPermanentSearchFailure(err *HTTPStatusError) bool {
	if err == nil || err.RateLimited {
		return false
	}
	return err.StatusCode == 401 || err.StatusCode == 403
}

func classifySearchError(err error) string {
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		if statusErr.RateLimited {
			return "github search rate limited"
		}
		switch statusErr.StatusCode {
		case 422:
			return "github rejected the exact keyword query"
		default:
			return fmt.Sprintf("github search HTTP %d", statusErr.StatusCode)
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "github search cancelled"
	}
	return "github search unavailable"
}

func (s *Service) saveKeywordState(ctx context.Context, state KeywordState) error {
	writeCtx, cancel := context.WithTimeout(contextWithoutCancellation(ctx), 5*time.Second)
	defer cancel()
	return s.store.SaveKeywordState(writeCtx, state)
}

func contextWithoutCancellation(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}
