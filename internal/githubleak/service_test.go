package githubleak

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type serviceTestPersistence struct {
	mu         sync.Mutex
	lock       bool
	states     map[string]KeywordState
	runs       []RunRecord
	candidates []Candidate
	finished   chan RunRecord
}

func newServiceTestPersistence() *serviceTestPersistence {
	return &serviceTestPersistence{
		lock: true, states: make(map[string]KeywordState), finished: make(chan RunRecord, 8),
	}
}

func (p *serviceTestPersistence) AcquireRunLock(context.Context) (func(), bool, error) {
	p.mu.Lock()
	locked := p.lock
	p.mu.Unlock()
	return func() {}, locked, nil
}

func (p *serviceTestPersistence) UpsertCandidates(_ context.Context, candidates []Candidate, _ time.Time) (int, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.candidates = append(p.candidates, candidates...)
	return len(candidates), 0, nil
}

func (p *serviceTestPersistence) List(context.Context, ListFilter) (ListResult, error) {
	return ListResult{}, nil
}

func (p *serviceTestPersistence) Get(context.Context, string) (Finding, error) {
	return Finding{}, ErrNotFound
}

func (p *serviceTestPersistence) UpdateStatus(_ context.Context, id, status string) (Finding, error) {
	if id == "" || !ValidStatus(status) {
		return Finding{}, ErrNotFound
	}
	return Finding{ID: id, Status: status}, nil
}

func (p *serviceTestPersistence) Stats(context.Context) (Stats, error) { return Stats{}, nil }

func (p *serviceTestPersistence) KeywordState(_ context.Context, keyword string) (KeywordState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state, ok := p.states[keyword]
	if !ok {
		state = KeywordState{Keyword: keyword}
	}
	return state, nil
}

func (p *serviceTestPersistence) SaveKeywordState(_ context.Context, state KeywordState) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.states[state.Keyword] = state
	return nil
}

func (p *serviceTestPersistence) BeginRun(_ context.Context, at time.Time) (RunRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	run := RunRecord{ID: fmt.Sprintf("run-%d", len(p.runs)+1), Status: "running", StartedAt: at, RateRemaining: -1}
	p.runs = append(p.runs, run)
	return run, nil
}

func (p *serviceTestPersistence) FinishRun(_ context.Context, run RunRecord) error {
	p.mu.Lock()
	for i := range p.runs {
		if p.runs[i].ID == run.ID {
			p.runs[i] = run
			break
		}
	}
	p.mu.Unlock()
	select {
	case p.finished <- run:
	default:
	}
	return nil
}

func (p *serviceTestPersistence) LatestRun(context.Context) (RunRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.runs) == 0 {
		return RunRecord{RateRemaining: -1}, nil
	}
	return p.runs[len(p.runs)-1], nil
}

type serviceProviderCall struct {
	keywords   []string
	etag       string
	maxResults int
}

type serviceTestProvider struct {
	mu      sync.Mutex
	calls   []serviceProviderCall
	result  SearchResult
	err     error
	results []SearchResult
	errs    []error
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (p *serviceTestProvider) SearchKeywords(ctx context.Context, keywords []string, etag string, maxResults int) (SearchResult, error) {
	p.mu.Lock()
	callIndex := len(p.calls)
	p.calls = append(p.calls, serviceProviderCall{keywords: append([]string(nil), keywords...), etag: etag, maxResults: maxResults})
	result, err := p.result, p.err
	if callIndex < len(p.results) {
		result = p.results[callIndex]
	}
	if callIndex < len(p.errs) {
		err = p.errs[callIndex]
	}
	p.mu.Unlock()
	if p.started != nil {
		p.once.Do(func() { close(p.started) })
	}
	if p.release != nil {
		select {
		case <-ctx.Done():
			return SearchResult{}, ctx.Err()
		case <-p.release:
		}
	}
	return result, err
}

func (p *serviceTestProvider) callSnapshot() []serviceProviderCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]serviceProviderCall(nil), p.calls...)
}

type serviceTestDetector struct{ candidates []Candidate }

func (d serviceTestDetector) Detect(keyword string, item SearchItem) []Candidate {
	out := append([]Candidate(nil), d.candidates...)
	for i := range out {
		out[i].Keyword = keyword
		if out[i].Repository == "" {
			out[i].Repository = item.Repository
		}
		if out[i].Path == "" {
			out[i].Path = item.Path
		}
	}
	return out
}

func serviceSettings(enabled bool, keywords ...string) Settings {
	return Settings{
		Enabled: enabled, Token: "unit-test-token", FingerprintKey: "stable-unit-fingerprint-key",
		Keywords: keywords, IntervalSeconds: MinIntervalSeconds,
		RequestTimeoutSeconds: 5, PollIntervalSeconds: DefaultPollSeconds, MaxResultsPerKeyword: 25,
	}
}

func waitForServiceRun(t *testing.T, finished <-chan RunRecord) RunRecord {
	t.Helper()
	select {
	case run := <-finished:
		return run
	case <-time.After(2 * time.Second):
		t.Fatal("service run did not finish")
		return RunRecord{}
	}
}

func TestServiceScheduledRunCoalescesQueuedManualTrigger(t *testing.T) {
	service := &Service{queue: make(chan struct{}, 1), queued: true}
	service.queue <- struct{}{}
	service.mu.Lock()
	manual := service.claimQueuedRunLocked(false)
	queued := service.queued
	service.mu.Unlock()
	if !manual || queued {
		t.Fatalf("coalesced trigger = manual:%v queued:%v", manual, queued)
	}
	select {
	case <-service.queue:
		t.Fatal("scheduled run left a second manual marker queued")
	default:
	}
}

func TestServiceLifecycleAndManualTriggerBypassesScheduledEnabledFlag(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{result: SearchResult{
		ETag: `"etag-1"`, RateRemaining: 19,
		Items: []SearchItem{{Repository: "owner/repo", Path: "config.env", BlobSHA: "blob", HTMLURL: "https://github.com/owner/repo/blob/main/config.env"}},
	}}
	detector := serviceTestDetector{candidates: []Candidate{{
		Line: 1, SecretType: "github_token", Confidence: "likely", Severity: "critical",
		Fingerprint: "sanitized-fingerprint", MaskedExcerpt: "token=<redacted:github_token>",
	}}}
	service, err := newService(store, serviceSettings(false, "vendor.example", "storage-service"), provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Trigger(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("trigger before Start = %v", err)
	}
	service.Start(context.Background())
	if err = service.Trigger(context.Background()); err != nil {
		service.Close()
		t.Fatalf("manual trigger for a configured disabled monitor = %v", err)
	}
	if err = service.Trigger(context.Background()); !errors.Is(err, ErrBusy) {
		service.Close()
		t.Fatalf("second trigger = %v, want busy", err)
	}
	run := waitForServiceRun(t, store.finished)
	if run.Status != "success" || run.Processed != 1 || run.Detected != 1 || run.RateRemaining != 19 {
		service.Close()
		t.Fatalf("finished run = %+v", run)
	}
	calls := provider.callSnapshot()
	if len(calls) != 1 || len(calls[0].keywords) != 2 || calls[0].keywords[0] != "storage-service" || calls[0].keywords[1] != "vendor.example" || calls[0].etag != "" || calls[0].maxResults != 25 {
		service.Close()
		t.Fatalf("provider calls = %+v", calls)
	}
	rule, ruleErr := newKeywordRule([]string{"storage-service", "vendor.example"})
	if ruleErr != nil {
		service.Close()
		t.Fatal(ruleErr)
	}
	store.mu.Lock()
	state := store.states[rule.Query]
	candidateCount := len(store.candidates)
	candidateRule := ""
	if candidateCount > 0 {
		candidateRule = store.candidates[0].Keyword
	}
	store.mu.Unlock()
	if state.LastStatus != "success" || state.ETag != `"etag-1"` || state.LastSuccessAt == nil || candidateCount != 1 || candidateRule != rule.Query {
		service.Close()
		t.Fatalf("state=%+v candidateCount=%d", state, candidateCount)
	}
	runtime, runtimeErr := service.RuntimeStatus(context.Background())
	if runtimeErr != nil || runtime.Query != rule.Query || len(runtime.Keywords) != 2 || runtime.Keywords[0] != "storage-service" {
		service.Close()
		t.Fatalf("runtime=%+v err=%v", runtime, runtimeErr)
	}
	service.Close()
	service.Close()
}

func TestServiceAppliesSettingsQueuedDuringActiveRun(t *testing.T) {
	store := newServiceTestPersistence()
	started := make(chan struct{})
	release := make(chan struct{})
	provider := &serviceTestProvider{
		started: started, release: release,
		result: SearchResult{ETag: `"old-etag"`, Items: []SearchItem{}},
	}
	service, err := newService(store, serviceSettings(false, "storage-service"), provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.Start(context.Background())
	defer service.Close()
	if err = service.Trigger(context.Background()); err != nil {
		t.Fatalf("manual trigger = %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider did not start")
	}
	pending := serviceSettings(false, "vendor.example")
	pending.MaxResultsPerKeyword = 40
	if err = service.UpdateSettings(pending); err != nil {
		close(release)
		t.Fatalf("queue settings during active run = %v", err)
	}
	close(release)
	_ = waitForServiceRun(t, store.finished)

	deadline := time.Now().Add(2 * time.Second)
	for {
		status, statusErr := service.RuntimeStatus(context.Background())
		if statusErr != nil {
			t.Fatal(statusErr)
		}
		if len(status.Keywords) == 1 && status.Keywords[0] == "vendor.example" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending settings were not applied: %+v", status)
		}
		time.Sleep(5 * time.Millisecond)
	}
	calls := provider.callSnapshot()
	if len(calls) != 1 || len(calls[0].keywords) != 1 || calls[0].keywords[0] != "storage-service" {
		t.Fatalf("active run did not retain its original settings snapshot: %+v", calls)
	}
}

func TestServiceIncompleteSearchClearsETagBeforeNextAttempt(t *testing.T) {
	store := newServiceTestPersistence()
	oldAttempt := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	rule, ruleErr := newKeywordRule([]string{"storage-service"})
	if ruleErr != nil {
		t.Fatal(ruleErr)
	}
	store.states[rule.Query] = KeywordState{Keyword: rule.Query, ETag: `"complete-etag"`, LastAttemptAt: &oldAttempt, LastStatus: "success"}
	provider := &serviceTestProvider{result: SearchResult{ETag: `"partial-etag"`, Incomplete: true, TotalCount: 500, Items: []SearchItem{}}}
	service, err := newService(store, serviceSettings(true, "storage-service"), provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	store.mu.Lock()
	state := store.states[rule.Query]
	store.mu.Unlock()
	if run.Status != "partial" || state.LastStatus != "partial" || !state.Incomplete {
		t.Fatalf("run=%+v state=%+v", run, state)
	}
	if state.ETag != "" {
		t.Fatalf("incomplete response retained ETag %q", state.ETag)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	_ = waitForServiceRun(t, store.finished)
	calls := provider.callSnapshot()
	if len(calls) != 2 || calls[0].etag != `"complete-etag"` || calls[1].etag != "" {
		t.Fatalf("ETags after partial state = %+v", calls)
	}
}

func TestServiceTruncatedSearchIsPartialAndVisibleInRuleStatus(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{result: SearchResult{ETag: `"truncated"`, Truncated: true, TotalCount: 200, Items: []SearchItem{}}}
	service, err := newService(store, serviceSettings(true, "storage-service"), provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	status, err := service.RuntimeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "partial" || len(status.Rules) != 1 || !status.Rules[0].Truncated || status.Rules[0].Incomplete || status.Rules[0].LastStatus != "partial" {
		t.Fatalf("run=%+v runtime=%+v", run, status)
	}
	if status.LastError != "" || status.LastWarning == "" {
		t.Fatalf("partial runtime message classification = error:%q warning:%q", status.LastError, status.LastWarning)
	}
	store.mu.Lock()
	state := store.states[status.Rules[0].Query]
	store.mu.Unlock()
	if state.ETag != "" {
		t.Fatalf("truncated state retained ETag %q", state.ETag)
	}
}

func TestServiceCanonicalRuleReusesStateAcrossKeywordOrder(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{result: SearchResult{ETag: `"combined-etag"`, Items: []SearchItem{}}}
	settings := serviceSettings(false, "vendor.example", "storage-service", "storage-service")
	service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), settings, provider, service.detector)
	_ = waitForServiceRun(t, store.finished)
	reordered := serviceSettings(false, "storage-service", "vendor.example")
	service.execute(context.Background(), reordered, provider, service.detector)
	_ = waitForServiceRun(t, store.finished)
	calls := provider.callSnapshot()
	if len(calls) != 2 || calls[0].etag != "" || calls[1].etag != `"combined-etag"` {
		t.Fatalf("combined query ETag calls = %+v", calls)
	}
	store.mu.Lock()
	stateCount := len(store.states)
	store.mu.Unlock()
	if stateCount != 1 {
		t.Fatalf("keyword reordering created %d state rows, want 1", stateCount)
	}
}

func TestServiceExecutesEnabledNamedRulesSeriallyAndAggregatesRunStats(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{results: []SearchResult{
		{ETag: `"example-corp"`, RateRemaining: 9, Items: []SearchItem{{Repository: "owner/one", Path: "one.env"}}},
		{ETag: `"access"`, RateRemaining: 8, Items: []SearchItem{{Repository: "owner/two", Path: "two.env"}, {Repository: "owner/three", Path: "three.env"}}},
	}}
	detector := serviceTestDetector{candidates: []Candidate{{
		SecretType: "generic_secret_assignment", Confidence: "suspected", Severity: "medium",
		Fingerprint: "sanitized-fingerprint", MaskedExcerpt: "value=<redacted>",
	}}}
	settings := serviceSettings(false)
	settings.Keywords = []string{"legacy.example", "hidden"}
	settings.Rules = []Rule{
		{Enabled: true, Name: "example-corp-clientid", Keywords: []string{"vendor.example", "clientid"}},
		{Enabled: false, Name: "disabled", Keywords: []string{"disabled.example", "secret"}},
		{Enabled: true, Name: "access-key", Keywords: []string{"example.com", "ACCESSKEY"}},
	}
	service, err := newService(store, settings, provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	if run.Status != "success" || run.Requests != 2 || run.Processed != 3 || run.Detected != 3 || run.RateRemaining != 8 {
		t.Fatalf("aggregated run = %+v", run)
	}
	calls := provider.callSnapshot()
	if len(calls) != 2 || calls[0].keywords[0] != "clientid" || calls[1].keywords[0] != "ACCESSKEY" {
		t.Fatalf("ordered provider calls = %+v", calls)
	}
	store.mu.Lock()
	ruleNames := make([]string, 0, len(store.candidates))
	for _, candidate := range store.candidates {
		ruleNames = append(ruleNames, candidate.RuleName)
	}
	store.mu.Unlock()
	if fmt.Sprint(ruleNames) != "[example-corp-clientid access-key access-key]" {
		t.Fatalf("candidate rule names = %v", ruleNames)
	}
	runtime, err := service.RuntimeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.Rules) != 3 || runtime.Rules[0].Name != "example-corp-clientid" || runtime.Rules[0].Query != `"clientid" AND "vendor.example" in:file` ||
		runtime.Rules[1].Enabled || runtime.Rules[2].Name != "access-key" || runtime.RequestIntervalSeconds != MinIntervalSeconds ||
		runtime.LastRequests != 2 || runtime.LastProcessed != 3 || runtime.LastDetected != 3 {
		t.Fatalf("runtime named rule status = %+v", runtime)
	}
	if len(runtime.Keywords) != 2 || runtime.Query != runtime.Rules[0].Query {
		t.Fatalf("legacy runtime fallback fields = %+v", runtime)
	}
}

func TestServiceContinuesAfterOrdinaryRuleErrorButStopsOnRateLimit(t *testing.T) {
	rules := []Rule{
		{Enabled: true, Name: "first", Keywords: []string{"first.example", "clientid"}},
		{Enabled: true, Name: "second", Keywords: []string{"second.example", "accesskey"}},
	}
	t.Run("ordinary error continues", func(t *testing.T) {
		store := newServiceTestPersistence()
		provider := &serviceTestProvider{
			results: []SearchResult{{}, {ETag: `"second"`, Items: []SearchItem{{Repository: "owner/repo", Path: "config.env"}}}},
			errs:    []error{errors.New("synthetic network failure"), nil},
		}
		settings := serviceSettings(false)
		settings.Rules = rules
		service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		service.execute(context.Background(), service.settings, provider, service.detector)
		run := waitForServiceRun(t, store.finished)
		if run.Status != "partial" || run.Requests != 2 || len(provider.callSnapshot()) != 2 {
			t.Fatalf("ordinary-error run = %+v calls=%+v", run, provider.callSnapshot())
		}
		status, statusErr := service.RuntimeStatus(context.Background())
		if statusErr != nil || status.LastError != "" || status.LastWarning == "" {
			t.Fatalf("partial error runtime = %+v err=%v", status, statusErr)
		}
	})

	t.Run("all rule errors remain errors", func(t *testing.T) {
		store := newServiceTestPersistence()
		provider := &serviceTestProvider{errs: []error{
			errors.New("synthetic first failure"), errors.New("synthetic second failure"),
		}}
		settings := serviceSettings(false)
		settings.Rules = rules
		service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		service.execute(context.Background(), service.settings, provider, service.detector)
		run := waitForServiceRun(t, store.finished)
		status, statusErr := service.RuntimeStatus(context.Background())
		if run.Status != "error" || statusErr != nil || status.LastError == "" || status.LastWarning != "" {
			t.Fatalf("failed run=%+v runtime=%+v err=%v", run, status, statusErr)
		}
	})

	t.Run("rate limit stops", func(t *testing.T) {
		store := newServiceTestPersistence()
		reset := time.Now().UTC().Add(time.Minute)
		provider := &serviceTestProvider{errs: []error{&HTTPStatusError{StatusCode: 403, RateLimited: true, Retryable: true, RateReset: &reset}}}
		settings := serviceSettings(false)
		settings.Rules = rules
		service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		service.execute(context.Background(), service.settings, provider, service.detector)
		run := waitForServiceRun(t, store.finished)
		if run.Status != "rate_limited" || run.Requests != 1 || len(provider.callSnapshot()) != 1 || run.RateResetAt == nil {
			t.Fatalf("rate-limited run = %+v calls=%+v", run, provider.callSnapshot())
		}
		status, statusErr := service.RuntimeStatus(context.Background())
		if statusErr != nil || status.LastError == "" || status.LastWarning != "" {
			t.Fatalf("rate-limited runtime = %+v err=%v", status, statusErr)
		}
	})

	t.Run("authentication failure stops remaining rules", func(t *testing.T) {
		store := newServiceTestPersistence()
		provider := &serviceTestProvider{errs: []error{
			&HTTPStatusError{StatusCode: 401, Retryable: false}, nil,
		}}
		settings := serviceSettings(false)
		settings.Rules = rules
		service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		service.execute(context.Background(), service.settings, provider, service.detector)
		run := waitForServiceRun(t, store.finished)
		if run.Status != "error" || run.Requests != 1 || len(provider.callSnapshot()) != 1 ||
			!strings.Contains(strings.ToLower(run.Error), "authentication") {
			t.Fatalf("authentication-failure run = %+v calls=%+v", run, provider.callSnapshot())
		}
	})
}

func TestRunTimeoutScalesWithEnabledRuleCount(t *testing.T) {
	settings := serviceSettings(true)
	settings.IntervalSeconds = 60
	settings.RequestTimeoutSeconds = 45
	if got := runTimeoutForRules(settings, MaxRules); got < 61*time.Minute {
		t.Fatalf("32-rule timeout = %s, want at least 61m", got)
	}
	if got := runTimeoutForRules(settings, 1); got != 30*time.Minute {
		t.Fatalf("single-rule timeout = %s, want 30m", got)
	}
}
