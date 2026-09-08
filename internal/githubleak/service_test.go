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
	findings   map[string]Finding
	finished   chan RunRecord
	listFilter ListFilter
	statsAfter *time.Time
	upsertErr  error
}

func newServiceTestPersistence() *serviceTestPersistence {
	return &serviceTestPersistence{
		lock: true, states: make(map[string]KeywordState), findings: make(map[string]Finding), finished: make(chan RunRecord, 8),
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
	if p.upsertErr != nil {
		return 0, 0, p.upsertErr
	}
	p.candidates = append(p.candidates, candidates...)
	return len(candidates), 0, nil
}

func (p *serviceTestPersistence) List(_ context.Context, filter ListFilter) (ListResult, error) {
	p.mu.Lock()
	p.listFilter = filter
	p.mu.Unlock()
	return ListResult{}, nil
}

func (p *serviceTestPersistence) Get(_ context.Context, id string) (Finding, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	finding, ok := p.findings[id]
	if !ok {
		return Finding{}, ErrNotFound
	}
	return finding, nil
}

func (p *serviceTestPersistence) UpdateStatus(_ context.Context, id, status string) (Finding, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	finding, ok := p.findings[id]
	if !ok || !ValidStatus(status) {
		return Finding{}, ErrNotFound
	}
	finding.Status = status
	p.findings[id] = finding
	return finding, nil
}

func (p *serviceTestPersistence) Stats(_ context.Context, sourceUpdatedAfter *time.Time) (Stats, error) {
	p.mu.Lock()
	p.statsAfter = copyTime(sourceUpdatedAfter)
	p.mu.Unlock()
	return Stats{}, nil
}

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
	mu               sync.Mutex
	calls            []serviceProviderCall
	metadataCalls    []SearchItem
	result           SearchResult
	err              error
	results          []SearchResult
	errs             []error
	latestCommitAt   time.Time
	latestCommitErr  error
	latestCommitAts  []time.Time
	latestCommitErrs []error
	started          chan struct{}
	release          <-chan struct{}
	once             sync.Once
}

func (p *serviceTestProvider) LatestPathCommitAt(_ context.Context, item SearchItem) (time.Time, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	callIndex := len(p.metadataCalls)
	p.metadataCalls = append(p.metadataCalls, item)
	updatedAt, err := p.latestCommitAt, p.latestCommitErr
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	if callIndex < len(p.latestCommitAts) {
		updatedAt = p.latestCommitAts[callIndex]
	}
	if callIndex < len(p.latestCommitErrs) {
		err = p.latestCommitErrs[callIndex]
	}
	return updatedAt, err
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

func (p *serviceTestProvider) metadataCallSnapshot() []SearchItem {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]SearchItem(nil), p.metadataCalls...)
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
	freshnessCheckedAt := time.Now().UTC()
	rule, ruleErr := newKeywordRule([]string{"storage-service"})
	if ruleErr != nil {
		t.Fatal(ruleErr)
	}
	store.states[rule.Query] = KeywordState{Keyword: rule.Query, ETag: `"complete-etag"`, FreshnessPolicy: freshnessPolicy(DefaultLookbackDays), FreshnessCheckedAt: &freshnessCheckedAt, LastAttemptAt: &oldAttempt, LastStatus: "success"}
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
	settings := serviceSettings(false, "vendor.example", "storage-service", "STORAGE-SERVICE")
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

func TestServiceInvalidatesETagWhenFreshnessPolicyChanges(t *testing.T) {
	store := newServiceTestPersistence()
	rule, err := newKeywordRule([]string{"example.com", "secret"})
	if err != nil {
		t.Fatal(err)
	}
	store.states[rule.Query] = KeywordState{Keyword: rule.Query, ETag: `"legacy-etag"`, FreshnessPolicy: ""}
	provider := &serviceTestProvider{result: SearchResult{ETag: `"lookback-etag"`}}
	settings := serviceSettings(false, "example.com", "secret")
	settings.LookbackDays = 365
	service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	_ = waitForServiceRun(t, store.finished)
	calls := provider.callSnapshot()
	if len(calls) != 1 || calls[0].etag != "" {
		t.Fatalf("freshness policy reused stale ETag: %+v", calls)
	}
	store.mu.Lock()
	state := store.states[rule.Query]
	store.mu.Unlock()
	if state.FreshnessPolicy != freshnessPolicy(365) || state.ETag != `"lookback-etag"` {
		t.Fatalf("state = %+v", state)
	}
}

func TestServiceFiltersDetectedCandidatesByPathCommitLookback(t *testing.T) {
	tests := []struct {
		name          string
		latestCommit  time.Time
		latestErr     error
		wantStatus    string
		wantDetected  int
		wantStored    int
		wantStateETag string
	}{
		{name: "fresh path is retained", latestCommit: time.Now().UTC().AddDate(0, 0, -30), wantStatus: "success", wantDetected: 1, wantStored: 1, wantStateETag: `"freshness-etag"`},
		{name: "small source clock skew is retained", latestCommit: time.Now().UTC().Add(5 * time.Minute), wantStatus: "success", wantDetected: 1, wantStored: 1, wantStateETag: `"freshness-etag"`},
		{name: "stale path is excluded", latestCommit: time.Now().UTC().AddDate(0, 0, -400), wantStatus: "success", wantDetected: 0, wantStored: 0, wantStateETag: `"freshness-etag"`},
		{name: "future path timestamp is rejected", latestCommit: time.Now().UTC().Add(24 * time.Hour), wantStatus: "partial", wantDetected: 0, wantStored: 0, wantStateETag: ""},
		{name: "metadata failure is partial and retryable", latestErr: errors.New("synthetic metadata failure"), wantStatus: "partial", wantDetected: 0, wantStored: 0, wantStateETag: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newServiceTestPersistence()
			provider := &serviceTestProvider{
				result: SearchResult{ETag: `"freshness-etag"`, Items: []SearchItem{{
					RepoNodeID: "R_shared", Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("a", 40),
					HTMLURL: "https://github.com/owner/repo/blob/main/config.env",
				}}},
				latestCommitAt:  tt.latestCommit,
				latestCommitErr: tt.latestErr,
			}
			detector := serviceTestDetector{candidates: []Candidate{{Fingerprint: "sanitized-fingerprint"}}}
			settings := serviceSettings(false, "example.com", "secret")
			settings.LookbackDays = 365
			service, err := newService(store, settings, provider, detector, nil)
			if err != nil {
				t.Fatal(err)
			}
			service.execute(context.Background(), service.settings, provider, detector)
			run := waitForServiceRun(t, store.finished)
			if run.Status != tt.wantStatus || run.Detected != tt.wantDetected || run.Requests != 2 {
				t.Fatalf("run = %+v", run)
			}
			if got := len(provider.metadataCallSnapshot()); got != 1 {
				t.Fatalf("metadata calls = %d, want 1", got)
			}
			store.mu.Lock()
			stored := len(store.candidates)
			state := store.states[`"example.com" AND "secret" in:file`]
			var sourceUpdatedAt time.Time
			if stored > 0 {
				sourceUpdatedAt = store.candidates[0].SourceUpdatedAt
			}
			store.mu.Unlock()
			if stored != tt.wantStored || state.ETag != tt.wantStateETag {
				t.Fatalf("stored=%d state=%+v", stored, state)
			}
			if stored > 0 && !sourceUpdatedAt.Equal(tt.latestCommit) {
				t.Fatalf("stored source update time = %v, want %v", sourceUpdatedAt, tt.latestCommit)
			}
		})
	}
}

func TestServiceRevalidatesFreshnessDailyDespiteSearchETag(t *testing.T) {
	tests := []struct {
		name       string
		checkedAgo time.Duration
		wantETag   string
	}{
		{name: "recent freshness check reuses ETag", checkedAgo: 23 * time.Hour, wantETag: `"current"`},
		{name: "old freshness check forces full response", checkedAgo: 25 * time.Hour, wantETag: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newServiceTestPersistence()
			rule, err := newKeywordRule([]string{"example.com", "secret"})
			if err != nil {
				t.Fatal(err)
			}
			checkedAt := time.Now().UTC().Add(-tt.checkedAgo)
			store.states[rule.Query] = KeywordState{
				Keyword: rule.Query, ETag: `"current"`, FreshnessPolicy: freshnessPolicy(DefaultLookbackDays),
				FreshnessCheckedAt: &checkedAt, LastStatus: "success",
			}
			provider := &serviceTestProvider{result: SearchResult{ETag: `"next"`}}
			service, err := newService(store, serviceSettings(false, "example.com", "secret"), provider, serviceTestDetector{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			service.execute(context.Background(), service.settings, provider, service.detector)
			_ = waitForServiceRun(t, store.finished)
			calls := provider.callSnapshot()
			if len(calls) != 1 || calls[0].etag != tt.wantETag {
				t.Fatalf("search calls = %+v", calls)
			}
			store.mu.Lock()
			state := store.states[rule.Query]
			store.mu.Unlock()
			if state.FreshnessCheckedAt == nil || !state.FreshnessCheckedAt.After(checkedAt) {
				t.Fatalf("freshness check timestamp was not advanced: %+v", state)
			}
		})
	}
}

func TestServiceStopsRunAfterMetadataFailure(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{
		results:         []SearchResult{{Items: []SearchItem{{Repository: "owner/one", Path: "one.env"}}}, {Items: []SearchItem{{Repository: "owner/two", Path: "two.env"}}}},
		latestCommitErr: errors.New("synthetic metadata failure"),
	}
	settings := serviceSettings(false)
	settings.Rules = []Rule{
		{Enabled: true, Name: "first", Keywords: []string{"first.example", "secret"}},
		{Enabled: true, Name: "second", Keywords: []string{"second.example", "secret"}},
	}
	detector := serviceTestDetector{candidates: []Candidate{{Fingerprint: "sanitized-fingerprint"}}}
	service, err := newService(store, settings, provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, detector)
	run := waitForServiceRun(t, store.finished)
	if run.Status != "partial" || run.Requests != 2 || run.Processed != 0 || len(provider.callSnapshot()) != 1 || len(provider.metadataCallSnapshot()) != 1 {
		t.Fatalf("metadata failure did not stop run: run=%+v searches=%d metadata=%d", run, len(provider.callSnapshot()), len(provider.metadataCallSnapshot()))
	}
	store.mu.Lock()
	state := store.states[`"first.example" AND "secret" in:file`]
	store.mu.Unlock()
	if state.LastSuccessAt != nil {
		t.Fatalf("partial freshness run advanced last success: %+v", state)
	}
}

func TestServiceSharesMetadataBudgetAcrossTruncatedRules(t *testing.T) {
	store := newServiceTestPersistence()
	makeItems := func(offset, count int) []SearchItem {
		items := make([]SearchItem, 0, count)
		for i := 0; i < count; i++ {
			n := offset + i
			items = append(items, SearchItem{RepoNodeID: fmt.Sprintf("R_%d", n), Repository: "owner/repo", Path: fmt.Sprintf("config-%d.env", n), BlobSHA: strings.Repeat("a", 40)})
		}
		return items
	}
	provider := &serviceTestProvider{results: []SearchResult{
		{Items: makeItems(0, 100), Truncated: true},
		{Items: makeItems(100, 100), Truncated: true},
		{Items: makeItems(200, 100), Truncated: true},
	}}
	settings := serviceSettings(false)
	settings.Rules = []Rule{
		{Enabled: true, Name: "first", Keywords: []string{"first.example", "secret"}},
		{Enabled: true, Name: "second", Keywords: []string{"second.example", "secret"}},
		{Enabled: true, Name: "third", Keywords: []string{"third.example", "secret"}},
	}
	detector := serviceTestDetector{candidates: []Candidate{{Fingerprint: "sanitized-fingerprint"}}}
	service, err := newService(store, settings, provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, detector)
	run := waitForServiceRun(t, store.finished)
	wantMetadata := maxFreshnessChecksPerRun
	metadataCalls := provider.metadataCallSnapshot()
	if run.Status != "partial" || run.Requests != wantMetadata+len(settings.Rules) || run.Detected != wantMetadata ||
		len(provider.callSnapshot()) != len(settings.Rules) || len(metadataCalls) != wantMetadata || run.Error == "" {
		t.Fatalf("metadata budget run=%+v searches=%d metadata=%d", run, len(provider.callSnapshot()), len(provider.metadataCallSnapshot()))
	}
	seenThirdRule := false
	for _, item := range metadataCalls {
		if strings.HasPrefix(item.Path, "config-2") {
			seenThirdRule = true
			break
		}
	}
	if !seenThirdRule {
		t.Fatal("a persistently truncated earlier rule starved the final rule")
	}
	store.mu.Lock()
	for _, state := range store.states {
		if state.LastStatus == "partial" && !strings.Contains(state.LastError, "limit") {
			store.mu.Unlock()
			t.Fatalf("budget-limited state lost its reason: %+v", state)
		}
	}
	store.mu.Unlock()
}

func TestServicePersistsCursorAcrossBudgetLimitedRuns(t *testing.T) {
	store := newServiceTestPersistence()
	items := make([]SearchItem, 0, 100)
	for i := 0; i < 100; i++ {
		items = append(items, SearchItem{RepoNodeID: fmt.Sprintf("R_%d", i), Repository: "owner/repo", Path: fmt.Sprintf("config-%d.env", i), BlobSHA: strings.Repeat("a", 40)})
	}
	provider := &serviceTestProvider{results: []SearchResult{
		{Items: items, Truncated: true, ETag: `"snapshot-v1"`}, {}, {},
		{Items: items, Truncated: true, ETag: `"snapshot-v1"`}, {}, {},
		{Items: items, Truncated: true, ETag: `"snapshot-v2"`}, {}, {},
	}}
	settings := serviceSettings(false)
	settings.Rules = []Rule{
		{Enabled: true, Name: "first", Keywords: []string{"first.example", "secret"}},
		{Enabled: true, Name: "second", Keywords: []string{"second.example", "secret"}},
		{Enabled: true, Name: "third", Keywords: []string{"third.example", "secret"}},
	}
	detector := serviceTestDetector{candidates: []Candidate{{Fingerprint: "sanitized-fingerprint"}}}
	service, err := newService(store, settings, provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	perRuleLimit := maxFreshnessChecksPerRun / len(settings.Rules)
	service.execute(context.Background(), service.settings, provider, detector)
	firstRun := waitForServiceRun(t, store.finished)
	store.mu.Lock()
	firstState := store.states[`"first.example" AND "secret" in:file`]
	store.mu.Unlock()
	if firstRun.Status != "partial" || firstState.FreshnessCursor != perRuleLimit || firstState.FreshnessCursorETag != `"snapshot-v1"` {
		t.Fatalf("first cursor run=%+v state=%+v", firstRun, firstState)
	}
	service.execute(context.Background(), service.settings, provider, detector)
	secondRun := waitForServiceRun(t, store.finished)
	metadataCalls := provider.metadataCallSnapshot()
	if secondRun.Status != "partial" || len(metadataCalls) != 2*perRuleLimit || metadataCalls[perRuleLimit].Path != fmt.Sprintf("config-%d.env", perRuleLimit) {
		t.Fatalf("second cursor run=%+v metadata=%d first-new=%q", secondRun, len(metadataCalls), metadataCalls[perRuleLimit].Path)
	}
	service.execute(context.Background(), service.settings, provider, detector)
	thirdRun := waitForServiceRun(t, store.finished)
	metadataCalls = provider.metadataCallSnapshot()
	if thirdRun.Status != "partial" || len(metadataCalls) != 3*perRuleLimit || metadataCalls[2*perRuleLimit].Path != "config-0.env" {
		t.Fatalf("changed snapshot did not reset cursor: run=%+v metadata=%d first-new=%q", thirdRun, len(metadataCalls), metadataCalls[2*perRuleLimit].Path)
	}
}

func TestServiceDoesNotAdvanceCursorWhenCandidateTransactionFails(t *testing.T) {
	store := newServiceTestPersistence()
	items := make([]SearchItem, 0, 100)
	for i := 0; i < 100; i++ {
		items = append(items, SearchItem{RepoNodeID: fmt.Sprintf("R_%d", i), Repository: "owner/repo", Path: fmt.Sprintf("config-%d.env", i), BlobSHA: strings.Repeat("a", 40)})
	}
	provider := &serviceTestProvider{results: []SearchResult{
		{Items: items, Truncated: true, ETag: `"snapshot"`}, {}, {},
		{Items: items, Truncated: true, ETag: `"snapshot"`}, {}, {},
	}}
	settings := serviceSettings(false)
	settings.Rules = []Rule{
		{Enabled: true, Name: "first", Keywords: []string{"first.example", "secret"}},
		{Enabled: true, Name: "second", Keywords: []string{"second.example", "secret"}},
		{Enabled: true, Name: "third", Keywords: []string{"third.example", "secret"}},
	}
	detector := serviceTestDetector{candidates: []Candidate{{Fingerprint: "sanitized-fingerprint"}}}
	service, err := newService(store, settings, provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.upsertErr = errors.New("synthetic transaction failure")
	service.execute(context.Background(), service.settings, provider, detector)
	_ = waitForServiceRun(t, store.finished)
	store.mu.Lock()
	failedState := store.states[`"first.example" AND "secret" in:file`]
	store.upsertErr = nil
	store.mu.Unlock()
	if failedState.FreshnessCursor != 0 {
		t.Fatalf("failed transaction advanced cursor: %+v", failedState)
	}
	perRuleLimit := maxFreshnessChecksPerRun / len(settings.Rules)
	service.execute(context.Background(), service.settings, provider, detector)
	_ = waitForServiceRun(t, store.finished)
	metadataCalls := provider.metadataCallSnapshot()
	if len(metadataCalls) != 2*perRuleLimit || metadataCalls[perRuleLimit].Path != "config-0.env" {
		t.Fatalf("retry skipped uncommitted batch: metadata=%d first-retry=%q", len(metadataCalls), metadataCalls[perRuleLimit].Path)
	}
}

func TestServiceSkipsItemLocalMetadataErrorAndContinuesRules(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{
		results: []SearchResult{
			{Items: []SearchItem{{Repository: "owner/one", Path: "deleted.env"}, {Repository: "owner/one", Path: "live.env"}}},
			{Items: []SearchItem{{Repository: "owner/two", Path: "live.env"}}},
		},
		latestCommitErrs: []error{errPathCommitUnavailable, nil, nil},
	}
	settings := serviceSettings(false)
	settings.Rules = []Rule{
		{Enabled: true, Name: "first", Keywords: []string{"first.example", "secret"}},
		{Enabled: true, Name: "second", Keywords: []string{"second.example", "secret"}},
	}
	detector := serviceTestDetector{candidates: []Candidate{{Fingerprint: "sanitized-fingerprint"}}}
	service, err := newService(store, settings, provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, detector)
	run := waitForServiceRun(t, store.finished)
	if run.Status != "partial" || len(provider.callSnapshot()) != 2 || len(provider.metadataCallSnapshot()) != 3 || run.Detected != 2 {
		t.Fatalf("item-local metadata error blocked later work: run=%+v searches=%d metadata=%d", run, len(provider.callSnapshot()), len(provider.metadataCallSnapshot()))
	}
}

func TestServiceMetadataRateLimitStopsRunAndPreservesReset(t *testing.T) {
	store := newServiceTestPersistence()
	reset := time.Now().UTC().Add(5 * time.Minute)
	provider := &serviceTestProvider{
		result:          SearchResult{Items: []SearchItem{{Repository: "owner/one", Path: "one.env"}}},
		latestCommitErr: &HTTPStatusError{StatusCode: 429, RateLimited: true, Retryable: true, RateReset: &reset},
	}
	settings := serviceSettings(false)
	settings.Rules = []Rule{
		{Enabled: true, Name: "first", Keywords: []string{"first.example", "secret"}},
		{Enabled: true, Name: "second", Keywords: []string{"second.example", "secret"}},
	}
	detector := serviceTestDetector{candidates: []Candidate{{Fingerprint: "sanitized-fingerprint"}}}
	service, err := newService(store, settings, provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	gotReset := service.execute(context.Background(), service.settings, provider, detector)
	run := waitForServiceRun(t, store.finished)
	if run.Status != "rate_limited" || run.RateResetAt == nil || !run.RateResetAt.Equal(reset) || gotReset == nil || !gotReset.Equal(reset) ||
		len(provider.callSnapshot()) != 1 || len(provider.metadataCallSnapshot()) != 1 {
		t.Fatalf("metadata rate limit = run:%+v returned:%v searches:%d metadata:%d", run, gotReset, len(provider.callSnapshot()), len(provider.metadataCallSnapshot()))
	}
}

func TestServiceListAndStatsApplyCurrentLookbackWindow(t *testing.T) {
	store := newServiceTestPersistence()
	settings := serviceSettings(false, "example.com", "secret")
	settings.LookbackDays = 30
	service, err := newService(store, settings, &serviceTestProvider{}, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().AddDate(0, 0, -30)
	userCutoff := time.Now().UTC().AddDate(-10, 0, 0)
	if _, err = service.List(context.Background(), ListFilter{Page: 1, PageSize: 20, SourceUpdatedAfter: &userCutoff}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Stats(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC().AddDate(0, 0, -30)
	store.mu.Lock()
	listCutoff := copyTime(store.listFilter.SourceUpdatedAfter)
	statsCutoff := copyTime(store.statsAfter)
	store.mu.Unlock()
	for name, cutoff := range map[string]*time.Time{"list": listCutoff, "stats": statsCutoff} {
		if cutoff == nil || cutoff.Before(before) || cutoff.After(after) {
			t.Fatalf("%s cutoff = %v, want between %v and %v", name, cutoff, before, after)
		}
	}
}

func TestServiceHidesStaleFindingDeepLinksAndUpdates(t *testing.T) {
	store := newServiceTestPersistence()
	freshAt := time.Now().UTC().AddDate(0, 0, -7)
	staleAt := time.Now().UTC().AddDate(0, 0, -400)
	store.findings["fresh"] = Finding{ID: "fresh", Status: "new", SourceUpdatedAt: &freshAt}
	store.findings["stale"] = Finding{ID: "stale", Status: "new", SourceUpdatedAt: &staleAt}
	store.findings["legacy"] = Finding{ID: "legacy", Status: "new"}
	service, err := newService(store, serviceSettings(false, "example.com", "secret"), &serviceTestProvider{}, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if finding, getErr := service.Get(context.Background(), "fresh"); getErr != nil || finding.ID != "fresh" {
		t.Fatalf("fresh finding = %+v, %v", finding, getErr)
	}
	for _, id := range []string{"stale", "legacy"} {
		if _, getErr := service.Get(context.Background(), id); !errors.Is(getErr, ErrNotFound) {
			t.Fatalf("%s finding remained visible: %v", id, getErr)
		}
		if _, updateErr := service.UpdateStatus(context.Background(), id, "triaged"); !errors.Is(updateErr, ErrNotFound) {
			t.Fatalf("%s finding remained mutable: %v", id, updateErr)
		}
	}
	if finding, updateErr := service.UpdateStatus(context.Background(), "fresh", "triaged"); updateErr != nil || finding.Status != "triaged" {
		t.Fatalf("fresh finding update = %+v, %v", finding, updateErr)
	}
}

func TestServiceReusesPathCommitFreshnessAcrossRules(t *testing.T) {
	store := newServiceTestPersistence()
	item := SearchItem{
		RepoNodeID: "R_shared", Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("a", 40),
		HTMLURL: "https://github.com/owner/repo/blob/main/config.env",
	}
	provider := &serviceTestProvider{
		results:        []SearchResult{{Items: []SearchItem{item}}, {Items: []SearchItem{item}}},
		latestCommitAt: time.Now().UTC().AddDate(0, 0, -7),
	}
	settings := serviceSettings(false)
	settings.Rules = []Rule{
		{Enabled: true, Name: "secret", Keywords: []string{"example.com", "secret"}},
		{Enabled: true, Name: "api-key", Keywords: []string{"example.com", "api_key"}},
	}
	detector := serviceTestDetector{candidates: []Candidate{{Fingerprint: "sanitized-fingerprint"}}}
	service, err := newService(store, settings, provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, detector)
	run := waitForServiceRun(t, store.finished)
	if run.Status != "success" || run.Requests != 3 || run.Detected != 2 {
		t.Fatalf("run = %+v", run)
	}
	if got := len(provider.metadataCallSnapshot()); got != 1 {
		t.Fatalf("metadata calls = %d, want one cached lookup", got)
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
	if run.Status != "success" || run.Requests != 5 || run.Processed != 3 || run.Detected != 3 || run.RateRemaining != 8 {
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
		runtime.LastRequests != 5 || runtime.LastProcessed != 3 || runtime.LastDetected != 3 || runtime.LookbackDays != DefaultLookbackDays {
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
		t.Fatalf("%d-rule timeout = %s, want at least 61m", MaxRules, got)
	}
	if got := runTimeoutForRules(settings, 14); got < 33*time.Minute {
		t.Fatalf("14-rule timeout = %s, metadata allowance was omitted", got)
	}
	if got := runTimeoutForRules(settings, 1); got != 30*time.Minute {
		t.Fatalf("single-rule timeout = %s, want 30m", got)
	}
}
