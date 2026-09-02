package vulnintel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/testutil/testpostgres"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := testpostgres.DSN(t)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := NewStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestStoreMergeIdempotencyFiltersAndIsolation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.db.Exec(`CREATE TABLE vulnerabilities(id INTEGER PRIMARY KEY); INSERT INTO vulnerabilities VALUES(1)`); err != nil {
		t.Fatal(err)
	}
	nvd := sampleNVD(t)
	kev := sampleKEV()
	kev.Vendor = "ExampleVendor"
	for i := 0; i < 2; i++ {
		if err := s.SaveNVD(ctx, []NVDRecord{nvd}); err != nil {
			t.Fatal(err)
		}
		if err := s.ReplaceKEV(ctx, []KEVRecord{kev}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Detail(ctx, nvd.ID)
	if err != nil || r.NVD == nil || r.KEV == nil || len(r.Sources) != 2 || !r.KnownExploited {
		t.Fatalf("merge %+v err=%v", r, err)
	}
	for _, f := range []Filter{{Query: "examplevendor"}, {Query: nvd.ID}, {Source: "kev", Severity: "critical", Exploited: true}} {
		f.Page = 1
		f.PageSize = 25
		res, err := s.List(ctx, f)
		if err != nil || res.Total != 1 {
			t.Fatalf("filter %+v -> %+v, %v", f, res, err)
		}
	}
	for _, query := range []string{"' OR 1=1 --", "%", "_"} {
		res, err := s.List(ctx, Filter{Query: query, Page: 1, PageSize: 25})
		if err != nil || res.Total != 0 {
			t.Fatalf("literal query %q -> %+v %v", query, res, err)
		}
	}
	var findings int
	s.db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&findings)
	if findings != 1 {
		t.Fatal("public intelligence changed asset findings")
	}
	stats, err := s.Stats(ctx)
	if err != nil || stats.Total != 1 || stats.KEV != 1 || stats.CriticalHigh != 1 {
		t.Fatalf("stats %+v %v", stats, err)
	}
	if _, err = s.List(ctx, Filter{Source: "nvd; DROP TABLE vulnerabilities", Page: 1, PageSize: 25}); err == nil {
		t.Fatal("source injection accepted")
	}
}
func TestKEVRemovalAndFailedSnapshotPreservesPrevious(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	nvd := sampleNVD(t)
	if err := s.SaveNVD(ctx, []NVDRecord{nvd}); err != nil {
		t.Fatal(err)
	}
	first := sampleKEV()
	second := first
	second.ID = "CVE-2026-12346"
	if err := s.ReplaceKEV(ctx, []KEVRecord{first, second}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceKEV(ctx, nil); err == nil {
		t.Fatal("empty snapshot accepted")
	}
	if err := s.ReplaceKEV(ctx, []KEVRecord{first, first}); err == nil {
		t.Fatal("duplicate snapshot accepted")
	}
	stats, _ := s.Stats(ctx)
	if stats.KEV != 2 || stats.Unknown != 1 {
		t.Fatalf("previous snapshot lost: %+v", stats)
	}
	third := first
	third.ID = "CVE-2026-12347"
	if err := s.ReplaceKEV(ctx, []KEVRecord{third}); err != nil {
		t.Fatal(err)
	}
	r, err := s.Detail(ctx, first.ID)
	if err != nil || r.NVD == nil || r.KEV != nil || r.KnownExploited {
		t.Fatalf("removed KEV state %+v %v", r, err)
	}
	if _, err = s.Detail(ctx, second.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("orphan removed KEV still present")
	}
}
func TestNVDBatchRollbackAndOlderUpdateIgnored(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	r := sampleNVD(t)
	bad := r
	bad.ID = "invalid"
	if err := s.SaveNVD(ctx, []NVDRecord{r, bad}); err == nil {
		t.Fatal("invalid batch succeeded")
	}
	stats, _ := s.Stats(ctx)
	if stats.Total != 0 {
		t.Fatal("partial transaction committed")
	}
	if err := s.SaveNVD(ctx, []NVDRecord{r}); err != nil {
		t.Fatal(err)
	}
	r.Modified = r.Modified.Add(-time.Hour)
	r.Description = "outdated"
	if err := s.SaveNVD(ctx, []NVDRecord{r}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Detail(ctx, r.ID)
	if got.Description == "outdated" {
		t.Fatal("outdated NVD overwrote newer record")
	}
}
func TestWorkerCheckpointFailureRecoveryAndIncremental(t *testing.T) {
	s := testStore(t)
	svc := NewService(s, nil)
	svc.client.nvdSpacing = 0
	ctx := context.Background()
	calls := 0
	fail := true
	incremental := false
	svc.client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if incremental && !r.URL.Query().Has("hasKev") && r.URL.Query().Get("lastModStartDate") == "" {
			t.Fatal("checkpoint not used for incremental sync")
		}
		if fail {
			if calls == 1 {
				return response(200, pageJSON(0, 2, sampleCVE)), nil
			}
			return response(200, `{}`), nil
		}
		return response(200, pageJSON(0, 1, sampleCVE)), nil
	})
	svc.run(ctx, []string{"nvd"})
	states, _ := s.Sources(ctx)
	state := states[1]
	if state.Source != "nvd" || state.Checkpoint != nil || state.Status != "error" || state.Processed != 1 {
		t.Fatalf("failed checkpoint %+v", state)
	}
	fail = false
	svc.run(ctx, []string{"nvd"})
	states, _ = s.Sources(ctx)
	state = states[1]
	if state.Checkpoint == nil || state.LastSuccess == nil || state.Status != "success" {
		t.Fatalf("retry failed %+v", state)
	}
	incremental = true
	svc.run(ctx, []string{"nvd"})
	stats, _ := s.Stats(ctx)
	if stats.Total != 1 {
		t.Fatalf("retry duplicated records %+v", stats)
	}
}

func TestRejectedArchiveFiltersStatsAndRestoration(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	active := sampleNVD(t)
	active.Score, active.Severity = nil, "unknown"
	rejected := active
	rejected.ID, rejected.Status = "CVE-2026-12346", "Rejected"
	if err := s.SaveNVD(ctx, []NVDRecord{active, rejected}); err != nil {
		t.Fatal(err)
	}
	kev := sampleKEV()
	kev.ID = "CVE-2020-12345"
	if err := s.ReplaceKEV(ctx, []KEVRecord{kev}); err != nil {
		t.Fatal(err)
	}
	stats, err := s.Stats(ctx)
	if err != nil || stats.Total != 3 || stats.Active != 2 || stats.Rejected != 1 || stats.Unknown != 2 {
		t.Fatalf("stats %+v %v", stats, err)
	}
	for status, want := range map[string]int{"": 2, "active": 2, "rejected": 1, "all": 3} {
		got, err := s.List(ctx, Filter{Status: status, Severity: "unknown", Page: 1, PageSize: 25})
		if err != nil || got.Total != want {
			t.Fatalf("status=%q got=%+v err=%v", status, got, err)
		}
	}
	for id, reason := range map[string]string{active.ID: "no_cvss", rejected.ID: "rejected", kev.ID: "missing_nvd"} {
		got, err := s.Detail(ctx, id)
		if err != nil || got.RatingReason != reason {
			t.Fatalf("detail %+v %v", got, err)
		}
	}
	if _, err := s.List(ctx, Filter{Status: "all OR TRUE", Page: 1, PageSize: 25}); err == nil {
		t.Fatal("invalid lifecycle filter accepted")
	}
	rejected.Status = "Analyzed"
	rejected.Modified = rejected.Modified.Add(time.Hour)
	if err := s.SaveNVD(ctx, []NVDRecord{rejected}); err != nil {
		t.Fatal(err)
	}
	stats, err = s.Stats(ctx)
	if err != nil || stats.Rejected != 0 || stats.Active != 3 {
		t.Fatalf("upstream reinstatement lost: %+v %v", stats, err)
	}
}

func TestWorkerBackfillFailureKeepsCheckpointAndRetries(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	checkpoint := time.Now().Add(-time.Hour)
	if err := s.finish(ctx, "nvd", checkpoint, 0, "old", nil); err != nil {
		t.Fatal(err)
	}
	kev := sampleKEV()
	kev.ID = "CVE-2021-44228"
	if err := s.ReplaceKEV(ctx, []KEVRecord{kev}); err != nil {
		t.Fatal(err)
	}
	svc := NewService(s, nil)
	svc.client.nvdSpacing = 0
	fail := true
	svc.client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Has("hasKev") {
			if fail {
				return response(200, `{}`), nil
			}
			return response(200, pageJSON(0, 1, strings.ReplaceAll(sampleCVE, "CVE-2026-12345", kev.ID))), nil
		}
		if r.URL.Query().Get("lastModStartDate") == "" {
			t.Fatal("incremental checkpoint replaced by KEV history")
		}
		return response(200, pageJSON(0, 1, sampleCVE)), nil
	})
	svc.run(ctx, []string{"nvd"})
	states, _ := s.Sources(ctx)
	if states[1].Status != "error" || states[1].Checkpoint == nil || states[1].Checkpoint.Sub(checkpoint).Abs() > time.Microsecond {
		t.Fatalf("backfill failure advanced checkpoint: %+v", states[1])
	}
	fail = false
	svc.run(ctx, []string{"nvd"})
	got, err := s.Detail(ctx, kev.ID)
	if err != nil || got.Score == nil || got.Severity != "critical" || got.KEV == nil {
		t.Fatalf("historical KEV not hydrated: %+v %v", got, err)
	}
	states, _ = s.Sources(ctx)
	if states[1].Status != "success" || !states[1].Checkpoint.After(checkpoint) {
		t.Fatalf("retry failed: %+v", states[1])
	}
	if states[0].Checkpoint != nil {
		t.Fatal("NVD hydration changed CISA source state")
	}
	if err := s.Enable(ctx, "nvd", false); err != nil {
		t.Fatal(err)
	}
	svc.client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("disabled NVD made a request")
		return nil, context.Canceled
	})
	svc.run(ctx, []string{"nvd"})
}

func TestWorkerRefreshesLegacyAffectedWithoutUpstreamModification(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	legacy := sampleNVD(t)
	legacy.SchemaVersion = 0
	legacy.ID = "CVE-2026-98765"
	if err := s.SaveNVD(ctx, []NVDRecord{legacy}); err != nil {
		t.Fatal(err)
	}
	if err := s.finish(ctx, "nvd", time.Now().Add(-time.Hour), 0, "old", nil); err != nil {
		t.Fatal(err)
	}
	svc := NewService(s, nil)
	svc.client.nvdSpacing = 0
	legacyCalls, fail := 0, true
	svc.client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		q := r.URL.Query()
		if q.Has("hasKev") {
			return response(200, pageJSON(0, 1, sampleCVE)), nil
		}
		if q.Has("lastModStartDate") {
			return response(200, pageJSON(0, 0)), nil
		}
		legacyCalls++
		from, e1 := parseDate(q.Get("pubStartDate"))
		to, e2 := parseDate(q.Get("pubEndDate"))
		if e1 != nil || e2 != nil || !from.Before(legacy.Published) || !to.After(legacy.Published) {
			t.Fatal("legacy publication boundaries excluded")
		}
		if fail {
			return response(200, `{}`), nil
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(sampleCVE), &raw); err != nil {
			t.Fatal(err)
		}
		raw["id"] = legacy.ID
		raw["affected"] = []any{map[string]any{"source": "CNA", "affectedData": []any{map[string]any{"product": "Legacy Gateway", "versions": []any{map[string]any{"lessThan": "2.0", "status": "affected"}}}}}}
		b, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		return response(200, pageJSON(0, 1, string(b))), nil
	})
	svc.run(ctx, []string{"nvd"})
	from, _, err := s.legacyNVDWindow(ctx)
	if err != nil || from == nil {
		t.Fatal("failed refresh removed pending migration")
	}
	fail = false
	svc.run(ctx, []string{"nvd"})
	got, err := s.Detail(ctx, legacy.ID)
	if err != nil || got.NVD.SchemaVersion != nvdSchemaVersion || !strings.Contains(string(got.NVD.Affected), "Legacy Gateway") || !got.NVD.Modified.Equal(legacy.Modified) {
		t.Fatalf("legacy refresh lost evidence: %+v %v", got, err)
	}
	from, _, err = s.legacyNVDWindow(ctx)
	if err != nil || from != nil {
		t.Fatal("migration did not finish")
	}
	svc.run(ctx, []string{"nvd"})
	if legacyCalls != 2 {
		t.Fatalf("already normalized records fetched again: %d", legacyCalls)
	}
}
func TestWorkerGlobalLockAndConcurrentTrigger(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	svc := NewService(s, nil)
	calls := 0
	svc.client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(200, `{}`), nil })
	conn, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", syncLockID); err != nil {
		t.Fatal(err)
	}
	svc.run(ctx, []string{"nvd"})
	if calls != 0 {
		t.Fatal("worker ignored another instance's lock")
	}
	conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", syncLockID)
	if err = svc.Trigger(ctx, "all"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unstarted service accepted work: %v", err)
	}
	svc.ctx = ctx
	svc.active = true
	if err = svc.Trigger(ctx, "nvd"); !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent trigger accepted")
	}
	svc.active = false
	if err = s.Enable(ctx, "nvd", false); err != nil {
		t.Fatal(err)
	}
	if err = svc.Trigger(ctx, "nvd"); !errors.Is(err, ErrNotDue) {
		t.Fatal("disabled source scheduled")
	}
	if err = s.begin(ctx, "kev", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = s.finish(ctx, "kev", time.Now(), 1, "test", nil); err != nil {
		t.Fatal(err)
	}
	if err = svc.Trigger(ctx, "kev"); !errors.Is(err, ErrNotDue) {
		t.Fatal("manual cooldown bypassed")
	}
}
func TestWorkerCancellationRetainsCheckpoint(t *testing.T) {
	s := testStore(t)
	svc := NewService(s, nil)
	svc.client.nvdSpacing = 0
	ctx, cancel := context.WithCancel(context.Background())
	svc.client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { cancel(); return nil, context.Canceled })
	svc.run(ctx, []string{"nvd"})
	states, _ := s.Sources(context.Background())
	if states[1].Status != "error" || states[1].Checkpoint != nil || !strings.Contains(states[1].Error, "canceled") {
		t.Fatalf("cancellation %+v", states[1])
	}
}

func TestEPSSSnapshotAtomicityMissingScoresAndPriorityOrdering(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	r := sampleNVD(t)
	unknown := r
	unknown.ID = "CVE-2026-12346"
	unknown.Score = nil
	unknown.Severity = "unknown"
	low := r
	low.ID = "CVE-2026-12347"
	score := 3.0
	low.Score = &score
	low.Severity = "low"
	if err := s.SaveNVD(ctx, []NVDRecord{r, unknown, low}); err != nil {
		t.Fatal(err)
	}
	kev := sampleKEV()
	kev.ID = low.ID
	if err := s.ReplaceKEV(ctx, []KEVRecord{kev}); err != nil {
		t.Fatal(err)
	}
	date := time.Now().UTC().Format("2006-01-02")
	feed := epssFeed{Date: date, Version: "4", Total: 2, Records: []EPSSRecord{{ID: r.ID, Probability: 0, Percentile: 0, Date: date}, {ID: unknown.ID, Probability: .25, Percentile: .95, Date: date}}}
	if err := s.saveEPSS(ctx, feed); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(ctx, Filter{Page: 1, PageSize: 25, Sort: "priority"})
	if err != nil || got.Items[0].ID != low.ID || got.Items[1].ID != unknown.ID || got.Items[0].Priority != "urgent" || got.Items[1].PriorityReason != "epss_10" {
		t.Fatalf("priority %+v %v", got, err)
	}
	if got.Items[2].EPSS == nil || got.Items[2].EPSS.Probability != 0 {
		t.Fatal("zero EPSS lost")
	}
	bad := feed
	bad.Records = append(append([]EPSSRecord{}, feed.Records...), feed.Records[0])
	bad.Total = 3
	if err = s.saveEPSS(ctx, bad); err == nil {
		t.Fatal("duplicate snapshot accepted")
	}
	feed.Records = feed.Records[:1]
	if err = s.saveEPSS(ctx, feed); err != nil {
		t.Fatal(err)
	}
	detail, err := s.Detail(ctx, unknown.ID)
	if err != nil || detail.EPSS != nil || detail.PriorityReason != "unrated" {
		t.Fatalf("missing score became zero or low priority: %+v %v", detail, err)
	}
	old := feed
	old.Date = time.Now().AddDate(0, 0, -1).UTC().Format("2006-01-02")
	old.Records = append([]EPSSRecord{}, feed.Records...)
	old.Records[0].Date = old.Date
	if err = s.saveEPSS(ctx, old); err == nil {
		t.Fatal("older snapshot replaced new scores")
	}
	detail.EPSS = &EPSSRecord{Probability: .99, Date: time.Now().AddDate(0, 0, -4).UTC().Format("2006-01-02")}
	setPriority(&detail, time.Now())
	if !detail.EPSS.Stale || detail.Priority != "review" {
		t.Fatal("stale EPSS changed priority")
	}
}

func TestSubscriptionsOutboxDeduplicationHistoryAndUserIsolation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	r := sampleNVD(t)
	if err := s.SaveNVD(ctx, []NVDRecord{r}); err != nil {
		t.Fatal(err)
	}
	a, err := s.Subscribe(ctx, "alice", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Subscribe(ctx, "alice", "Example"); err != nil {
		t.Fatal(err)
	}
	b, err := s.Subscribe(ctx, "bob", "Something else")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DispatchNotifications(ctx); err != nil {
		t.Fatal(err)
	}
	initial, _ := s.Notifications(ctx, "alice")
	if initial.Unread != 0 {
		t.Fatal("historical records flooded subscription")
	}
	if err = s.SaveNVD(ctx, []NVDRecord{r}); err != nil {
		t.Fatal(err)
	}
	if err = s.DispatchNotifications(ctx); err != nil {
		t.Fatal(err)
	}
	initial, _ = s.Notifications(ctx, "alice")
	if initial.Unread != 0 {
		t.Fatal("idempotent sync created a notification")
	}
	if err = s.ReplaceKEV(ctx, []KEVRecord{sampleKEV()}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = s.DispatchNotifications(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Notifications(ctx, "alice")
	if err != nil || got.Unread != 1 || len(got.Items) != 1 || got.Items[0].Kind != "kev_added" {
		t.Fatalf("notification %+v %v", got, err)
	}
	bob, _ := s.Notifications(ctx, "bob")
	if bob.Unread != 0 {
		t.Fatal("notification crossed user boundary")
	}
	if err = s.ReadNotifications(ctx, "bob", got.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Notifications(ctx, "alice")
	if got.Unread != 1 {
		t.Fatal("other user marked notification read")
	}
	if err = s.Unsubscribe(ctx, "alice", b.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("cross-user unsubscribe accepted")
	}
	if err = s.ReadNotifications(ctx, "alice", got.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Notifications(ctx, "alice")
	if got.Unread != 0 {
		t.Fatal("own read did not persist")
	}
	r.Score = nil
	r.Severity = "unknown"
	r.Status = "Rejected"
	r.Modified = r.Modified.Add(time.Hour)
	if err = s.SaveNVD(ctx, []NVDRecord{r}); err != nil {
		t.Fatal(err)
	}
	if err = s.DispatchNotifications(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Notifications(ctx, "alice")
	if got.Items[0].Kind != "rejected" || got.Unread != 1 {
		t.Fatalf("retraction not delivered %+v", got)
	}
	if err = s.Unsubscribe(ctx, "alice", a.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAnalysisCachingInvalidationQuotaAndNoOfficialMutation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	r := sampleNVD(t)
	if err := s.SaveNVD(ctx, []NVDRecord{r}); err != nil {
		t.Fatal(err)
	}
	oa := config.OpenAIConfig{Provider: "codex_account", Model: "test-model"}
	calls := 0
	generate := func(ctx context.Context, oa config.OpenAIConfig, system, input string) (string, error) {
		calls++
		if !strings.Contains(system, "不要执行任何工具") || !strings.Contains(input, r.ID) {
			t.Fatal("missing evidence boundaries")
		}
		return `{"summary":"中文摘要","conditions":["核验版本"],"impact":"来源所述影响","remediation":["按厂商公告更新"],"uncertainties":["资产未核验"],"sources":["https://nvd.nist.gov/vuln/detail/` + r.ID + `"]}`, nil
	}
	first, err := s.Analyze(ctx, "alice", r.ID, oa, generate)
	if err != nil || first.Cached || first.Analysis == nil {
		t.Fatalf("analysis %+v %v", first, err)
	}
	second, err := s.Analyze(ctx, "alice", r.ID, oa, generate)
	if err != nil || !second.Cached || calls != 1 {
		t.Fatalf("cache %+v %v calls=%d", second, err, calls)
	}
	bob, err := s.GetAnalysis(ctx, "bob", r.ID, oa)
	if err != nil || bob.Analysis != nil {
		t.Fatal("analysis cache crossed user boundary")
	}
	detail, _ := s.Detail(ctx, r.ID)
	if detail.Score == nil || *detail.Score != *r.Score || detail.Description != r.Description {
		t.Fatal("AI mutated official data")
	}
	r.Description = "Updated source"
	r.Modified = r.Modified.Add(time.Hour)
	if err = s.SaveNVD(ctx, []NVDRecord{r}); err != nil {
		t.Fatal(err)
	}
	view, _ := s.GetAnalysis(ctx, "alice", r.ID, oa)
	if !view.Stale {
		t.Fatal("changed source did not stale cache")
	}
	if _, err = s.Analyze(ctx, "alice", r.ID, oa, generate); !errors.Is(err, ErrAnalysisQuota) {
		t.Fatalf("cooldown bypassed: %v", err)
	}
	if _, err = s.db.Exec(`UPDATE intel_analysis_attempts SET created_at=CURRENT_TIMESTAMP-INTERVAL '61 seconds' WHERE user_id='alice'`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Analyze(ctx, "alice", r.ID, oa, generate); err != nil || calls != 2 {
		t.Fatalf("regeneration failed %v", err)
	}
	oa.Model = "other-model"
	view, _ = s.GetAnalysis(ctx, "alice", r.ID, oa)
	if !view.Stale {
		t.Fatal("model change did not stale cache")
	}
}

func TestAnalysisRejectsFabricatedReferencesAndMalformedOutput(t *testing.T) {
	allowed := map[string]bool{"https://example.com": true}
	base := `{"summary":"摘要","impact":"影响","sources":["https://example.com"]}`
	for _, raw := range []string{base + "junk", base + `{}`, strings.Replace(base, "https://example.com", "https://invented.example", 1), `{"summary":"x","impact":"y","score":10,"sources":[]}`} {
		if _, err := parseAnalysis(raw, allowed); err == nil {
			t.Fatalf("invalid analysis accepted: %s", raw)
		}
	}
}

func TestAnalysisBusyDailyQuotaAndFailureNeverCaches(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	r := sampleNVD(t)
	if err := s.SaveNVD(ctx, []NVDRecord{r}); err != nil {
		t.Fatal(err)
	}
	oa := config.OpenAIConfig{Provider: "codex_account", Model: "test"}
	calls := 0
	generate := func(context.Context, config.OpenAIConfig, string, string) (string, error) {
		calls++
		return "secret-provider-error", errors.New("secret")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(739521805)`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Analyze(ctx, "alice", r.ID, oa, generate); !errors.Is(err, ErrAnalysisBusy) || calls != 0 {
		t.Fatal("global concurrency guard failed")
	}
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(739521805)`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Analyze(ctx, "alice", r.ID, oa, generate); !errors.Is(err, ErrAnalysisFailed) || strings.Contains(err.Error(), "secret") {
		t.Fatal("upstream error leaked")
	}
	result, err := s.GetAnalysis(ctx, "alice", r.ID, oa)
	if err != nil || result.Analysis != nil {
		t.Fatal("failed analysis cached as success")
	}
	if _, err = s.db.Exec(`INSERT INTO intel_analysis_attempts(user_id,cve_id,created_at) SELECT 'bob',$1,CURRENT_TIMESTAMP-INTERVAL '2 minutes' FROM generate_series(1,20)`, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Analyze(ctx, "bob", r.ID, oa, generate); !errors.Is(err, ErrAnalysisQuota) || calls != 1 {
		t.Fatal("daily quota failed")
	}
}
