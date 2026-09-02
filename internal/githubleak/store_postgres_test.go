package githubleak

import (
	"context"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/testutil/testpostgres"

	"go.uber.org/zap"
)

func TestStorePersistsCombinedRuleStateThroughApplicationPostgresWrapper(t *testing.T) {
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewStore(context.Background(), db.DB)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := newKeywordRule([]string{"storage-service", "vendor.example"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	want := KeywordState{
		Keyword: rule.Query, ETag: `W/"integration"`, LastAttemptAt: &now,
		LastSuccessAt: &now, LastStatus: "partial", Incomplete: true, Truncated: true,
	}
	if err = store.SaveKeywordState(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := store.KeywordState(context.Background(), rule.Query)
	if err != nil {
		t.Fatal(err)
	}
	if got.Keyword != want.Keyword || got.ETag != want.ETag || got.LastStatus != want.LastStatus || !got.Incomplete || !got.Truncated || got.LastAttemptAt == nil || got.LastSuccessAt == nil {
		t.Fatalf("persisted state = %+v", got)
	}
}

func TestStoreMigratesExistingFindingsAndKeepsDistinctFingerprints(t *testing.T) {
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.ExecContext(context.Background(), `
CREATE TABLE github_leak_findings (
 id TEXT PRIMARY KEY,status TEXT NOT NULL DEFAULT 'new',keyword TEXT NOT NULL,repository TEXT NOT NULL,path TEXT NOT NULL,
 blob_sha TEXT NOT NULL,line_number INTEGER NOT NULL DEFAULT 0,secret_type TEXT NOT NULL,confidence TEXT NOT NULL,severity TEXT NOT NULL,
 fingerprint TEXT NOT NULL,masked_excerpt TEXT NOT NULL,html_url TEXT NOT NULL,first_seen_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX github_leak_findings_identity_idx ON github_leak_findings(repository,path,blob_sha,keyword,secret_type,line_number);
CREATE TABLE github_leak_keyword_state (
 keyword TEXT PRIMARY KEY,etag TEXT NOT NULL DEFAULT '',last_attempt_at TIMESTAMPTZ,last_success_at TIMESTAMPTZ,
 last_status TEXT NOT NULL DEFAULT 'idle',last_error TEXT NOT NULL DEFAULT '',incomplete BOOLEAN NOT NULL DEFAULT FALSE,updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE github_leak_runs (
 id TEXT PRIMARY KEY,status TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',started_at TIMESTAMPTZ NOT NULL,finished_at TIMESTAMPTZ,
 rate_remaining INTEGER NOT NULL DEFAULT -1,rate_reset_at TIMESTAMPTZ,processed INTEGER NOT NULL DEFAULT 0,detected INTEGER NOT NULL DEFAULT 0
);
INSERT INTO github_leak_findings
 (id,status,keyword,repository,path,blob_sha,line_number,secret_type,confidence,severity,fingerprint,masked_excerpt,html_url,first_seen_at,last_seen_at)
SELECT 'legacy-'||g,'new','"clientid" AND "vendor.example" in:file','owner/repo','legacy-'||g||'.env',repeat('a',40),0,
 'oauth_client_id','suspected','low',repeat(md5(g::text),2),'clientId=<redacted:oauth_client_id>',
 'https://github.com/owner/repo/blob/main/legacy-'||g||'.env',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM generate_series(1,3) g;
`)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(context.Background(), db.DB)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	var minRule string
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*),MIN(rule_name) FROM github_leak_findings WHERE id LIKE 'legacy-%'`).Scan(&count, &minRule); err != nil {
		t.Fatal(err)
	}
	if count != 3 || minRule != "legacy" {
		t.Fatalf("migrated legacy rows = count:%d rule:%q", count, minRule)
	}
	rule, err := newKeywordRule([]string{"vendor.example", "clientid"})
	if err != nil {
		t.Fatal(err)
	}
	base := Candidate{
		RuleName: "example-corp-clientid", Keyword: rule.Query, Repository: "owner/new-repo", Path: "config.env",
		BlobSHA: strings.Repeat("b", 40), SecretType: "oauth_client_id", Confidence: "suspected", Severity: "low",
		MaskedExcerpt: "clientId=<redacted:oauth_client_id>", HTMLURL: "https://github.com/owner/new-repo/blob/main/config.env",
	}
	first, second := base, base
	first.Fingerprint, second.Fingerprint = strings.Repeat("c", 64), strings.Repeat("d", 64)
	inserted, updated, err := store.UpsertCandidates(context.Background(), []Candidate{first, second}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 2 || updated != 0 {
		t.Fatalf("fingerprint identity = inserted:%d updated:%d", inserted, updated)
	}
	var requests, truncated int
	if err = db.QueryRowContext(context.Background(), `SELECT
 (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='github_leak_runs' AND column_name='requests'),
 (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='github_leak_keyword_state' AND column_name='truncated')`).Scan(&requests, &truncated); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || truncated != 1 {
		t.Fatalf("migration columns = requests:%d truncated:%d", requests, truncated)
	}
}
