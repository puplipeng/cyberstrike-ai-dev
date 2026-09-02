package githubleak

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
)

const runLockID int64 = 739522101

type Store struct{ db *sql.DB }

func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("github leak store database is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS github_leak_findings (
 id TEXT PRIMARY KEY,
 status TEXT NOT NULL DEFAULT 'new' CHECK(status IN('new','triaged','false_positive','resolved')),
	rule_name TEXT NOT NULL DEFAULT 'legacy',
 keyword TEXT NOT NULL,
 repository TEXT NOT NULL,
 path TEXT NOT NULL,
 blob_sha TEXT NOT NULL,
 line_number INTEGER NOT NULL DEFAULT 0,
 secret_type TEXT NOT NULL,
 confidence TEXT NOT NULL CHECK(confidence IN('likely','suspected')),
 severity TEXT NOT NULL CHECK(severity IN('critical','high','medium','low')),
 fingerprint TEXT NOT NULL,
 masked_excerpt TEXT NOT NULL,
 html_url TEXT NOT NULL,
 first_seen_at TIMESTAMPTZ NOT NULL,
 last_seen_at TIMESTAMPTZ NOT NULL
);
DO $github_leak_migration$
DECLARE old_constraint TEXT;
BEGIN
 FOR old_constraint IN
 SELECT conname FROM pg_constraint
 WHERE conrelid='github_leak_findings'::regclass AND contype='u'
   AND pg_get_constraintdef(oid) LIKE 'UNIQUE (repository, path, blob_sha, keyword, secret_type%'
   AND pg_get_constraintdef(oid) NOT LIKE '%fingerprint%'
 LOOP
  EXECUTE format('ALTER TABLE github_leak_findings DROP CONSTRAINT %I',old_constraint);
 END LOOP;
END $github_leak_migration$;
ALTER TABLE github_leak_findings ADD COLUMN IF NOT EXISTS rule_name TEXT NOT NULL DEFAULT 'legacy';
DO $github_leak_identity_migration$
BEGIN
 IF EXISTS (
  SELECT 1 FROM pg_indexes
 WHERE schemaname=current_schema() AND indexname='github_leak_findings_identity_idx'
   AND POSITION('fingerprint' IN LOWER(indexdef))=0
 ) THEN
  EXECUTE 'DROP INDEX IF EXISTS github_leak_findings_identity_idx';
 END IF;
END $github_leak_identity_migration$;
CREATE UNIQUE INDEX IF NOT EXISTS github_leak_findings_identity_idx
 ON github_leak_findings(repository,path,blob_sha,keyword,secret_type,line_number,fingerprint);
CREATE INDEX IF NOT EXISTS github_leak_findings_status_idx ON github_leak_findings(status,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS github_leak_findings_keyword_idx ON github_leak_findings(keyword,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS github_leak_findings_confidence_idx ON github_leak_findings(confidence,last_seen_at DESC);
CREATE TABLE IF NOT EXISTS github_leak_keyword_state (
 keyword TEXT PRIMARY KEY,
 etag TEXT NOT NULL DEFAULT '',
 last_attempt_at TIMESTAMPTZ,
 last_success_at TIMESTAMPTZ,
 last_status TEXT NOT NULL DEFAULT 'idle',
 last_error TEXT NOT NULL DEFAULT '',
 incomplete BOOLEAN NOT NULL DEFAULT FALSE,
	truncated BOOLEAN NOT NULL DEFAULT FALSE,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE github_leak_keyword_state ADD COLUMN IF NOT EXISTS truncated BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS github_leak_runs (
 id TEXT PRIMARY KEY,
 status TEXT NOT NULL CHECK(status IN('running','success','partial','error','rate_limited','cancelled')),
 error TEXT NOT NULL DEFAULT '',
 started_at TIMESTAMPTZ NOT NULL,
 finished_at TIMESTAMPTZ,
 rate_remaining INTEGER NOT NULL DEFAULT -1,
 rate_reset_at TIMESTAMPTZ,
	requests INTEGER NOT NULL DEFAULT 0,
 processed INTEGER NOT NULL DEFAULT 0,
 detected INTEGER NOT NULL DEFAULT 0
);
ALTER TABLE github_leak_runs ADD COLUMN IF NOT EXISTS requests INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS github_leak_runs_started_idx ON github_leak_runs(started_at DESC);
`)
	if err != nil {
		return nil, fmt.Errorf("initialize github leak schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) AcquireRunLock(ctx context.Context) (func(), bool, error) {
	if s == nil || s.db == nil {
		return nil, false, errors.New("github leak store unavailable")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	var locked bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, runLockID).Scan(&locked); err != nil || !locked {
		_ = conn.Close()
		return nil, false, err
	}
	var once sync.Once
	unlock := func() {
		once.Do(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = conn.ExecContext(cleanup, `SELECT pg_advisory_unlock($1)`, runLockID)
			_ = conn.Close()
		})
	}
	return unlock, true, nil
}

func (s *Store) UpsertCandidates(ctx context.Context, candidates []Candidate, seenAt time.Time) (inserted, updated int, err error) {
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO github_leak_findings
 (id,status,rule_name,keyword,repository,path,blob_sha,line_number,secret_type,confidence,severity,fingerprint,masked_excerpt,html_url,first_seen_at,last_seen_at)
VALUES($1,'new',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)
ON CONFLICT(repository,path,blob_sha,keyword,secret_type,line_number,fingerprint) DO UPDATE SET
	rule_name=EXCLUDED.rule_name,
 confidence=EXCLUDED.confidence,severity=EXCLUDED.severity,
 fingerprint=EXCLUDED.fingerprint,masked_excerpt=EXCLUDED.masked_excerpt,html_url=EXCLUDED.html_url,
 last_seen_at=EXCLUDED.last_seen_at
RETURNING (xmax=0)`)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()
	for _, candidate := range candidates {
		candidate, err = validateCandidate(candidate)
		if err != nil {
			return 0, 0, err
		}
		var created bool
		err = stmt.QueryRowContext(ctx, uuid.NewString(), candidate.RuleName, candidate.Keyword, candidate.Repository, candidate.Path,
			candidate.BlobSHA, candidate.Line, candidate.SecretType, candidate.Confidence, candidate.Severity,
			candidate.Fingerprint, candidate.MaskedExcerpt, candidate.HTMLURL, seenAt.UTC()).Scan(&created)
		if err != nil {
			return 0, 0, err
		}
		if created {
			inserted++
		} else {
			updated++
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, err
	}
	return inserted, updated, nil
}

func validateCandidate(candidate Candidate) (Candidate, error) {
	var err error
	if strings.TrimSpace(candidate.RuleName) == "" {
		candidate.RuleName = "legacy"
	}
	if candidate.RuleName, err = normalizeRuleName(candidate.RuleName); err != nil {
		return Candidate{}, err
	}
	if candidate.Keyword, err = normalizeRuleQuery(candidate.Keyword); err != nil {
		return Candidate{}, err
	}
	candidate.Repository = strings.TrimSpace(candidate.Repository)
	candidate.Path = strings.TrimSpace(candidate.Path)
	candidate.BlobSHA = strings.TrimSpace(candidate.BlobSHA)
	candidate.SecretType = strings.TrimSpace(candidate.SecretType)
	candidate.Confidence = strings.ToLower(strings.TrimSpace(candidate.Confidence))
	candidate.Severity = strings.ToLower(strings.TrimSpace(candidate.Severity))
	candidate.Fingerprint = strings.ToLower(strings.TrimSpace(candidate.Fingerprint))
	candidate.MaskedExcerpt = strings.TrimSpace(candidate.MaskedExcerpt)
	candidate.HTMLURL = strings.TrimSpace(candidate.HTMLURL)
	if candidate.Repository == "" || len(candidate.Repository) > 300 || candidate.Path == "" || len(candidate.Path) > 2000 || hasUnsafeMetadataText(candidate.Repository) || hasUnsafeMetadataText(candidate.Path) {
		return Candidate{}, errors.New("invalid GitHub finding metadata")
	}
	repositoryParts := strings.Split(candidate.Repository, "/")
	if len(repositoryParts) != 2 || repositoryParts[0] == "" || repositoryParts[1] == "" {
		return Candidate{}, errors.New("invalid GitHub finding repository")
	}
	if (len(candidate.BlobSHA) != 40 && len(candidate.BlobSHA) != 64) || !isHexString(candidate.BlobSHA) {
		return Candidate{}, errors.New("invalid GitHub blob SHA")
	}
	if candidate.Line < 0 || candidate.Line > 100000000 {
		return Candidate{}, errors.New("invalid GitHub finding line")
	}
	if candidate.SecretType == "" || len(candidate.SecretType) > 100 || hasUnsafeMetadataText(candidate.SecretType) {
		return Candidate{}, errors.New("invalid secret type")
	}
	if candidate.Confidence != "likely" && candidate.Confidence != "suspected" {
		return Candidate{}, errors.New("invalid confidence")
	}
	switch candidate.Severity {
	case "critical", "high", "medium", "low":
	default:
		return Candidate{}, errors.New("invalid severity")
	}
	decoded, decodeErr := hex.DecodeString(candidate.Fingerprint)
	if decodeErr != nil || len(decoded) != sha256Size {
		return Candidate{}, errors.New("invalid HMAC fingerprint")
	}
	if candidate.MaskedExcerpt == "" || len(candidate.MaskedExcerpt) > 2048 || containsControl(candidate.MaskedExcerpt) {
		return Candidate{}, errors.New("invalid masked excerpt")
	}
	u, parseErr := url.Parse(candidate.HTMLURL)
	if parseErr != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") || u.Port() != "" || u.User != nil || u.RawQuery != "" {
		return Candidate{}, errors.New("invalid GitHub finding URL")
	}
	if u.Fragment != "" && lineNumberFromURL(candidate.HTMLURL) == 0 {
		return Candidate{}, errors.New("invalid GitHub finding URL fragment")
	}
	if line := lineNumberFromURL(candidate.HTMLURL); line != candidate.Line {
		return Candidate{}, errors.New("GitHub finding line does not match URL")
	}
	return candidate, nil
}

const sha256Size = 32

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

const findingColumns = `id,status,rule_name,keyword,repository,path,blob_sha,line_number,secret_type,confidence,severity,fingerprint,masked_excerpt,html_url,first_seen_at,last_seen_at`

type rowScanner interface{ Scan(...any) error }

func scanFinding(row rowScanner) (Finding, error) {
	var finding Finding
	err := row.Scan(&finding.ID, &finding.Status, &finding.RuleName, &finding.Keyword, &finding.Repository, &finding.Path, &finding.BlobSHA,
		&finding.Line, &finding.SecretType, &finding.Confidence, &finding.Severity, &finding.Fingerprint,
		&finding.MaskedExcerpt, &finding.HTMLURL, &finding.FirstSeenAt, &finding.LastSeenAt)
	return finding, err
}

func (s *Store) List(ctx context.Context, filter ListFilter) (ListResult, error) {
	result := ListResult{Items: []Finding{}}
	if err := filter.Validate(); err != nil {
		return result, err
	}
	result.Page, result.PageSize = filter.Page, filter.PageSize
	where, args := buildListWhere(filter)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM github_leak_findings WHERE "+where, args...).Scan(&result.Total); err != nil {
		return result, err
	}
	result.TotalPages = (result.Total + filter.PageSize - 1) / filter.PageSize
	args = append(args, filter.PageSize, (filter.Page-1)*filter.PageSize)
	query := fmt.Sprintf("SELECT %s FROM github_leak_findings WHERE %s ORDER BY last_seen_at DESC,id LIMIT $%d OFFSET $%d", findingColumns, where, len(args)-1, len(args))
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		finding, scanErr := scanFinding(rows)
		if scanErr != nil {
			_ = rows.Close()
			return result, scanErr
		}
		result.Items = append(result.Items, finding)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func buildListWhere(filter ListFilter) (string, []any) {
	where := "TRUE"
	args := make([]any, 0, 5)
	add := func(expression string, value any) {
		args = append(args, value)
		where += " AND " + fmt.Sprintf(expression, len(args))
	}
	if filter.Status != "" {
		add("status=$%d", filter.Status)
	}
	if filter.Keyword != "" {
		add("LOWER(keyword)=LOWER($%d)", filter.Keyword)
	}
	if filter.Query != "" {
		query := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(filter.Query))
		add(`LOWER(id||' '||fingerprint||' '||repository||' '||path||' '||rule_name||' '||keyword||' '||secret_type) LIKE $%d ESCAPE '\\'`, "%"+query+"%")
	}
	return where, args
}

func (s *Store) Get(ctx context.Context, id string) (Finding, error) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 100 {
		return Finding{}, ErrNotFound
	}
	finding, err := scanFinding(s.db.QueryRowContext(ctx, "SELECT "+findingColumns+" FROM github_leak_findings WHERE id=$1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, ErrNotFound
	}
	return finding, err
}

func (s *Store) UpdateStatus(ctx context.Context, id, status string) (Finding, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	if !ValidStatus(status) {
		return Finding{}, errors.New("invalid finding status")
	}
	finding, err := scanFinding(s.db.QueryRowContext(ctx, `UPDATE github_leak_findings SET status=$2 WHERE id=$1 RETURNING `+findingColumns, strings.TrimSpace(id), status))
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, ErrNotFound
	}
	return finding, err
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var stats Stats
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
 COUNT(*) FILTER(WHERE status='new'),COUNT(*) FILTER(WHERE status='triaged'),
 COUNT(*) FILTER(WHERE status='false_positive'),COUNT(*) FILTER(WHERE status='resolved'),
 COUNT(*) FILTER(WHERE confidence='likely'),COUNT(*) FILTER(WHERE confidence='suspected')
 FROM github_leak_findings`).Scan(&stats.Total, &stats.New, &stats.Triaged, &stats.FalsePositive, &stats.Resolved, &stats.Likely, &stats.Suspected)
	return stats, err
}

func (s *Store) KeywordState(ctx context.Context, keyword string) (KeywordState, error) {
	keyword, err := normalizeRuleQuery(keyword)
	if err != nil {
		return KeywordState{}, err
	}
	var state KeywordState
	err = s.db.QueryRowContext(ctx, `SELECT keyword,etag,last_attempt_at,last_success_at,last_status,last_error,incomplete,truncated FROM github_leak_keyword_state WHERE keyword=$1`, keyword).
		Scan(&state.Keyword, &state.ETag, &state.LastAttemptAt, &state.LastSuccessAt, &state.LastStatus, &state.LastError, &state.Incomplete, &state.Truncated)
	if errors.Is(err, sql.ErrNoRows) {
		return KeywordState{Keyword: keyword}, nil
	}
	return state, err
}

func (s *Store) SaveKeywordState(ctx context.Context, state KeywordState) error {
	keyword, err := normalizeRuleQuery(state.Keyword)
	if err != nil {
		return err
	}
	state.LastError = safeError(state.LastError)
	incomplete := int64(0)
	if state.Incomplete {
		incomplete = 1
	}
	truncated := int64(0)
	if state.Truncated {
		truncated = 1
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO github_leak_keyword_state
 (keyword,etag,last_attempt_at,last_success_at,last_status,last_error,incomplete,truncated,updated_at)
 VALUES($1,$2,$3,$4,$5,$6,($7::bigint <> 0),($8::bigint <> 0),CURRENT_TIMESTAMP)
 ON CONFLICT(keyword) DO UPDATE SET etag=EXCLUDED.etag,last_attempt_at=EXCLUDED.last_attempt_at,
	last_success_at=EXCLUDED.last_success_at,last_status=EXCLUDED.last_status,last_error=EXCLUDED.last_error,
	incomplete=EXCLUDED.incomplete,truncated=EXCLUDED.truncated,updated_at=CURRENT_TIMESTAMP`, keyword, strings.TrimSpace(state.ETag), state.LastAttemptAt,
		state.LastSuccessAt, strings.TrimSpace(state.LastStatus), state.LastError, incomplete, truncated)
	return err
}

func (s *Store) BeginRun(ctx context.Context, at time.Time) (RunRecord, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	// A process crash may leave a durable running marker; the advisory lock is
	// the authority, so a new lock owner may safely close those old rows.
	_, _ = s.db.ExecContext(ctx, `UPDATE github_leak_runs SET status='cancelled',error='previous run interrupted',finished_at=$1 WHERE status='running'`, at.UTC())
	run := RunRecord{ID: uuid.NewString(), Status: "running", StartedAt: at.UTC(), RateRemaining: -1}
	_, err := s.db.ExecContext(ctx, `INSERT INTO github_leak_runs(id,status,error,started_at,rate_remaining,requests,processed,detected) VALUES($1,$2,'',$3,-1,0,0,0)`, run.ID, run.Status, run.StartedAt)
	return run, err
}

func (s *Store) FinishRun(ctx context.Context, run RunRecord) error {
	if run.ID == "" {
		return errors.New("run id is required")
	}
	switch run.Status {
	case "success", "partial", "error", "rate_limited", "cancelled":
	default:
		return errors.New("invalid run status")
	}
	finished := time.Now().UTC()
	if run.FinishedAt != nil {
		finished = run.FinishedAt.UTC()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE github_leak_runs SET status=$2,error=$3,finished_at=$4,
 rate_remaining=$5,rate_reset_at=$6,requests=$7,processed=$8,detected=$9 WHERE id=$1`, run.ID, run.Status,
		safeError(run.Error), finished, run.RateRemaining, run.RateResetAt, run.Requests, run.Processed, run.Detected)
	return err
}

func (s *Store) LatestRun(ctx context.Context) (RunRecord, error) {
	var run RunRecord
	err := s.db.QueryRowContext(ctx, `SELECT id,status,error,started_at,finished_at,rate_remaining,rate_reset_at,requests,processed,detected FROM github_leak_runs ORDER BY started_at DESC LIMIT 1`).
		Scan(&run.ID, &run.Status, &run.Error, &run.StartedAt, &run.FinishedAt, &run.RateRemaining, &run.RateResetAt, &run.Requests, &run.Processed, &run.Detected)
	if errors.Is(err, sql.ErrNoRows) {
		return RunRecord{RateRemaining: -1}, nil
	}
	return run, err
}

func safeError(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	// Provider errors are deliberately generic. Still remove controls and cap
	// storage so a future dependency cannot copy a response body into runtime.
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = maskOtherSecrets(value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 300 {
		value = value[:300]
	}
	return value
}
