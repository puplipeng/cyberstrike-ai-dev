package vulnintel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Store struct{ db *sql.DB }

func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS vulnerability_intelligence (
 cve_id TEXT PRIMARY KEY, nvd JSONB, kev JSONB,
 severity TEXT NOT NULL DEFAULT 'unknown', score DOUBLE PRECISION,
 published_at TIMESTAMPTZ, nvd_modified_at TIMESTAMPTZ, kev_added_at TIMESTAMPTZ,
 synced_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS intel_severity_idx ON vulnerability_intelligence(severity);
CREATE INDEX IF NOT EXISTS intel_modified_idx ON vulnerability_intelligence((GREATEST(nvd_modified_at, kev_added_at)) DESC, cve_id);
CREATE TABLE IF NOT EXISTS vulnerability_intelligence_sources (
 source TEXT PRIMARY KEY, enabled BOOLEAN NOT NULL DEFAULT TRUE,
 status TEXT NOT NULL DEFAULT 'idle', last_attempt TIMESTAMPTZ, last_success TIMESTAMPTZ,
 checkpoint TIMESTAMPTZ, error TEXT NOT NULL DEFAULT '', processed INTEGER NOT NULL DEFAULT 0,
 version TEXT NOT NULL DEFAULT ''
);
INSERT INTO vulnerability_intelligence_sources(source) VALUES ('nvd'),('kev'),('epss') ON CONFLICT DO NOTHING;
ALTER TABLE vulnerability_intelligence ADD COLUMN IF NOT EXISTS epss JSONB;`)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err = s.initExtensions(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) SaveNVD(ctx context.Context, records []NVDRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO vulnerability_intelligence
 (cve_id,nvd,severity,score,published_at,nvd_modified_at) VALUES($1,$2,$3,$4,$5,$6)
 ON CONFLICT(cve_id) DO UPDATE SET nvd=EXCLUDED.nvd,severity=EXCLUDED.severity,
 score=EXCLUDED.score,published_at=EXCLUDED.published_at,nvd_modified_at=EXCLUDED.nvd_modified_at,synced_at=CURRENT_TIMESTAMP
 WHERE vulnerability_intelligence.nvd_modified_at IS NULL OR vulnerability_intelligence.nvd_modified_at<=EXCLUDED.nvd_modified_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range records {
		if !ValidCVE(r.ID) {
			return fmt.Errorf("invalid CVE in NVD batch")
		}
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err = stmt.ExecContext(ctx, r.ID, string(b), r.Severity, r.Score, r.Published, r.Modified); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReplaceKEV is atomic. A failed/invalid feed never removes the previous catalog.
func (s *Store) ReplaceKEV(ctx context.Context, records []KEVRecord) error {
	if len(records) == 0 {
		return fmt.Errorf("empty KEV catalog rejected")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ids := make([]string, 0, len(records))
	seen := make(map[string]bool, len(records))
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO vulnerability_intelligence(cve_id,kev,kev_added_at) VALUES($1,$2,$3)
 ON CONFLICT(cve_id) DO UPDATE SET kev=EXCLUDED.kev,kev_added_at=EXCLUDED.kev_added_at,synced_at=CURRENT_TIMESTAMP`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range records {
		if !ValidCVE(r.ID) || seen[r.ID] {
			return fmt.Errorf("invalid or duplicate KEV CVE")
		}
		seen[r.ID] = true
		added, err := parseDate(r.Added)
		if err != nil {
			return err
		}
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err = stmt.ExecContext(ctx, r.ID, string(b), added); err != nil {
			return err
		}
		ids = append(ids, r.ID)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM vulnerability_intelligence WHERE nvd IS NULL AND NOT(cve_id=ANY($1::text[]))`, ids); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE vulnerability_intelligence SET kev=NULL,kev_added_at=NULL,synced_at=CURRENT_TIMESTAMP WHERE kev IS NOT NULL AND NOT(cve_id=ANY($1::text[]))`, ids); err != nil {
		return err
	}
	return tx.Commit()
}

const activeCondition = `LOWER(COALESCE(nvd->>'status','')) <> 'rejected'`

const summaryColumns = `cve_id,COALESCE(kev->>'vulnerabilityName',cve_id),
 COALESCE(NULLIF(nvd->>'description',''),kev->>'shortDescription',''),severity,score,
 published_at,nvd_modified_at,kev_added_at,synced_at,nvd IS NOT NULL,kev IS NOT NULL,
 CASE WHEN ` + activeCondition + ` THEN 'active' ELSE 'rejected' END,epss`

type scanner interface{ Scan(...any) error }

func scanRecord(row scanner) (Record, error) {
	var r Record
	var nvd, kev bool
	var epss []byte
	err := row.Scan(&r.ID, &r.Title, &r.Description, &r.Severity, &r.Score, &r.Published, &r.Modified, &r.KEVAdded, &r.Synced, &nvd, &kev, &r.Lifecycle, &epss)
	if err != nil {
		return r, err
	}
	if len(epss) > 0 {
		if err = json.Unmarshal(epss, &r.EPSS); err != nil {
			return r, err
		}
	}
	r.Sources = make([]string, 0, 2)
	if nvd {
		r.Sources = append(r.Sources, "nvd")
	}
	if kev {
		r.Sources = append(r.Sources, "kev")
	}
	r.KnownExploited = kev
	setPriority(&r, time.Now())
	switch {
	case r.Lifecycle == "rejected":
		r.RatingReason = "rejected"
	case !nvd:
		r.RatingReason = "missing_nvd"
	case r.Score == nil:
		r.RatingReason = "no_cvss"
	case r.Severity == "unknown":
		r.RatingReason = "unknown_severity"
	}
	return r, err
}

func (s *Store) List(ctx context.Context, f Filter) (ListResult, error) {
	result := ListResult{Items: []Record{}, Page: f.Page, PageSize: f.PageSize}
	if err := f.Validate(); err != nil {
		return result, err
	}
	where := "TRUE"
	switch f.Status {
	case "", "active":
		where = activeCondition
	case "rejected":
		where = "NOT (" + activeCondition + ")"
	}
	args := []any{}
	add := func(expr string, value any) {
		args = append(args, value)
		where += " AND " + fmt.Sprintf(expr, len(args))
	}
	if f.Query != "" {
		// Escape LIKE wildcards; query text is data, never SQL syntax.
		q := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(strings.ToLower(f.Query))
		add(`LOWER(cve_id || ' ' || COALESCE(nvd->>'description','') || ' ' || COALESCE((nvd->'affected')::text,'') || ' ' || COALESCE(kev->>'vulnerabilityName','') || ' ' || COALESCE(kev->>'vendorProject','') || ' ' || COALESCE(kev->>'product','')) LIKE $%d`, "%"+q+"%")
	}
	if f.Severity != "" {
		add("severity=$%d", f.Severity)
	}
	if f.Source != "" {
		where += " AND " + f.Source + " IS NOT NULL"
	} // enum validated above
	if f.Exploited {
		where += " AND kev IS NOT NULL"
	}
	// Keep total and page consistent if a sync commits between queries.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerability_intelligence WHERE "+where, args...).Scan(&result.Total); err != nil {
		return result, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	order := "GREATEST(nvd_modified_at,kev_added_at) DESC NULLS LAST,cve_id"
	epssOrder := "CASE WHEN " + freshEPSS + " THEN (epss->>'probability')::double precision END DESC NULLS LAST,score DESC NULLS LAST,"
	if f.Sort == "priority" {
		order = priorityOrder + "," + epssOrder + order
	} else if f.Sort == "epss" {
		order = epssOrder + order
	}
	query := fmt.Sprintf("SELECT %s FROM vulnerability_intelligence WHERE %s ORDER BY %s LIMIT $%d OFFSET $%d", summaryColumns, where, order, len(args)-1, len(args))
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		r, e := scanRecord(rows)
		if e != nil {
			rows.Close()
			return result, e
		}
		result.Items = append(result.Items, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func (s *Store) Detail(ctx context.Context, id string) (Record, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	r, err := scanRecord(tx.QueryRowContext(ctx, "SELECT "+summaryColumns+" FROM vulnerability_intelligence WHERE cve_id=$1", id))
	if err != nil {
		return r, err
	}
	var nvd, kev []byte
	if err = tx.QueryRowContext(ctx, "SELECT nvd,kev FROM vulnerability_intelligence WHERE cve_id=$1", id).Scan(&nvd, &kev); err != nil {
		return r, err
	}
	if len(nvd) > 0 {
		if err = json.Unmarshal(nvd, &r.NVD); err != nil {
			return r, err
		}
	}
	if len(kev) > 0 {
		if err = json.Unmarshal(kev, &r.KEV); err != nil {
			return r, err
		}
	}
	return r, tx.Commit()
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var r Stats
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE active),COUNT(*) FILTER(WHERE NOT active),
 COUNT(*) FILTER(WHERE active AND kev IS NOT NULL),COUNT(*) FILTER(WHERE active AND severity IN ('critical','high')),
 COUNT(*) FILTER(WHERE active AND severity='unknown') FROM
 (SELECT *,`+activeCondition+` AS active FROM vulnerability_intelligence) i`).Scan(&r.Total, &r.Active, &r.Rejected, &r.KEV, &r.CriticalHigh, &r.Unknown)
	return r, err
}

// Re-fetch legacy rows even when upstream lastModified has not changed. Written
// pages carry the schema version, so interrupted upgrades resume from remaining rows.
func (s *Store) legacyNVDWindow(ctx context.Context) (*time.Time, *time.Time, error) {
	var start, end sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT MIN(published_at),MAX(published_at)
 FROM vulnerability_intelligence WHERE nvd IS NOT NULL
 AND COALESCE(nvd->>'schema_version','')<>$1`, fmt.Sprint(nvdSchemaVersion)).Scan(&start, &end)
	if err != nil || !start.Valid || !end.Valid {
		return nil, nil, err
	}
	// NVD accepts millisecond precision. Include both boundary records.
	a, b := start.Time.Add(-time.Millisecond), end.Time.Add(time.Millisecond)
	return &a, &b, nil
}

func (s *Store) Sources(ctx context.Context) ([]SourceState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source,enabled,status,last_attempt,last_success,checkpoint,error,processed,version FROM vulnerability_intelligence_sources ORDER BY CASE source WHEN 'kev' THEN 0 WHEN 'nvd' THEN 1 ELSE 2 END`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []SourceState{}
	for rows.Next() {
		var r SourceState
		if err = rows.Scan(&r.Source, &r.Enabled, &r.Status, &r.LastAttempt, &r.LastSuccess, &r.Checkpoint, &r.Error, &r.Processed, &r.Version); err != nil {
			return nil, err
		}
		if r.Enabled && r.LastAttempt != nil {
			next := r.LastAttempt.Add(sourceInterval(r.Source))
			r.NextSync = &next
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) Enable(ctx context.Context, source string, enabled bool) error {
	if !sourceValid(source) {
		return fmt.Errorf("invalid source")
	}
	_, err := s.db.ExecContext(ctx, "UPDATE vulnerability_intelligence_sources SET enabled=$2 WHERE source=$1", source, enabled)
	return err
}

func (s *Store) begin(ctx context.Context, source string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vulnerability_intelligence_sources SET status='running',last_attempt=$2,error='',processed=0 WHERE source=$1`, source, now)
	return err
}
func (s *Store) progress(ctx context.Context, source string, count int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vulnerability_intelligence_sources SET processed=$2 WHERE source=$1`, source, count)
	return err
}
func (s *Store) finish(ctx context.Context, source string, checkpoint time.Time, count int, version string, syncErr error) error {
	if syncErr != nil {
		_, err := s.db.ExecContext(ctx, `UPDATE vulnerability_intelligence_sources SET status='error',error=$2,processed=$3 WHERE source=$1`, source, syncErr.Error(), count)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE vulnerability_intelligence_sources SET status='success',last_success=CURRENT_TIMESTAMP,checkpoint=$2,error='',processed=$3,version=$4 WHERE source=$1`, source, checkpoint, count, version)
	return err
}
