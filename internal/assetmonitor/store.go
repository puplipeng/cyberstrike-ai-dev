package assetmonitor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Store struct{ db *sql.DB }

func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("asset monitor store database is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS asset_monitors (
 id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 owner_user_id TEXT NOT NULL,
 name TEXT NOT NULL,
 root_domain TEXT NOT NULL,
 provider TEXT NOT NULL DEFAULT 'quake',
 query TEXT NOT NULL,
 cron_expr TEXT NOT NULL DEFAULT '',
 interval_minutes INTEGER NOT NULL DEFAULT 1440 CHECK(interval_minutes BETWEEN 60 AND 10080),
 max_results INTEGER NOT NULL DEFAULT 200 CHECK(max_results BETWEEN 1 AND 1000),
 enabled BIGINT NOT NULL DEFAULT 1 CONSTRAINT asset_monitors_enabled_value_check CHECK(enabled IN(0,1)),
 next_run_at TIMESTAMPTZ,
 last_run_at TIMESTAMPTZ,
 last_status TEXT NOT NULL DEFAULT 'idle' CHECK(last_status IN('idle','queued','running','success','partial','error','disabled')),
 last_error TEXT NOT NULL DEFAULT '',
 last_seen_count INTEGER NOT NULL DEFAULT 0,
 last_new_count INTEGER NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 UNIQUE(project_id,root_domain,provider)
);
ALTER TABLE asset_monitors ADD COLUMN IF NOT EXISTS cron_expr TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_monitors ADD COLUMN IF NOT EXISTS interval_minutes INTEGER NOT NULL DEFAULT 1440;
ALTER TABLE asset_monitors ADD COLUMN IF NOT EXISTS max_results INTEGER NOT NULL DEFAULT 200;
ALTER TABLE asset_monitors ADD COLUMN IF NOT EXISTS last_seen_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE asset_monitors ADD COLUMN IF NOT EXISTS last_new_count INTEGER NOT NULL DEFAULT 0;
DO $asset_monitor_enabled_migration$
BEGIN
 IF EXISTS (
  SELECT 1 FROM information_schema.columns
  WHERE table_schema=current_schema() AND table_name='asset_monitors'
    AND column_name='enabled' AND data_type='boolean'
 ) THEN
  DROP INDEX IF EXISTS asset_monitors_due_idx;
  ALTER TABLE asset_monitors ALTER COLUMN enabled DROP DEFAULT;
  ALTER TABLE asset_monitors ALTER COLUMN enabled TYPE BIGINT USING CASE WHEN enabled THEN 1 ELSE 0 END;
  ALTER TABLE asset_monitors ALTER COLUMN enabled SET DEFAULT 1;
 END IF;
 IF NOT EXISTS (
  SELECT 1 FROM pg_constraint
  WHERE conrelid='asset_monitors'::regclass AND conname='asset_monitors_enabled_value_check'
 ) THEN
  ALTER TABLE asset_monitors ADD CONSTRAINT asset_monitors_enabled_value_check CHECK(enabled IN(0,1));
 END IF;
END $asset_monitor_enabled_migration$;
CREATE INDEX IF NOT EXISTS asset_monitors_project_idx ON asset_monitors(project_id,created_at DESC);
CREATE INDEX IF NOT EXISTS asset_monitors_due_idx ON asset_monitors(next_run_at) WHERE enabled=1;

CREATE TABLE IF NOT EXISTS asset_monitor_runs (
 id TEXT PRIMARY KEY,
 monitor_id TEXT NOT NULL REFERENCES asset_monitors(id) ON DELETE CASCADE,
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 trigger_kind TEXT NOT NULL CHECK(trigger_kind IN('manual','scheduled')),
 triggered_by TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL CHECK(status IN('queued','running','success','partial','error','cancelled')),
 started_at TIMESTAMPTZ,
 finished_at TIMESTAMPTZ,
 total_count INTEGER NOT NULL DEFAULT 0,
 seen_count INTEGER NOT NULL DEFAULT 0,
 new_count INTEGER NOT NULL DEFAULT 0,
 created_count INTEGER NOT NULL DEFAULT 0,
 updated_count INTEGER NOT NULL DEFAULT 0,
 skipped_count INTEGER NOT NULL DEFAULT 0,
 conflict_count INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS asset_monitor_runs_monitor_idx ON asset_monitor_runs(monitor_id,created_at DESC);
CREATE INDEX IF NOT EXISTS asset_monitor_runs_project_idx ON asset_monitor_runs(project_id,created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS asset_monitor_runs_active_idx ON asset_monitor_runs(monitor_id) WHERE status IN('queued','running');

CREATE TABLE IF NOT EXISTS asset_monitor_assets (
 monitor_id TEXT NOT NULL REFERENCES asset_monitors(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 first_seen_at TIMESTAMPTZ NOT NULL,
 last_seen_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(monitor_id,asset_id)
);
CREATE INDEX IF NOT EXISTS asset_monitor_assets_last_seen_idx ON asset_monitor_assets(monitor_id,last_seen_at DESC);

CREATE TABLE IF NOT EXISTS asset_monitor_run_assets (
 run_id TEXT NOT NULL REFERENCES asset_monitor_runs(id) ON DELETE CASCADE,
 monitor_id TEXT NOT NULL REFERENCES asset_monitors(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 state TEXT NOT NULL CHECK(state IN('new','seen')),
 observed_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(run_id,asset_id)
);
CREATE INDEX IF NOT EXISTS asset_monitor_run_assets_state_idx ON asset_monitor_run_assets(run_id,state);
`)
	if err != nil {
		return nil, fmt.Errorf("initialize asset monitor schema: %w", err)
	}
	return &Store{db: db}, nil
}

const monitorColumns = `id,project_id,owner_user_id,name,root_domain,provider,query,cron_expr,interval_minutes,max_results,enabled,next_run_at,last_run_at,last_status,last_error,last_seen_count,last_new_count,created_at,updated_at`

type rowScanner interface{ Scan(...any) error }

func scanMonitor(row rowScanner) (Monitor, error) {
	var monitor Monitor
	var nextRun, lastRun sql.NullTime
	err := row.Scan(&monitor.ID, &monitor.ProjectID, &monitor.OwnerUserID, &monitor.Name, &monitor.RootDomain,
		&monitor.Provider, &monitor.Query, &monitor.CronExpr, &monitor.IntervalMinutes, &monitor.MaxResults,
		&monitor.Enabled, &nextRun, &lastRun, &monitor.LastStatus, &monitor.LastError, &monitor.LastSeenCount, &monitor.LastNewCount,
		&monitor.CreatedAt, &monitor.UpdatedAt)
	if nextRun.Valid {
		value := nextRun.Time.UTC()
		monitor.NextRunAt = &value
	}
	if lastRun.Valid {
		value := lastRun.Time.UTC()
		monitor.LastRunAt = &value
	}
	monitor.CreatedAt = monitor.CreatedAt.UTC()
	monitor.UpdatedAt = monitor.UpdatedAt.UTC()
	return monitor, err
}

func (s *Store) createMonitor(ctx context.Context, monitor Monitor) (Monitor, error) {
	monitor.ID = uuid.NewString()
	now := time.Now().UTC()
	monitor.CreatedAt, monitor.UpdatedAt = now, now
	created, err := scanMonitor(s.db.QueryRowContext(ctx, `INSERT INTO asset_monitors
(id,project_id,owner_user_id,name,root_domain,provider,query,cron_expr,interval_minutes,max_results,enabled,next_run_at,last_status,last_error,created_at,updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'',$14,$14) RETURNING `+monitorColumns,
		monitor.ID, monitor.ProjectID, monitor.OwnerUserID, monitor.Name, monitor.RootDomain, monitor.Provider, monitor.Query,
		monitor.CronExpr, monitor.IntervalMinutes, monitor.MaxResults, boolInt(monitor.Enabled), monitor.NextRunAt, monitor.LastStatus, now))
	if err != nil {
		return Monitor{}, mapStoreError(err)
	}
	return created, nil
}

func (s *Store) listMonitors(ctx context.Context, projectID string) ([]Monitor, error) {
	query := `SELECT ` + monitorColumns + ` FROM asset_monitors`
	args := []any{}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		query += ` WHERE project_id=$1`
		args = append(args, projectID)
	}
	query += ` ORDER BY created_at DESC,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	monitors := []Monitor{}
	for rows.Next() {
		monitor, scanErr := scanMonitor(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		monitors = append(monitors, monitor)
	}
	return monitors, rows.Err()
}

func (s *Store) getMonitor(ctx context.Context, projectID, monitorID string) (Monitor, error) {
	query := `SELECT ` + monitorColumns + ` FROM asset_monitors WHERE id=$1`
	args := []any{strings.TrimSpace(monitorID)}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		query += ` AND project_id=$2`
		args = append(args, projectID)
	}
	monitor, err := scanMonitor(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Monitor{}, ErrNotFound
	}
	return monitor, err
}

func (s *Store) replaceMonitor(ctx context.Context, projectID string, monitor Monitor, rootChanged bool) (Monitor, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Monitor{}, err
	}
	defer func() { _ = tx.Rollback() }()
	query := `UPDATE asset_monitors SET name=$2,root_domain=$3,provider=$4,query=$5,cron_expr=$6,interval_minutes=$7,max_results=$8,
enabled=$9,next_run_at=$10,last_status=$11,last_error=$12,updated_at=$13 WHERE id=$1`
	args := []any{monitor.ID, monitor.Name, monitor.RootDomain, monitor.Provider, monitor.Query, monitor.CronExpr,
		monitor.IntervalMinutes, monitor.MaxResults, boolInt(monitor.Enabled), monitor.NextRunAt, monitor.LastStatus, monitor.LastError, time.Now().UTC()}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		query += ` AND project_id=$14`
		args = append(args, projectID)
	}
	query += ` RETURNING ` + monitorColumns
	updated, err := scanMonitor(tx.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Monitor{}, ErrNotFound
	}
	if err != nil {
		return Monitor{}, mapStoreError(err)
	}
	if rootChanged {
		if _, err = tx.ExecContext(ctx, `DELETE FROM asset_monitor_assets WHERE monitor_id=$1`, monitor.ID); err != nil {
			return Monitor{}, err
		}
	}
	if !updated.Enabled {
		if _, err = tx.ExecContext(ctx, `UPDATE asset_monitor_runs SET status='cancelled',finished_at=$2,error='monitor disabled' WHERE monitor_id=$1 AND status='queued'`, monitor.ID, time.Now().UTC()); err != nil {
			return Monitor{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Monitor{}, err
	}
	return updated, nil
}

func (s *Store) deleteMonitor(ctx context.Context, projectID, monitorID string) error {
	busy, err := s.monitorBusy(ctx, monitorID)
	if err != nil {
		return err
	}
	if busy {
		return ErrBusy
	}
	query := `DELETE FROM asset_monitors WHERE id=$1`
	args := []any{strings.TrimSpace(monitorID)}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		query += ` AND project_id=$2`
		args = append(args, projectID)
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) monitorBusy(ctx context.Context, monitorID string) (bool, error) {
	var busy bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM asset_monitor_runs WHERE monitor_id=$1 AND status IN('queued','running'))`, strings.TrimSpace(monitorID)).Scan(&busy)
	return busy, err
}

func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	type sqlStateError interface{ SQLState() string }
	var state sqlStateError
	if errors.As(err, &state) && state.SQLState() == "23505" {
		return fmt.Errorf("%w: duplicate project, root domain and provider", ErrConflict)
	}
	if errors.As(err, &state) && (state.SQLState() == "23503" || state.SQLState() == "23514") {
		return validationErrorf("referenced project or monitor values are invalid")
	}
	return err
}

const runColumns = `id,monitor_id,project_id,trigger_kind,triggered_by,status,started_at,finished_at,total_count,seen_count,new_count,created_count,updated_count,skipped_count,conflict_count,error,created_at`

func scanRun(row rowScanner) (Run, error) {
	var run Run
	var started, finished sql.NullTime
	err := row.Scan(&run.ID, &run.MonitorID, &run.ProjectID, &run.Trigger, &run.TriggeredBy, &run.Status,
		&started, &finished, &run.TotalCount, &run.SeenCount, &run.NewCount, &run.CreatedCount,
		&run.UpdatedCount, &run.SkippedCount, &run.ConflictCount, &run.Error, &run.CreatedAt)
	if started.Valid {
		value := started.Time.UTC()
		run.StartedAt = &value
	}
	if finished.Valid {
		value := finished.Time.UTC()
		run.FinishedAt = &value
	}
	run.CreatedAt = run.CreatedAt.UTC()
	return run, err
}

func (s *Store) enqueueRun(ctx context.Context, monitor Monitor, trigger, triggeredBy string) (Run, error) {
	now := time.Now().UTC()
	runID := uuid.NewString()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, err
	}
	defer func() { _ = tx.Rollback() }()
	run, err := scanRun(tx.QueryRowContext(ctx, `INSERT INTO asset_monitor_runs
(id,monitor_id,project_id,trigger_kind,triggered_by,status,created_at)
VALUES($1,$2,$3,$4,$5,'queued',$6) RETURNING `+runColumns,
		runID, monitor.ID, monitor.ProjectID, trigger, strings.TrimSpace(triggeredBy), now))
	if err != nil {
		if isUniqueViolation(err) {
			return Run{}, ErrBusy
		}
		return Run{}, mapStoreError(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE asset_monitors SET last_status='queued',last_error='',updated_at=$2 WHERE id=$1`, monitor.ID, now); err != nil {
		return Run{}, err
	}
	if err = tx.Commit(); err != nil {
		return Run{}, err
	}
	return run, nil
}

func isUniqueViolation(err error) bool {
	type sqlStateError interface{ SQLState() string }
	var state sqlStateError
	return errors.As(err, &state) && state.SQLState() == "23505"
}

func (s *Store) listDueMonitors(ctx context.Context, now time.Time, limit int) ([]Monitor, error) {
	if limit < 1 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+monitorColumns+` FROM asset_monitors
WHERE enabled=1 AND next_run_at IS NOT NULL AND next_run_at <= $1
ORDER BY next_run_at,id LIMIT $2`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	monitors := []Monitor{}
	for rows.Next() {
		monitor, scanErr := scanMonitor(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		monitors = append(monitors, monitor)
	}
	return monitors, rows.Err()
}

// enqueueDueRun atomically advances the schedule before queueing. Multiple app
// processes may see a due row, but only one can satisfy the guarded update.
func (s *Store) enqueueDueRun(ctx context.Context, monitor Monitor, now, next time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE asset_monitors SET next_run_at=$3,last_status='queued',last_error='',updated_at=$2
WHERE id=$1 AND enabled=1 AND next_run_at IS NOT NULL AND next_run_at <= $2`, monitor.ID, now.UTC(), next.UTC())
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return false, err
	}
	insertResult, err := tx.ExecContext(ctx, `INSERT INTO asset_monitor_runs(id,monitor_id,project_id,trigger_kind,status,created_at)
VALUES($1,$2,$3,'scheduled','queued',$4) ON CONFLICT DO NOTHING`, uuid.NewString(), monitor.ID, monitor.ProjectID, now.UTC())
	if err != nil {
		return false, err
	}
	inserted, err := insertResult.RowsAffected()
	if err != nil {
		return false, err
	}
	// A manual/running job already covers this interval when inserted is zero.
	// Keeping the schedule advance coalesces the missed tick without a catch-up storm.
	return inserted > 0, tx.Commit()
}

func (s *Store) claimNextRun(ctx context.Context, now time.Time) (Run, Monitor, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, Monitor{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var runID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM asset_monitor_runs WHERE status='queued' ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&runID)
	if err != nil {
		return Run{}, Monitor{}, err
	}
	run, err := scanRun(tx.QueryRowContext(ctx, `UPDATE asset_monitor_runs SET status='running',started_at=$2 WHERE id=$1 AND status='queued' RETURNING `+runColumns, runID, now.UTC()))
	if err != nil {
		return Run{}, Monitor{}, err
	}
	monitor, err := scanMonitor(tx.QueryRowContext(ctx, `SELECT `+monitorColumns+` FROM asset_monitors WHERE id=$1`, run.MonitorID))
	if err != nil {
		return Run{}, Monitor{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE asset_monitors SET last_status='running',last_run_at=$2,last_error='',updated_at=$2 WHERE id=$1`, monitor.ID, now.UTC()); err != nil {
		return Run{}, Monitor{}, err
	}
	if err = tx.Commit(); err != nil {
		return Run{}, Monitor{}, err
	}
	return run, monitor, nil
}

func (s *Store) finishRun(ctx context.Context, run Run) error {
	finishedAt := time.Now().UTC()
	if run.FinishedAt != nil {
		finishedAt = run.FinishedAt.UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE asset_monitor_runs SET status=$2,finished_at=$3,total_count=$4,seen_count=$5,new_count=$6,
created_count=$7,updated_count=$8,skipped_count=$9,conflict_count=$10,error=$11 WHERE id=$1 AND status='running'`,
		run.ID, run.Status, finishedAt, run.TotalCount, run.SeenCount, run.NewCount, run.CreatedCount,
		run.UpdatedCount, run.SkippedCount, run.ConflictCount, run.Error)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	_, err = tx.ExecContext(ctx, `UPDATE asset_monitors SET last_status=CASE WHEN enabled=1 THEN $2 ELSE 'disabled' END,
last_error=$3,last_run_at=COALESCE($4,last_run_at),last_seen_count=$5,last_new_count=$6,updated_at=$7 WHERE id=$1`,
		run.MonitorID, run.Status, run.Error, run.StartedAt, run.SeenCount, run.NewCount, finishedAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) reconcileStaleRuns(ctx context.Context, staleBefore time.Time) error {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `UPDATE asset_monitor_runs SET status='error',finished_at=$2,error='interrupted stale run'
WHERE status='running' AND started_at < $1 RETURNING monitor_id`, staleBefore.UTC(), now)
	if err != nil {
		return err
	}
	monitorIDs := []string{}
	for rows.Next() {
		var monitorID string
		if err = rows.Scan(&monitorID); err != nil {
			_ = rows.Close()
			return err
		}
		monitorIDs = append(monitorIDs, monitorID)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	for _, monitorID := range monitorIDs {
		if _, err = tx.ExecContext(ctx, `UPDATE asset_monitors SET last_status=CASE WHEN enabled=1 THEN 'error' ELSE 'disabled' END,
last_error='interrupted stale run',updated_at=$2 WHERE id=$1`, monitorID, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) listRuns(ctx context.Context, projectID, monitorID string, options RunListOptions) (RunListResult, error) {
	limit, offset, err := normalizePage(options.Limit, options.Offset)
	if err != nil {
		return RunListResult{}, err
	}
	where := `monitor_id=$1`
	args := []any{strings.TrimSpace(monitorID)}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		args = append(args, projectID)
		where += fmt.Sprintf(` AND project_id=$%d`, len(args))
	}
	result := RunListResult{Items: []Run{}}
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_monitor_runs WHERE `+where, args...).Scan(&result.Total); err != nil {
		return result, err
	}
	args = append(args, limit, offset)
	query := fmt.Sprintf(`SELECT %s FROM asset_monitor_runs WHERE %s ORDER BY created_at DESC,id LIMIT $%d OFFSET $%d`, runColumns, where, len(args)-1, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		run, scanErr := scanRun(rows)
		if scanErr != nil {
			return result, scanErr
		}
		result.Items = append(result.Items, run)
	}
	return result, rows.Err()
}

func (s *Store) getRun(ctx context.Context, projectID, monitorID, runID string) (Run, error) {
	query := `SELECT ` + runColumns + ` FROM asset_monitor_runs WHERE id=$1 AND monitor_id=$2`
	args := []any{strings.TrimSpace(runID), strings.TrimSpace(monitorID)}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		query += ` AND project_id=$3`
		args = append(args, projectID)
	}
	run, err := scanRun(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return run, err
}

type persistenceResult struct {
	Seen      int
	New       int
	Created   int
	Updated   int
	Conflicts int
}

func (s *Store) persistObservations(ctx context.Context, monitor Monitor, run Run, observations []Observation, seenAt time.Time) (persistenceResult, error) {
	result := persistenceResult{}
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	seenAt = seenAt.UTC()
	timestamp := seenAt.Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, observation := range observations {
		assetID := uuid.NewString()
		var persistedID string
		var assetCreated bool
		err = tx.QueryRowContext(ctx, `INSERT INTO assets(
id,dedup_key,project_id,host,ip,port,domain,protocol,title,server,country,province,city,
source,source_query,status,tags_json,responsible_person,department,business_system,environment,criticality,
first_seen_at,last_seen_at,created_at,updated_at,owner_user_id)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'quake',$14,'active','[]','','','','','',$15,$15,$15,$15,NULLIF($16,''))
ON CONFLICT(dedup_key) DO UPDATE SET
 project_id=CASE WHEN assets.project_id IS NULL OR assets.project_id='' THEN EXCLUDED.project_id ELSE assets.project_id END,
 owner_user_id=CASE WHEN assets.owner_user_id IS NULL OR assets.owner_user_id='' THEN EXCLUDED.owner_user_id ELSE assets.owner_user_id END,
 host=EXCLUDED.host,ip=CASE WHEN EXCLUDED.ip<>'' THEN EXCLUDED.ip ELSE assets.ip END,
 domain=EXCLUDED.domain,protocol=CASE WHEN EXCLUDED.protocol<>'' THEN EXCLUDED.protocol ELSE assets.protocol END,
 title=CASE WHEN EXCLUDED.title<>'' THEN EXCLUDED.title ELSE assets.title END,
 server=CASE WHEN EXCLUDED.server<>'' THEN EXCLUDED.server ELSE assets.server END,
 country=CASE WHEN EXCLUDED.country<>'' THEN EXCLUDED.country ELSE assets.country END,
 province=CASE WHEN EXCLUDED.province<>'' THEN EXCLUDED.province ELSE assets.province END,
 city=CASE WHEN EXCLUDED.city<>'' THEN EXCLUDED.city ELSE assets.city END,
 last_seen_at=EXCLUDED.last_seen_at,updated_at=EXCLUDED.updated_at
WHERE assets.project_id=EXCLUDED.project_id OR
 ((assets.project_id IS NULL OR assets.project_id='') AND
  (assets.owner_user_id IS NULL OR assets.owner_user_id='' OR assets.owner_user_id=EXCLUDED.owner_user_id))
RETURNING id,(xmax=0)`, assetID, observationDedupKey(observation), monitor.ProjectID, observation.Host,
			observation.IP, observation.Port, observation.Domain, observation.Protocol, observation.Title, observation.Server,
			observation.Country, observation.Province, observation.City, monitor.Query, timestamp, monitor.OwnerUserID).Scan(&persistedID, &assetCreated)
		if errors.Is(err, sql.ErrNoRows) {
			result.Conflicts++
			continue
		}
		if err != nil {
			return result, fmt.Errorf("persist monitored asset: %w", err)
		}
		if assetCreated {
			result.Created++
		} else {
			result.Updated++
		}
		if monitor.OwnerUserID != "" {
			if _, err = tx.ExecContext(ctx, `INSERT INTO rbac_resource_assignments(id,user_id,resource_type,resource_id,created_at)
SELECT $1,id,'asset',$2,$3 FROM rbac_users WHERE id=$4 ON CONFLICT DO NOTHING`, uuid.NewString(), persistedID, timestamp, monitor.OwnerUserID); err != nil {
				return result, fmt.Errorf("assign monitored asset: %w", err)
			}
		}
		var firstForMonitor bool
		err = tx.QueryRowContext(ctx, `INSERT INTO asset_monitor_assets(monitor_id,asset_id,first_seen_at,last_seen_at)
VALUES($1,$2,$3,$3) ON CONFLICT(monitor_id,asset_id) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at
RETURNING (xmax=0)`, monitor.ID, persistedID, seenAt).Scan(&firstForMonitor)
		if err != nil {
			return result, fmt.Errorf("record monitor asset history: %w", err)
		}
		state := RunAssetStateSeen
		if firstForMonitor {
			state = RunAssetStateNew
			result.New++
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO asset_monitor_run_assets(run_id,monitor_id,asset_id,state,observed_at)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(run_id,asset_id) DO UPDATE SET
state=CASE WHEN asset_monitor_run_assets.state='new' THEN 'new' ELSE EXCLUDED.state END,observed_at=EXCLUDED.observed_at`,
			run.ID, monitor.ID, persistedID, state, seenAt); err != nil {
			return result, fmt.Errorf("record run asset: %w", err)
		}
		result.Seen++
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Store) listRunAssets(ctx context.Context, projectID, monitorID, runID string, options RunAssetListOptions) (RunAssetListResult, error) {
	limit, offset, err := normalizePage(options.Limit, options.Offset)
	if err != nil {
		return RunAssetListResult{}, err
	}
	state, err := normalizeRunAssetState(options.State)
	if err != nil {
		return RunAssetListResult{}, err
	}
	where := `ra.run_id=$1 AND ra.monitor_id=$2`
	args := []any{strings.TrimSpace(runID), strings.TrimSpace(monitorID)}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		args = append(args, projectID)
		where += fmt.Sprintf(` AND r.project_id=$%d`, len(args))
	}
	if state != "" {
		args = append(args, state)
		where += fmt.Sprintf(` AND ra.state=$%d`, len(args))
	}
	result := RunAssetListResult{Items: []RunAsset{}}
	countQuery := `SELECT COUNT(*) FROM asset_monitor_run_assets ra JOIN asset_monitor_runs r ON r.id=ra.run_id WHERE ` + where
	if err = s.db.QueryRowContext(ctx, countQuery, args...).Scan(&result.Total); err != nil {
		return result, err
	}
	args = append(args, limit, offset)
	query := fmt.Sprintf(`SELECT ra.run_id,ra.monitor_id,ra.asset_id,ra.state,ra.observed_at,
a.host,a.ip,a.port,a.domain,a.protocol,a.title,a.server
FROM asset_monitor_run_assets ra JOIN asset_monitor_runs r ON r.id=ra.run_id JOIN assets a ON a.id=ra.asset_id
WHERE %s ORDER BY ra.observed_at DESC,ra.asset_id LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var asset RunAsset
		if err = rows.Scan(&asset.RunID, &asset.MonitorID, &asset.AssetID, &asset.State, &asset.ObservedAt,
			&asset.Host, &asset.IP, &asset.Port, &asset.Domain, &asset.Protocol, &asset.Title, &asset.Server); err != nil {
			return result, err
		}
		asset.ObservedAt = asset.ObservedAt.UTC()
		result.Items = append(result.Items, asset)
	}
	return result, rows.Err()
}
