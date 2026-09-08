package assetmonitor

import (
	"context"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/testutil/testpostgres"
	"go.uber.org/zap"
)

func TestStoreTracksNewPerMonitorAndNeverReassignsCrossProjectAsset(t *testing.T) {
	dsn := testpostgres.DSN(t)
	db, err := database.NewPostgresDB(dsn, "UTC", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	nowText := time.Now().UTC().Format(time.RFC3339Nano)
	for _, projectID := range []string{"project-one", "project-two"} {
		_, err = db.ExecContext(ctx, `INSERT INTO projects(id,name,description,scope_json,status,pinned,created_at,updated_at,owner_user_id)
VALUES($1,$1,'','{}','active',0,$2,$2,NULL)`, projectID, nowText)
		if err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewStore(ctx, db.DB)
	if err != nil {
		t.Fatal(err)
	}
	monitorOne, err := store.createMonitor(ctx, integrationMonitor("project-one"))
	if err != nil {
		t.Fatal(err)
	}
	monitorTwo, err := store.createMonitor(ctx, integrationMonitor("project-two"))
	if err != nil {
		t.Fatal(err)
	}
	observation := Observation{Host: "api.example.com", Domain: "api.example.com", IP: "1.2.3.4", Port: 443, Protocol: "https"}

	firstRun := startStoreTestRun(t, store, monitorOne)
	first, err := store.persistObservations(ctx, monitorOne, firstRun, []Observation{observation}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if first.Seen != 1 || first.New != 1 || first.Created != 1 || first.Conflicts != 0 {
		t.Fatalf("first persistence = %+v", first)
	}
	finishStoreTestRun(t, store, firstRun, first)

	secondRun := startStoreTestRun(t, store, monitorOne)
	second, err := store.persistObservations(ctx, monitorOne, secondRun, []Observation{observation}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if second.Seen != 1 || second.New != 0 || second.Updated != 1 || second.Conflicts != 0 {
		t.Fatalf("second persistence = %+v", second)
	}
	finishStoreTestRun(t, store, secondRun, second)
	assets, err := store.listRunAssets(ctx, monitorOne.ProjectID, monitorOne.ID, secondRun.ID, RunAssetListOptions{})
	if err != nil || len(assets.Items) != 1 || assets.Items[0].State != RunAssetStateSeen {
		t.Fatalf("second run assets = %+v, %v", assets, err)
	}

	conflictRun := startStoreTestRun(t, store, monitorTwo)
	conflict, err := store.persistObservations(ctx, monitorTwo, conflictRun, []Observation{observation}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if conflict.Seen != 0 || conflict.New != 0 || conflict.Conflicts != 1 {
		t.Fatalf("cross-project persistence = %+v", conflict)
	}
	var projectID string
	if err = db.QueryRowContext(ctx, `SELECT project_id FROM assets WHERE dedup_key=$1`, observationDedupKey(observation)).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if projectID != monitorOne.ProjectID {
		t.Fatalf("cross-project conflict reassigned asset to %q", projectID)
	}
}

func TestStoreMigratesLegacyBooleanEnabledColumn(t *testing.T) {
	dsn := testpostgres.DSN(t)
	db, err := database.NewPostgresDB(dsn, "UTC", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	_, err = db.ExecContext(ctx, `CREATE TABLE asset_monitors (
 id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 owner_user_id TEXT NOT NULL,
 name TEXT NOT NULL,
 root_domain TEXT NOT NULL,
 provider TEXT NOT NULL DEFAULT 'quake',
 query TEXT NOT NULL,
 cron_expr TEXT NOT NULL DEFAULT '',
 interval_minutes INTEGER NOT NULL DEFAULT 1440,
 max_results INTEGER NOT NULL DEFAULT 200,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 next_run_at TIMESTAMPTZ,
 last_run_at TIMESTAMPTZ,
 last_status TEXT NOT NULL DEFAULT 'idle',
 last_error TEXT NOT NULL DEFAULT '',
 last_seen_count INTEGER NOT NULL DEFAULT 0,
 last_new_count INTEGER NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 UNIQUE(project_id,root_domain,provider)
);
CREATE INDEX asset_monitors_due_idx ON asset_monitors(next_run_at) WHERE enabled;`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewStore(ctx, db.DB); err != nil {
		t.Fatalf("migrate legacy boolean enabled column: %v", err)
	}
	var dataType string
	if err = db.QueryRowContext(ctx, `SELECT data_type FROM information_schema.columns
WHERE table_schema=current_schema() AND table_name='asset_monitors' AND column_name='enabled'`).Scan(&dataType); err != nil {
		t.Fatal(err)
	}
	if dataType != "bigint" {
		t.Fatalf("enabled data type = %q, want bigint", dataType)
	}
}

func integrationMonitor(projectID string) Monitor {
	next := time.Now().UTC().Add(time.Hour)
	return Monitor{
		ProjectID: projectID, OwnerUserID: "owner-one", Name: projectID, RootDomain: "example.com",
		Provider: ProviderQuake, Query: generatedQuery("example.com"), IntervalMinutes: 60,
		MaxResults: 100, Enabled: true, NextRunAt: &next, LastStatus: MonitorStatusIdle,
	}
}

func startStoreTestRun(t *testing.T, store *Store, monitor Monitor) Run {
	t.Helper()
	run, err := store.enqueueRun(context.Background(), monitor, RunTriggerManual, "owner-one")
	if err != nil {
		t.Fatal(err)
	}
	claimed, claimedMonitor, err := store.claimNextRun(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != run.ID || claimedMonitor.ID != monitor.ID {
		t.Fatalf("claimed run/monitor = %+v / %+v", claimed, claimedMonitor)
	}
	return claimed
}

func finishStoreTestRun(t *testing.T, store *Store, run Run, result persistenceResult) {
	t.Helper()
	run.Status = RunStatusSuccess
	run.SeenCount, run.NewCount = result.Seen, result.New
	run.CreatedCount, run.UpdatedCount, run.ConflictCount = result.Created, result.Updated, result.Conflicts
	finished := time.Now().UTC()
	run.FinishedAt = &finished
	if err := store.finishRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
}
