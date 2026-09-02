package hitl

import (
	"cyberstrike-ai/internal/testutil/testpostgres"
	"testing"
	"time"

	appconfig "cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestServicePurgeExpired_respectsZeroRetention(t *testing.T) {
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS hitl_interrupts (
		id TEXT PRIMARY KEY,
		conversation_id TEXT NOT NULL,
		mode TEXT NOT NULL,
		tool_name TEXT NOT NULL,
		status TEXT NOT NULL,
		decision TEXT,
		created_at TEXT NOT NULL,
		decided_at TEXT
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	old := time.Now().AddDate(0, 0, -100).UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO hitl_interrupts
		(id, conversation_id, mode, tool_name, status, decision, created_at, decided_at)
		VALUES ('old-1', 'c1', 'approval', 'exec', 'decided', 'approve', $1, $2)`, old, old); err != nil {
		t.Fatalf("insert: %v", err)
	}

	zero := 0
	svc := NewService(db, &appconfig.Config{
		Hitl: appconfig.HitlConfig{RetentionDays: &zero},
	}, zap.NewNop())
	svc.PurgeExpired()

	if err := db.QueryRow(`SELECT id FROM hitl_interrupts WHERE id = 'old-1'`).Scan(new(string)); err != nil {
		t.Fatalf("record should remain when retention_days=0: %v", err)
	}
}
