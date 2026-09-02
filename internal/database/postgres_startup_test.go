package database

import (
	"cyberstrike-ai/internal/testutil/testpostgres"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// Use a dedicated disposable PostgreSQL database without the vector extension.
// This test creates the application schema but never drops existing objects.
func TestPostgresStartupWithoutOptionalKnowledge(t *testing.T) {
	dsn := testpostgres.DSN(t)
	probe, err := openPostgres(dsn, "UTC")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var hasVector bool
	if err := probe.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'vector')`).Scan(&hasVector); err != nil {
		t.Fatal(err)
	}
	if hasVector {
		t.Skip("this regression requires PostgreSQL without pgvector")
	}

	db, err := NewPostgresDB(dsn, "UTC", zap.NewNop())
	if err != nil {
		t.Fatalf("main database must start without optional knowledge: %v", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversations`).Scan(&count); err != nil {
		t.Fatalf("core schema is not usable: %v", err)
	}
	if err := db.EnsureKnowledgeTables(); err == nil || !strings.Contains(err.Error(), "vector") {
		t.Fatalf("explicit knowledge initialization must report the missing dependency, got %v", err)
	}
}
