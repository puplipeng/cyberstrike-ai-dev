package database

import (
	"cyberstrike-ai/internal/testutil/testpostgres"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestBuildAuditLogsWhere_timeFilterSQL(t *testing.T) {
	since := time.Date(2026, 6, 16, 17, 2, 0, 0, time.UTC)
	until := time.Date(2026, 6, 17, 3, 3, 0, 0, time.UTC)
	where, args := buildAuditLogsWhere(ListAuditLogsFilter{Since: &since, Until: &until})
	if !strings.Contains(where, "EXTRACT(EPOCH FROM created_at::timestamptz) >=") {
		t.Fatalf("expected epoch comparison for since, got %q", where)
	}
	if !strings.Contains(where, "EXTRACT(EPOCH FROM created_at::timestamptz) <=") {
		t.Fatalf("expected epoch comparison for until, got %q", where)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 time args, got %d", len(args))
	}
	for i, arg := range args {
		s, ok := arg.(string)
		if !ok || s == "" {
			t.Fatalf("arg %d: want non-empty UTC RFC3339 string, got %v", i, arg)
		}
	}
}

func TestBuildAuditLogsWhere_relatedUserID(t *testing.T) {
	where, args := buildAuditLogsWhere(ListAuditLogsFilter{Category: "rbac", RelatedUserID: "user-123"})
	if !strings.Contains(where, "resource_id = $2") || !strings.Contains(where, "detail_json ILIKE $3") {
		t.Fatalf("expected related-user predicates, got %q", where)
	}
	if len(args) != 4 {
		t.Fatalf("expected category plus 3 related-user args, got %#v", args)
	}
	if args[1] != "user-123" || args[2] != `%"user_id":"user-123"%` || args[3] != `%"userId":"user-123"%` {
		t.Fatalf("unexpected related-user args: %#v", args)
	}
}

func TestListAuditLogs_timeFilterMixedStorageFormats(t *testing.T) {
	db, err := NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, row := range []struct{ id, at string }{
		{"inside-rfc3339", "2026-06-17T01:03:00+08:00"},
		{"inside-naive", "2026-06-17 03:00:00"},
		{"outside-offset", "2026-06-17T03:02:00-08:00"},
		{"outside-naive", "2026-06-16 17:01:00"},
	} {
		if _, err := db.Exec(`INSERT INTO audit_logs (id,created_at,level,category,action,result,actor,message) VALUES ($1,$2,'info','test','check','ok','test','fixture')`, row.id, row.at); err != nil {
			t.Fatal(err)
		}
	}
	since, _ := ParseRFC3339Time("2026-06-16T17:02:00Z")
	until, _ := ParseRFC3339Time("2026-06-17T03:03:00Z")
	filter := ListAuditLogsFilter{Since: &since, Until: &until, Limit: 50}
	logs, err := db.ListAuditLogs(filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("want 2 in-range rows, got %d", len(logs))
	}
	for _, row := range logs {
		at := row.CreatedAt.UTC()
		if at.Before(since) || at.After(until) {
			t.Fatalf("log %s at %s outside [%s, %s]", row.ID, at, since, until)
		}
	}
}
