package database

import (
	"testing"
	"time"
)

func TestParseSQLiteLikeTime(t *testing.T) {
	valid := []string{
		"2026-08-26 07:00:00.123456+00",
		"2026-08-26 15:00:00.123456+0800",
		"2026-08-26T07:00:00Z",
		"2026-08-26T07:00:00.123456789Z",
		"2026-08-26T15:04:05+08:00",
		"2026-08-26 15:04:05",
		"2026-08-26 15:04:05.5",
		"2026-08-26T15:04:05.999999999-07:00",
	}
	for _, s := range valid {
		if _, ok := parseSQLiteLikeTime(s); !ok {
			t.Fatalf("expected parseable: %s", s)
		}
	}
	invalid := []string{
		"2026-08-26",           // 仅日期（date() 表达式结果）
		"2026-08-26 14:00:00X", // 尾部杂质
		"hello world 123",
		"",
		"[]",
		"{\"a\":1}",
	}
	for _, s := range invalid {
		if _, ok := parseSQLiteLikeTime(s); ok {
			t.Fatalf("expected unparseable: %s", s)
		}
	}
	// 无时区值按 UTC 解析
	ts, ok := parseSQLiteLikeTime("2026-08-26 15:04:05")
	if !ok || ts != time.Date(2026, 8, 26, 15, 4, 5, 0, time.UTC) {
		t.Fatalf("naive datetime should parse as UTC: %v %v", ts, ok)
	}
}

func TestIsPgTimeColumnName(t *testing.T) {
	for _, name := range []string{"created_at", "updated_at", "last_call_time", "start_time", "end_time", "last_check_in", "read_at", "expires_at", "next_attempt_at", "CREATED_AT"} {
		if !isPgTimeColumnName(name) {
			t.Fatalf("expected time column: %s", name)
		}
	}
	for _, name := range []string{"bucket", "k", "label", "date", "content", "id", "total"} {
		if isPgTimeColumnName(name) {
			t.Fatalf("expected non-time column: %s", name)
		}
	}
}
