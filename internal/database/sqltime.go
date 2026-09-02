package database

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"strconv"
	"strings"
	"time"
)

// formatSQLiteUTC stores instants as UTC RFC3339 for consistent SQLite reads/writes.
func formatSQLiteUTC(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// sqliteEpochGE returns PG SQL comparing column (TEXT timestamp) to param as Unix seconds.
// idx 为该参数在 SQL 中的占位符编号（= len(args)+1）。
func sqliteEpochGE(column, op string, idx int) string {
	return "EXTRACT(EPOCH FROM " + column + "::timestamptz) " + op + " EXTRACT(EPOCH FROM $" + strconv.Itoa(idx) + "::timestamptz)"
}

// ParseRFC3339Time parses API/query timestamps (RFC3339 or RFC3339Nano).
func ParseRFC3339Time(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, errors.New("empty time value")
	}
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// postgresArgValue 将 Go 参数值转换为 PG TEXT 时间列 / BIGINT 布尔列可接受的值。
// - time.Time：沿用 SQLite 侧的 UTC RFC3339Nano 文本，保证双方言读回一致；
// - bool：SQLite 以 0/1 存储，PG 列为 BIGINT，布尔需显式转为整数。
func postgresArgValue(v driver.Value) (driver.Value, error) {
	switch t := v.(type) {
	case time.Time:
		return formatSQLiteUTC(t), nil
	case sql.NullTime:
		if t.Valid {
			return formatSQLiteUTC(t.Time), nil
		}
		return nil, nil
	case bool:
		if t {
			return int64(1), nil
		}
		return int64(0), nil
	default:
		return v, nil
	}
}

// parseSQLiteLikeTime 尝试把字符串解析为时间戳；失败返回 false（保持原字符串）。
func parseSQLiteLikeTime(s string) (time.Time, bool) {
	if len(s) < 16 || len(s) > 35 {
		return time.Time{}, false
	}
	// 快速预检：YYYY-MM-DD 前缀，避免对任意文本做时间解析
	if s[4] != '-' || s[7] != '-' || !isDigit(s[0]) || !isDigit(s[1]) {
		return time.Time{}, false
	}
	for _, layout := range pgRowTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// pgRowTimeLayouts 与 mattn/go-sqlite3 对 datetime 声明列的行为对齐：
// 可解析为时间戳的字符串读回为 time.Time；扫描到 string 目标时由
// database/sql 自动格式化为 RFC3339Nano（值不变）。
var pgRowTimeLayouts = []string{
	time.RFC3339Nano,                      // 2026-01-02T15:04:05(.frac)Z / ±hh:mm
	"2006-01-02 15:04:05.999999999-07",    // PostgreSQL CURRENT_TIMESTAMP stored in TEXT (UTC +00)
	"2006-01-02 15:04:05.999999999-0700",  // compact timezone offset
	"2006-01-02 15:04:05.999999999-07:00", // 2026-01-02 15:04:05(.frac)+08:00
	"2006-01-02 15:04:05.999999999",       // 无时区 → UTC
	"2006-01-02T15:04:05.999999999",       // 无时区 → UTC
}
