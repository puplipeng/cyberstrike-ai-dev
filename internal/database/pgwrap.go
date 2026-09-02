package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// PostgreSQL driver wrapper: SQL is already native PostgreSQL. Only timestamp
// and legacy boolean argument/row normalization is performed here.
// localTZ remains in the constructor signature for compatibility; sessions use UTC.
func openPostgres(dsn, localTZ string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("解析 PostgreSQL DSN 失败: %w", err)
	}
	base := stdlib.GetConnector(*cfg)
	return sql.OpenDB(&pgConnector{
		base: base,
	}), nil
}

// pgConnector 包装 driver.Connector，为每个物理连接设置会话时区。
type pgConnector struct {
	base driver.Connector
}

func (c *pgConnector) Connect(ctx context.Context) (driver.Conn, error) {
	raw, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	conn := &pgConn{base: raw}
	if err := conn.initSession(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func (c *pgConnector) Driver() driver.Driver {
	return &pgDriver{base: c.base.Driver()}
}

type pgDriver struct {
	base driver.Driver
}

func (d *pgDriver) Open(name string) (driver.Conn, error) {
	raw, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return &pgConn{base: raw}, nil
}

// pgConn 包装 driver.Conn：执行原生 SQL、规范化参数。
type pgConn struct {
	base driver.Conn
}

// initSession 统一会话时区为 UTC，保证裸时间字符串（CURRENT_TIMESTAMP 写入的
// "YYYY-MM-DD HH:MM:SS"）在 ::timestamptz cast 时与 SQLite 的 UTC 语义一致。
func (c *pgConn) initSession(ctx context.Context) error {
	if execer, ok := c.base.(driver.ExecerContext); ok {
		if _, err := execer.ExecContext(ctx, "SET TIME ZONE 'UTC'", nil); err != nil {
			return fmt.Errorf("设置 PostgreSQL 会话时区失败: %w", err)
		}
		return nil
	}
	// 理论上 pgx 一定实现 ExecerContext；兜底走 Prepare 路径。
	stmt, err := c.base.Prepare("SET TIME ZONE 'UTC'")
	if err != nil {
		return fmt.Errorf("设置 PostgreSQL 会话时区失败: %w", err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(nil)
	return err
}

func (c *pgConn) Prepare(query string) (driver.Stmt, error) {
	stmt, err := c.base.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &pgStmt{base: stmt, conn: c}, nil
}

func (c *pgConn) Close() error { return c.base.Close() }

func (c *pgConn) Begin() (driver.Tx, error) { return c.base.Begin() }

// --- 可选接口透传（存在才实现，避免吞掉 pgx 能力） ---

func (c *pgConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if pc, ok := c.base.(driver.ConnPrepareContext); ok {
		stmt, err := pc.PrepareContext(ctx, query)
		if err != nil {
			return nil, err
		}
		return &pgStmt{base: stmt, conn: c}, nil
	}
	return c.Prepare(query)
}

func (c *pgConn) ExecContext(ctx context.Context, query string, argsV []driver.NamedValue) (driver.Result, error) {
	if execer, ok := c.base.(driver.ExecerContext); ok {
		if err := c.checkArgs(argsV); err != nil {
			return nil, err
		}
		return execer.ExecContext(ctx, query, argsV)
	}
	return nil, driver.ErrSkip
}

func (c *pgConn) QueryContext(ctx context.Context, query string, argsV []driver.NamedValue) (driver.Rows, error) {
	if queryer, ok := c.base.(driver.QueryerContext); ok {
		if err := c.checkArgs(argsV); err != nil {
			return nil, err
		}
		rows, err := queryer.QueryContext(ctx, query, argsV)
		if err != nil {
			return nil, err
		}
		return newPgRows(rows), nil
	}
	return nil, driver.ErrSkip
}

// pgRows 包装 driver.Rows：把时间列（列名以 _at / _time 结尾或 last_check_in）
// 中可解析为时间戳的 TEXT 值转换为 time.Time，对齐 mattn/go-sqlite3 对
// datetime 声明列的读取行为：
//   - Scan 到 time.Time / sql.NullTime 的场景照常工作；
//   - Scan 到 string 的场景由 database/sql 自动格式化为 RFC3339Nano（与 SQLite 一致）；
//   - 表达式结果列（如 date(...) AS bucket）不在命名规则内，保持原字符串。
//
// 通过内嵌 driver.Rows 透传 Columns/Close 及可选的 ColumnType* 接口。
type pgRows struct {
	driver.Rows
	columns []string
}

func newPgRows(base driver.Rows) driver.Rows {
	return &pgRows{Rows: base, columns: base.Columns()}
}

func (r *pgRows) Next(dest []driver.Value) error {
	if err := r.Rows.Next(dest); err != nil {
		return err
	}
	for i, v := range dest {
		if i >= len(r.columns) {
			break
		}
		if s, ok := v.(string); ok && isPgTimeColumnName(r.columns[i]) {
			if t, ok := parseSQLiteLikeTime(s); ok {
				dest[i] = t
			}
		}
	}
	return nil
}

// isPgTimeColumnName 判断列名是否属于时间语义列（与项目 DDL 命名约定对齐）。
func isPgTimeColumnName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "last_check_in" {
		return true
	}
	return strings.HasSuffix(lower, "_at") || strings.HasSuffix(lower, "_time")
}

func (c *pgConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if bt, ok := c.base.(driver.ConnBeginTx); ok {
		return bt.BeginTx(ctx, opts)
	}
	return nil, driver.ErrSkip
}

// CheckNamedValue 实现 driver.NamedValueChecker：原地规范化参数。
func (c *pgConn) CheckNamedValue(nv *driver.NamedValue) error {
	if nv == nil {
		return nil
	}
	v, err := postgresArgValue(nv.Value)
	if err != nil {
		return err
	}
	nv.Value = v
	return nil
}

func (c *pgConn) checkArgs(argsV []driver.NamedValue) error {
	for i := range argsV {
		v, err := postgresArgValue(argsV[i].Value)
		if err != nil {
			return err
		}
		argsV[i].Value = v
	}
	return nil
}

// pgStmt 包装 driver.Stmt：SQL 已在 Prepare 时翻译，这里只透传并规范化参数。
type pgStmt struct {
	base driver.Stmt
	conn *pgConn
}

func (s *pgStmt) Close() error { return s.base.Close() }

func (s *pgStmt) NumInput() int { return s.base.NumInput() }

func (s *pgStmt) Exec(args []driver.Value) (driver.Result, error) {
	converted, err := convertValues(args)
	if err != nil {
		return nil, err
	}
	return s.base.Exec(converted)
}

func (s *pgStmt) Query(args []driver.Value) (driver.Rows, error) {
	converted, err := convertValues(args)
	if err != nil {
		return nil, err
	}
	rows, err := s.base.Query(converted)
	if err != nil {
		return nil, err
	}
	return newPgRows(rows), nil
}

func (s *pgStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if ec, ok := s.base.(driver.StmtExecContext); ok {
		if err := s.conn.checkArgs(args); err != nil {
			return nil, err
		}
		return ec.ExecContext(ctx, args)
	}
	values, err := namedValuesToValues(args)
	if err != nil {
		return nil, err
	}
	return s.Exec(values)
}

func (s *pgStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if qc, ok := s.base.(driver.StmtQueryContext); ok {
		if err := s.conn.checkArgs(args); err != nil {
			return nil, err
		}
		rows, err := qc.QueryContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return newPgRows(rows), nil
	}
	values, err := namedValuesToValues(args)
	if err != nil {
		return nil, err
	}
	return s.Query(values)
}

// CheckNamedValue 实现 driver.NamedValueChecker（语句级优先于连接级）。
func (s *pgStmt) CheckNamedValue(nv *driver.NamedValue) error {
	return s.conn.CheckNamedValue(nv)
}

func convertValues(args []driver.Value) ([]driver.Value, error) {
	if len(args) == 0 {
		return args, nil
	}
	out := make([]driver.Value, len(args))
	for i, v := range args {
		cv, err := postgresArgValue(v)
		if err != nil {
			return nil, err
		}
		out[i] = cv
	}
	return out, nil
}

func namedValuesToValues(args []driver.NamedValue) ([]driver.Value, error) {
	out := make([]driver.Value, len(args))
	for i, nv := range args {
		out[i] = nv.Value
	}
	return out, nil
}
