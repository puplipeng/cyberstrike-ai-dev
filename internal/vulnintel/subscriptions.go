package vulnintel

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrSubscriptionLimit = errors.New("最多保存 50 个情报订阅")

func (s *Store) initExtensions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
 CREATE TABLE IF NOT EXISTS intel_changes (
 id BIGSERIAL PRIMARY KEY,cve_id TEXT NOT NULL,kind TEXT NOT NULL,title TEXT NOT NULL,
 search_text TEXT NOT NULL,severity TEXT NOT NULL,known_exploited BOOLEAN NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP);
 CREATE INDEX IF NOT EXISTS intel_changes_time_idx ON intel_changes(created_at);
 CREATE TABLE IF NOT EXISTS intel_subscriptions (
 id BIGSERIAL PRIMARY KEY,user_id TEXT NOT NULL,query TEXT NOT NULL,cursor BIGINT NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id,query));
 CREATE TABLE IF NOT EXISTS intel_notifications (
 user_id TEXT NOT NULL,event_id BIGINT NOT NULL REFERENCES intel_changes(id) ON DELETE CASCADE,
 read_at TIMESTAMPTZ,PRIMARY KEY(user_id,event_id));
 CREATE TABLE IF NOT EXISTS intel_analyses (
 user_id TEXT NOT NULL,cve_id TEXT NOT NULL,input_hash TEXT NOT NULL,model TEXT NOT NULL,
 content JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(user_id,cve_id));
 CREATE TABLE IF NOT EXISTS intel_analysis_attempts (
 id BIGSERIAL PRIMARY KEY,user_id TEXT NOT NULL,cve_id TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP);
 CREATE INDEX IF NOT EXISTS intel_analysis_attempts_user_idx ON intel_analysis_attempts(user_id,created_at);
 CREATE OR REPLACE FUNCTION intel_capture_change() RETURNS trigger LANGUAGE plpgsql AS $fn$
 DECLARE event_kind TEXT; search_value TEXT;
 BEGIN
 IF TG_OP='UPDATE' AND OLD.nvd IS NOT DISTINCT FROM NEW.nvd AND OLD.kev IS NOT DISTINCT FROM NEW.kev
 AND OLD.score IS NOT DISTINCT FROM NEW.score AND OLD.severity IS NOT DISTINCT FROM NEW.severity THEN RETURN NEW; END IF;
 event_kind:='updated';
 IF TG_OP='INSERT' THEN event_kind:='new';
 ELSIF lower(coalesce(NEW.nvd->>'status',''))='rejected' AND lower(coalesce(OLD.nvd->>'status',''))<>'rejected' THEN event_kind:='rejected';
 ELSIF lower(coalesce(OLD.nvd->>'status',''))='rejected' AND lower(coalesce(NEW.nvd->>'status',''))<>'rejected' THEN event_kind:='restored';
 ELSIF OLD.kev IS NULL AND NEW.kev IS NOT NULL THEN event_kind:='kev_added';
 ELSIF OLD.kev IS NOT NULL AND NEW.kev IS NULL THEN event_kind:='kev_removed';
 ELSIF OLD.score IS DISTINCT FROM NEW.score OR OLD.severity IS DISTINCT FROM NEW.severity THEN event_kind:='rating'; END IF;
 search_value:=NEW.cve_id||' '||coalesce(NEW.nvd::text,'')||' '||coalesce(NEW.kev::text,'');
 IF TG_OP='UPDATE' THEN search_value:=search_value||' '||coalesce(OLD.nvd::text,'')||' '||coalesce(OLD.kev::text,''); END IF;
 INSERT INTO intel_changes(cve_id,kind,title,search_text,severity,known_exploited)
 VALUES(NEW.cve_id,event_kind,coalesce(NEW.kev->>'vulnerabilityName',NEW.cve_id),lower(search_value),NEW.severity,NEW.kev IS NOT NULL);
 RETURN NEW;
 END $fn$;
 DO $block$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='intel_change_capture' AND tgrelid='vulnerability_intelligence'::regclass)
 THEN CREATE TRIGGER intel_change_capture AFTER INSERT OR UPDATE OF nvd,kev,severity,score ON vulnerability_intelligence FOR EACH ROW EXECUTE FUNCTION intel_capture_change(); END IF;
 END $block$;`)
	return err
}

type Subscription struct {
	ID      int64     `json:"id"`
	Query   string    `json:"query"`
	Created time.Time `json:"created"`
}
type IntelNotification struct {
	ID      int64     `json:"id"`
	CVE     string    `json:"cve_id"`
	Kind    string    `json:"kind"`
	Title   string    `json:"title"`
	Created time.Time `json:"created"`
	Read    bool      `json:"read"`
}
type NotificationResult struct {
	Items  []IntelNotification `json:"items"`
	Unread int                 `json:"unread"`
}

func validateSubscription(query string) (string, error) {
	query = strings.TrimSpace(query)
	if !utf8.ValidString(query) || len(query) < 2 || len(query) > 200 || strings.ContainsAny(query, "\x00\r\n") {
		return "", errors.New("订阅关键词需为 2–200 字节的单行文本")
	}
	return query, nil
}
func (s *Store) Subscriptions(ctx context.Context, user string) ([]Subscription, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,query,created_at FROM intel_subscriptions WHERE user_id=$1 ORDER BY id DESC`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Subscription{}
	for rows.Next() {
		var r Subscription
		if err = rows.Scan(&r.ID, &r.Query, &r.Created); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) Subscribe(ctx context.Context, user, query string) (Subscription, error) {
	var out Subscription
	query, err := validateSubscription(query)
	if err != nil {
		return out, err
	}
	if user == "" {
		return out, errors.New("unauthorized")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	// Serializes quota/duplicate checks for the same user, including across instances.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,739521806))`, user); err != nil {
		return out, err
	}
	err = tx.QueryRowContext(ctx, `SELECT id,query,created_at FROM intel_subscriptions WHERE user_id=$1 AND query=$2`, user, query).Scan(&out.ID, &out.Query, &out.Created)
	if err == nil {
		return out, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM intel_subscriptions WHERE user_id=$1`, user).Scan(&count); err != nil {
		return out, err
	}
	if count >= 50 {
		return out, ErrSubscriptionLimit
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO intel_subscriptions(user_id,query,cursor) SELECT $1,$2,COALESCE(MAX(id),0) FROM intel_changes RETURNING id,query,created_at`, user, query).Scan(&out.ID, &out.Query, &out.Created)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Store) Unsubscribe(ctx context.Context, user string, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM intel_subscriptions WHERE user_id=$1 AND id=$2`, user, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Outbox delivery and cursor advancement commit together. A retry cannot duplicate
// a notification, including when several subscriptions match the same CVE event.
func (s *Store) DispatchNotifications(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(739521807)`).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return nil
	}
	// Lock subscription rows before snapshotting the high-water mark. New subscriptions
	// created afterwards keep their own initial cursor and are processed on the next pass.
	rows, err := tx.QueryContext(ctx, `SELECT id FROM intel_subscriptions ORDER BY id FOR UPDATE`)
	if err != nil {
		return err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var high int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM intel_changes`).Scan(&high); err != nil {
		return err
	}
	if len(ids) > 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO intel_notifications(user_id,event_id)
 SELECT s.user_id,e.id FROM intel_subscriptions s JOIN intel_changes e ON e.id>s.cursor AND e.id<=$1
 WHERE s.id=ANY($2::bigint[]) AND CASE WHEN upper(s.query) ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'
 THEN e.cve_id=upper(s.query) ELSE strpos(e.search_text,lower(s.query))>0 END ON CONFLICT DO NOTHING`, high, ids)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE intel_subscriptions SET cursor=$1 WHERE id=ANY($2::bigint[])`, high, ids); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM intel_changes WHERE created_at<CURRENT_TIMESTAMP-INTERVAL '90 days'`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM intel_analysis_attempts WHERE created_at<CURRENT_TIMESTAMP-INTERVAL '2 days'`); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Notifications(ctx context.Context, user string) (NotificationResult, error) {
	out := NotificationResult{Items: []IntelNotification{}}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM intel_notifications WHERE user_id=$1 AND read_at IS NULL`, user).Scan(&out.Unread); err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.id,e.cve_id,e.kind,e.title,e.created_at,n.read_at IS NOT NULL FROM intel_notifications n JOIN intel_changes e ON e.id=n.event_id WHERE n.user_id=$1 ORDER BY e.id DESC LIMIT 50`, user)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var r IntelNotification
		if err = rows.Scan(&r.ID, &r.CVE, &r.Kind, &r.Title, &r.Created, &r.Read); err != nil {
			rows.Close()
			return out, err
		}
		out.Items = append(out.Items, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Store) ReadNotifications(ctx context.Context, user string, through int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE intel_notifications SET read_at=CURRENT_TIMESTAMP WHERE user_id=$1 AND event_id<=$2 AND read_at IS NULL`, user, through)
	return err
}
