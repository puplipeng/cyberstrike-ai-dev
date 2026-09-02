package vulnintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// FIRST recommends the daily file for bulk synchronization, not the lookup API.
const epssURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

type EPSSRecord struct {
	ID          string  `json:"cve_id,omitempty"`
	Probability float64 `json:"probability"`
	Percentile  float64 `json:"percentile"`
	Date        string  `json:"date"`
	Stale       bool    `json:"stale"`
}
type epssFeed struct {
	Date, Version string
	Records       []EPSSRecord
	Total         int
}

func validProbability(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 && n <= 1 }

func parseEPSS(data []byte, wanted map[string]bool, now time.Time) (epssFeed, error) {
	f := epssFeed{Records: []EPSSRecord{}}
	header, body, ok := bytes.Cut(data, []byte("\n"))
	if !ok {
		return f, errors.New("EPSS metadata missing")
	}
	for _, part := range strings.Split(strings.TrimSpace(string(header)), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "#")), ":")
		if ok {
			switch key {
			case "model_version":
				f.Version = strings.TrimSpace(value)
			case "score_date":
				f.Date = strings.TrimSpace(value)
			}
		}
	}
	date, err := parseDate(f.Date)
	date = date.UTC().Truncate(24 * time.Hour)
	today := now.UTC().Truncate(24 * time.Hour)
	if err != nil || f.Version == "" || date.After(today) || date.Before(today.AddDate(0, 0, -7)) {
		return f, errors.New("invalid or outdated EPSS metadata")
	}
	f.Date = date.Format("2006-01-02")
	reader := csv.NewReader(bytes.NewReader(body))
	cols, err := reader.Read()
	if err != nil || strings.Join(cols, ",") != "cve,epss,percentile" {
		return f, errors.New("invalid EPSS CSV columns")
	}
	seen := map[string]bool{}
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(row) != 3 {
			return f, errors.New("invalid EPSS CSV row")
		}
		p, e1 := strconv.ParseFloat(row[1], 64)
		percentile, e2 := strconv.ParseFloat(row[2], 64)
		if !ValidCVE(row[0]) || seen[row[0]] || e1 != nil || e2 != nil || !validProbability(p) || !validProbability(percentile) {
			return f, errors.New("invalid or duplicate EPSS score")
		}
		seen[row[0]] = true
		f.Total++
		if f.Total > 1000000 {
			return f, errors.New("EPSS catalog exceeds record limit")
		}
		if wanted[row[0]] {
			f.Records = append(f.Records, EPSSRecord{ID: row[0], Probability: p, Percentile: percentile, Date: f.Date})
		}
	}
	if f.Total == 0 {
		return f, errors.New("empty EPSS catalog rejected")
	}
	return f, nil
}

func (c *feedClient) epss(ctx context.Context, wanted map[string]bool) (epssFeed, error) {
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, epssURL, nil)
		if err != nil {
			return epssFeed{}, err
		}
		req.Header.Set("User-Agent", "CyberStrikeAI-vulnerability-intelligence/1.0")
		// No NVD or AI credentials are ever sent to this host.
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return epssFeed{}, ctx.Err()
			}
			if attempt < 2 {
				if err = waitContext(ctx, retryDelay("", attempt)); err != nil {
					return epssFeed{}, err
				}
				continue
			}
			return epssFeed{}, errors.New("EPSS network/TLS request failed; previous data retained")
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			delay := retryDelay(resp.Header.Get("Retry-After"), attempt)
			resp.Body.Close()
			if attempt < 2 {
				if err = waitContext(ctx, delay); err != nil {
					return epssFeed{}, err
				}
				continue
			}
			return epssFeed{}, fmt.Errorf("EPSS HTTP %d after retries", resp.StatusCode)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return epssFeed{}, fmt.Errorf("EPSS HTTP %d", resp.StatusCode)
		}
		compressed, err := io.ReadAll(io.LimitReader(resp.Body, (32<<20)+1))
		resp.Body.Close()
		if err != nil || len(compressed) > 32<<20 {
			return epssFeed{}, errors.New("EPSS download incomplete or exceeds 32 MiB")
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return epssFeed{}, errors.New("invalid EPSS gzip")
		}
		data, err := io.ReadAll(io.LimitReader(reader, (96<<20)+1))
		reader.Close()
		if err != nil || len(data) > 96<<20 {
			return epssFeed{}, errors.New("EPSS decompression failed or exceeds 96 MiB")
		}
		return parseEPSS(data, wanted, time.Now())
	}
	return epssFeed{}, errors.New("EPSS unavailable")
}

func (s *Store) intelIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT cve_id FROM vulnerability_intelligence")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[string]bool{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids[id] = true
	}
	return ids, rows.Err()
}

func (s *Store) saveEPSS(ctx context.Context, f epssFeed) error {
	if _, err := time.Parse("2006-01-02", f.Date); err != nil {
		return errors.New("invalid EPSS snapshot date")
	}
	if f.Total < 1 || f.Total < len(f.Records) || f.Version == "" {
		return errors.New("invalid EPSS snapshot")
	}
	if f.Records == nil {
		f.Records = []EPSSRecord{}
	}
	seen := map[string]bool{}
	for _, r := range f.Records {
		if !ValidCVE(r.ID) || seen[r.ID] || r.Date != f.Date || !validProbability(r.Probability) || !validProbability(r.Percentile) {
			return errors.New("invalid EPSS snapshot record")
		}
		seen[r.ID] = true
	}
	data, err := json.Marshal(f.Records)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var newer bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM vulnerability_intelligence WHERE epss->>'date'>$1)`, f.Date).Scan(&newer); err != nil {
		return err
	}
	if newer {
		return errors.New("EPSS snapshot older than stored data")
	}
	_, err = tx.ExecContext(ctx, `WITH feed AS (SELECT * FROM jsonb_to_recordset($1::jsonb) AS x(cve_id text,probability double precision,percentile double precision,date text))
 UPDATE vulnerability_intelligence i SET epss=jsonb_build_object('probability',f.probability,'percentile',f.percentile,'date',f.date)
 FROM feed f WHERE i.cve_id=f.cve_id`, string(data))
	if err != nil {
		return err
	}
	// An omitted score is unknown, never a numeric zero. The whole snapshot is atomic.
	_, err = tx.ExecContext(ctx, `UPDATE vulnerability_intelligence SET epss=NULL WHERE epss IS NOT NULL AND NOT(cve_id=ANY($1::text[]))`, mapKeys(seen))
	if err != nil {
		return err
	}
	return tx.Commit()
}
func mapKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	return out
}

// Match the displayed reasons and ordering; stale EPSS never raises a priority.
const freshEPSS = `(epss IS NOT NULL AND (epss->>'date')::date BETWEEN (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date-3 AND (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date)`
const priorityOrder = `CASE WHEN NOT (` + activeCondition + `) THEN 4 WHEN kev IS NOT NULL THEN 0
 WHEN severity='critical' OR (` + freshEPSS + ` AND (epss->>'probability')::double precision>=0.1) THEN 1
 WHEN severity IN ('high','unknown') OR (` + freshEPSS + ` AND (epss->>'probability')::double precision>=0.01) THEN 2 ELSE 3 END`

func setPriority(r *Record, now time.Time) {
	p := 0.0
	if r.EPSS != nil {
		d, err := time.Parse("2006-01-02", r.EPSS.Date)
		today := now.UTC().Truncate(24 * time.Hour)
		r.EPSS.Stale = err != nil || d.Before(today.AddDate(0, 0, -3)) || d.After(today)
		if !r.EPSS.Stale {
			p = r.EPSS.Probability
		}
	}
	switch {
	case r.Lifecycle == "rejected":
		r.Priority, r.PriorityReason = "archived", "rejected"
	case r.KnownExploited:
		r.Priority, r.PriorityReason = "urgent", "kev"
	case p >= 0.1:
		r.Priority, r.PriorityReason = "high", "epss_10"
	case r.Severity == "critical":
		r.Priority, r.PriorityReason = "high", "cvss_critical"
	case p >= 0.01:
		r.Priority, r.PriorityReason = "review", "epss_1"
	case r.Severity == "high":
		r.Priority, r.PriorityReason = "review", "cvss_high"
	case r.Severity == "unknown":
		r.Priority, r.PriorityReason = "review", "unrated"
	default:
		r.Priority, r.PriorityReason = "normal", "routine"
	}
}
