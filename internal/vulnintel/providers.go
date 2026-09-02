package vulnintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const nvdURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
const kevMirrorURL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

type feedClient struct {
	http       *http.Client
	apiKey     string
	nvdSpacing time.Duration
	lastNVD    time.Time // only accessed by the single sync worker
}

func newFeedClient(apiKey string) *feedClient {
	return &feedClient{apiKey: apiKey, nvdSpacing: 6500 * time.Millisecond, http: &http.Client{
		Timeout: 90 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host || req.URL.User != nil {
				return errors.New("cross-origin redirect rejected")
			}
			return nil
		},
	}}
}

func waitContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func retryDelay(header string, attempt int) time.Duration {
	d := time.Duration(5*(attempt+1)) * time.Second
	if n, err := strconv.Atoi(header); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(header); err == nil {
		d = time.Until(t)
	}
	if d < time.Second {
		d = time.Second
	}
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	return d
}

func (c *feedClient) get(ctx context.Context, endpoint string, out any) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return errors.New("invalid feed URL")
	}
	base := *u
	base.RawQuery = ""
	if base.String() != nvdURL && base.String() != kevURL && base.String() != kevMirrorURL {
		return errors.New("unapproved feed URL")
	}
	isNVD := base.String() == nvdURL
	for attempt := 0; attempt < 3; attempt++ {
		if isNVD {
			if err := waitContext(ctx, time.Until(c.lastNVD.Add(c.nvdSpacing))); err != nil {
				return err
			}
			c.lastNVD = time.Now()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return errors.New("invalid feed request")
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "CyberStrikeAI-vulnerability-intelligence/1.0")
		if isNVD && c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt < 2 {
				if err = waitContext(ctx, retryDelay("", attempt)); err != nil {
					return err
				}
				continue
			}
			return errors.New("feed network/TLS request failed; previous data retained")
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			delay := retryDelay(resp.Header.Get("Retry-After"), attempt)
			resp.Body.Close()
			if attempt < 2 {
				if err = waitContext(ctx, delay); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("feed HTTP %d after retries", resp.StatusCode)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("feed HTTP %d", resp.StatusCode)
		}
		const maxSize = 64 << 20
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
		resp.Body.Close()
		if err != nil {
			return errors.New("feed response incomplete")
		}
		if len(data) > maxSize {
			return errors.New("feed response exceeds 64 MiB")
		}
		if err = json.Unmarshal(data, out); err != nil {
			return errors.New("feed returned invalid JSON")
		}
		return nil
	}
	return errors.New("feed unavailable")
}

type nvdMetric struct {
	Source       string `json:"source"`
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"`
	Data         struct {
		Version  string   `json:"version"`
		Vector   string   `json:"vectorString"`
		Score    *float64 `json:"baseScore"`
		Severity string   `json:"baseSeverity"`
	} `json:"cvssData"`
}
type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	Modified     string `json:"lastModified"`
	Status       string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics        map[string][]nvdMetric `json:"metrics"`
	References     []Reference            `json:"references"`
	Weaknesses     json.RawMessage        `json:"weaknesses"`
	Configurations json.RawMessage        `json:"configurations"`
	Affected       json.RawMessage        `json:"affected"`
}
type nvdPage struct {
	ResultsPerPage  *int `json:"resultsPerPage"`
	StartIndex      *int `json:"startIndex"`
	TotalResults    *int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

func normalizeNVD(c nvdCVE) (NVDRecord, error) {
	r := NVDRecord{ID: c.ID, Status: c.Status, Severity: "unknown", References: []Reference{}, Configurations: c.Configurations, Weaknesses: c.Weaknesses, Affected: c.Affected, SchemaVersion: nvdSchemaVersion}
	if !ValidCVE(c.ID) {
		return r, errors.New("invalid NVD CVE identifier")
	}
	var err error
	if r.Published, err = parseDate(c.Published); err != nil {
		return r, err
	}
	if r.Modified, err = parseDate(c.Modified); err != nil {
		return r, err
	}
	for _, d := range c.Descriptions {
		if r.Description == "" || d.Lang == "en" {
			r.Description = d.Value
		}
		if d.Lang == "en" {
			break
		}
	}
	for _, ref := range c.References {
		if safeURL(ref.URL) {
			r.References = append(r.References, ref)
		}
	}
	if strings.EqualFold(c.Status, "Rejected") {
		return r, nil
	}
	for _, version := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		metrics := c.Metrics[version]
		chosen := -1
		for i, m := range metrics {
			if m.Data.Score != nil && *m.Data.Score >= 0 && *m.Data.Score <= 10 {
				if chosen < 0 || strings.EqualFold(m.Type, "Primary") {
					chosen = i
				}
				if strings.EqualFold(m.Type, "Primary") {
					break
				}
			}
		}
		if chosen < 0 {
			continue
		}
		m := metrics[chosen]
		r.Score = m.Data.Score
		r.Vector = m.Data.Vector
		r.CVSSVersion = m.Data.Version
		r.CVSSSource = m.Source
		r.CVSSType = m.Type
		r.Severity = strings.ToLower(m.Data.Severity)
		if r.Severity == "" {
			r.Severity = strings.ToLower(m.BaseSeverity)
		}
		switch r.Severity {
		case "critical", "high", "medium", "low", "none":
		default:
			r.Severity = "unknown"
		}
		break
	}
	return r, nil
}

type kevFeed struct {
	Version  string      `json:"catalogVersion"`
	Released string      `json:"dateReleased"`
	Count    int         `json:"count"`
	Records  []KEVRecord `json:"vulnerabilities"`
}

func validateKEV(feed kevFeed) error {
	if feed.Version == "" || feed.Count < 1 || feed.Count != len(feed.Records) || feed.Count > 100000 {
		return errors.New("invalid KEV catalog count/version")
	}
	if _, err := parseDate(feed.Released); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range feed.Records {
		if !ValidCVE(r.ID) || seen[r.ID] || r.Title == "" || r.Description == "" || r.Action == "" {
			return errors.New("invalid or duplicate KEV record")
		}
		seen[r.ID] = true
		if _, err := parseDate(r.Added); err != nil {
			return err
		}
		if _, err := parseDate(r.Due); err != nil {
			return err
		}
	}
	return nil
}

func (c *feedClient) kev(ctx context.Context) (kevFeed, error) {
	var feed kevFeed
	err := c.get(ctx, kevURL, &feed)
	if err == nil {
		err = validateKEV(feed)
	}
	if err != nil && ctx.Err() == nil {
		feed = kevFeed{}
		err = c.get(ctx, kevMirrorURL, &feed)
		if err == nil {
			err = validateKEV(feed)
		}
	}
	return feed, err
}

// Each successfully written page is idempotent; checkpoint advancement is owned by the worker.
func (c *feedClient) nvd(ctx context.Context, start, end time.Time, initial bool, save func([]NVDRecord) error, progress func(int) error) (int, error) {
	count := 0
	for windowStart := start; windowStart.Before(end); {
		windowEnd := windowStart.Add(119 * 24 * time.Hour)
		if windowEnd.After(end) {
			windowEnd = end
		}
		startKey, endKey := "lastModStartDate", "lastModEndDate"
		if initial {
			startKey, endKey = "pubStartDate", "pubEndDate"
		}
		q := url.Values{startKey: {windowStart.UTC().Format("2006-01-02T15:04:05.000")}, endKey: {windowEnd.UTC().Format("2006-01-02T15:04:05.000")}}
		offset := count
		n, err := c.nvdPages(ctx, q, 500000, save, func(n int) error { return progress(offset + n) })
		count += n
		if err != nil {
			return count, err
		}
		windowStart = windowEnd
	}
	return count, nil
}

// KEV includes old CVEs outside the initial publication window. One bounded,
// paginated NVD query fills their scores without a request for every CVE.
func (c *feedClient) nvdKEV(ctx context.Context, save func([]NVDRecord) error, progress func(int) error) (int, error) {
	n, err := c.nvdPages(ctx, url.Values{"hasKev": {""}}, 100000, save, progress)
	if err == nil && n == 0 {
		err = errors.New("NVD KEV response unexpectedly empty; checkpoint unchanged")
	}
	return n, err
}

func (c *feedClient) nvdPages(ctx context.Context, q url.Values, limit int, save func([]NVDRecord) error, progress func(int) error) (int, error) {
	count, totalExpected := 0, -1
	seen := map[string]bool{}
	for {
		q.Set("startIndex", strconv.Itoa(count))
		q.Set("resultsPerPage", "2000")
		var page nvdPage
		if err := c.get(ctx, nvdURL+"?"+q.Encode(), &page); err != nil {
			return count, err
		}
		if page.StartIndex == nil || page.TotalResults == nil || page.ResultsPerPage == nil || *page.StartIndex != count || *page.TotalResults < 0 || *page.TotalResults > limit || *page.ResultsPerPage != len(page.Vulnerabilities) || len(page.Vulnerabilities) > 2000 {
			return count, errors.New("invalid NVD pagination response")
		}
		if totalExpected < 0 {
			totalExpected = *page.TotalResults
		} else if totalExpected != *page.TotalResults {
			return count, errors.New("NVD result count changed during pagination; retry will resume safely")
		}
		if len(page.Vulnerabilities) == 0 && count < totalExpected {
			return count, errors.New("NVD returned an incomplete page")
		}
		if count+len(page.Vulnerabilities) > totalExpected {
			return count, errors.New("NVD page exceeds total results")
		}
		records := make([]NVDRecord, 0, len(page.Vulnerabilities))
		for _, v := range page.Vulnerabilities {
			r, err := normalizeNVD(v.CVE)
			if err != nil {
				return count, err
			}
			if seen[r.ID] {
				return count, errors.New("duplicate NVD CVE during pagination; retry required")
			}
			seen[r.ID] = true
			records = append(records, r)
		}
		if err := save(records); err != nil {
			return count, err
		}
		count += len(records)
		if err := progress(count); err != nil {
			return count, err
		}
		if count >= totalExpected {
			return count, nil
		}
	}
}
