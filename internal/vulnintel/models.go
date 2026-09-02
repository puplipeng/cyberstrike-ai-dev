// Package vulnintel stores public advisories separately from verified asset findings.
package vulnintel

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

const nvdSchemaVersion = 2

func ValidCVE(id string) bool { return cvePattern.MatchString(id) }

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

type NVDRecord struct {
	ID            string          `json:"id"`
	Description   string          `json:"description"`
	Published     time.Time       `json:"published"`
	Modified      time.Time       `json:"modified"`
	Status        string          `json:"status"`
	Severity      string          `json:"severity"`
	Score         *float64        `json:"score"`
	Vector        string          `json:"vector,omitempty"`
	CVSSVersion   string          `json:"cvss_version,omitempty"`
	CVSSSource    string          `json:"cvss_source,omitempty"`
	CVSSType      string          `json:"cvss_type,omitempty"`
	SchemaVersion int             `json:"schema_version"`
	References    []Reference     `json:"references"`
	Weaknesses    json.RawMessage `json:"weaknesses,omitempty"`
	// Preserve AND/OR/negate and non-vulnerable prerequisites; do not flatten to asset matches.
	Configurations json.RawMessage `json:"configurations,omitempty"`
	// Keep publisher, version bounds and unfamiliar schema extensions intact.
	Affected json.RawMessage `json:"affected,omitempty"`
}

type KEVRecord struct {
	ID          string   `json:"cveID"`
	Vendor      string   `json:"vendorProject"`
	Product     string   `json:"product"`
	Title       string   `json:"vulnerabilityName"`
	Added       string   `json:"dateAdded"`
	Description string   `json:"shortDescription"`
	Action      string   `json:"requiredAction"`
	Due         string   `json:"dueDate"`
	Ransomware  string   `json:"knownRansomwareCampaignUse"`
	Notes       string   `json:"notes"`
	CWEs        []string `json:"cwes"`
}

type Record struct {
	ID             string      `json:"id"`
	Title          string      `json:"title"`
	Description    string      `json:"description"`
	Severity       string      `json:"severity"`
	Lifecycle      string      `json:"lifecycle"`
	RatingReason   string      `json:"rating_reason,omitempty"`
	Score          *float64    `json:"score"`
	Published      *time.Time  `json:"published"`
	Modified       *time.Time  `json:"modified"`
	KEVAdded       *time.Time  `json:"kev_added"`
	Synced         time.Time   `json:"synced"`
	KnownExploited bool        `json:"known_exploited"`
	Sources        []string    `json:"sources"`
	NVD            *NVDRecord  `json:"nvd,omitempty"`
	KEV            *KEVRecord  `json:"kev,omitempty"`
	EPSS           *EPSSRecord `json:"epss,omitempty"`
	Priority       string      `json:"priority"`
	PriorityReason string      `json:"priority_reason"`
}

type SourceState struct {
	Source      string     `json:"source"`
	Enabled     bool       `json:"enabled"`
	Status      string     `json:"status"`
	LastAttempt *time.Time `json:"last_attempt"`
	LastSuccess *time.Time `json:"last_success"`
	Checkpoint  *time.Time `json:"checkpoint"`
	NextSync    *time.Time `json:"next_sync"`
	Error       string     `json:"error"`
	Processed   int        `json:"processed"`
	Version     string     `json:"version"`
}

type Filter struct {
	Query, Severity, Source, Status, Sort string
	Exploited                             bool
	Page, PageSize                        int
}
type ListResult struct {
	Items    []Record `json:"items"`
	Total    int      `json:"total"`
	Page     int      `json:"page"`
	PageSize int      `json:"page_size"`
}
type Stats struct {
	Total        int `json:"total"`
	Active       int `json:"active"`
	Rejected     int `json:"rejected"`
	KEV          int `json:"kev"`
	CriticalHigh int `json:"critical_high"`
	Unknown      int `json:"unknown"`
}

func sourceValid(source string) bool { return source == "nvd" || source == "kev" || source == "epss" }

func sourceInterval(source string) time.Duration {
	if source == "epss" {
		return 24 * time.Hour
	}
	return syncInterval
}

func parseDate(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid source timestamp")
}

func safeURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil
}

func (f *Filter) Validate() error {
	f.Query = strings.TrimSpace(f.Query)
	if len(f.Query) > 200 {
		return fmt.Errorf("query must be at most 200 bytes")
	}
	if f.Source != "" && !sourceValid(f.Source) {
		return fmt.Errorf("invalid source")
	}
	switch f.Status {
	case "", "active", "rejected", "all":
	default:
		return fmt.Errorf("invalid status")
	}
	switch f.Sort {
	case "", "updated", "priority", "epss":
	default:
		return fmt.Errorf("invalid sort")
	}
	switch f.Severity {
	case "", "critical", "high", "medium", "low", "none", "unknown":
	default:
		return fmt.Errorf("invalid severity")
	}
	if f.Page < 1 || f.Page > 100000 || f.PageSize < 1 || f.PageSize > 100 {
		return fmt.Errorf("invalid pagination")
	}
	return nil
}
