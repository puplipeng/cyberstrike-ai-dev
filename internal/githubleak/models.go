// Package githubleak monitors GitHub code search for likely credential leaks.
// It never validates discovered credentials and never persists raw secret values.
package githubleak

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MinIntervalSeconds     = 31
	DefaultIntervalSeconds = 60
	DefaultTimeoutSeconds  = 45
	DefaultPollSeconds     = 7200
	DefaultMaxResults      = 100
	MaxRules               = 32
	MaxKeywords            = 6
	maxKeywordBytes        = 200
	maxRuleNameBytes       = 100
	maxQueryLiteralBytes   = 256
	maxRuleQueryBytes      = 512
)

var (
	ErrBusy         = errors.New("github leak monitor is already running")
	ErrUnconfigured = errors.New("github leak monitor is not configured")
	ErrUnavailable  = errors.New("github leak monitor worker is not running")
	ErrNotFound     = errors.New("github leak finding not found")
)

// Settings is intentionally independent of the application config package.
// Callers may map their persisted configuration onto this type.
type Settings struct {
	Enabled               bool     `json:"enabled"`
	Token                 string   `json:"-"`
	FingerprintKey        string   `json:"-"`
	Keywords              []string `json:"keywords"`
	Rules                 []Rule   `json:"rules,omitempty"`
	IntervalSeconds       int      `json:"interval_seconds"`
	RequestTimeoutSeconds int      `json:"request_timeout_seconds"`
	PollIntervalSeconds   int      `json:"poll_interval_seconds,omitempty"`
	MaxResultsPerKeyword  int      `json:"max_results_per_keyword,omitempty"`
}

// Normalize validates settings and applies conservative defaults. The request
// interval is a hard safety boundary and can never be configured below 31s.
func (s Settings) Normalize() (Settings, error) {
	s.Token = strings.TrimSpace(s.Token)
	s.FingerprintKey = strings.TrimSpace(s.FingerprintKey)
	if s.IntervalSeconds == 0 {
		s.IntervalSeconds = DefaultIntervalSeconds
	}
	if s.IntervalSeconds < MinIntervalSeconds {
		return Settings{}, fmt.Errorf("interval_seconds must be at least %d", MinIntervalSeconds)
	}
	if s.RequestTimeoutSeconds == 0 {
		s.RequestTimeoutSeconds = DefaultTimeoutSeconds
	}
	if s.RequestTimeoutSeconds < 1 || s.RequestTimeoutSeconds > 300 {
		return Settings{}, errors.New("request_timeout_seconds must be between 1 and 300")
	}
	if s.PollIntervalSeconds == 0 {
		s.PollIntervalSeconds = DefaultPollSeconds
	}
	if s.PollIntervalSeconds < s.IntervalSeconds {
		s.PollIntervalSeconds = s.IntervalSeconds
	}
	if s.MaxResultsPerKeyword == 0 {
		s.MaxResultsPerKeyword = DefaultMaxResults
	}
	// A single request per AND rule keeps ETag semantics unambiguous and avoids
	// accidentally walking GitHub's capped search result window.
	if s.MaxResultsPerKeyword < 1 || s.MaxResultsPerKeyword > 100 {
		return Settings{}, errors.New("max_results_per_keyword must be between 1 and 100")
	}
	// Named rules take precedence. Clearing the legacy field prevents an old
	// keywords value from becoming a hidden extra request after rules are added.
	if len(s.Rules) > 0 {
		s.Keywords = nil
	}
	normalized, err := canonicalKeywords(s.Keywords)
	if err != nil {
		return Settings{}, err
	}
	s.Keywords = normalized
	if err = validateAndNormalizeRules(&s); err != nil {
		return Settings{}, err
	}
	return s, nil
}

// Rule is one independently executed exact AND search. Rules are kept in
// configuration order so operators can control the deterministic request
// sequence. The legacy Settings.Keywords field is represented as "legacy".
type Rule struct {
	Enabled  bool     `json:"enabled" yaml:"enabled"`
	Name     string   `json:"name" yaml:"name"`
	Keywords []string `json:"keywords" yaml:"keywords"`
}

func validateAndNormalizeRules(settings *Settings) error {
	if settings == nil {
		return errors.New("github leak settings are required")
	}
	total := len(settings.Rules)
	if len(settings.Rules) == 0 && len(settings.Keywords) > 0 {
		total++
		if _, err := newKeywordRule(settings.Keywords); err != nil {
			return err
		}
	}
	if total > MaxRules {
		return fmt.Errorf("at most %d GitHub leak rules are allowed", MaxRules)
	}

	seenNames := make(map[string]struct{}, total)
	seenQueries := make(map[string]string, total)
	if len(settings.Rules) == 0 && len(settings.Keywords) > 0 {
		seenNames["legacy"] = struct{}{}
		legacy, _ := newKeywordRule(settings.Keywords)
		seenQueries[strings.ToLower(legacy.Query)] = "legacy"
	}
	for i := range settings.Rules {
		rule := settings.Rules[i]
		name, err := normalizeRuleName(rule.Name)
		if err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
		foldedName := strings.ToLower(name)
		if _, exists := seenNames[foldedName]; exists {
			return fmt.Errorf("duplicate GitHub leak rule name %q", name)
		}
		seenNames[foldedName] = struct{}{}
		compiled, err := newKeywordRule(rule.Keywords)
		if err != nil {
			return fmt.Errorf("rule %q: %w", name, err)
		}
		queryKey := strings.ToLower(compiled.Query)
		if previous, exists := seenQueries[queryKey]; exists {
			return fmt.Errorf("rules %q and %q have the same canonical query", previous, name)
		}
		seenQueries[queryKey] = name
		rule.Name = name
		rule.Keywords = compiled.Keywords
		settings.Rules[i] = rule
	}
	return nil
}

func normalizeRuleName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || len(value) < 1 || len(value) > maxRuleNameBytes {
		return "", errors.New("GitHub leak rule name must be 1-100 bytes of single-line UTF-8 text")
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return "", errors.New("GitHub leak rule name must be 1-100 bytes of single-line UTF-8 text")
		}
	}
	return value, nil
}

func canonicalKeywords(values []string) ([]string, error) {
	if len(values) > MaxKeywords {
		return nil, fmt.Errorf("at most %d keywords are allowed", MaxKeywords)
	}
	byFoldedValue := make(map[string]string, len(values))
	for _, raw := range values {
		keyword, err := normalizeKeyword(raw)
		if err != nil {
			return nil, err
		}
		folded := strings.ToLower(keyword)
		current, ok := byFoldedValue[folded]
		if !ok || keyword == folded || (current != folded && keyword < current) {
			byFoldedValue[folded] = keyword
		}
	}
	normalized := make([]string, 0, len(byFoldedValue))
	for _, keyword := range byFoldedValue {
		normalized = append(normalized, keyword)
	}
	sort.Slice(normalized, func(i, j int) bool {
		left, right := strings.ToLower(normalized[i]), strings.ToLower(normalized[j])
		if left == right {
			return normalized[i] < normalized[j]
		}
		return left < right
	})
	return normalized, nil
}

func normalizeKeyword(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || len(value) < 2 || len(value) > maxKeywordBytes {
		return "", errors.New("github leak keyword must be 2-200 bytes of single-line UTF-8 text")
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return "", errors.New("github leak keyword must be 2-200 bytes of single-line UTF-8 text")
		}
	}
	return value, nil
}

type keywordRule struct {
	Name     string
	Enabled  bool
	Keywords []string
	Query    string
}

func newKeywordRule(values []string) (keywordRule, error) {
	keywords, err := canonicalKeywords(values)
	if err != nil {
		return keywordRule{}, err
	}
	if len(keywords) == 0 {
		return keywordRule{}, ErrUnconfigured
	}
	terms := make([]string, 0, len(keywords))
	literalBytes := 0
	for _, keyword := range keywords {
		escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(keyword)
		literalBytes += len(escaped) + 2 // quoted phrase; operators/qualifier are excluded
		if literalBytes > maxQueryLiteralBytes {
			return keywordRule{}, fmt.Errorf("combined GitHub leak literals must not exceed %d bytes", maxQueryLiteralBytes)
		}
		terms = append(terms, `"`+escaped+`"`)
	}
	query := strings.Join(terms, " AND ") + " in:file"
	if len(query) > maxRuleQueryBytes {
		return keywordRule{}, errors.New("combined GitHub leak query is too long")
	}
	return keywordRule{Keywords: keywords, Query: query}, nil
}

func compiledRules(settings Settings, includeDisabled bool) ([]keywordRule, error) {
	rules := make([]keywordRule, 0, len(settings.Rules)+1)
	if len(settings.Rules) == 0 && len(settings.Keywords) > 0 {
		legacy, err := newKeywordRule(settings.Keywords)
		if err != nil {
			return nil, err
		}
		legacy.Name, legacy.Enabled = "legacy", true
		rules = append(rules, legacy)
	}
	for _, configured := range settings.Rules {
		if !includeDisabled && !configured.Enabled {
			continue
		}
		compiled, err := newKeywordRule(configured.Keywords)
		if err != nil {
			return nil, err
		}
		compiled.Name, compiled.Enabled = configured.Name, configured.Enabled
		rules = append(rules, compiled)
	}
	return rules, nil
}

func normalizeRuleQuery(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || len(value) < 2 || len(value) > maxRuleQueryBytes || !strings.HasSuffix(value, " in:file") {
		return "", errors.New("invalid GitHub leak AND rule query")
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return "", errors.New("invalid GitHub leak AND rule query")
		}
	}
	return value, nil
}

func (s Settings) Configured() bool {
	if strings.TrimSpace(s.Token) == "" {
		return false
	}
	if len(s.Rules) > 0 {
		for _, rule := range s.Rules {
			if rule.Enabled && len(rule.Keywords) > 0 {
				return true
			}
		}
		return false
	}
	return len(s.Keywords) > 0
}

func (s Settings) interval() time.Duration { return time.Duration(s.IntervalSeconds) * time.Second }
func (s Settings) timeout() time.Duration {
	return time.Duration(s.RequestTimeoutSeconds) * time.Second
}
func (s Settings) pollInterval() time.Duration {
	return time.Duration(s.PollIntervalSeconds) * time.Second
}

const (
	StatusNew           = "new"
	StatusTriaged       = "triaged"
	StatusFalsePositive = "false_positive"
	StatusResolved      = "resolved"
)

func ValidStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case StatusNew, StatusTriaged, StatusFalsePositive, StatusResolved:
		return true
	default:
		return false
	}
}

type Finding struct {
	ID            string    `json:"id"`
	Status        string    `json:"status"`
	RuleName      string    `json:"rule_name"`
	Keyword       string    `json:"keyword"`
	Repository    string    `json:"repository"`
	Path          string    `json:"path"`
	BlobSHA       string    `json:"-"`
	Line          int       `json:"line"`
	SecretType    string    `json:"secret_type"`
	Confidence    string    `json:"confidence"`
	Severity      string    `json:"severity"`
	Fingerprint   string    `json:"fingerprint"`
	MaskedExcerpt string    `json:"masked_excerpt"`
	HTMLURL       string    `json:"html_url"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

// Candidate is already sanitized. It intentionally has no field capable of
// carrying a raw secret or a raw GitHub response.
type Candidate struct {
	RuleName      string
	Keyword       string
	Repository    string
	Path          string
	BlobSHA       string
	Line          int
	SecretType    string
	Confidence    string
	Severity      string
	Fingerprint   string
	MaskedExcerpt string
	HTMLURL       string
}

type ListFilter struct {
	Query    string
	Status   string
	Keyword  string
	Page     int
	PageSize int
}

func (f *ListFilter) Validate() error {
	f.Query = strings.TrimSpace(f.Query)
	f.Keyword = strings.TrimSpace(f.Keyword)
	f.Status = strings.ToLower(strings.TrimSpace(f.Status))
	if len(f.Query) > 200 || len(f.Keyword) > maxRuleQueryBytes {
		return errors.New("query or rule filter is too long")
	}
	if f.Status != "" && !ValidStatus(f.Status) {
		return errors.New("invalid finding status")
	}
	if f.Page == 0 {
		f.Page = 1
	}
	if f.PageSize == 0 {
		f.PageSize = 25
	}
	if f.Page < 1 || f.Page > 100000 || f.PageSize < 1 || f.PageSize > 100 {
		return errors.New("invalid pagination")
	}
	return nil
}

type ListResult struct {
	Items      []Finding `json:"items"`
	Total      int       `json:"total"`
	Page       int       `json:"page"`
	PageSize   int       `json:"page_size"`
	TotalPages int       `json:"total_pages"`
}

type Stats struct {
	Total         int `json:"total"`
	New           int `json:"new"`
	Triaged       int `json:"triaged"`
	FalsePositive int `json:"false_positive"`
	Resolved      int `json:"resolved"`
	Likely        int `json:"likely"`
	Suspected     int `json:"suspected"`
}

type RuntimeStatus struct {
	Enabled                bool         `json:"enabled"`
	Configured             bool         `json:"configured"`
	Running                bool         `json:"running"`
	LastRunAt              *time.Time   `json:"last_run_at,omitempty"`
	NextRunAt              *time.Time   `json:"next_run_at,omitempty"`
	LastStatus             string       `json:"last_status"`
	LastError              string       `json:"last_error"`
	LastWarning            string       `json:"last_warning"`
	RateRemaining          int          `json:"rate_remaining"`
	RateResetAt            *time.Time   `json:"rate_reset_at,omitempty"`
	IntervalSeconds        int          `json:"interval_seconds"`
	RequestIntervalSeconds int          `json:"request_interval_seconds"`
	RequestTimeoutSeconds  int          `json:"request_timeout_seconds"`
	Keywords               []string     `json:"keywords"`
	Query                  string       `json:"query"`
	Rules                  []RuleStatus `json:"rules"`
	LastRequests           int          `json:"last_requests"`
	LastProcessed          int          `json:"last_processed"`
	LastDetected           int          `json:"last_detected"`
}

type RuleStatus struct {
	Enabled       bool       `json:"enabled"`
	Name          string     `json:"name"`
	Keywords      []string   `json:"keywords"`
	Query         string     `json:"query"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastStatus    string     `json:"last_status"`
	LastError     string     `json:"last_error"`
	Incomplete    bool       `json:"incomplete"`
	Truncated     bool       `json:"truncated"`
}

type KeywordState struct {
	Keyword       string
	ETag          string
	LastAttemptAt *time.Time
	LastSuccessAt *time.Time
	LastStatus    string
	LastError     string
	Incomplete    bool
	Truncated     bool
}

type RunRecord struct {
	ID            string
	Status        string
	Error         string
	StartedAt     time.Time
	FinishedAt    *time.Time
	RateRemaining int
	RateResetAt   *time.Time
	Requests      int
	Processed     int
	Detected      int
}
