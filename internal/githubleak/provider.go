package githubleak

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	githubAPIBase    = "https://api.github.com"
	maxSearchBody    = 8 << 20
	maxRetryAttempts = 3
)

type SearchItem struct {
	Repository string
	RepoNodeID string
	Path       string
	BlobSHA    string
	HTMLURL    string
	Fragments  []string
}

type SearchResult struct {
	Items         []SearchItem
	ETag          string
	NotModified   bool
	Incomplete    bool
	Truncated     bool
	TotalCount    int
	RateRemaining int
	RateResetAt   *time.Time
}

// HTTPStatusError intentionally excludes response bodies so provider output
// can never copy a raw search result or credential into logs.
type HTTPStatusError struct {
	StatusCode  int
	Retryable   bool
	RateLimited bool
	RateReset   *time.Time
}

func (e *HTTPStatusError) Error() string {
	if e == nil {
		return "github search failed"
	}
	return fmt.Sprintf("github search HTTP %d", e.StatusCode)
}

type timeSource interface {
	Now() time.Time
	Wait(context.Context, time.Duration) error
}

type realTimeSource struct{}

func (realTimeSource) Now() time.Time { return time.Now() }
func (realTimeSource) Wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
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

type clientOptions struct {
	httpClient *http.Client
	baseURL    string
	clock      timeSource
}

type ClientOption func(*clientOptions)

// WithHTTPClient injects a transport. The client is shallow-cloned and a
// same-origin redirect policy is always enforced.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(o *clientOptions) { o.httpClient = client }
}

// withBaseURL is intentionally private and exists only for local httptest use.
func withBaseURL(base string) ClientOption { return func(o *clientOptions) { o.baseURL = base } }
func withTimeSource(clock timeSource) ClientOption {
	return func(o *clientOptions) { o.clock = clock }
}

type Client struct {
	token       string
	base        *url.URL
	http        *http.Client
	interval    time.Duration
	clock       timeSource
	requestMu   sync.Mutex
	lastRequest time.Time
}

func NewClient(settings Settings, options ...ClientOption) (*Client, error) {
	normalized, err := settings.Normalize()
	if err != nil {
		return nil, err
	}
	opts := clientOptions{baseURL: githubAPIBase, clock: realTimeSource{}}
	for _, option := range options {
		option(&opts)
	}
	base, err := url.Parse(strings.TrimRight(opts.baseURL, "/"))
	if err != nil || base.Hostname() == "" || base.User != nil || (base.Scheme != "https" && !(base.Scheme == "http" && base.IsAbs())) {
		return nil, errors.New("invalid GitHub API base URL")
	}
	if opts.clock == nil {
		opts.clock = realTimeSource{}
	}
	httpClient := &http.Client{Timeout: normalized.timeout()}
	if opts.httpClient != nil {
		clone := *opts.httpClient
		httpClient = &clone
		httpClient.Timeout = normalized.timeout()
	}
	originScheme, originHost := base.Scheme, base.Host
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme != originScheme || req.URL.Host != originHost || req.URL.User != nil {
			return errors.New("cross-origin redirect rejected")
		}
		return nil
	}
	return &Client{
		token:    normalized.Token,
		base:     base,
		http:     httpClient,
		interval: normalized.interval(),
		clock:    opts.clock,
	}, nil
}

func exactKeywordQuery(keyword string) (string, error) {
	return exactKeywordsQuery([]string{keyword})
}

func exactKeywordsQuery(keywords []string) (string, error) {
	rule, err := newKeywordRule(keywords)
	if err != nil {
		return "", err
	}
	return rule.Query, nil
}

func (c *Client) Search(ctx context.Context, keyword, etag string, maxResults int) (SearchResult, error) {
	return c.SearchKeywords(ctx, []string{keyword}, etag, maxResults)
}

// SearchKeywords performs one GitHub code-search request whose quoted terms
// must all occur in the same result file. Caller-provided syntax is always
// escaped as phrase data; only this package adds AND and in:file operators.
func (c *Client) SearchKeywords(ctx context.Context, keywords []string, etag string, maxResults int) (SearchResult, error) {
	query, err := exactKeywordsQuery(keywords)
	if err != nil {
		return SearchResult{}, err
	}
	if maxResults < 1 || maxResults > 100 {
		return SearchResult{}, errors.New("max results must be between 1 and 100")
	}
	endpoint := *c.base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/search/code"
	values := endpoint.Query()
	values.Set("q", query)
	values.Set("per_page", strconv.Itoa(maxResults))
	values.Set("page", "1")
	endpoint.RawQuery = values.Encode()

	var lastErr error
	for attempt := 0; attempt < maxRetryAttempts; attempt++ {
		result, status, headers, err := c.doSearch(ctx, endpoint.String(), etag)
		if err == nil {
			if len(result.Items) > maxResults {
				result.Items = result.Items[:maxResults]
				result.Truncated = true
			}
			if result.TotalCount > len(result.Items) {
				result.Truncated = true
			}
			return result, nil
		}
		lastErr = err
		if status == http.StatusUnprocessableEntity {
			return SearchResult{}, &HTTPStatusError{StatusCode: status, Retryable: false}
		}
		rateLimited := isRateLimitedResponse(status, headers, c.clock.Now())
		retryable := rateLimited || status >= 500 || status == 0
		if !retryable || attempt == maxRetryAttempts-1 {
			if status > 0 {
				return SearchResult{}, &HTTPStatusError{
					StatusCode:  status,
					Retryable:   retryable,
					RateLimited: rateLimited,
					RateReset:   retryAt(headers, c.clock.Now(), rateLimited),
				}
			}
			return SearchResult{}, lastErr
		}
		delay := providerBackoff(headers, attempt, c.clock.Now(), rateLimited)
		if rateLimited && delay > 15*time.Minute {
			return SearchResult{}, &HTTPStatusError{
				StatusCode:  status,
				Retryable:   true,
				RateLimited: true,
				RateReset:   retryAt(headers, c.clock.Now(), true),
			}
		}
		if err = c.clock.Wait(ctx, delay); err != nil {
			return SearchResult{}, err
		}
	}
	return SearchResult{}, lastErr
}

func (c *Client) doSearch(ctx context.Context, endpoint, etag string) (SearchResult, int, http.Header, error) {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	if !c.lastRequest.IsZero() {
		if err := c.clock.Wait(ctx, c.lastRequest.Add(c.interval).Sub(c.clock.Now())); err != nil {
			return SearchResult{}, 0, nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return SearchResult{}, 0, nil, errors.New("invalid GitHub search request")
	}
	if req.URL.Scheme != c.base.Scheme || req.URL.Host != c.base.Host || req.URL.User != nil {
		return SearchResult{}, 0, nil, errors.New("unapproved GitHub search origin")
	}
	req.Header.Set("Accept", "application/vnd.github.text-match+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "CyberStrikeAI-github-leak-monitor/1.0")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if strings.TrimSpace(etag) != "" {
		req.Header.Set("If-None-Match", strings.TrimSpace(etag))
	}
	attempted := true
	defer func() {
		if attempted {
			// Spacing is measured from completion, including network failures, so
			// a slow request cannot shorten the quiet period before the next one.
			c.lastRequest = c.clock.Now()
		}
	}()
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return SearchResult{}, 0, nil, ctx.Err()
		}
		return SearchResult{}, 0, nil, errors.New("GitHub search network/TLS request failed")
	}
	defer resp.Body.Close()
	result := SearchResult{
		ETag:          cleanETag(resp.Header.Get("ETag")),
		RateRemaining: parseHeaderInt(resp.Header.Get("X-RateLimit-Remaining"), -1),
	}
	if resp.StatusCode == http.StatusNotModified {
		result.RateResetAt = rateReset(resp.Header, c.clock.Now())
		result.NotModified = true
		if result.ETag == "" {
			result.ETag = cleanETag(etag)
		}
		return result, resp.StatusCode, resp.Header, nil
	}
	if resp.StatusCode != http.StatusOK {
		return SearchResult{}, resp.StatusCode, resp.Header, &HTTPStatusError{StatusCode: resp.StatusCode}
	}
	result.RateResetAt = rateReset(resp.Header, c.clock.Now())
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSearchBody+1))
	if err != nil || len(data) > maxSearchBody {
		return SearchResult{}, resp.StatusCode, resp.Header, errors.New("GitHub search response incomplete or too large")
	}
	var payload struct {
		TotalCount        int  `json:"total_count"`
		IncompleteResults bool `json:"incomplete_results"`
		Items             []struct {
			Path       string `json:"path"`
			SHA        string `json:"sha"`
			HTMLURL    string `json:"html_url"`
			Repository struct {
				FullName   string `json:"full_name"`
				NodeID     string `json:"node_id"`
				Private    *bool  `json:"private"`
				Visibility string `json:"visibility"`
			} `json:"repository"`
			TextMatches []struct {
				Fragment string `json:"fragment"`
			} `json:"text_matches"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return SearchResult{}, resp.StatusCode, resp.Header, errors.New("GitHub search returned invalid JSON")
	}
	result.TotalCount = payload.TotalCount
	// A single page is not a complete snapshot when GitHub reports additional
	// matches, even if incomplete_results itself is false.
	result.Incomplete = payload.IncompleteResults
	result.Truncated = payload.TotalCount > len(payload.Items)
	result.Items = make([]SearchItem, 0, len(payload.Items))
	for _, item := range payload.Items {
		// Public-only monitoring is a hard trust boundary. A missing/null
		// visibility flag is not evidence that a repository is public.
		if item.Repository.Private == nil || *item.Repository.Private ||
			(item.Repository.Visibility != "" && !strings.EqualFold(item.Repository.Visibility, "public")) {
			continue
		}
		if !validSearchMetadata(item.Repository.FullName, item.Repository.NodeID, item.Path, item.SHA, item.HTMLURL) {
			continue
		}
		fragments := make([]string, 0, len(item.TextMatches))
		for _, match := range item.TextMatches {
			if match.Fragment != "" && len(match.Fragment) <= 64<<10 {
				fragments = append(fragments, match.Fragment)
			}
		}
		result.Items = append(result.Items, SearchItem{
			Repository: item.Repository.FullName,
			RepoNodeID: item.Repository.NodeID,
			Path:       item.Path,
			BlobSHA:    item.SHA,
			HTMLURL:    item.HTMLURL,
			Fragments:  fragments,
		})
	}
	if result.TotalCount > len(result.Items) {
		result.Truncated = true
	}
	return result, resp.StatusCode, resp.Header, nil
}

func validSearchMetadata(repository, repoNodeID, path, sha, htmlURL string) bool {
	if repository == "" || repoNodeID == "" || path == "" || len(repository) > 300 || len(repoNodeID) > 300 || len(path) > 2000 {
		return false
	}
	if hasUnsafeMetadataText(repository) || hasUnsafeMetadataText(repoNodeID) || hasUnsafeMetadataText(path) {
		return false
	}
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
		return false
	}
	if (len(sha) != 40 && len(sha) != 64) || !isHexString(sha) {
		return false
	}
	u, err := url.Parse(htmlURL)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") || u.Port() != "" || u.User != nil || u.RawQuery != "" {
		return false
	}
	return u.Fragment == "" || lineNumberFromURL(htmlURL) > 0
}

func hasUnsafeMetadataText(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func isHexString(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

func cleanETag(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 || hasUnsafeMetadataText(value) {
		return ""
	}
	return value
}

func parseHeaderInt(value string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return n
}

func rateReset(headers http.Header, now time.Time) *time.Time {
	if headers == nil {
		return nil
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(headers.Get("X-RateLimit-Reset")), 10, 64)
	if err != nil || seconds <= 0 {
		return nil
	}
	t := time.Unix(seconds, 0).UTC()
	if t.Before(now.Add(-time.Minute)) {
		return nil
	}
	return &t
}

func retryAt(headers http.Header, now time.Time, includeRateReset bool) *time.Time {
	if headers != nil {
		if raw := strings.TrimSpace(headers.Get("Retry-After")); raw != "" {
			if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
				when := now.Add(time.Duration(seconds) * time.Second).UTC()
				return &when
			}
			if when, err := http.ParseTime(raw); err == nil && !when.Before(now.Add(-time.Minute)) {
				when = when.UTC()
				return &when
			}
		}
	}
	if includeRateReset {
		return rateReset(headers, now)
	}
	return nil
}

func isRateLimitedResponse(status int, headers http.Header, now time.Time) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	if status != http.StatusForbidden || headers == nil {
		return false
	}
	if strings.TrimSpace(headers.Get("Retry-After")) != "" || strings.TrimSpace(headers.Get("X-RateLimit-Remaining")) == "0" {
		return true
	}
	// Some secondary-limit responses omit Remaining but provide only a reset.
	return strings.TrimSpace(headers.Get("X-RateLimit-Remaining")) == "" && rateReset(headers, now) != nil
}

func providerBackoff(headers http.Header, attempt int, now time.Time, rateLimited bool) time.Duration {
	if headers != nil {
		if raw := strings.TrimSpace(headers.Get("Retry-After")); raw != "" {
			if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
				return boundedBackoff(time.Duration(seconds) * time.Second)
			}
			if when, err := http.ParseTime(raw); err == nil {
				return boundedBackoff(when.Sub(now))
			}
		}
		if rateLimited {
			if reset := rateReset(headers, now); reset != nil {
				return boundedBackoff(reset.Sub(now))
			}
		}
	}
	delay := time.Minute * time.Duration(1<<attempt)
	return boundedBackoff(delay)
}

func boundedBackoff(delay time.Duration) time.Duration {
	if delay < time.Second {
		return time.Second
	}
	if delay > 24*time.Hour {
		return 24 * time.Hour
	}
	return delay
}
