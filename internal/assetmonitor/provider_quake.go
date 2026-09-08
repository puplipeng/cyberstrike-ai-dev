package assetmonitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultQuakeBaseURL         = "https://quake.360.net/api/v3/search/quake_service"
	maxQuakeBodyBytes           = 8 << 20
	maxProviderErrorLen         = 500
	defaultQuakeRequestInterval = 1500 * time.Millisecond
	defaultQuakeMaxAttempts     = 4
	defaultQuakeRetryBackoff    = 2 * time.Second
	defaultQuakeMaxBackoff      = 8 * time.Second
	defaultQuakeMaxRetryAfter   = 30 * time.Second
)

var quakeIncludeFields = []string{
	"ip", "port", "domain", "service.name", "service.http.title",
	"location.country_cn", "location.province_cn", "location.city_cn",
}

type ProviderError struct {
	Provider   string        `json:"provider"`
	Kind       string        `json:"kind"`
	StatusCode int           `json:"status_code,omitempty"`
	Message    string        `json:"message"`
	RetryAfter time.Duration `json:"-"`
}

func (e *ProviderError) Error() string {
	if e == nil {
		return ""
	}
	return e.Provider + ": " + e.Message
}

type QuakeProvider struct {
	apiKey  string
	baseURL *url.URL
	client  *http.Client

	// gate serializes all pages and adjacent runs for this credential. Keeping
	// pacing state in the provider avoids a new run immediately bursting after
	// the previous run's final page.
	gate            chan struct{}
	lastRequest     time.Time
	requestInterval time.Duration
	maxAttempts     int
	retryBackoff    time.Duration
	maxBackoff      time.Duration
	maxRetryAfter   time.Duration
	now             func() time.Time
	sleep           func(context.Context, time.Duration) error
}

// NewQuakeProvider deliberately permits an empty API key so application
// startup and monitor CRUD remain available. Search returns ErrUnconfigured
// until a key-backed provider is installed.
func NewQuakeProvider(apiKey, baseURL string, client *http.Client) (Provider, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = defaultQuakeBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, validationErrorf("invalid Quake base URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &QuakeProvider{
		apiKey: strings.TrimSpace(apiKey), baseURL: parsed, client: client,
		gate: make(chan struct{}, 1), requestInterval: defaultQuakeRequestInterval,
		maxAttempts: defaultQuakeMaxAttempts, retryBackoff: defaultQuakeRetryBackoff,
		maxBackoff: defaultQuakeMaxBackoff, maxRetryAfter: defaultQuakeMaxRetryAfter,
		now: func() time.Time { return time.Now().UTC() }, sleep: sleepWithContext,
	}, nil
}

func (p *QuakeProvider) Name() string     { return ProviderQuake }
func (p *QuakeProvider) Configured() bool { return p != nil && strings.TrimSpace(p.apiKey) != "" }

type quakeEnvelope struct {
	Code       any             `json:"code"`
	Message    string          `json:"message"`
	Data       json.RawMessage `json:"data"`
	TotalCount int             `json:"total_count"`
	Meta       struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

func (p *QuakeProvider) Search(ctx context.Context, request SearchRequest) (SearchPage, error) {
	if p == nil || !p.Configured() {
		return SearchPage{}, ErrUnconfigured
	}
	if ctx == nil {
		ctx = context.Background()
	}
	root, err := NormalizeRootDomain(request.RootDomain)
	if err != nil {
		return SearchPage{}, err
	}
	if request.Page < 1 || request.PageSize < 1 || request.PageSize > 100 {
		return SearchPage{}, validationErrorf("invalid Quake pagination")
	}
	body, err := json.Marshal(map[string]any{
		"query": generatedQuery(root), "size": request.PageSize,
		"start": (request.Page - 1) * request.PageSize, "latest": true,
		"include": quakeIncludeFields,
	})
	if err != nil {
		return SearchPage{}, fmt.Errorf("encode Quake request: %w", err)
	}
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return SearchPage{}, ctx.Err()
	}
	attempts := p.maxAttempts
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if err = p.waitForRequestSlot(ctx); err != nil {
			return SearchPage{}, err
		}
		page, searchErr := p.searchOnce(ctx, root, request, body)
		if searchErr == nil {
			return page, nil
		}
		var providerErr *ProviderError
		if !errors.As(searchErr, &providerErr) || providerErr.Kind != "rate_limited" || attempt == attempts-1 {
			return SearchPage{}, searchErr
		}
		delay := providerErr.RetryAfter
		if delay <= 0 {
			delay = p.retryDelay(attempt)
		}
		// Do not retry earlier than an upstream Retry-After. If it exceeds our
		// bounded wait budget, return the rate-limit error for a later run.
		if p.maxRetryAfter > 0 && delay > p.maxRetryAfter {
			return SearchPage{}, searchErr
		}
		if err = p.sleep(ctx, delay); err != nil {
			return SearchPage{}, err
		}
	}
	return SearchPage{}, &ProviderError{Provider: ProviderQuake, Kind: "rate_limited", Message: "rate limit retry budget exhausted"}
}

func (p *QuakeProvider) waitForRequestSlot(ctx context.Context) error {
	if p.requestInterval > 0 && !p.lastRequest.IsZero() {
		delay := p.lastRequest.Add(p.requestInterval).Sub(p.now())
		if delay > 0 {
			if err := p.sleep(ctx, delay); err != nil {
				return err
			}
		}
	}
	p.lastRequest = p.now()
	return nil
}

func (p *QuakeProvider) retryDelay(attempt int) time.Duration {
	delay := p.retryBackoff
	if delay <= 0 {
		delay = defaultQuakeRetryBackoff
	}
	for step := 0; step < attempt; step++ {
		if p.maxBackoff > 0 && delay >= p.maxBackoff/2 {
			return p.maxBackoff
		}
		delay *= 2
	}
	if p.maxBackoff > 0 && delay > p.maxBackoff {
		return p.maxBackoff
	}
	return delay
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *QuakeProvider) searchOnce(ctx context.Context, root string, request SearchRequest, body []byte) (SearchPage, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL.String(), bytes.NewReader(body))
	if err != nil {
		return SearchPage{}, fmt.Errorf("create Quake request: %w", err)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("User-Agent", "CyberStrikeAI/asset-monitor")
	httpRequest.Header.Set("X-QuakeToken", p.apiKey)

	response, err := p.client.Do(httpRequest)
	if err != nil {
		kind := "upstream"
		if errors.Is(err, context.Canceled) {
			return SearchPage{}, context.Canceled
		}
		var netError net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netError) && netError.Timeout()) {
			kind = "timeout"
		}
		return SearchPage{}, &ProviderError{Provider: ProviderQuake, Kind: kind, Message: "request failed"}
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxQuakeBodyBytes+1))
	_ = response.Body.Close()
	if err != nil {
		return SearchPage{}, &ProviderError{Provider: ProviderQuake, Kind: "upstream", StatusCode: response.StatusCode, Message: "response read failed"}
	}
	if len(responseBody) > maxQuakeBodyBytes {
		return SearchPage{}, &ProviderError{Provider: ProviderQuake, Kind: "upstream", StatusCode: response.StatusCode, Message: "response exceeded size limit"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		kind := "upstream"
		message := safeQuakeMessage(responseBody, p.apiKey, "request rejected")
		if response.StatusCode == http.StatusTooManyRequests || quakeRateLimited(nil, message) {
			kind = "rate_limited"
		} else if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			kind = "unauthorized"
		}
		retryAfter, _ := parseRetryAfter(response.Header.Get("Retry-After"), p.now())
		return SearchPage{}, &ProviderError{Provider: ProviderQuake, Kind: kind, StatusCode: response.StatusCode, Message: message, RetryAfter: retryAfter}
	}

	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.UseNumber()
	var envelope quakeEnvelope
	if err = decoder.Decode(&envelope); err != nil {
		return SearchPage{}, &ProviderError{Provider: ProviderQuake, Kind: "upstream", StatusCode: response.StatusCode, Message: "invalid JSON response"}
	}
	if !quakeSuccessCode(envelope.Code) {
		message := strings.TrimSpace(envelope.Message)
		if message == "" {
			message = quakeMessageFromData(envelope.Data)
		}
		message = sanitizeProviderMessage(message, p.apiKey, "provider returned an error")
		kind := "upstream"
		if quakeRateLimited(envelope.Code, message) {
			kind = "rate_limited"
		}
		retryAfter, _ := parseRetryAfter(response.Header.Get("Retry-After"), p.now())
		return SearchPage{}, &ProviderError{Provider: ProviderQuake, Kind: kind, StatusCode: response.StatusCode, Message: message, RetryAfter: retryAfter}
	}
	rows, err := decodeQuakeRows(envelope.Data)
	if err != nil {
		return SearchPage{}, &ProviderError{Provider: ProviderQuake, Kind: "upstream", StatusCode: response.StatusCode, Message: "invalid result payload"}
	}
	page := SearchPage{RawCount: len(rows), Total: envelope.TotalCount, Observations: make([]Observation, 0, len(rows))}
	if page.Total <= 0 {
		page.Total = envelope.Meta.Pagination.Total
	}
	for _, row := range rows {
		observations := observationsFromQuakeRow(root, row)
		if len(observations) == 0 {
			page.Skipped++
			continue
		}
		page.Observations = append(page.Observations, observations...)
	}
	offset := (request.Page - 1) * request.PageSize
	if page.Total > 0 {
		page.HasMore = offset+len(rows) < page.Total
	} else {
		page.HasMore = len(rows) == request.PageSize
	}
	return page, nil
}

func quakeRateLimited(code any, message string) bool {
	normalized := strings.ToLower(strings.TrimSpace(message))
	for _, marker := range []string{
		"调用api过于频繁", "调用 api 过于频繁", "请求过于频繁", "访问过于频繁", "操作过于频繁",
		"too many requests", "rate limit", "rate-limit", "too frequent", "frequency limit",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	// Some Quake deployments use an HTTP-like numeric business code.
	switch value := code.(type) {
	case json.Number:
		number, _ := value.Int64()
		return number == http.StatusTooManyRequests
	case float64:
		return int(value) == http.StatusTooManyRequests
	case string:
		return strings.TrimSpace(value) == strconv.Itoa(http.StatusTooManyRequests)
	case int:
		return value == http.StatusTooManyRequests
	case int64:
		return value == http.StatusTooManyRequests
	default:
		return false
	}
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := when.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return delay, true
}

func quakeSuccessCode(code any) bool {
	switch value := code.(type) {
	case json.Number:
		number, err := value.Int64()
		return err == nil && number == 0
	case float64:
		return value == 0
	case string:
		return strings.TrimSpace(value) == "0"
	case int:
		return value == 0
	case int64:
		return value == 0
	default:
		return false
	}
}

func decodeQuakeRows(raw json.RawMessage) ([]map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return []map[string]any{}, nil
	}
	if raw[0] == '[' {
		var rows []map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&rows); err != nil {
			return nil, err
		}
		return rows, nil
	}
	if raw[0] != '{' {
		return nil, errors.New("unexpected Quake data type")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	for _, key := range []string{"data", "items", "matches", "results", "list", "records"} {
		value, ok := object[key]
		if !ok {
			continue
		}
		return decodeQuakeRows(value)
	}
	return []map[string]any{}, nil
}

func observationsFromQuakeRow(root string, row map[string]any) []Observation {
	domains := make([]string, 0, 4)
	seen := map[string]struct{}{}
	for _, field := range []string{"domain", "hostname", "hostnames", "domains", "host", "service.http.host", "service.http.http_load_url"} {
		for _, raw := range quakeStrings(quakeValue(row, field)) {
			domain := normalizeCandidateDomain(raw)
			if domain == "" || !withinRoot(domain, root) {
				continue
			}
			if _, exists := seen[domain]; !exists {
				seen[domain] = struct{}{}
				domains = append(domains, domain)
			}
		}
	}
	if len(domains) == 0 {
		return nil
	}
	ip := firstQuakeString(row, "ip", "ip_str")
	port := quakeInt(quakeValue(row, "port"))
	protocol := strings.ToLower(firstQuakeString(row, "service.name", "protocol", "transport"))
	base := Observation{
		IP: ip, Port: port, Protocol: protocol,
		Title:    firstQuakeString(row, "service.http.title", "title"),
		Server:   firstQuakeString(row, "service.product", "product", "server"),
		Country:  firstQuakeString(row, "location.country_cn", "location.country_name", "country"),
		Province: firstQuakeString(row, "location.province_cn", "province"),
		City:     firstQuakeString(row, "location.city_cn", "location.city", "city"),
	}
	result := make([]Observation, 0, len(domains))
	for _, domain := range domains {
		candidate := base
		candidate.Domain, candidate.Host = domain, domain
		if normalized, ok := NormalizeObservationForRoot(root, candidate); ok {
			result = append(result, normalized)
		}
	}
	return result
}

func quakeValue(row map[string]any, field string) any {
	if value, ok := row[field]; ok {
		return value
	}
	var value any = row
	for _, part := range strings.Split(field, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value, ok = object[part]
		if !ok {
			return nil
		}
	}
	return value
}

func quakeStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return typed
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			result = append(result, quakeStrings(item)...)
		}
		return result
	case json.Number:
		return []string{typed.String()}
	case float64:
		return []string{strconv.FormatFloat(typed, 'f', -1, 64)}
	default:
		return nil
	}
}

func firstQuakeString(row map[string]any, fields ...string) string {
	for _, field := range fields {
		for _, value := range quakeStrings(quakeValue(row, field)) {
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}
	return ""
}

func quakeInt(value any) int {
	for _, raw := range quakeStrings(value) {
		if number, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			return number
		}
	}
	return 0
}

func safeQuakeMessage(body []byte, apiKey, fallback string) string {
	var object map[string]any
	if json.Unmarshal(body, &object) == nil {
		for _, key := range []string{"error", "message", "errmsg", "msg"} {
			if message, ok := object[key].(string); ok && strings.TrimSpace(message) != "" {
				return sanitizeProviderMessage(message, apiKey, fallback)
			}
		}
	}
	return fallback
}

func quakeMessageFromData(raw json.RawMessage) string {
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		return ""
	}
	for _, key := range []string{"error", "message", "errmsg", "msg"} {
		if message, ok := object[key].(string); ok {
			return strings.TrimSpace(message)
		}
	}
	return ""
}

func sanitizeProviderMessage(message, apiKey, fallback string) string {
	message = strings.TrimSpace(message)
	if apiKey != "" {
		message = strings.ReplaceAll(message, apiKey, "<redacted>")
	}
	message = cleanProviderText(message, maxProviderErrorLen)
	if message == "" {
		return fallback
	}
	return message
}
