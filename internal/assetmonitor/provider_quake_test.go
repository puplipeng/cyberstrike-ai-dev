package assetmonitor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQuakeProviderAllowsUnconfiguredConstruction(t *testing.T) {
	provider, err := NewQuakeProvider("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if configured := provider.(configuredProvider).Configured(); configured {
		t.Fatal("empty-key provider reported configured")
	}
	_, err = provider.Search(context.Background(), SearchRequest{RootDomain: "example.com", Page: 1, PageSize: 10})
	if !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("Search() error = %v, want ErrUnconfigured", err)
	}
}

func TestQuakeProviderBuildsSafeQueryAndFiltersRows(t *testing.T) {
	const apiKey = "unit-quake-key"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("X-QuakeToken") != apiKey {
			t.Errorf("unexpected request method/header: %s %q", request.Method, request.Header.Get("X-QuakeToken"))
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["query"] != `domain:"example.com"` {
			t.Errorf("query = %#v", body["query"])
		}
		if body["start"] != float64(0) || body["size"] != float64(3) {
			t.Errorf("pagination = %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{
 "code":"0","total_count":4,"data":[
  {"ip":"1.2.3.4","port":443,"domain":["api.example.com","static.example.com","notexample.com"],"service":{"name":"https","http":{"title":"OK"}},"location":{"country_name":"CN"}},
  {"ip":"2.3.4.5","port":80},
  {"ip":"3.4.5.6","port":443,"domain":"example.com.evil.test"}
 ]}`))
	}))
	defer server.Close()

	provider, err := NewQuakeProvider(apiKey, server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	page, err := provider.Search(context.Background(), SearchRequest{
		RootDomain: "example.com", Query: `domain:"evil.test"`, Page: 1, PageSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.RawCount != 3 || page.Skipped != 2 || len(page.Observations) != 2 || !page.HasMore {
		t.Fatalf("page = %+v", page)
	}
	for _, observation := range page.Observations {
		if !withinRoot(observation.Domain, "example.com") || observation.IP != "1.2.3.4" || observation.Title != "OK" {
			t.Errorf("unexpected observation: %+v", observation)
		}
	}
}

func TestQuakeProviderSanitizesUpstreamCredentialEcho(t *testing.T) {
	const apiKey = "secret-quake-token"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"message":"bad token ` + apiKey + `"}`))
	}))
	defer server.Close()
	provider, err := NewQuakeProvider(apiKey, server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Search(context.Background(), SearchRequest{RootDomain: "example.com", Page: 1, PageSize: 1})
	if err == nil || strings.Contains(err.Error(), apiKey) || !strings.Contains(err.Error(), "<redacted>") {
		t.Fatalf("unsafe provider error: %v", err)
	}
}

func TestDecodeQuakeRowsAcceptsObjectWrapper(t *testing.T) {
	rows, err := decodeQuakeRows(json.RawMessage(`{"items":[{"domain":"api.example.com"}]}`))
	if err != nil || len(rows) != 1 {
		t.Fatalf("decodeQuakeRows() = %#v, %v", rows, err)
	}
}

func TestQuakeProviderRetriesRateLimitAndRespectsRetryAfter(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			writer.Header().Set("Retry-After", "3")
			writer.WriteHeader(http.StatusTooManyRequests)
			_, _ = writer.Write([]byte(`{"message":"调用API过于频繁"}`))
			return
		}
		_, _ = writer.Write([]byte(`{"code":0,"data":[]}`))
	}))
	defer server.Close()
	provider, err := NewQuakeProvider("key", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	quake := provider.(*QuakeProvider)
	quake.requestInterval = 0
	var delays []time.Duration
	quake.sleep = func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}
	if _, err = quake.Search(context.Background(), SearchRequest{RootDomain: "example.com", Page: 1, PageSize: 10}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(delays) != 1 || delays[0] != 3*time.Second {
		t.Fatalf("calls=%d delays=%v", calls.Load(), delays)
	}
}

func TestQuakeProviderRecognizesBusinessRateLimitAndUsesBoundedBackoff(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = writer.Write([]byte(`{"code":"Q3005","message":"调用API过于频繁，请稍后再试","data":null}`))
	}))
	defer server.Close()
	provider, err := NewQuakeProvider("key", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	quake := provider.(*QuakeProvider)
	quake.requestInterval = 0
	quake.maxAttempts = 3
	quake.retryBackoff = 250 * time.Millisecond
	quake.maxBackoff = 500 * time.Millisecond
	var delays []time.Duration
	quake.sleep = func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}
	_, err = quake.Search(context.Background(), SearchRequest{RootDomain: "example.com", Page: 1, PageSize: 10})
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "rate_limited" {
		t.Fatalf("Search() error = %#v", err)
	}
	if calls.Load() != 3 || len(delays) != 2 || delays[0] != 250*time.Millisecond || delays[1] != 500*time.Millisecond {
		t.Fatalf("calls=%d delays=%v", calls.Load(), delays)
	}
}

func TestQuakeProviderRateLimitWaitHonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Retry-After", "5")
		writer.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	provider, err := NewQuakeProvider("key", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	quake := provider.(*QuakeProvider)
	quake.requestInterval = 0
	entered := make(chan struct{})
	var once sync.Once
	quake.sleep = func(ctx context.Context, _ time.Duration) error {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, searchErr := quake.Search(ctx, SearchRequest{RootDomain: "example.com", Page: 1, PageSize: 10})
		result <- searchErr
	}()
	select {
	case <-entered:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("provider did not enter retry wait")
	}
	select {
	case err = <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Search() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider did not stop after context cancellation")
	}
}

func TestQuakeProviderPacesAdjacentSearches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"code":0,"data":[]}`))
	}))
	defer server.Close()
	provider, err := NewQuakeProvider("key", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	quake := provider.(*QuakeProvider)
	fakeNow := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	quake.now = func() time.Time { return fakeNow }
	var delays []time.Duration
	quake.sleep = func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		fakeNow = fakeNow.Add(delay)
		return nil
	}
	request := SearchRequest{RootDomain: "example.com", Page: 1, PageSize: 10}
	if _, err = quake.Search(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err = quake.Search(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(delays) != 1 || delays[0] != defaultQuakeRequestInterval {
		t.Fatalf("adjacent request delays = %v", delays)
	}
}

func TestParseRetryAfterSupportsHTTPDate(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	delay, ok := parseRetryAfter(now.Add(7*time.Second).Format(http.TimeFormat), now)
	if !ok || delay != 7*time.Second {
		t.Fatalf("parseRetryAfter() = %v, %v", delay, ok)
	}
}
