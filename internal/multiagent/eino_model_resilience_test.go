package multiagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/modelbudget"
	copenai "cyberstrike-ai/internal/openai"

	agenticclaude "github.com/cloudwego/eino-ext/components/model/agenticclaude"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type outputBudgetFixtureTransport func(*http.Request) (*http.Response, error)

func (f outputBudgetFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func drainOutputBudgetFixtureStream[T any](t *testing.T, stream *schema.StreamReader[T]) {
	t.Helper()
	defer stream.Close()
	for {
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestEinoOpenAIModelFactoriesNormalizeOutputBudget(t *testing.T) {
	for _, kind := range []string{"classic", "native"} {
		for _, tc := range []struct {
			name     string
			override int
			want     int
			summary  bool
			stream   bool
			budget   bool
		}{
			{name: "no override", want: 4096},
			{name: "smaller common limit", override: 128, want: 128},
			{name: "larger common limit", override: 8192, want: 4096},
			{name: "summary modifier", override: 128, want: 128, summary: true},
			{name: "streaming common limit", override: 128, want: 128, stream: true},
			{name: "streaming summary modifier", override: 128, want: 128, summary: true, stream: true},
			{name: "remaining task budget", budget: true},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				var got map[string]json.RawMessage
				var summaryHeader string
				calls := 0
				baseClient := &http.Client{Transport: outputBudgetFixtureTransport(func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodPost || req.URL.Path != "/v1/chat/completions" {
						return nil, fmt.Errorf("unexpected fixture request: %s %s", req.Method, req.URL.Path)
					}
					raw, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}
					if err := json.Unmarshal(raw, &got); err != nil {
						return nil, err
					}
					if req.ContentLength != int64(len(raw)) || req.GetBody == nil {
						return nil, fmt.Errorf("normalized request has invalid length or missing replay body")
					}
					replay, err := req.GetBody()
					if err != nil {
						return nil, err
					}
					replayed, err := io.ReadAll(replay)
					_ = replay.Close()
					if err != nil || string(replayed) != string(raw) {
						return nil, fmt.Errorf("replay body does not preserve normalized output limit")
					}
					calls++
					summaryHeader = req.Header.Get(copenai.SummarizationRequestHeader)
					body := `{"id":"fixture","object":"chat.completion","created":1,"model":"output-budget-fixture","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`
					contentType := "application/json"
					if tc.stream {
						contentType = "text/event-stream"
						body = "data: " + `{"id":"fixture","object":"chat.completion.chunk","created":1,"model":"output-budget-fixture","choices":[{"index":0,"delta":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}` + "\n\ndata: [DONE]\n\n"
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{contentType}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
				})}
				oa := config.OpenAIConfig{
					Provider: "openai_compatible", Model: "output-budget-fixture", APIKey: "fixture-key",
					BaseURL: "https://example.invalid/v1", MaxCompletionTokens: 4096,
					Reasoning: config.OpenAIReasoningConfig{
						Mode: "on", Profile: "openai_compat", Effort: "high",
						ExtraRequestFields: map[string]any{"fixture_marker": "retained"},
					},
				}
				ctx := context.Background()
				if tc.budget {
					// The unknown fixture model uses the budget estimator's local
					// fallback, never a downloaded tokenizer vocabulary.
					ctx = modelbudget.WithContext(ctx, 1800)
				}
				var opts []model.Option
				if tc.summary {
					opts = newEinoSummarizationModelOptions(1024, oa.Model, kind, &oa, nil)
				}
				if tc.override > 0 {
					opts = append(opts, model.WithMaxTokens(tc.override))
				}
				if kind == "native" {
					m, err := newEinoAgenticChatModelFactory(baseClient, nil, nil)(ctx, oa, einoModelModeNormal)
					if err != nil {
						t.Fatal(err)
					}
					input := []*schema.AgenticMessage{{Role: schema.AgenticRoleTypeUser, ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.UserInputText{Text: "output budget fixture"})}}}
					if tc.stream {
						stream, err := m.Stream(ctx, input, opts...)
						if err != nil {
							t.Fatal(err)
						}
						drainOutputBudgetFixtureStream(t, stream)
					} else if _, err := m.Generate(ctx, input, opts...); err != nil {
						t.Fatal(err)
					}
				} else {
					m, err := newEinoToolCallingChatModelFactory(baseClient, nil, nil)(ctx, oa, einoModelModeNormal)
					if err != nil {
						t.Fatal(err)
					}
					input := []*schema.Message{schema.UserMessage("output budget fixture")}
					if tc.stream {
						stream, err := m.Stream(ctx, input, opts...)
						if err != nil {
							t.Fatal(err)
						}
						drainOutputBudgetFixtureStream(t, stream)
					} else if _, err := m.Generate(ctx, input, opts...); err != nil {
						t.Fatal(err)
					}
				}
				if calls != 1 {
					t.Fatalf("fixture request count = %d, want 1", calls)
				}
				if _, exists := got["max_tokens"]; exists {
					t.Fatal("legacy max_tokens conflicts with max_completion_tokens")
				}
				var limit int
				if err := json.Unmarshal(got["max_completion_tokens"], &limit); err != nil {
					t.Fatal(err)
				}
				if tc.budget {
					if limit <= 0 || limit >= 1800 {
						t.Fatalf("remaining task output budget = %d, want 0 < limit < 1800", limit)
					}
				} else if limit != tc.want {
					t.Fatalf("output limit = %d, want %d", limit, tc.want)
				}
				if tc.summary {
					if _, exists := got["reasoning_effort"]; exists || summaryHeader != "1" {
						t.Fatal("summarization request modifier/header was lost")
					}
				} else if string(got["reasoning_effort"]) != `"high"` {
					t.Fatal("ordinary reasoning setting was lost")
				}
				if string(got["fixture_marker"]) != `"retained"` || !strings.Contains(string(got["messages"]), "output budget fixture") {
					t.Fatal("unrelated payload fields or messages were lost")
				}
			})
		}
	}
}

func TestNewEinoModelRetryConfigUsesNativeFieldsFirst(t *testing.T) {
	t.Parallel()
	mw := &config.MultiAgentEinoMiddlewareConfig{
		ModelRetryMaxRetries:    2,
		ModelRetryMaxBackoffSec: 7,
		RunRetryMaxAttempts:     9,
		RunRetryMaxBackoffSec:   11,
	}
	cfg := newEinoModelRetryConfig(mw, nil, "test")
	if cfg.MaxRetries != 2 {
		t.Fatalf("MaxRetries = %d, want 2", cfg.MaxRetries)
	}
	backoff := cfg.BackoffFunc(context.Background(), 1)
	if backoff < 500*time.Millisecond || backoff > 2*time.Second {
		t.Fatalf("attempt 1 backoff = %v, want first equal-jitter window", backoff)
	}
	if got := einoRunRetryMaxBackoffFromConfig(mw); got != 7*time.Second {
		t.Fatalf("backoff from config = %v, want 7s", got)
	}
}

func TestEinoModelRetryPolicyRetriesTransientAndEmptyOutput(t *testing.T) {
	t.Parallel()
	cfg := newEinoModelRetryConfig(&config.MultiAgentEinoMiddlewareConfig{ModelRetryMaxRetries: 1}, nil, "test")
	if got := cfg.ShouldRetry(context.Background(), &adk.RetryContext{Err: errors.New("HTTP 429 Too Many Requests")}); got == nil || !got.Retry {
		t.Fatal("transient model error should retry")
	}
	if got := cfg.ShouldRetry(context.Background(), &adk.RetryContext{OutputMessage: schema.AssistantMessage("", nil)}); got == nil || !got.Retry {
		t.Fatal("empty assistant output should retry")
	}
	if got := cfg.ShouldRetry(context.Background(), &adk.RetryContext{OutputMessage: schema.AssistantMessage("", []schema.ToolCall{{ID: "call_1"}})}); got == nil || got.Retry {
		t.Fatal("assistant tool call output should not be treated as empty")
	}
	if got := cfg.ShouldRetry(context.Background(), &adk.RetryContext{Err: errors.New("invalid api key")}); got == nil || got.Retry {
		t.Fatal("permanent auth error should not retry")
	}
}

func TestEinoAgenticModelRetryPolicyRetriesTransientAndEmptyOutput(t *testing.T) {
	t.Parallel()
	cfg := newEinoAgenticModelRetryConfig(&config.MultiAgentEinoMiddlewareConfig{ModelRetryMaxRetries: 1}, nil, "agentic")
	if got := cfg.ShouldRetry(context.Background(), &adk.TypedRetryContext[*schema.AgenticMessage]{Err: errors.New("HTTP 429 Too Many Requests")}); got == nil || !got.Retry {
		t.Fatal("transient agentic model error should retry")
	}
	if got := cfg.ShouldRetry(context.Background(), &adk.TypedRetryContext[*schema.AgenticMessage]{
		OutputMessage: &schema.AgenticMessage{Role: schema.AgenticRoleTypeAssistant},
	}); got == nil || !got.Retry {
		t.Fatal("empty agentic assistant output should retry")
	}
	if got := cfg.ShouldRetry(context.Background(), &adk.TypedRetryContext[*schema.AgenticMessage]{
		OutputMessage: &schema.AgenticMessage{
			Role:          schema.AgenticRoleTypeAssistant,
			ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.AssistantGenText{Text: "ok"})},
		},
	}); got == nil || got.Retry {
		t.Fatal("agentic assistant text should not be treated as empty")
	}
	if got := cfg.ShouldRetry(context.Background(), &adk.TypedRetryContext[*schema.AgenticMessage]{
		OutputMessage: &schema.AgenticMessage{
			Role: schema.AgenticRoleTypeAssistant,
			ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.FunctionToolCall{
				CallID: "call_1", Name: "search", Arguments: `{"q":"x"}`,
			})},
		},
	}); got == nil || got.Retry {
		t.Fatal("agentic tool call output should not be treated as empty")
	}
	if got := cfg.ShouldRetry(context.Background(), &adk.TypedRetryContext[*schema.AgenticMessage]{Err: errors.New("invalid api key")}); got == nil || got.Retry {
		t.Fatal("permanent auth error should not retry")
	}
}

func TestResolveEinoFailoverChannelsSkipsPrimaryDuplicateAndUnknown(t *testing.T) {
	t.Parallel()
	appCfg := &config.Config{
		OpenAI: config.OpenAIConfig{Provider: "openai", APIKey: "k1", BaseURL: "https://api.example/v1", Model: "primary"},
		AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{
			"same": {Provider: "openai", APIKey: "k1", BaseURL: "https://api.example/v1", Model: "primary"},
			"fb1":  {Provider: "openai", APIKey: "k2", BaseURL: "https://api.example/v1", Model: "fallback-1"},
			"fb2":  {Provider: "claude", APIKey: "k3", BaseURL: "https://api.anthropic.com/v1", Model: "claude-sonnet"},
		}},
	}
	got := resolveEinoFailoverChannels(appCfg, &config.MultiAgentEinoMiddlewareConfig{
		ModelFailoverChannels:   []string{"same", "missing", "fb1", "fb1", "fb2"},
		ModelFailoverMaxRetries: 1,
	})
	if len(got) != 2 {
		t.Fatalf("resolved channels len = %d, want 2 before max cap is applied by config builder", len(got))
	}
	if got[0].id != "fb1" || got[1].id != "fb2" {
		t.Fatalf("resolved channel order = %#v", got)
	}
}

func TestNewEinoModelFailoverConfigBuildsDistinctFallbackModel(t *testing.T) {
	t.Parallel()
	appCfg := &config.Config{
		OpenAI: config.OpenAIConfig{APIKey: "k1", BaseURL: "https://api.example/v1", Model: "primary"},
		AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{
			"fb1": {APIKey: "k2", BaseURL: "https://api.example/v1", Model: "fallback-1"},
			"fb2": {APIKey: "k3", BaseURL: "https://api.example/v1", Model: "fallback-2"},
		}},
	}
	var built []string
	cfg, err := newEinoModelFailoverConfig(
		context.Background(),
		appCfg,
		&config.MultiAgentEinoMiddlewareConfig{
			ModelFailoverChannels:   []string{"fb1", "fb2"},
			ModelFailoverMaxRetries: 1,
		},
		einoModelModeNormal,
		func(_ context.Context, oa config.OpenAIConfig, _ einoModelMode) (model.ToolCallingChatModel, error) {
			built = append(built, oa.Model)
			return &streamToolCallIndexFakeModel{}, nil
		},
		nil,
		"test",
		nil,
		"deep",
		"conv-1",
	)
	if err != nil {
		t.Fatalf("newEinoModelFailoverConfig: %v", err)
	}
	if cfg == nil || cfg.MaxRetries != 1 {
		t.Fatalf("failover cfg = %#v, want max retries 1", cfg)
	}
	m, msgs, err := cfg.GetFailoverModel(context.Background(), &adk.FailoverContext[*schema.Message]{FailoverAttempt: 1})
	if err != nil || m == nil || msgs != nil {
		t.Fatalf("GetFailoverModel = (%v, %v, %v)", m, msgs, err)
	}
	if len(built) != 1 || built[0] != "fallback-1" {
		t.Fatalf("built models = %v, want [fallback-1]", built)
	}
	if !cfg.ShouldFailover(context.Background(), nil, &adk.RetryExhaustedError{LastErr: errors.New("upstream returned 503"), TotalRetries: 4}) {
		t.Fatal("retry-exhausted transient error should fail over")
	}
	if cfg.ShouldFailover(context.Background(), nil, &adk.RetryExhaustedError{LastErr: errors.New("invalid api key"), TotalRetries: 4}) {
		t.Fatal("retry-exhausted permanent error should not fail over")
	}
}

func TestNewEinoModelFailoverConfigEmitsProgressEvent(t *testing.T) {
	t.Parallel()
	appCfg := &config.Config{
		OpenAI: config.OpenAIConfig{APIKey: "k1", BaseURL: "https://api.example/v1", Model: "primary"},
		AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{
			"fb1": {APIKey: "k2", BaseURL: "https://api.example/v1", Model: "fallback-1"},
		}},
	}
	var events []struct {
		eventType string
		message   string
		data      interface{}
	}
	cfg, err := newEinoModelFailoverConfig(
		context.Background(),
		appCfg,
		&config.MultiAgentEinoMiddlewareConfig{ModelFailoverChannels: []string{"fb1"}},
		einoModelModeNormal,
		func(_ context.Context, _ config.OpenAIConfig, _ einoModelMode) (model.ToolCallingChatModel, error) {
			return &streamToolCallIndexFakeModel{}, nil
		},
		nil,
		"test",
		func(eventType, message string, data interface{}) {
			events = append(events, struct {
				eventType string
				message   string
				data      interface{}
			}{eventType: eventType, message: message, data: data})
		},
		"deep",
		"conv-1",
	)
	if err != nil {
		t.Fatalf("newEinoModelFailoverConfig: %v", err)
	}
	if _, _, err := cfg.GetFailoverModel(context.Background(), &adk.FailoverContext[*schema.Message]{FailoverAttempt: 1}); err != nil {
		t.Fatalf("GetFailoverModel: %v", err)
	}
	if len(events) != 1 || events[0].eventType != "eino_model_failover" {
		t.Fatalf("events = %#v, want one eino_model_failover", events)
	}
	payload, ok := events[0].data.(map[string]interface{})
	if !ok {
		t.Fatalf("event payload type = %T", events[0].data)
	}
	if payload["conversationId"] != "conv-1" || payload["orchestration"] != "deep" || payload["channel"] != "fb1" || payload["model"] != "fallback-1" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestNewEinoAgenticModelFailoverConfigBuildsDistinctFallbackModel(t *testing.T) {
	t.Parallel()
	appCfg := &config.Config{
		OpenAI: config.OpenAIConfig{Provider: "openai", APIKey: "k1", BaseURL: "https://api.example/v1", Model: "primary"},
		AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{
			"fb1": {Provider: "openai", APIKey: "k2", BaseURL: "https://api.example/v1", Model: "fallback-1"},
			"fb2": {Provider: "openai", APIKey: "k3", BaseURL: "https://api.example/v1", Model: "fallback-2"},
		}},
	}
	var built []string
	cfg, err := newEinoAgenticModelFailoverConfig(
		context.Background(),
		appCfg,
		&config.MultiAgentEinoMiddlewareConfig{
			ModelFailoverChannels:   []string{"fb1", "fb2"},
			ModelFailoverMaxRetries: 1,
		},
		einoModelModeNormal,
		func(_ context.Context, oa config.OpenAIConfig, _ einoModelMode) (model.AgenticModel, error) {
			built = append(built, oa.Model)
			return &fakeAgenticGateModel{}, nil
		},
		nil,
		"agentic",
		nil,
		"eino_single_agentic",
		"conv-1",
	)
	if err != nil {
		t.Fatalf("newEinoAgenticModelFailoverConfig: %v", err)
	}
	if cfg == nil || cfg.MaxRetries != 1 {
		t.Fatalf("agentic failover cfg = %#v, want max retries 1", cfg)
	}
	m, msgs, err := cfg.GetFailoverModel(context.Background(), &adk.FailoverContext[*schema.AgenticMessage]{FailoverAttempt: 1})
	if err != nil || m == nil || msgs != nil {
		t.Fatalf("GetFailoverModel = (%v, %v, %v)", m, msgs, err)
	}
	if len(built) != 1 || built[0] != "fallback-1" {
		t.Fatalf("built models = %v, want [fallback-1]", built)
	}
	if !cfg.ShouldFailover(context.Background(), nil, &adk.RetryExhaustedError{LastErr: errors.New("upstream returned 503"), TotalRetries: 4}) {
		t.Fatal("retry-exhausted transient agentic error should fail over")
	}
	if cfg.ShouldFailover(context.Background(), nil, &adk.RetryExhaustedError{LastErr: errors.New("invalid api key"), TotalRetries: 4}) {
		t.Fatal("retry-exhausted permanent agentic error should not fail over")
	}
}

func TestNewEinoAgenticModelFailoverConfigEmitsProgressEvent(t *testing.T) {
	t.Parallel()
	appCfg := &config.Config{
		OpenAI: config.OpenAIConfig{Provider: "openai", APIKey: "k1", BaseURL: "https://api.example/v1", Model: "primary"},
		AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{
			"fb1": {Provider: "openai", APIKey: "k2", BaseURL: "https://api.example/v1", Model: "fallback-1"},
		}},
	}
	var events []struct {
		eventType string
		message   string
		data      interface{}
	}
	cfg, err := newEinoAgenticModelFailoverConfig(
		context.Background(),
		appCfg,
		&config.MultiAgentEinoMiddlewareConfig{ModelFailoverChannels: []string{"fb1"}},
		einoModelModeNormal,
		func(_ context.Context, _ config.OpenAIConfig, _ einoModelMode) (model.AgenticModel, error) {
			return &fakeAgenticGateModel{}, nil
		},
		nil,
		"agentic",
		func(eventType, message string, data interface{}) {
			events = append(events, struct {
				eventType string
				message   string
				data      interface{}
			}{eventType: eventType, message: message, data: data})
		},
		"eino_single_agentic",
		"conv-1",
	)
	if err != nil {
		t.Fatalf("newEinoAgenticModelFailoverConfig: %v", err)
	}
	if _, _, err := cfg.GetFailoverModel(context.Background(), &adk.FailoverContext[*schema.AgenticMessage]{FailoverAttempt: 1}); err != nil {
		t.Fatalf("GetFailoverModel: %v", err)
	}
	if len(events) != 1 || events[0].eventType != "eino_model_failover" {
		t.Fatalf("events = %#v, want one eino_model_failover", events)
	}
	payload, ok := events[0].data.(map[string]interface{})
	if !ok {
		t.Fatalf("event payload type = %T", events[0].data)
	}
	if payload["conversationId"] != "conv-1" || payload["orchestration"] != "eino_single_agentic" || payload["channel"] != "fb1" || payload["model"] != "fallback-1" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestNewEinoAgenticChatModelFactoryBuildsOpenAIBackend(t *testing.T) {
	t.Parallel()
	factory := newEinoAgenticChatModelFactory(newEinoBaseHTTPClient(), nil, nil)
	m, err := factory(context.Background(), config.OpenAIConfig{
		Provider: "openai",
		APIKey:   "test-key",
		BaseURL:  "https://api.example/v1",
		Model:    "gpt-4o-mini",
		Reasoning: config.OpenAIReasoningConfig{
			Profile: "openai_compat",
			Mode:    "on",
			Effort:  "high",
		},
	}, einoModelModeNormal)
	if err != nil {
		t.Fatalf("agentic factory: %v", err)
	}
	if m == nil {
		t.Fatal("agentic factory returned nil model")
	}
	gate := evaluateEinoAgenticModelGate(agenticModelGateFactory(factory, config.OpenAIConfig{
		Provider: "openai",
		APIKey:   "test-key",
		BaseURL:  "https://api.example/v1",
		Model:    "gpt-4o-mini",
	}, einoModelModeNormal), einoAgenticRuntimeSupportV0914())
	if !gate.Ready {
		t.Fatalf("gate = %#v, want ready with buildable agentic backend", gate)
	}
}

func TestNewEinoAgenticChatModelFactoryBuildsNativeClaudeBackend(t *testing.T) {
	t.Parallel()
	factory := newEinoAgenticChatModelFactory(newEinoBaseHTTPClient(), nil, nil)
	m, err := factory(context.Background(), config.OpenAIConfig{
		Provider: "claude",
		APIKey:   "test-key",
		BaseURL:  "https://api.anthropic.com/v1",
		Model:    "claude-sonnet-4",
	}, einoModelModeNormal)
	if err != nil {
		t.Fatalf("claude agentic factory: %v", err)
	}
	if m == nil {
		t.Fatal("claude agentic factory returned nil model")
	}
	if _, ok := modelbudget.Unwrap(m).(*agenticclaude.Model); !ok {
		t.Fatalf("claude agentic factory returned %T, want native agenticclaude.Model", m)
	}
	gate := evaluateEinoAgenticModelGate(agenticModelGateFactory(factory, config.OpenAIConfig{
		Provider: "claude",
		APIKey:   "test-key",
		BaseURL:  "https://api.anthropic.com/v1",
		Model:    "claude-sonnet-4",
	}, einoModelModeNormal), einoAgenticRuntimeSupportV0914())
	if !gate.Ready {
		t.Fatalf("gate = %#v, want ready with native Claude backend", gate)
	}
}

func TestNewEinoToolCallingChatModelFactoryUsesNativeClaudeAdapter(t *testing.T) {
	t.Parallel()
	factory := newEinoToolCallingChatModelFactory(newEinoBaseHTTPClient(), nil, nil)
	m, err := factory(context.Background(), config.OpenAIConfig{
		Provider: "claude",
		APIKey:   "test-key",
		BaseURL:  "https://api.anthropic.com",
		Model:    "claude-sonnet-4",
	}, einoModelModePlanner)
	if err != nil {
		t.Fatalf("claude planner factory: %v", err)
	}
	if _, ok := modelbudget.Unwrap(m).(*agenticToolCallingChatModelAdapter); !ok {
		t.Fatalf("claude planner factory returned %T, want native agentic adapter", m)
	}
}

func TestEinoNativeRetryErrorsDoNotTriggerRunLevelTransientRetry(t *testing.T) {
	t.Parallel()
	err := &adk.WillRetryError{ErrStr: "HTTP 429 Too Many Requests", RetryAttempt: 1}
	if isEinoTransientRunError(err) {
		t.Fatal("WillRetryError should be observed, not treated as a run-level transient failure")
	}
	exhausted := &adk.RetryExhaustedError{LastErr: errors.New("HTTP 429 Too Many Requests"), TotalRetries: 4}
	if isEinoTransientRunError(exhausted) {
		t.Fatal("RetryExhaustedError should not trigger a second run-level retry layer")
	}
	if got := unwrapEinoRetryExhausted(exhausted); got == exhausted {
		t.Fatal("unwrapEinoRetryExhausted should return the underlying model error")
	}
}
