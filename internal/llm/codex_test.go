package llm

import (
	"cyberstrike-ai/internal/codexbridge"
	"cyberstrike-ai/internal/config"
	"encoding/json"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"strings"
	"testing"
)

func TestCodexToolDecisionValidation(t *testing.T) {
	for _, body := range []string{
		`{"text":"","tool_calls":[{"name":"unknown","arguments":"{}"}]}`,
		`{"text":"","tool_calls":[]}`,
	} {
		if _, err := decodeCodexResult(&codexbridge.Result{Text: body}, map[string]bool{"allowed": true}, true); err == nil {
			t.Fatalf("accepted invalid decision: %s", body)
		}
	}
	result, err := decodeCodexResult(&codexbridge.Result{Text: `{"text":"Checking","tool_calls":[{"name":"allowed","arguments":{"value":1}}]}`, TotalTokens: 9}, map[string]bool{"allowed": true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ContentBlocks) != 2 || result.ContentBlocks[1].FunctionToolCall.Name != "allowed" || result.ContentBlocks[1].FunctionToolCall.CallID == "" || result.ContentBlocks[1].FunctionToolCall.Arguments != `{"value":1}` {
		t.Fatalf("bad tool conversion: %+v", result)
	}
}

func TestNormalizeCodexToolArguments(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "native object", raw: `{"value":1}`, want: `{"value":1}`},
		{name: "strict envelope", raw: `{"json_object":"{\"value\":1}"}`, want: `{"value":1}`},
		{name: "invalid strict envelope", raw: `{"json_object":"not json"}`, want: `{}`},
		{name: "legacy encoded object", raw: `"{\"value\":1}"`, want: `{"value":1}`},
		{name: "double encoded object", raw: `"\"{\\\"value\\\":1}\""`, want: `{"value":1}`},
		{name: "fenced legacy object", raw: "\"```json\\n{\\\"value\\\":1}\\n```\"", want: `{"value":1}`},
		{name: "legacy object members", raw: `"\"value\":1"`, want: `{"value":1}`},
		{name: "missing", raw: ``, want: `{}`},
		{name: "null", raw: `null`, want: `{}`},
		{name: "empty string", raw: `""`, want: `{}`},
		{name: "array is not executable", raw: `[1,2]`, want: `{}`},
		{name: "scalar is not executable", raw: `"not json"`, want: `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeCodexToolArguments(json.RawMessage(tt.raw)); got != tt.want {
				t.Fatalf("normalizeCodexToolArguments(%s) = %s, want %s", tt.raw, got, tt.want)
			}
		})
	}
}
func TestPartialCodexTextEveryBoundary(t *testing.T) {
	expected := "中文 \"quote\"\nemoji 😀 and slash \\"
	bytes, err := json.Marshal(map[string]any{"text": expected, "tool_calls": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(bytes)
	last := ""
	for i := 0; i <= len(raw); i++ {
		text := partialCodexText(raw[:i])
		if !strings.HasPrefix(expected, text) || !strings.HasPrefix(text, last) {
			t.Fatalf("invalid prefix at %d: %q after %q", i, text, last)
		}
		last = text
	}
	if last != expected {
		t.Fatalf("got %q", last)
	}
	escaped := `{"text":"\u4e2d\ud83d\ude00","tool_calls":[]}`
	last = ""
	for i := 0; i <= len(escaped); i++ {
		got := partialCodexText(escaped[:i])
		if !strings.HasPrefix("中😀", got) || !strings.HasPrefix(got, last) {
			t.Fatalf("invalid escaped prefix %q", got)
		}
		last = got
	}
}
func TestCodexRequestPreservesToolHistoryAndForbidsUnavailableTools(t *testing.T) {
	tool := &schema.ToolInfo{Name: "allowed", Desc: "Read approved information"}
	input := []*schema.AgenticMessage{schema.UserAgenticMessage("hello")}
	req, names, _, err := codexRequest(config.OpenAIConfig{Model: "test"}, input, model.WithTools([]*schema.ToolInfo{tool}), model.WithAgenticToolChoice(&schema.AgenticToolChoice{Type: schema.ToolChoiceForbidden}))
	if err != nil {
		t.Fatal(err)
	}
	if req.OutputSchema != nil || len(names) != 0 {
		t.Fatal("forbidden tools were exposed")
	}
	req, names, forced, err := codexRequest(config.OpenAIConfig{Model: "test"}, input, model.WithTools([]*schema.ToolInfo{tool}), model.WithAgenticToolChoice(&schema.AgenticToolChoice{Type: schema.ToolChoiceForced}))
	if err != nil || !forced || !names["allowed"] || req.OutputSchema == nil {
		t.Fatalf("bad forced tool request: %v", err)
	}
	if !strings.Contains(req.Instructions, "arguments.json_object") {
		t.Fatalf("unexpected Codex tool instructions: %s", req.Instructions)
	}
	schemaRoot, ok := req.OutputSchema.(map[string]any)
	if !ok {
		t.Fatalf("output schema type = %T", req.OutputSchema)
	}
	properties := schemaRoot["properties"].(map[string]any)
	toolCallsSchema := properties["tool_calls"].(map[string]any)
	itemSchema := toolCallsSchema["items"].(map[string]any)
	callProperties := itemSchema["properties"].(map[string]any)
	argumentSchema := callProperties["arguments"].(map[string]any)
	if argumentSchema["type"] != "object" || argumentSchema["additionalProperties"] != false {
		t.Fatalf("arguments schema = %#v, want strict object", argumentSchema)
	}
	argumentProperties := argumentSchema["properties"].(map[string]any)
	if _, ok := argumentProperties["json_object"]; !ok {
		t.Fatalf("arguments schema = %#v, missing json_object envelope", argumentSchema)
	}
	assertCodexStrictObjectSchemas(t, req.OutputSchema)
	var payload map[string]any
	if err = json.Unmarshal([]byte(req.Input), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload["available_tools"].([]any)) != 1 {
		t.Fatal("tool definitions missing")
	}
}

func TestCodexRequestResolvesSoftBudgetAndExplicitReasoning(t *testing.T) {
	cfg := config.OpenAIConfig{Model: "test", MaxCompletionTokens: 32768}
	cfg.Reasoning.Effort = "high"
	for _, test := range []struct {
		name   string
		opts   []model.Option
		budget int
		effort string
	}{
		{name: "ordinary tool-free answer", budget: 32768, effort: "high"},
		{name: "call budget only", opts: []model.Option{model.WithMaxTokens(4096)}, budget: 4096, effort: "high"},
		{name: "explicit summary", opts: []model.Option{model.WithMaxTokens(4096), WithCodexReasoningEffort("low")}, budget: 4096, effort: "low"},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, _, _, err := codexRequest(cfg, []*schema.AgenticMessage{schema.UserAgenticMessage("hello")}, test.opts...)
			if err != nil {
				t.Fatal(err)
			}
			if req.MaxOutputTokens != test.budget || req.Effort != test.effort {
				t.Fatalf("budget/effort override lost: budget=%d effort=%q", req.MaxOutputTokens, req.Effort)
			}
		})
	}
	defaultReq, _, _, err := codexRequest(config.OpenAIConfig{Model: "test"}, nil)
	if err != nil || defaultReq.MaxOutputTokens != config.DefaultMaxCompletionTokens {
		t.Fatalf("default output budget missing: req=%+v err=%v", defaultReq, err)
	}
	for _, invalid := range []int{0, -1} {
		if _, _, _, err := codexRequest(cfg, nil, model.WithMaxTokens(invalid)); err == nil {
			t.Fatalf("invalid output budget %d accepted", invalid)
		}
	}
}

func TestCodexUsageDetailsSurviveDecodeButNotNextPrompt(t *testing.T) {
	result := &codexbridge.Result{
		Text: "answer", InputTokens: 12, OutputTokens: 3, TotalTokens: 15,
		CachedInputTokens: 8, ReasoningOutputTokens: 2, CacheWriteInputTokens: 1,
		UsageReported: true, CachedInputTokensReported: true, ReasoningOutputTokensReported: true,
		CacheWriteInputTokensReported: true,
	}
	message, err := decodeCodexResult(result, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	usage := message.ResponseMeta.TokenUsage
	if usage.PromptTokens != 12 || usage.CompletionTokens != 3 || usage.TotalTokens != 15 ||
		usage.PromptTokenDetails.CachedTokens != 8 || usage.CompletionTokensDetails.ReasoningTokens != 2 {
		t.Fatalf("Codex usage details dropped or double-counted: %+v", usage)
	}
	details := message.Extra["codex_usage_details"].(map[string]any)
	if details["cached_input_tokens_reported"] != true || details["reasoning_output_tokens_reported"] != true ||
		details["cache_write_input_tokens"] != 1 {
		t.Fatalf("reported detail metadata missing: %#v", details)
	}
	req, _, _, err := codexRequest(config.OpenAIConfig{Model: "test"}, []*schema.AgenticMessage{message})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(req.Input, "codex_usage_details") || strings.Contains(req.Input, "token_usage") || !strings.Contains(req.Input, "answer") {
		t.Fatalf("usage metadata leaked into next model prompt: %s", req.Input)
	}
}

func TestCodexUsageOnlyMessageNeverExposesInvalidToolOutput(t *testing.T) {
	result := &codexbridge.Result{
		Text:        `{"text":"partial","tool_calls":[{"name":"unknown","arguments":{}}]}`,
		InputTokens: 12, OutputTokens: 3, TotalTokens: 15, UsageReported: true,
	}
	if _, err := decodeCodexResult(result, map[string]bool{"allowed": true}, false); err == nil {
		t.Fatal("invalid tool response accepted")
	}
	usageOnly := codexUsageMessage(result)
	if len(usageOnly.ContentBlocks) != 0 || usageOnly.ResponseMeta.TokenUsage.TotalTokens != 15 {
		t.Fatalf("error usage message leaked model output or lost usage: %+v", usageOnly)
	}
	details := usageOnly.Extra["codex_usage_details"].(map[string]any)
	if details["cached_input_tokens_reported"] != false || details["reasoning_output_tokens_reported"] != false {
		t.Fatalf("missing details reported as measured: %#v", details)
	}
	if codexUsageMessage(nil) != nil {
		t.Fatal("missing bridge result produced a synthetic usage message")
	}
}

func assertCodexStrictObjectSchemas(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		if typed["type"] == "object" {
			if additional, ok := typed["additionalProperties"]; !ok || additional != false {
				t.Fatalf("non-strict object schema: %#v", typed)
			}
			properties, _ := typed["properties"].(map[string]any)
			requiredValues, _ := typed["required"].([]string)
			required := make(map[string]bool, len(requiredValues))
			for _, name := range requiredValues {
				required[name] = true
			}
			for name := range properties {
				if !required[name] {
					t.Fatalf("strict object property %q is not required: %#v", name, typed)
				}
			}
		}
		for _, child := range typed {
			assertCodexStrictObjectSchemas(t, child)
		}
	case []any:
		for _, child := range typed {
			assertCodexStrictObjectSchemas(t, child)
		}
	}
}
