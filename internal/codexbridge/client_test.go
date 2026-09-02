package codexbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type writeBuffer struct{ bytes.Buffer }

func (w *writeBuffer) Close() error { return nil }
func fakeClient(lines ...string) (*Client, *writeBuffer) {
	w := &writeBuffer{}
	c := &Client{in: w, packets: make(chan packet, len(lines)+1), cwd: "isolated", mcpNames: []string{"private_mcp"}}
	for _, line := range lines {
		var p packet
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			panic(err)
		}
		c.packets <- p
	}
	return c, w
}
func TestAccountRequiresChatGPT(t *testing.T) {
	for _, account := range []string{"null", `{"type":"apiKey"}`, `{"type":"amazonBedrock"}`} {
		c, _ := fakeClient(`{"id":1,"result":{"account":` + account + `}}`)
		if err := c.requireAccount(context.Background()); err == nil {
			t.Fatal("accepted a non-ChatGPT account")
		}
	}
}
func TestRunStreamsAndDeniesBuiltInExecution(t *testing.T) {
	c, w := fakeClient(
		`{"id":1,"result":{"account":{"type":"chatgpt"}}}`,
		`{"id":2,"result":{"thread":{"id":"thread-1"}}}`,
		`{"id":3,"result":{"turn":{"id":"turn-1"}}}`,
		`{"id":"approval-1","method":"item/commandExecution/requestApproval","params":{"command":"must-not-run"}}`,
		`{"method":"item/agentMessage/delta","params":{"threadId":"another","delta":"wrong"}}`,
		`{"method":"item/agentMessage/delta","params":{"threadId":"thread-1","delta":"Hello"}}`,
		`{"method":"item/completed","params":{"threadId":"thread-1","item":{"type":"agentMessage","phase":"final_answer","text":"Hello"}}}`,
		`{"method":"thread/tokenUsage/updated","params":{"threadId":"thread-1","tokenUsage":{"last":{"inputTokens":7,"outputTokens":2,"totalTokens":9,"cachedInputTokens":4,"reasoningOutputTokens":1},"total":{"inputTokens":12,"outputTokens":3,"totalTokens":15,"cachedInputTokens":8,"reasoningOutputTokens":2,"cacheWriteInputTokens":1}}}}`,
		`{"method":"thread/tokenUsage/updated","params":{"threadId":"thread-1","tokenUsage":{"last":{"inputTokens":7,"outputTokens":2,"totalTokens":9,"cachedInputTokens":4,"reasoningOutputTokens":1},"total":{"inputTokens":12,"outputTokens":3,"totalTokens":15,"cachedInputTokens":8,"reasoningOutputTokens":2,"cacheWriteInputTokens":1}}}}`,
		`{"method":"thread/tokenUsage/updated","params":{"threadId":"another","tokenUsage":{"total":{"inputTokens":900,"outputTokens":100,"totalTokens":1000}}}}`,
		`{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"status":"completed"}}}`)
	var text strings.Builder
	r, err := c.Run(context.Background(), Request{Model: "test-model", Input: "hello"}, func(s string) error { text.WriteString(s); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if r.Text != "Hello" || text.String() != "Hello" || r.TotalTokens != 15 {
		t.Fatalf("bad response: %+v, stream=%q", r, text.String())
	}
	if r.InputTokens != 12 || r.OutputTokens != 3 || r.CachedInputTokens != 8 || r.ReasoningOutputTokens != 2 || r.CacheWriteInputTokens != 1 {
		t.Fatalf("thread cumulative usage details were not preserved: %+v", r)
	}
	if !r.UsageReported || !r.CachedInputTokensReported || !r.ReasoningOutputTokensReported || !r.CacheWriteInputTokensReported {
		t.Fatalf("reported usage marked as unavailable: %+v", r)
	}
	var messages []map[string]any
	dec := json.NewDecoder(bytes.NewReader(w.Bytes()))
	for dec.More() {
		var m map[string]any
		if err = dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		messages = append(messages, m)
	}
	start := messages[1]["params"].(map[string]any)
	if start["ephemeral"] != true || start["sandbox"] != "read-only" {
		t.Fatal("thread was not isolated")
	}
	if start["config"].(map[string]any)["mcp_servers.private_mcp.enabled"] != false {
		t.Fatal("inherited MCP was not disabled")
	}
	approval := messages[len(messages)-1]["result"].(map[string]any)
	if approval["decision"] != "decline" {
		t.Fatal("built-in execution was approved")
	}
}

func TestRunSoftBudgetPreservesCompleteStructuredResponse(t *testing.T) {
	body := `{"text":"","tool_calls":[{"name":"read_file","arguments":{"json_object":"{\"path\":\"report.txt\"}"}}]}`
	delta, _ := json.Marshal(map[string]any{
		"method": "item/agentMessage/delta",
		"params": map[string]any{"threadId": "thread-1", "delta": body},
	})
	c, w := fakeClient(
		`{"id":1,"result":{"account":{"type":"chatgpt"}}}`,
		`{"id":2,"result":{"thread":{"id":"thread-1"}}}`,
		`{"id":3,"result":{"turn":{"id":"turn-1"}}}`,
		string(delta),
		`{"method":"thread/tokenUsage/updated","params":{"threadId":"thread-1","tokenUsage":{"last":{"inputTokens":12,"outputTokens":25,"totalTokens":37}}}}`,
		`{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"status":"completed"}}}`,
	)
	var streamed strings.Builder
	result, err := c.Run(context.Background(), Request{
		Model: "test-model", Instructions: "Follow the host conversation.", Input: "hello",
		MaxOutputTokens: 1, OutputSchema: map[string]any{"type": "object"},
	}, func(delta string) error { streamed.WriteString(delta); return nil })
	if err != nil || result.Text != body || streamed.String() != body {
		t.Fatalf("soft budget truncated or rejected valid tool JSON: result=%+v err=%v stream=%q", result, err, streamed.String())
	}
	if !json.Valid([]byte(result.Text)) || result.OutputTokens != 25 {
		t.Fatalf("valid response or actual over-budget usage lost: %+v", result)
	}
	var messages []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(w.Bytes()))
	for decoder.More() {
		var message map[string]any
		if err := decoder.Decode(&message); err != nil {
			t.Fatal(err)
		}
		messages = append(messages, message)
	}
	instructions := messages[1]["params"].(map[string]any)["baseInstructions"].(string)
	if !strings.Contains(instructions, "soft output budget of at most 1 tokens") ||
		!strings.Contains(instructions, "finish valid, complete JSON") ||
		!strings.HasPrefix(instructions, "Follow the host conversation.") {
		t.Fatalf("missing explicit soft-budget instructions: %q", instructions)
	}
	turn := messages[2]["params"].(map[string]any)
	for _, invented := range []string{"max_tokens", "max_completion_tokens", "maxOutputTokens", "maxTokens"} {
		if _, ok := turn[invented]; ok {
			t.Fatalf("invented server output-limit field sent: %s", invented)
		}
	}
	if turn["outputSchema"].(map[string]any)["type"] != "object" {
		t.Fatal("output schema was removed by soft budget")
	}
	support := OutputBudgetSupport()
	if support.Mode != "advisory" || support.HardLimitSupported || !support.CallOverrideSupported {
		t.Fatalf("misleading output-budget capability: %+v", support)
	}
}

func TestRunRejectsNegativeBudgetBeforeStarting(t *testing.T) {
	c, written := fakeClient()
	_, err := c.Run(context.Background(), Request{Model: "test-model", MaxOutputTokens: -1}, nil)
	if err == nil || written.Len() != 0 {
		t.Fatalf("negative budget reached Codex: err=%v writes=%q", err, written.String())
	}
	if got := instructionsWithOutputBudget(Request{Instructions: "unchanged"}); got != "unchanged" {
		t.Fatalf("unspecified budget changed instructions: %q", got)
	}
}

func TestRunUsageDistinguishesMissingDetailsFromZero(t *testing.T) {
	for _, test := range []struct {
		name     string
		usage    string
		reported bool
		detailed bool
	}{
		{name: "no notification"},
		{name: "legacy last only", usage: `{"last":{"inputTokens":12,"outputTokens":3,"totalTokens":15}}`, reported: true},
		{name: "measured zeros", usage: `{"last":{"inputTokens":12,"outputTokens":3,"totalTokens":15,"cachedInputTokens":0,"reasoningOutputTokens":0,"cacheWriteInputTokens":0}}`, reported: true, detailed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			lines := []string{
				`{"id":1,"result":{"account":{"type":"chatgpt"}}}`,
				`{"id":2,"result":{"thread":{"id":"thread-1"}}}`,
				`{"id":3,"result":{"turn":{"id":"turn-1"}}}`,
				`{"method":"item/agentMessage/delta","params":{"threadId":"thread-1","delta":"Hello"}}`,
			}
			if test.usage != "" {
				lines = append(lines, `{"method":"thread/tokenUsage/updated","params":{"threadId":"thread-1","tokenUsage":`+test.usage+`}}`)
			}
			lines = append(lines, `{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"status":"completed"}}}`)
			c, _ := fakeClient(lines...)
			result, err := c.Run(context.Background(), Request{Model: "test-model"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.UsageReported != test.reported ||
				result.CachedInputTokensReported != test.detailed ||
				result.ReasoningOutputTokensReported != test.detailed ||
				result.CacheWriteInputTokensReported != test.detailed {
				t.Fatalf("missing detail confused with zero: %+v", result)
			}
			if test.reported && result.TotalTokens != 15 {
				t.Fatalf("legacy last usage was not used: %+v", result)
			}
		})
	}
}

func TestRunPreservesReportedUsageOnFailure(t *testing.T) {
	callbackErr := errors.New("consumer stopped")
	for _, test := range []struct {
		name    string
		last    string
		onDelta func(string) error
	}{
		{name: "failed turn", last: `{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"status":"failed","error":{"message":"request failed"}}}}`},
		{name: "empty response", last: `{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"status":"completed"}}}`},
		{name: "stream consumer error", last: `{"method":"item/agentMessage/delta","params":{"threadId":"thread-1","delta":"partial"}}`, onDelta: func(string) error { return callbackErr }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, _ := fakeClient(
				`{"id":1,"result":{"account":{"type":"chatgpt"}}}`,
				`{"id":2,"result":{"thread":{"id":"thread-1"}}}`,
				`{"id":3,"result":{"turn":{"id":"turn-1"}}}`,
				`{"method":"thread/tokenUsage/updated","params":{"threadId":"thread-1","tokenUsage":{"total":{"inputTokens":12,"outputTokens":3,"totalTokens":15,"cachedInputTokens":8,"reasoningOutputTokens":2}}}}`,
				test.last,
			)
			result, err := c.Run(context.Background(), Request{Model: "test-model"}, test.onDelta)
			if err == nil || result == nil || !result.UsageReported || result.TotalTokens != 15 || result.CachedInputTokens != 8 {
				t.Fatalf("failed call usage discarded: result=%+v err=%v", result, err)
			}
			if test.onDelta != nil && !errors.Is(err, callbackErr) {
				t.Fatalf("stream failure changed: %v", err)
			}
		})
	}
}
func TestRequestCancellation(t *testing.T) {
	c, _ := fakeClient()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := c.call(ctx, "test", nil, nil); err != context.Canceled {
		t.Fatalf("error=%v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation blocked")
	}
}
func TestRPCSecretsAreRedacted(t *testing.T) {
	c, _ := fakeClient(`{"id":1,"error":{"code":401,"message":"credential sk-test-secret-invalid rejected"}}`)
	_, err := c.call(context.Background(), "test", nil, nil)
	if err == nil || strings.Contains(err.Error(), "sk-test") {
		t.Fatalf("secret not redacted: %v", err)
	}
}
func TestAccountEnvironmentDoesNotFallbackToAPIKeys(t *testing.T) {
	got := accountEnvironment([]string{"OPENAI_API_KEY=secret", "codex_api_key=secret", "PATH=bin", "USERPROFILE=profile"})
	if len(got) != 2 || got[0] != "PATH=bin" {
		t.Fatalf("unsafe environment: %v", got)
	}
}
func TestPermissionAndUnknownRequestsFailClosed(t *testing.T) {
	for _, method := range []string{"item/fileChange/requestApproval", "item/permissions/requestApproval", "item/tool/call", "tool/requestUserInput"} {
		c, w := fakeClient()
		if err := c.handle(packet{ID: json.RawMessage("9"), Method: method}, nil); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(w.String(), "accept") || strings.Contains(w.String(), `"success":true`) {
			t.Fatalf("unsafe approval: %s", w.String())
		}
	}
}

func TestRunRejectsAmbiguousMCPNames(t *testing.T) {
	for _, name := range []string{"", "private.mcp", `"private_mcp"`, "private mcp"} {
		t.Run(name, func(t *testing.T) {
			c, w := fakeClient(`{"id":1,"result":{"account":{"type":"chatgpt"}}}`)
			c.mcpNames = []string{name}
			_, err := c.Run(context.Background(), Request{Model: "test-model"}, nil)
			if err == nil || !strings.Contains(err.Error(), "cannot be isolated safely") {
				t.Fatalf("unsafe MCP name accepted: %v", err)
			}
			if strings.Contains(w.String(), "thread/start") {
				t.Fatal("thread started before MCP isolation was verified")
			}
		})
	}
}
