package openai

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestStripReasoningFromChatCompletionBody(t *testing.T) {
	in := []byte(`{"model":"deepseek-chat","messages":[],"thinking":{"type":"enabled"},"reasoning_effort":"high"}`)
	out, err := StripReasoningFromChatCompletionBody(in)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "thinking") || strings.Contains(s, "reasoning_effort") {
		t.Fatalf("expected reasoning fields stripped, got %s", s)
	}
	if !strings.Contains(s, `"model":"deepseek-chat"`) {
		t.Fatalf("expected model preserved, got %s", s)
	}

	plain := []byte(`{"model":"gpt-4o","messages":[]}`)
	out2, err := StripReasoningFromChatCompletionBody(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(out2) != string(plain) {
		t.Fatalf("expected unchanged payload, got %s", out2)
	}
}

func TestStripReasoningIfForcedToolChoice(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		strip   bool
		contain string
	}{
		{
			name:  "required strips thinking",
			in:    `{"model":"minimax","messages":[],"thinking":{"type":"enabled"},"tool_choice":"required","tools":[]}`,
			strip: true,
		},
		{
			name:  "object tool_choice strips thinking",
			in:    `{"model":"qwen","messages":[],"thinking":{"type":"enabled"},"tool_choice":{"type":"function","function":{"name":"respond"}}}`,
			strip: true,
		},
		{
			name:    "auto keeps thinking",
			in:      `{"model":"qwen","messages":[],"thinking":{"type":"enabled"},"tool_choice":"auto"}`,
			strip:   false,
			contain: "thinking",
		},
		{
			name:    "no tool_choice keeps thinking",
			in:      `{"model":"qwen","messages":[],"thinking":{"type":"enabled"}}`,
			strip:   false,
			contain: "thinking",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := StripReasoningIfForcedToolChoice([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			s := string(out)
			hasThinking := strings.Contains(s, "thinking")
			if tc.strip && hasThinking {
				t.Fatalf("expected thinking stripped, got %s", s)
			}
			if !tc.strip && tc.contain != "" && !strings.Contains(s, tc.contain) {
				t.Fatalf("expected %q in %s", tc.contain, s)
			}
			if !tc.strip && string(out) != tc.in {
				t.Fatalf("expected unchanged payload, got %s", s)
			}
		})
	}
}

func TestStripToolChoiceForThinkingMode(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		wantToolChoice bool
		wantThinking   bool
	}{
		{
			name:           "enabled thinking removes tool_choice",
			in:             `{"model":"deepseek-v4","messages":[],"thinking":{"type":"enabled"},"tool_choice":"required","tools":[{"type":"function","function":{"name":"scan"}}]}`,
			wantToolChoice: false,
			wantThinking:   true,
		},
		{
			name:           "default thinking removes tool_choice",
			in:             `{"model":"deepseek-v4","messages":[],"tool_choice":"auto","tools":[]}`,
			wantToolChoice: false,
			wantThinking:   false,
		},
		{
			name:           "disabled thinking keeps tool_choice",
			in:             `{"model":"deepseek-v4","messages":[],"thinking":{"type":"disabled"},"tool_choice":"required","tools":[]}`,
			wantToolChoice: true,
			wantThinking:   true,
		},
		{
			name:           "no tool_choice unchanged",
			in:             `{"model":"deepseek-v4","messages":[],"thinking":{"type":"enabled"},"tools":[]}`,
			wantToolChoice: false,
			wantThinking:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := StripToolChoiceForThinkingMode([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			s := string(out)
			if strings.Contains(s, "tool_choice") != tc.wantToolChoice {
				t.Fatalf("tool_choice presence mismatch, got %s", s)
			}
			if strings.Contains(s, "thinking") != tc.wantThinking {
				t.Fatalf("thinking presence mismatch, got %s", s)
			}
			if !strings.Contains(s, "tools") {
				t.Fatalf("expected tools preserved, got %s", s)
			}
		})
	}
}

func TestReasoningToolChoiceCompatRoundTripper(t *testing.T) {
	var gotBody string
	rt := &reasoningToolChoiceCompatRoundTripper{
		base: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			gotBody = string(b)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"ok"}}]}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}, nil
		}),
	}
	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/chat/completions", strings.NewReader(
		`{"model":"m","thinking":{"type":"enabled"},"tool_choice":"required","messages":[]}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	_, err = rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotBody, "thinking") {
		t.Fatalf("expected thinking stripped in transit, got %s", gotBody)
	}
	if !strings.Contains(gotBody, `"tool_choice":"required"`) {
		t.Fatalf("expected tool_choice preserved, got %s", gotBody)
	}
}

func TestReasoningToolChoiceCompatRoundTripperDeepSeek(t *testing.T) {
	var gotBody string
	rt := &reasoningToolChoiceCompatRoundTripper{
		cfg: &config.OpenAIConfig{
			BaseURL: "https://api.deepseek.com/v1",
			Model:   "deepseek-v4",
		},
		base: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			gotBody = string(b)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"ok"}}]}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}, nil
		}),
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(
		`{"model":"deepseek-v4","thinking":{"type":"enabled"},"tool_choice":"required","tools":[],"messages":[]}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	_, err = rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotBody, "tool_choice") {
		t.Fatalf("expected DeepSeek tool_choice stripped in transit, got %s", gotBody)
	}
	if !strings.Contains(gotBody, "thinking") {
		t.Fatalf("expected thinking preserved for DeepSeek, got %s", gotBody)
	}
	if !strings.Contains(gotBody, "tools") {
		t.Fatalf("expected tools preserved for DeepSeek, got %s", gotBody)
	}
}

func TestReasoningToolChoiceCompatRoundTripperOpenAIProfileWinsOverDeepSeekEndpoint(t *testing.T) {
	var gotBody string
	rt := &reasoningToolChoiceCompatRoundTripper{
		cfg: &config.OpenAIConfig{
			BaseURL: "https://api.deepseek.com/v1",
			Model:   "deepseek-v4-flash",
			Reasoning: config.OpenAIReasoningConfig{
				Profile: "openai_compat",
			},
		},
		base: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			gotBody = string(b)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"ok"}}]}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}, nil
		}),
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(
		`{"model":"deepseek-v4-flash","tool_choice":"required","tools":[],"messages":[]}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	_, err = rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotBody, "tool_choice") {
		t.Fatalf("expected tool_choice preserved for explicit openai_compat profile, got %s", gotBody)
	}
	if !strings.Contains(gotBody, "tools") {
		t.Fatalf("expected tools preserved for explicit openai_compat profile, got %s", gotBody)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNormalizeChatCompletionOutputLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want int64
	}{
		{"budget tighter", `{"max_tokens":128,"max_completion_tokens":32768}`, 128},
		{"configured limit tighter", `{"max_tokens":2048,"max_completion_tokens":512}`, 512},
		{"equal limits", `{"max_tokens":512,"max_completion_tokens":512}`, 512},
		{"zero is not a positive limit", `{"max_tokens":0,"max_completion_tokens":256}`, 256},
		{"negative is not a positive limit", `{"max_tokens":128,"max_completion_tokens":-1}`, 128},
		{"null is not a positive limit", `{"max_tokens":128,"max_completion_tokens":null}`, 128},
		{"fraction is not a token limit", `{"max_tokens":0.5,"max_completion_tokens":128}`, 128},
		{"string is not a token limit", `{"max_tokens":"64","max_completion_tokens":128}`, 128},
		{"current field alone", `{ "max_completion_tokens": 256 }`, 0},
		{"legacy field alone", `{ "max_tokens": 256 }`, 0},
		{"neither field", `{"messages":[]}`, 0},
		{"neither limit valid", `{"max_tokens":0,"max_completion_tokens":null}`, 0},
		{"invalid JSON", `not JSON`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeChatCompletionOutputLimits([]byte(tc.in))
			if tc.want == 0 {
				if string(got) != tc.in {
					t.Fatalf("unrelated/single-field payload changed: %s", got)
				}
				return
			}
			var payload map[string]int64
			if err := json.Unmarshal(got, &payload); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(payload, map[string]int64{"max_completion_tokens": tc.want}) {
				t.Fatalf("output limits = %s, want only max_completion_tokens=%d", got, tc.want)
			}
		})
	}
}

func TestOutputLimitCompatLeavesOtherRequestsUnchanged(t *testing.T) {
	const body = `{"max_tokens":128,"max_completion_tokens":4096,"reasoning_effort":"high"}`
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/responses"},
		{http.MethodPost, "/v1/messages"},
		{http.MethodPost, "/v1/embeddings"},
		{http.MethodGet, "/v1/chat/completions"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			var got string
			client := NewEinoHTTPClient(nil, &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				b, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				got = string(b)
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}, nil
			})})
			req, err := http.NewRequest(tc.method, "https://example.invalid"+tc.path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if got != body {
				t.Fatalf("non-chat request changed: %s", got)
			}
		})
	}
}
