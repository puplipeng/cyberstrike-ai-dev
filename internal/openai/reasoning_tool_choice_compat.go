package openai

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/config"
)

// reasoningToolChoiceCompatRoundTripper strips thinking/reasoning fields from
// chat/completions requests that force tool_choice, which some gateways reject
// when thinking mode is enabled on the same request. It also reconciles the two
// output-limit fields after SDK options and request payload modifiers run.
type reasoningToolChoiceCompatRoundTripper struct {
	base http.RoundTripper
	cfg  *config.OpenAIConfig
}

func (rt *reasoningToolChoiceCompatRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt == nil || rt.base == nil || req == nil || req.Body == nil {
		if rt != nil && rt.base != nil {
			return rt.base.RoundTrip(req)
		}
		return http.DefaultTransport.RoundTrip(req)
	}
	if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/chat/completions") {
		return rt.base.RoundTrip(req)
	}

	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}

	patched := body
	var perr error
	if isDeepSeekToolChoiceCompatProfile(rt.cfg) {
		patched, perr = StripToolChoiceForThinkingMode(body)
	} else {
		patched, perr = StripReasoningIfForcedToolChoice(body)
	}
	if perr != nil {
		patched = body
	}
	patched = normalizeChatCompletionOutputLimits(patched)
	req.Body = io.NopCloser(bytes.NewReader(patched))
	// Redirects and transport retries must replay the normalized limit, not the
	// SDK's original body containing both max_tokens and max_completion_tokens.
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(patched)), nil
	}
	req.ContentLength = int64(len(patched))
	req.Header.Set("Content-Length", strconv.Itoa(len(patched)))
	return rt.base.RoundTrip(req)
}

func isDeepSeekToolChoiceCompatProfile(cfg *config.OpenAIConfig) bool {
	if cfg == nil {
		return false
	}
	profile := strings.ToLower(strings.TrimSpace(cfg.Reasoning.ProfileEffective()))
	if profile == "deepseek" || profile == "deepseek_compat" {
		return true
	}
	if profile != "" && profile != "auto" {
		return false
	}
	return cfg.IsDeepSeekEndpointOrModel()
}
