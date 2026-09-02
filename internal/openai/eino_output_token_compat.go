package openai

import "encoding/json"

// Eino's common WithMaxTokens option and provider-specific MaxCompletionTokens
// config are serialized independently, including by native agenticopenai. When
// both are present, send only the current OpenAI field with the tighter positive
// bound. This also preserves a summary's smaller provider-specific limit when a
// task budget supplies a larger common limit. A single field is left untouched
// for existing OpenAI-compatible providers using the legacy parameter.
func normalizeChatCompletionOutputLimits(rawBody []byte) []byte {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		return rawBody
	}
	legacy, hasLegacy := payload["max_tokens"]
	completion, hasCompletion := payload["max_completion_tokens"]
	if !hasLegacy || !hasCompletion {
		return rawBody
	}

	legacyLimit, legacyValid := positiveChatCompletionTokenLimit(legacy)
	completionLimit, completionValid := positiveChatCompletionTokenLimit(completion)
	if !legacyValid && !completionValid {
		// Do not invent an unlimited request or silently repair wholly invalid
		// input; leave validation to the provider as before.
		return rawBody
	}
	if legacyValid && (!completionValid || legacyLimit < completionLimit) {
		completion = legacy
	}
	delete(payload, "max_tokens")
	payload["max_completion_tokens"] = completion
	out, err := json.Marshal(payload)
	if err != nil {
		return rawBody
	}
	return out
}

func positiveChatCompletionTokenLimit(raw json.RawMessage) (int64, bool) {
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}
