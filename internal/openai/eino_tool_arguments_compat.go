package openai

import (
	"bytes"
	"encoding/json"
	"strings"
)

// normalizeChatCompletionToolArguments repairs only outbound history. Eino's
// omitempty removes empty arguments after a failed tool call; some compatible
// gateways then crash in their chat template instead of letting the model see
// the tool error. Never apply this to model output before tool execution.
func normalizeChatCompletionToolArguments(body []byte) []byte {
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil {
		return body
	}
	var messages []map[string]json.RawMessage
	if json.Unmarshal(payload["messages"], &messages) != nil {
		return body
	}
	changed := false
	for _, message := range messages {
		var role string
		_ = json.Unmarshal(message["role"], &role)
		if role != "assistant" {
			continue
		}
		var calls []map[string]json.RawMessage
		if json.Unmarshal(message["tool_calls"], &calls) == nil {
			callsChanged := false
			for _, call := range calls {
				if repaired, ok := normalizeHistoricalFunctionArguments(call["function"]); ok {
					call["function"] = repaired
					callsChanged = true
				}
			}
			if callsChanged {
				message["tool_calls"], _ = json.Marshal(calls)
				changed = true
			}
		}
		if repaired, ok := normalizeHistoricalFunctionArguments(message["function_call"]); ok {
			message["function_call"] = repaired
			changed = true
		}
	}
	if !changed {
		return body
	}
	payload["messages"], _ = json.Marshal(messages)
	out, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return out
}

func normalizeHistoricalFunctionArguments(raw json.RawMessage) (json.RawMessage, bool) {
	var function map[string]json.RawMessage
	if json.Unmarshal(raw, &function) != nil || function == nil {
		return raw, false
	}
	args := function["arguments"]
	var text string
	isString := json.Unmarshal(args, &text) == nil && len(args) > 0 && args[0] == '"'
	if !isString {
		text = string(args)
	}
	trimmed := strings.TrimSpace(text)
	var object map[string]json.RawMessage
	if json.Unmarshal([]byte(trimmed), &object) == nil && object != nil {
		if isString {
			return raw, false // Preserve valid arguments exactly, including numbers.
		}
	} else if trimmed == "" || trimmed == "null" {
		text = "{}"
	} else {
		// Retain malformed/scalar/array input as data in the model-facing history,
		// together with its unchanged tool error; do not invent valid tool inputs.
		preserved, _ := json.Marshal(map[string]string{"_invalid_tool_arguments": text})
		text = string(preserved)
	}
	encoded, _ := json.Marshal(text) // OpenAI wire format requires a JSON string.
	if bytes.Equal(encoded, args) {
		return raw, false
	}
	function["arguments"] = encoded
	repaired, _ := json.Marshal(function)
	return repaired, true
}
