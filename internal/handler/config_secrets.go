package handler

import (
	"cyberstrike-ai/internal/config"
	"fmt"
	"strings"
)

// A masked key can only be used against its saved provider endpoint. A caller
// must explicitly enter a new key or save the configuration to change endpoints.
func (h *ConfigHandler) resolveTestAPIKey(ref, key, provider, baseURL string) (string, error) {
	if key != config.SecretMask {
		return key, nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	var saved config.OpenAIConfig
	switch {
	case strings.HasPrefix(ref, "/ai/channels/") && strings.HasSuffix(ref, "/api_key"):
		id := strings.TrimSuffix(strings.TrimPrefix(ref, "/ai/channels/"), "/api_key")
		id = strings.ReplaceAll(strings.ReplaceAll(id, "~1", "/"), "~0", "~")
		channel, ok := h.config.AI.Channels[id]
		if !ok {
			return "", fmt.Errorf("saved model channel not found")
		}
		saved = channel.ToOpenAIConfig()
	case ref == "" || ref == "/openai/api_key":
		saved = h.config.OpenAI
	case ref == "/vision/api_key":
		saved = h.config.Vision.OpenAICfgEffective(h.config.OpenAI)
	case ref == "/hitl/audit_model/api_key":
		saved = h.config.OpenAI
		audit := h.config.Hitl.AuditModel
		if audit.Provider != "" {
			saved.Provider = audit.Provider
		}
		if audit.BaseURL != "" {
			saved.BaseURL = audit.BaseURL
		}
		if audit.APIKey != "" {
			saved.APIKey = audit.APIKey
		}
	case ref == "/knowledge/embedding/api_key":
		embed := h.config.Knowledge.Embedding
		saved = config.OpenAIConfig{Provider: embed.Provider, BaseURL: embed.BaseURL, APIKey: embed.APIKey}
	default:
		return "", fmt.Errorf("invalid saved key reference")
	}
	if saved.APIKey == "" || saved.APIKey == config.SecretMask {
		return "", fmt.Errorf("no saved API key; enter a new key")
	}
	if normalizeKeyProvider(saved.Provider) != normalizeKeyProvider(provider) || normalizeKeyEndpoint(saved.Provider, saved.BaseURL) != normalizeKeyEndpoint(provider, baseURL) {
		return "", fmt.Errorf("saved key endpoint changed; save settings first or enter a new key")
	}
	return saved.APIKey, nil
}

func normalizeKeyProvider(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" || p == "openai_compatible" {
		return "openai"
	}
	return p
}

func normalizeKeyEndpoint(provider, endpoint string) string {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		if normalizeKeyProvider(provider) == "claude" {
			return "https://api.anthropic.com"
		}
		return "https://api.openai.com/v1"
	}
	return endpoint
}
