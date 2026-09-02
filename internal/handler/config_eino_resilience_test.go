package handler

import (
	"encoding/json"
	"testing"

	"cyberstrike-ai/internal/config"
	"gopkg.in/yaml.v3"
)

func TestUpdateMultiAgentConfigWritesEinoModelResilience(t *testing.T) {
	doc := &yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}},
	}

	updateMultiAgentConfig(doc, config.MultiAgentConfig{
		Enabled:                      true,
		RobotDefaultAgentMode:        "deep",
		PlanExecuteLoopMaxIterations: 3,
		EinoMiddleware: config.MultiAgentEinoMiddlewareConfig{
			ModelRetryMaxRetries:    5,
			ModelRetryMaxBackoffSec: 45,
			ModelFailoverChannels:   []string{"backup-openai", "backup-claude", "backup-openai"},
			ModelFailoverMaxRetries: 2,
		},
	})

	var got struct {
		MultiAgent struct {
			EinoMiddleware struct {
				ModelRetryMaxRetries    int      `yaml:"model_retry_max_retries"`
				ModelRetryMaxBackoffSec int      `yaml:"model_retry_max_backoff_sec"`
				ModelFailoverChannels   []string `yaml:"model_failover_channels"`
				ModelFailoverMaxRetries int      `yaml:"model_failover_max_retries"`
			} `yaml:"eino_middleware"`
		} `yaml:"multi_agent"`
	}
	if err := doc.Decode(&got); err != nil {
		t.Fatalf("decode config yaml: %v", err)
	}

	mw := got.MultiAgent.EinoMiddleware
	if mw.ModelRetryMaxRetries != 5 {
		t.Fatalf("model_retry_max_retries = %d, want 5", mw.ModelRetryMaxRetries)
	}
	if mw.ModelRetryMaxBackoffSec != 45 {
		t.Fatalf("model_retry_max_backoff_sec = %d, want 45", mw.ModelRetryMaxBackoffSec)
	}
	if mw.ModelFailoverMaxRetries != 2 {
		t.Fatalf("model_failover_max_retries = %d, want 2", mw.ModelFailoverMaxRetries)
	}
	wantChannels := []string{"backup-openai", "backup-claude"}
	if len(mw.ModelFailoverChannels) != len(wantChannels) {
		t.Fatalf("model_failover_channels = %#v, want %#v", mw.ModelFailoverChannels, wantChannels)
	}
	for i, want := range wantChannels {
		if mw.ModelFailoverChannels[i] != want {
			t.Fatalf("model_failover_channels[%d] = %q, want %q", i, mw.ModelFailoverChannels[i], want)
		}
	}
}

func TestTokenOptimizationSettingsRoundTripAndPartialUpdate(t *testing.T) {
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	ma := config.MultiAgentConfig{EinoMiddleware: config.MultiAgentEinoMiddlewareConfig{ToolSearchEnable: true, ReductionEnable: true}}
	updateMultiAgentConfig(doc, ma)
	agentCfg := config.AgentConfig{MaxIterations: 30, MaxTaskTokens: 250000}
	var partial AgentConfigUpdate
	if err := json.Unmarshal([]byte(`{"tool_timeout_minutes":12}`), &partial); err != nil {
		t.Fatal(err)
	}
	applyAgentConfigUpdate(&agentCfg, &partial)
	if agentCfg.MaxTaskTokens != 250000 {
		t.Fatal("unrelated update cleared the task token budget")
	}
	disabled := -1
	applyAgentConfigUpdate(&agentCfg, &AgentConfigUpdate{MaxTaskTokens: &disabled})
	updateAgentConfig(doc, agentCfg)
	updateKnowledgeConfig(doc, config.KnowledgeConfig{Retrieval: config.RetrievalConfig{
		MultiQuery:   config.MultiQueryConfig{Enabled: false, MaxQueries: 4},
		PostRetrieve: config.PostRetrieveConfig{MaxContextTokens: 4096},
	}})
	var saved config.Config
	if err := doc.Decode(&saved); err != nil {
		t.Fatal(err)
	}
	if !saved.MultiAgent.EinoMiddleware.ToolSearchEnable || !saved.MultiAgent.EinoMiddleware.ReductionEnable {
		t.Fatal("token optimization switches were not persisted")
	}
	if saved.Agent.MaxTaskTokens != -1 || saved.Agent.MaxTaskTokensEffective() != 0 {
		t.Fatal("explicit unlimited task budget was not persisted")
	}
	if saved.Knowledge.Retrieval.MultiQuery.Enabled || saved.Knowledge.Retrieval.PostRetrieve.MaxContextTokens != 4096 {
		t.Fatal("knowledge query budget or opt-in rewriting lost on save")
	}
}
