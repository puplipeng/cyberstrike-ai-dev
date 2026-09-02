package multiagent

import (
	"testing"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/summarization"
	"github.com/cloudwego/eino/schema"
)

func TestEinoRunUsageAccumulatorCountsSummaryAttemptsOnce(t *testing.T) {
	acc := newEinoRunUsageAccumulator()
	classic := schema.AssistantMessage("internal summary", nil)
	classic.ResponseMeta = &schema.ResponseMeta{Usage: &schema.TokenUsage{PromptTokens: 10, CompletionTokens: 2, TotalTokens: 12}}
	first := &adk.AgentAction{CustomizedAction: &summarization.CustomizedAction{
		Type:            summarization.ActionTypeGenerateSummary,
		GenerateSummary: &summarization.GenerateSummaryAction{Attempt: 1, Phase: summarization.GenerateSummaryPhasePrimary, ModelResponse: classic},
	}}
	if !acc.ObserveSummaryAction(first) || !acc.ObserveSummaryAction(first) {
		t.Fatal("summary generation event was not handled")
	}
	agentic := agenticAssistantTextMessage("internal typed summary")
	agentic.ResponseMeta = &schema.AgenticResponseMeta{TokenUsage: &schema.TokenUsage{PromptTokens: 20, CompletionTokens: 3, TotalTokens: 23}}
	second := &adk.AgentAction{CustomizedAction: &summarization.TypedCustomizedAction[*schema.AgenticMessage]{
		Type:            summarization.ActionTypeGenerateSummary,
		GenerateSummary: &summarization.TypedGenerateSummaryAction[*schema.AgenticMessage]{Attempt: 1, Phase: summarization.GenerateSummaryPhaseFailover, ModelResponse: agentic},
	}}
	acc.ObserveSummaryAction(second)
	acc.ObserveSummaryAction(second)
	// Same phase/attempt in a later compaction is a different model call.
	acc.ObserveSummaryAction(&adk.AgentAction{CustomizedAction: &summarization.CustomizedAction{
		Type:            summarization.ActionTypeGenerateSummary,
		GenerateSummary: &summarization.GenerateSummaryAction{Attempt: 1, Phase: summarization.GenerateSummaryPhasePrimary, ModelResponse: classic},
	}})
	acc.ObserveSummaryAction(&adk.AgentAction{CustomizedAction: &summarization.CustomizedAction{
		Type:  summarization.ActionTypeAfterSummarize,
		After: &summarization.AfterSummarizeAction{Messages: []*schema.Message{classic}},
	}})
	acc.ObserveSummaryAction(&adk.AgentAction{CustomizedAction: &summarization.TypedCustomizedAction[*schema.AgenticMessage]{
		Type:            summarization.ActionTypeGenerateSummary,
		GenerateSummary: &summarization.TypedGenerateSummaryAction[*schema.AgenticMessage]{Attempt: 2},
	}})
	got := acc.Summary()
	if got.ModelCalls != 3 || got.TotalTokens != 47 || got.PromptTokens != 40 || got.CompletionTokens != 7 {
		t.Fatalf("summary usage counted snapshots/duplicates or omitted attempts: %+v", got)
	}
	if acc.ObserveSummaryAction(nil) || acc.ObserveSummaryAction(&adk.AgentAction{CustomizedAction: "other action"}) {
		t.Fatal("unrelated action was consumed")
	}
}

func TestEinoRunUsageAccumulatorSumsModelCalls(t *testing.T) {
	acc := newEinoRunUsageAccumulator()
	acc.AddUsage(&schema.TokenUsage{
		PromptTokens:     10,
		CompletionTokens: 4,
		TotalTokens:      14,
		PromptTokenDetails: schema.PromptTokenDetails{
			CachedTokens: 3,
		},
		CompletionTokensDetails: schema.CompletionTokensDetails{
			ReasoningTokens: 2,
		},
	})
	msg := schema.AssistantMessage("ok", nil)
	msg.ResponseMeta = &schema.ResponseMeta{Usage: &schema.TokenUsage{
		PromptTokens:     7,
		CompletionTokens: 5,
		TotalTokens:      12,
		CompletionTokensDetails: schema.CompletionTokensDetails{
			ReasoningTokens: 1,
		},
	}}
	acc.AddMessage(msg)

	got := acc.Summary()
	if got.ModelCalls != 2 || got.PromptTokens != 17 || got.CompletionTokens != 9 || got.TotalTokens != 26 || got.CachedTokens != 3 || got.ReasoningTokens != 3 {
		t.Fatalf("summary = %#v", got)
	}
}

func TestEinoRunUsageAccumulatorEmitOnce(t *testing.T) {
	acc := newEinoRunUsageAccumulator()
	acc.AddUsage(&schema.TokenUsage{PromptTokens: 1, CompletionTokens: 2, TotalTokens: 3})
	var events []map[string]interface{}
	progress := func(eventType, _ string, data interface{}) {
		if eventType != "eino_usage_summary" {
			return
		}
		if m, ok := data.(map[string]interface{}); ok {
			events = append(events, m)
		}
	}

	if !acc.EmitOnce("conv-1", "deep", "final", "gpt-test", progress, nil) {
		t.Fatal("first emit should return true")
	}
	if acc.EmitOnce("conv-1", "deep", "partial", "gpt-test", progress, nil) {
		t.Fatal("second emit should return false")
	}
	if len(events) != 1 {
		t.Fatalf("events = %#v, want one usage summary", events)
	}
	if events[0]["conversationId"] != "conv-1" || events[0]["orchestration"] != "deep" || events[0]["reason"] != "final" || events[0]["model"] != "gpt-test" || events[0]["totalTokens"] != 3 {
		t.Fatalf("event = %#v", events[0])
	}
}

func TestMaxEinoTokenUsageUsesLargestStreamChunkValues(t *testing.T) {
	var got *schema.TokenUsage
	got = maxEinoTokenUsage(got, &schema.TokenUsage{PromptTokens: 10, CompletionTokens: 2, TotalTokens: 12})
	got = maxEinoTokenUsage(got, &schema.TokenUsage{
		PromptTokens:     9,
		CompletionTokens: 5,
		TotalTokens:      14,
		CompletionTokensDetails: schema.CompletionTokensDetails{
			ReasoningTokens: 3,
		},
	})

	if got.PromptTokens != 10 || got.CompletionTokens != 5 || got.TotalTokens != 14 || got.CompletionTokensDetails.ReasoningTokens != 3 {
		t.Fatalf("usage = %#v", got)
	}
}
