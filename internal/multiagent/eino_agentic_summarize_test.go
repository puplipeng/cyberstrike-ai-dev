package multiagent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/modelbudget"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/components/tool/utils"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

func TestEinoAgenticSummarizationOverflowRetryRebuildsSmallerInput(t *testing.T) {
	ctx := context.Background()
	emit := false
	appCfg := &config.Config{OpenAI: config.OpenAIConfig{Model: "gpt-4o", MaxTotalTokens: 12000}}
	mwCfg := &config.MultiAgentEinoMiddlewareConfig{SummarizationEmitInternalEvents: &emit, SummarizationOutputReserveTokens: 1024}
	fake := &overflowOnceSummaryModel[*schema.AgenticMessage]{output: agenticAssistantTextMessage("<summary>Retain the authorized scope example.com.</summary>")}
	mw, err := newEinoAgenticSummarizationMiddleware(ctx, fake, appCfg, mwCfg, "", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, after, err := mw.BeforeModelRewriteState(ctx, &adk.TypedChatModelAgentState[*schema.AgenticMessage]{Messages: EinoMessagesToAgentic(summaryOverflowTestHistory())}, nil)
	if err != nil || after == nil {
		t.Fatalf("overflow recovery failed: %v", err)
	}
	if len(fake.inputs) != 2 {
		t.Fatalf("model calls=%d, want initial plus one compacted retry", len(fake.inputs))
	}
	counter := einoSummarizationTokenCounter(appCfg.OpenAI.Model)
	beforeTokens, _ := countMessagesTokens(ctx, AgenticMessagesToEino(fake.inputs[0]), counter, nil)
	afterTokens, _ := countMessagesTokens(ctx, AgenticMessagesToEino(fake.inputs[1]), counter, nil)
	if afterTokens >= beforeTokens {
		t.Fatalf("overflow retried unchanged input: before=%d after=%d", beforeTokens, afterTokens)
	}
}

func TestEinoRunLoopCountsSummaryRetriesWithoutExposingText(t *testing.T) {
	ctx := context.Background()
	withUsage := func(text string, total int) *schema.AgenticMessage {
		msg := agenticAssistantTextMessage(text)
		msg.ResponseMeta = &schema.AgenticResponseMeta{TokenUsage: &schema.TokenUsage{PromptTokens: total - 1, CompletionTokens: 1, TotalTokens: total}}
		return msg
	}
	fakeSummary := &capturingAgenticChatModel{outputs: []*schema.AgenticMessage{
		withUsage("", 10), // Empty content still consumed tokens before the retry.
		withUsage("<summary>INTERNAL_SUMMARY_ONLY</summary>", 20),
	}}
	fakeBusiness := &capturingAgenticChatModel{output: withUsage("public answer", 30)}
	appCfg := &config.Config{OpenAI: config.OpenAIConfig{Model: "gpt-4o", MaxTotalTokens: 12000}}
	mwCfg := &config.MultiAgentEinoMiddlewareConfig{SummarizationOutputReserveTokens: 1024}
	summaryMW, err := newEinoAgenticSummarizationMiddleware(ctx, fakeSummary, appCfg, mwCfg, "", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	lead, err := newEinoAgenticChatModelAgentAdapter(ctx, einoAgenticChatModelAgentConfig{
		Name: "lead", Description: "summary usage test", Instruction: "root instruction", Model: fakeBusiness,
		Handlers: appendEinoAgenticChatModelTailMiddlewares(nil, einoChatModelTailConfig{agenticSummarization: summaryMW}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var usage map[string]interface{}
	var visible strings.Builder
	result, err := runEinoADKAgentLoop(ctx, &einoADKRunLoopArgs{
		OrchMode: "eino_single", OrchestratorName: "lead", DA: lead,
		Progress: func(kind, text string, data interface{}) {
			if kind == "eino_usage_summary" {
				usage, _ = data.(map[string]interface{})
			}
			visible.WriteString(text)
		},
	}, summaryOverflowTestHistory())
	if err != nil || result == nil || result.Response != "public answer" {
		t.Fatalf("unexpected run result=%+v err=%v", result, err)
	}
	if usage == nil || usage["modelCalls"] != 3 || usage["totalTokens"] != 60 {
		t.Fatalf("usage must include failed summary, summary retry and business call: %#v", usage)
	}
	if strings.Contains(visible.String(), "INTERNAL_SUMMARY_ONLY") {
		t.Fatal("internal summary leaked into user-facing output")
	}
}

func TestEinoRunLoopSharesTaskBudgetAcrossSummaryAndBusinessCalls(t *testing.T) {
	ctx := context.Background()
	const limit = 50000
	withUsage := func(text string, total int) *schema.AgenticMessage {
		msg := agenticAssistantTextMessage(text)
		msg.ResponseMeta = &schema.AgenticResponseMeta{TokenUsage: &schema.TokenUsage{PromptTokens: total - 1, CompletionTokens: 1, TotalTokens: total}}
		return msg
	}
	// Neither response individually exhausts the task budget; their combined
	// reported usage must prevent the next business call before it reaches a model.
	fakeSummary := &capturingAgenticChatModel{output: withUsage("<summary>INTERNAL_SUMMARY_ONLY</summary>", 25000)}
	partial := withUsage("partial result retained", 30000)
	partial.ContentBlocks = append(partial.ContentBlocks, schema.NewContentBlock(&schema.FunctionToolCall{
		CallID: "local-evidence-1", Name: "local_evidence", Arguments: `{}`,
	}))
	fakeBusiness := &capturingAgenticChatModel{outputs: []*schema.AgenticMessage{
		partial,
		withUsage("UNEXPECTED_EXTRA_MODEL_CALL", 1),
	}}
	var localToolCalls atomic.Int32
	localTool, err := utils.InferTool("local_evidence", "Return a fixed local test result", func(context.Context, struct{}) (string, error) {
		localToolCalls.Add(1)
		return "local evidence retained", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	appCfg := &config.Config{OpenAI: config.OpenAIConfig{Model: "gpt-4o", MaxTotalTokens: 12000}}
	mwCfg := &config.MultiAgentEinoMiddlewareConfig{SummarizationOutputReserveTokens: 1024}
	summaryMW, err := newEinoAgenticSummarizationMiddleware(ctx, modelbudget.WrapAgentic(fakeSummary, appCfg.OpenAI.Model, 1024), appCfg, mwCfg, "", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	retryCfg := newEinoAgenticModelRetryConfig(mwCfg, nil, "budget-integration")
	shouldRetry := retryCfg.ShouldRetry
	var budgetRejections atomic.Int32
	retryCfg.ShouldRetry = func(ctx context.Context, retry *adk.TypedRetryContext[*schema.AgenticMessage]) *adk.TypedRetryDecision[*schema.AgenticMessage] {
		if retry != nil && errors.Is(retry.Err, modelbudget.ErrExceeded) {
			budgetRejections.Add(1)
		}
		return shouldRetry(ctx, retry)
	}
	trace := newModelFacingTraceHolder()
	lead, err := newEinoAgenticChatModelAgentAdapter(ctx, einoAgenticChatModelAgentConfig{
		Name: "lead", Description: "shared task budget test", Instruction: "root instruction",
		Model: modelbudget.WrapAgentic(fakeBusiness, appCfg.OpenAI.Model, 1024),
		ToolsConfig: adk.ToolsConfig{ToolsNodeConfig: compose.ToolsNodeConfig{
			Tools: []tool.BaseTool{localTool},
		}},
		MaxIterations: 10, ModelRetryConfig: retryCfg,
		Handlers: appendEinoAgenticChatModelTailMiddlewares(nil, einoChatModelTailConfig{agenticSummarization: summaryMW, trace: trace}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var progressMu sync.Mutex
	var budget modelbudget.Snapshot
	var usage map[string]interface{}
	var events []string
	result, err := runEinoADKAgentLoop(ctx, &einoADKRunLoopArgs{
		OrchMode: "eino_single", OrchestratorName: "lead", DA: lead,
		MaxTaskTokens: limit, MaxTotalTokens: appCfg.OpenAI.MaxTotalTokens,
		ModelName: appCfg.OpenAI.Model, MiddlewareConfig: mwCfg, ModelFacingTrace: trace,
		Progress: func(kind, _ string, data interface{}) {
			progressMu.Lock()
			defer progressMu.Unlock()
			events = append(events, kind)
			if kind == "token_budget_summary" {
				budget, _ = data.(modelbudget.Snapshot)
			}
			if kind == "eino_usage_summary" {
				usage, _ = data.(map[string]interface{})
			}
		},
	}, summaryOverflowTestHistory())
	if !errors.Is(err, modelbudget.ErrExceeded) {
		t.Fatalf("run error = %v, want task budget exhaustion", err)
	}
	if got := len(fakeSummary.snapshotInputs()); got != 1 {
		t.Fatalf("summary model calls = %d, want 1", got)
	}
	if got := len(fakeBusiness.snapshotInputs()); got != 1 {
		t.Fatalf("business model calls = %d, want only the first call", got)
	}
	if localToolCalls.Load() != 1 || budgetRejections.Load() != 1 {
		t.Fatalf("tool calls = %d, budget decisions = %d; want one of each, without model retry", localToolCalls.Load(), budgetRejections.Load())
	}
	if result == nil || result.Response != "partial result retained" || !strings.Contains(result.LastAgentTraceInput, "local evidence retained") {
		t.Fatalf("partial output and tool evidence were not retained: %+v", result)
	}
	progressMu.Lock()
	defer progressMu.Unlock()
	if budget.Limit != limit || budget.Used != 55000 || budget.Calls != 2 || budget.Reserved != 0 || !budget.Stopped {
		t.Fatalf("summary and main model did not share the runloop budget across the typed adapter: %+v", budget)
	}
	if usage["modelCalls"] != 2 || usage["totalTokens"] != 55000 {
		t.Fatalf("partial run usage lost or duplicated a call: %#v", usage)
	}
	for _, kind := range events {
		if strings.Contains(kind, "retry") || strings.Contains(kind, "failover") {
			t.Fatalf("budget exhaustion triggered recovery event %q", kind)
		}
	}
}

func TestNewEinoAgenticSummarizationMiddlewareCompactsWithNativeTypedMiddleware(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	emit := false
	summaryModel := &capturingAgenticChatModel{
		output: &schema.AgenticMessage{
			Role: schema.AgenticRoleTypeAssistant,
			ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.AssistantGenText{Text: `<analysis>检查历史</analysis>
<summary>
## 1. 授权范围与约束
- 仅测试 example.com

## 7. 当前进度、策略决策与下一步
- 继续验证 SQL 注入路径
</summary>`})},
		},
	}
	appCfg := &config.Config{}
	appCfg.OpenAI.Model = "gpt-4o"
	appCfg.OpenAI.MaxTotalTokens = 5000
	mwCfg := &config.MultiAgentEinoMiddlewareConfig{
		SummarizationEmitInternalEvents:  &emit,
		SummarizationOutputReserveTokens: 1024,
	}

	mw, err := newEinoAgenticSummarizationMiddleware(ctx, summaryModel, appCfg, mwCfg, "conv-agentic", nil, "", nil)
	if err != nil {
		t.Fatalf("newEinoAgenticSummarizationMiddleware: %v", err)
	}
	state := &adk.TypedChatModelAgentState[*schema.AgenticMessage]{
		Messages: []*schema.AgenticMessage{
			schema.SystemAgenticMessage("system root"),
			schema.UserAgenticMessage("授权范围 example.com\n" + strings.Repeat("历史扫描输出 ", 12000)),
			agenticAssistantTextMessage("已记录范围"),
			schema.UserAgenticMessage("继续验证 SQL 注入路径"),
		},
	}

	_, after, err := mw.BeforeModelRewriteState(ctx, state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState: %v", err)
	}
	inputs := summaryModel.snapshotInputs()
	if len(inputs) != 1 || len(inputs[0]) == 0 {
		t.Fatalf("summary model inputs = %#v, want one typed AgenticMessage call", inputs)
	}
	if after == nil {
		t.Fatal("after state is nil")
	}
	classicAfter := AgenticMessagesToEino(after.Messages)
	joined := joinClassicMessageContent(classicAfter)
	if strings.Contains(joined, "<analysis>") {
		t.Fatalf("analysis block leaked into compacted context: %s", joined)
	}
	for _, want := range []string{"继续验证 SQL 注入路径", "原始用户输入与约束账本", "完整的对话记录位于"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("compacted context missing %q:\n%s", want, joined)
		}
	}
}

func TestEinoAgenticChatModelAgentCompactsContextBeforeBusinessModel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	emit := false
	summaryModel := &capturingAgenticChatModel{
		output: agenticAssistantTextMessage(`<analysis>internal scratchpad</analysis>
<summary>
## 1. 授权范围与约束
- 仅测试 example.com

## 7. 当前进度、策略决策与下一步
- 继续验证 SQL 注入路径
</summary>`),
	}
	businessModel := &capturingAgenticChatModel{
		output: agenticAssistantTextMessage("business answer after compaction"),
	}
	appCfg := &config.Config{}
	appCfg.OpenAI.Model = "gpt-4o"
	appCfg.OpenAI.MaxTotalTokens = 5000
	mwCfg := &config.MultiAgentEinoMiddlewareConfig{
		SummarizationEmitInternalEvents:  &emit,
		SummarizationOutputReserveTokens: 1024,
	}
	sumMw, err := newEinoAgenticSummarizationMiddleware(ctx, summaryModel, appCfg, mwCfg, "conv-agentic-e2e", nil, "", nil)
	if err != nil {
		t.Fatalf("newEinoAgenticSummarizationMiddleware: %v", err)
	}
	trace := newModelFacingTraceHolder()
	agent, err := newEinoAgenticChatModelAgentAdapter(ctx, einoAgenticChatModelAgentConfig{
		Name:        "agentic",
		Description: "agentic compaction e2e test",
		Instruction: "system root",
		Model:       businessModel,
		Handlers: appendEinoAgenticChatModelTailMiddlewares(nil, einoChatModelTailConfig{
			phase:                "agentic",
			agenticSummarization: sumMw,
			trace:                trace,
		}),
	})
	if err != nil {
		t.Fatalf("newEinoAgenticChatModelAgentAdapter: %v", err)
	}

	rawHistory := "授权范围 example.com\n" + strings.Repeat("原始扫描输出SHOULD_NOT_REACH_BUSINESS_MODEL ", 12000)
	iter := agent.Run(ctx, &adk.AgentInput{
		Messages: []*schema.Message{
			schema.UserMessage(rawHistory),
			schema.AssistantMessage("已记录范围", nil),
			schema.UserMessage("继续验证 SQL 注入路径"),
		},
	})
	var last *adk.AgentEvent
	for {
		ev, ok := iter.Next()
		if !ok {
			break
		}
		if ev.Err != nil {
			t.Fatalf("agent event error: %v", ev.Err)
		}
		last = ev
	}
	if last == nil || last.Output == nil || last.Output.MessageOutput == nil {
		t.Fatalf("last event = %#v, want message output", last)
	}
	if got := last.Output.MessageOutput.Message.Content; got != "business answer after compaction" {
		t.Fatalf("business output = %q", got)
	}

	if inputs := summaryModel.snapshotInputs(); len(inputs) != 1 {
		t.Fatalf("summary model calls = %d, want 1", len(inputs))
	}
	businessInputs := businessModel.snapshotInputs()
	if len(businessInputs) != 1 {
		t.Fatalf("business model calls = %d, want 1", len(businessInputs))
	}
	finalClassicInput := AgenticMessagesToEino(businessInputs[0])
	joined := joinClassicMessageContent(finalClassicInput)
	for _, want := range []string{"继续验证 SQL 注入路径", "原始用户输入与约束账本", "完整的对话记录位于"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("business model input missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "<analysis>") {
		t.Fatalf("analysis leaked to business model input:\n%s", joined)
	}
	if strings.Count(joined, "原始扫描输出SHOULD_NOT_REACH_BUSINESS_MODEL") > 3 {
		t.Fatalf("raw oversized history leaked to business model input, count=%d", strings.Count(joined, "原始扫描输出SHOULD_NOT_REACH_BUSINESS_MODEL"))
	}
	traceJoined := joinClassicMessageContent(trace.Snapshot())
	if !strings.Contains(traceJoined, "继续验证 SQL 注入路径") || strings.Count(traceJoined, "原始扫描输出SHOULD_NOT_REACH_BUSINESS_MODEL") > 3 {
		t.Fatalf("model-facing trace not compacted:\n%s", traceJoined)
	}
}

func TestEinoAgenticSummarizationMiddlewareRetriesWhenSummaryModelReturnsEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	emit := false
	summaryModel := &capturingAgenticChatModel{
		outputs: []*schema.AgenticMessage{
			agenticAssistantTextMessage(""),
			agenticAssistantTextMessage("<summary>有效摘要：继续验证 SQL 注入路径</summary>"),
		},
	}
	appCfg := &config.Config{}
	appCfg.OpenAI.Model = "gpt-4o"
	appCfg.OpenAI.MaxTotalTokens = 5000
	mwCfg := &config.MultiAgentEinoMiddlewareConfig{
		SummarizationEmitInternalEvents:  &emit,
		SummarizationOutputReserveTokens: 1024,
	}

	mw, err := newEinoAgenticSummarizationMiddleware(ctx, summaryModel, appCfg, mwCfg, "conv-agentic-empty-summary", nil, "", nil)
	if err != nil {
		t.Fatalf("newEinoAgenticSummarizationMiddleware: %v", err)
	}
	state := &adk.TypedChatModelAgentState[*schema.AgenticMessage]{
		Messages: []*schema.AgenticMessage{
			schema.SystemAgenticMessage("system root"),
			schema.UserAgenticMessage("授权范围 example.com\n" + strings.Repeat("历史扫描输出 ", 12000)),
			agenticAssistantTextMessage("已记录范围"),
			schema.UserAgenticMessage("继续验证 SQL 注入路径"),
		},
	}

	_, after, err := mw.BeforeModelRewriteState(ctx, state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState should retry instead of failing on empty summary: %v", err)
	}
	if after == nil {
		t.Fatal("after state is nil")
	}
	if inputs := summaryModel.snapshotInputs(); len(inputs) < 2 {
		t.Fatalf("summary model calls=%d, want retry after empty output", len(inputs))
	}
	joined := joinClassicMessageContent(AgenticMessagesToEino(after.Messages))
	for _, want := range []string{"有效摘要", "继续验证 SQL 注入路径", "原始用户输入与约束账本"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("retried compacted context missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "本地压缩摘要") {
		t.Fatalf("local fallback should not be used:\n%s", joined)
	}
}

func TestAppendEinoAgenticChatModelTailMiddlewaresIncludesTypedSummarization(t *testing.T) {
	t.Parallel()
	mw := newAgenticSystemMessageNormalizerMiddleware(nil, "summary")
	handlers := appendEinoAgenticChatModelTailMiddlewares(nil, einoChatModelTailConfig{
		agenticSummarization: mw,
		skipTrace:            true,
	})
	found := false
	for _, h := range handlers {
		if h == mw {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("agentic summarization middleware was not appended")
	}
}

func agenticAssistantTextMessage(text string) *schema.AgenticMessage {
	return &schema.AgenticMessage{
		Role:          schema.AgenticRoleTypeAssistant,
		ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.AssistantGenText{Text: text})},
	}
}

func joinClassicMessageContent(msgs []*schema.Message) string {
	var b strings.Builder
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		b.WriteString(msg.Content)
		b.WriteByte('\n')
	}
	return b.String()
}
