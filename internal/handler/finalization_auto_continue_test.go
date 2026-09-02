package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	agentpkg "cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/modelbudget"
	"cyberstrike-ai/internal/multiagent"
	"cyberstrike-ai/internal/testutil/testpostgres"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

type continuationBudgetTestModel struct{ calls int }

func (m *continuationBudgetTestModel) Generate(context.Context, []*schema.AgenticMessage, ...model.Option) (*schema.AgenticMessage, error) {
	m.calls++
	return &schema.AgenticMessage{
		Role:          schema.AgenticRoleTypeAssistant,
		ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.AssistantGenText{Text: "partial result"})},
		ResponseMeta:  &schema.AgenticResponseMeta{TokenUsage: &schema.TokenUsage{PromptTokens: 699, CompletionTokens: 1, TotalTokens: 700}},
	}, nil
}

func (m *continuationBudgetTestModel) Stream(ctx context.Context, input []*schema.AgenticMessage, opts ...model.Option) (*schema.StreamReader[*schema.AgenticMessage], error) {
	msg, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.AgenticMessage{msg}), nil
}

func TestEinoTaskBudgetSurvivesHandlerContinuation(t *testing.T) {
	for _, mode := range []string{"json_auto_continue", "sse_auto_continue", "sse_interrupt_fallback"} {
		t.Run(mode, func(t *testing.T) {
			requestCtx := context.Background()
			cfg := config.AgentConfig{MaxTaskTokens: 1000}
			baseCtx, cancelWithCause := newEinoTaskBaseContext(requestCtx, cfg)
			taskCtx, timeoutCancel := context.WithTimeout(baseCtx, time.Minute)
			defer cancelWithCause(nil)
			defer timeoutCancel()
			tracker := modelbudget.FromContext(baseCtx)
			h := &AgentHandler{tasks: &AgentTaskManager{tasks: make(map[string]*AgentTask)}}
			if _, err := h.tasks.StartTask(mode, "test", cancelWithCause); err != nil {
				t.Fatal(err)
			}
			fake := &continuationBudgetTestModel{}
			wrapped := modelbudget.WrapAgentic(fake, "gpt-4o", 8)
			input := []*schema.AgenticMessage{schema.UserAgenticMessage("continue")}
			// Each segment's Runner still requests its configured limit. It must
			// reuse the tracker created at the HTTP task boundary.
			generateSegment := func() error {
				_, err := wrapped.Generate(modelbudget.WithContext(taskCtx, cfg.MaxTaskTokensEffective()), input)
				return err
			}
			if err := generateSegment(); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "sse_auto_continue":
				nextBaseCtx, nextCancel, nextTaskCtx, nextTimeoutCancel := h.rebindEinoRunningTask(taskCtx, mode, timeoutCancel)
				defer nextCancel(nil)
				defer nextTimeoutCancel()
				baseCtx, taskCtx = nextBaseCtx, nextTaskCtx
			case "sse_interrupt_fallback":
				cancelWithCause(multiagent.ErrInterruptContinue)
				timeoutCancel()
				nextBaseCtx, nextCancel := context.WithCancelCause(detachedAgentContext(baseCtx))
				nextTaskCtx, nextTimeoutCancel := context.WithTimeout(nextBaseCtx, time.Minute)
				defer nextCancel(nil)
				defer nextTimeoutCancel()
				baseCtx, taskCtx = nextBaseCtx, nextTaskCtx
			}
			if taskCtx.Err() != nil || modelbudget.FromContext(taskCtx) != tracker || modelbudget.FromContext(baseCtx) != tracker {
				t.Fatal("continuation lost the budget tracker or inherited cancellation")
			}
			if err := generateSegment(); err != nil {
				t.Fatal(err)
			}
			if err := generateSegment(); !errors.Is(err, modelbudget.ErrExceeded) {
				t.Fatalf("next segment error = %v, want shared task budget exhaustion", err)
			}
			if got := tracker.Snapshot(); fake.calls != 2 || got.Calls != 2 || got.Used != 1400 || !got.Stopped {
				t.Fatalf("continuation reset or duplicated usage: model calls=%d budget=%+v", fake.calls, got)
			}
			newTaskCtx, newTaskCancel := newEinoTaskBaseContext(requestCtx, cfg)
			defer newTaskCancel(nil)
			if next := modelbudget.FromContext(newTaskCtx); next == tracker || next.Snapshot().Used != 0 {
				t.Fatal("a genuinely new task inherited the previous task's exhausted budget")
			}
			if _, err := wrapped.Generate(newTaskCtx, input); err != nil {
				t.Fatalf("new task should have its own budget: %v", err)
			}
		})
	}
}

func TestShouldAutoContinueAfterFinalization(t *testing.T) {
	missingEvidence := agentfinalizer.Decision{
		Status:           agentfinalizer.StatusBlocked,
		CompletionReason: agentfinalizer.ReasonMissingEvidence,
	}
	if !shouldAutoContinueAfterFinalization(missingEvidence, 0) {
		t.Fatal("missing execution evidence should trigger auto-continue")
	}
	if shouldAutoContinueAfterFinalization(missingEvidence, finalizationAutoContinueMaxAttempts) {
		t.Fatal("auto-continue should stop at max attempts")
	}

	finalized := agentfinalizer.Decision{
		Status:           agentfinalizer.StatusCompleted,
		CompletionReason: agentfinalizer.ReasonVerified,
		Finalizable:      true,
		Finalized:        true,
	}
	if shouldAutoContinueAfterFinalization(finalized, 0) {
		t.Fatal("finalized decision should not auto-continue")
	}

	awaitingHITL := agentfinalizer.Decision{
		Status:           agentfinalizer.StatusAwaitingHITL,
		CompletionReason: agentfinalizer.ReasonAwaitingHITL,
	}
	if shouldAutoContinueAfterFinalization(awaitingHITL, 0) {
		t.Fatal("awaiting HITL should not auto-continue without approval")
	}
}

func TestRequestRequiresExecutionEvidenceUsesExplicitPolicyOnly(t *testing.T) {
	if requestRequiresExecutionEvidence(nil) {
		t.Fatal("nil request should not require execution evidence")
	}
	if requestRequiresExecutionEvidence(&ChatRequest{}) {
		t.Fatal("missing finalization policy should not require execution evidence")
	}
	require := true
	if !requestRequiresExecutionEvidence(&ChatRequest{
		Finalization: ChatFinalizationRequest{RequireExecutionEvidence: &require},
	}) {
		t.Fatal("explicit true policy should require execution evidence")
	}
	require = false
	if requestRequiresExecutionEvidence(&ChatRequest{
		Finalization: ChatFinalizationRequest{RequireExecutionEvidence: &require},
	}) {
		t.Fatal("explicit false policy should not require execution evidence")
	}
}

func TestCleanupPendingToolExecutionsAfterIterationAllowsFinalization(t *testing.T) {
	logger := zap.NewNop()
	db, err := database.NewDB(testpostgres.DSN(t), logger)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	server := mcp.NewServerWithStorage(logger, db)
	server.ConfigureToolWaitTimeoutSeconds(1)
	server.RegisterTool(mcp.Tool{Name: "block", InputSchema: map[string]interface{}{"type": "object"}}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ag := agentpkg.NewAgent(&config.OpenAIConfig{}, &config.AgentConfig{}, server, nil, logger, 10)
	h := &AgentHandler{agent: ag, db: db, logger: logger}

	callCtx := mcp.WithMCPConversationID(context.Background(), "conv-cleanup")
	result, execID, err := server.CallTool(callCtx, "block", nil)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result == nil || !result.IsError || execID == "" {
		t.Fatalf("expected background wait result, result=%#v execID=%q", result, execID)
	}

	decision := agentfinalizer.Decide(db, agentfinalizer.Input{
		Response:        "基于已完成信息的阶段性总结。",
		MCPExecutionIDs: []string{execID},
	})
	if decision.CompletionReason != agentfinalizer.ReasonPendingTools {
		t.Fatalf("decision reason = %s, want pending tools: %+v", decision.CompletionReason, decision)
	}

	var eventType string
	cancelled := h.cleanupPendingToolExecutionsAfterIteration(context.Background(), "conv-cleanup", decision, func(et, _ string, _ interface{}) {
		eventType = et
	})
	if len(cancelled) != 1 || cancelled[0] != execID {
		t.Fatalf("cancelled = %#v, want [%s]", cancelled, execID)
	}
	if eventType != "finalization_pending_tools_cancelled" {
		t.Fatalf("event type = %q", eventType)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		exec, err := db.GetToolExecution(execID)
		if err == nil && exec != nil && exec.Status == mcp.ToolExecutionStatusCancelled {
			after := agentfinalizer.Decide(db, agentfinalizer.Input{
				Response:        "基于已完成信息的阶段性总结。",
				MCPExecutionIDs: []string{execID},
			})
			if !after.Finalizable || !after.Finalized {
				t.Fatalf("decision should finalize after cleanup: %+v", after)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("execution did not become cancelled")
}
