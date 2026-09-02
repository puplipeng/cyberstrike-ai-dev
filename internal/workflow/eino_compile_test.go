package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/modelbudget"
	"cyberstrike-ai/internal/testutil/testpostgres"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

type workflowBudgetTestModel struct{ calls int }

func (m *workflowBudgetTestModel) Generate(context.Context, []*schema.AgenticMessage, ...model.Option) (*schema.AgenticMessage, error) {
	m.calls++
	return &schema.AgenticMessage{
		Role:          schema.AgenticRoleTypeAssistant,
		ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.AssistantGenText{Text: "retained evidence"})},
		ResponseMeta:  &schema.AgenticResponseMeta{TokenUsage: &schema.TokenUsage{PromptTokens: 699, CompletionTokens: 1, TotalTokens: 700}},
	}, nil
}

func (m *workflowBudgetTestModel) Stream(ctx context.Context, input []*schema.AgenticMessage, opts ...model.Option) (*schema.StreamReader[*schema.AgenticMessage], error) {
	msg, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.AgenticMessage{msg}), nil
}

func TestWorkflowTaskBudgetSharedAcrossNodesAndCheckpointResume(t *testing.T) {
	args := RunArgs{AppCfg: &config.Config{Agent: config.AgentConfig{MaxTaskTokens: 1000}}}
	ctx := workflowTaskBudgetContext(context.Background(), args, "")
	tracker := modelbudget.FromContext(ctx)
	fake := &workflowBudgetTestModel{}
	wrapped := modelbudget.WrapAgentic(fake, "gpt-4o", 8)
	generate := func(runCtx context.Context) (WorkflowNodeOutput, error) {
		// Agent nodes create their own Runner but must inherit the workflow's tracker.
		runCtx = modelbudget.WithContext(runCtx, args.AppCfg.Agent.MaxTaskTokensEffective())
		_, err := wrapped.Generate(runCtx, []*schema.AgenticMessage{schema.UserAgenticMessage("continue")})
		return WorkflowNodeOutput{"output": "retained evidence"}, err
	}
	wf := compose.NewWorkflow[WorkflowInput, WorkflowOutput]()
	first := wf.AddLambdaNode("first", compose.InvokableLambda(func(runCtx context.Context, _ WorkflowInput) (WorkflowNodeOutput, error) {
		return generate(runCtx)
	}))
	var sawPrevious string
	second := wf.AddLambdaNode("second", compose.InvokableLambda(func(runCtx context.Context, input WorkflowNodeOutput) (WorkflowNodeOutput, error) {
		sawPrevious, _ = input["output"].(string)
		return generate(runCtx)
	}))
	third := wf.AddLambdaNode("third", compose.InvokableLambda(func(runCtx context.Context, _ WorkflowNodeOutput) (WorkflowNodeOutput, error) {
		return generate(runCtx)
	}))
	first.AddInput(compose.START)
	second.AddInput("first")
	third.AddInput("second")
	wf.End().AddInput("third", compose.ToField("result"))
	checkpointStore, err := newFileCheckPointStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnable, err := wf.Compile(ctx, compose.WithCheckPointStore(checkpointStore), compose.WithInterruptAfterNodes([]string{"first"}))
	if err != nil {
		t.Fatal(err)
	}
	g := &graphDef{Nodes: []graphNode{{ID: "first", Type: "agent"}, {ID: "second", Type: "agent"}, {ID: "third", Type: "agent"}}}
	const workflowID = "budget-checkpoint-fixture"
	key := cacheKey(workflowID, 1)
	defaultEngine.mu.Lock()
	defaultEngine.cache[key] = &compiledArtifact{runnable: runnable, idx: indexGraph(g)}
	defaultEngine.mu.Unlock()
	t.Cleanup(func() {
		defaultEngine.mu.Lock()
		delete(defaultEngine.cache, key)
		defaultEngine.mu.Unlock()
	})
	state := newWorkflowLocalState(map[string]interface{}{"message": "test"}, "budget-run")
	_, err = invokeEinoGraph(ctx, args, "budget-run", workflowID, 1, g, state, false)
	if _, interrupted := compose.ExtractInterruptInfo(err); !interrupted {
		t.Fatalf("first segment error = %v, want checkpoint interrupt", err)
	}
	if got := tracker.Snapshot(); got.Used != 700 || got.Calls != 1 {
		t.Fatalf("first node usage = %+v", got)
	}
	previousJSON, err := json.Marshal(map[string]any{"status": "awaiting_hitl", "tokenBudget": tracker.Snapshot()})
	if err != nil {
		t.Fatal(err)
	}
	if same := workflowTaskBudgetContext(ctx, args, string(previousJSON)); modelbudget.FromContext(same) != tracker {
		t.Fatal("in-process resume restored usage a second time")
	}
	// A later HTTP approval has a fresh context; restore settled usage from the
	// workflow result while Eino restores completed nodes from its checkpoint.
	pausedRun := &database.WorkflowRun{Status: "awaiting_hitl", PendingHITLJSON: string(previousJSON)}
	resumeCtx := workflowTaskBudgetContext(context.Background(), args, pausedRun.PendingHITLJSON)
	_, err = invokeEinoGraph(resumeCtx, args, "budget-run", workflowID, 1, g, state, true)
	if !modelbudget.IsExceeded(err) {
		t.Fatalf("resumed workflow error = %v, want task budget exhaustion", err)
	}
	if got := modelbudget.FromContext(resumeCtx).Snapshot(); fake.calls != 2 || got.Calls != 2 || got.Used != 1400 || got.Reserved != 0 {
		t.Fatalf("node or checkpoint resume reset usage: model calls=%d budget=%+v", fake.calls, got)
	}
	if sawPrevious != "retained evidence" {
		t.Fatalf("checkpoint lost the completed node output: %q", sawPrevious)
	}
	newTask := workflowTaskBudgetContext(context.Background(), args, "")
	if got := modelbudget.FromContext(newTask).Snapshot(); got.Used != 0 || got.Calls != 0 {
		t.Fatalf("new workflow inherited exhausted usage: %+v", got)
	}
	legacyResume := workflowTaskBudgetContext(context.Background(), args, `{"status":"awaiting_hitl"}`)
	if got := modelbudget.FromContext(legacyResume).Snapshot(); got.Limit != 1000 || got.Used != 0 {
		t.Fatalf("legacy checkpoint without usage is incompatible: %+v", got)
	}
}

func testWorkflowDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func linearStartOutputGraph() string {
	return `{
  "nodes": [
    {"id": "start-1", "type": "start", "label": "开始", "position": {"x": 0, "y": 0}, "config": {}},
    {"id": "out-1", "type": "output", "label": "输出", "position": {"x": 0, "y": 120}, "config": {"output_key": "result", "source_binding": {"from": "inputs", "field": "message"}}}
  ],
  "edges": [
    {"id": "e1", "source": "start-1", "target": "out-1"}
  ],
  "config": {"schema_version": 1}
}`
}

func conditionBranchGraph() string {
	return `{
  "nodes": [
    {"id": "start-1", "type": "start", "label": "开始", "position": {"x": 0, "y": 0}, "config": {}},
    {"id": "cond-1", "type": "condition", "label": "判断", "position": {"x": 0, "y": 80}, "config": {"expression": "{{inputs.message}} == yes"}},
    {"id": "out-yes", "type": "output", "label": "是", "position": {"x": -80, "y": 160}, "config": {"output_key": "branch", "static_value": "yes"}},
    {"id": "out-no", "type": "output", "label": "否", "position": {"x": 80, "y": 160}, "config": {"output_key": "branch", "static_value": "no"}}
  ],
  "edges": [
    {"id": "e1", "source": "start-1", "target": "cond-1"},
    {"id": "e2", "source": "cond-1", "target": "out-yes", "label": "是"},
    {"id": "e3", "source": "cond-1", "target": "out-no", "label": "否"}
  ],
  "config": {"schema_version": 1}
}`
}

func TestValidateGraphJSON_linear(t *testing.T) {
	if err := ValidateGraphJSON(context.Background(), linearStartOutputGraph()); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateGraphJSON_rejectsInvalidGraphs(t *testing.T) {
	tests := []struct {
		name    string
		graph   string
		wantErr string
	}{
		{
			name: "start with incoming edge",
			graph: `{
  "nodes": [
    {"id": "start-1", "type": "start", "label": "开始", "position": {"x": 0, "y": 0}, "config": {}},
    {"id": "agent-1", "type": "agent", "label": "Agent", "position": {"x": 0, "y": 80}, "config": {"instruction": "noop"}},
    {"id": "out-1", "type": "output", "label": "输出", "position": {"x": 0, "y": 160}, "config": {"output_key": "result"}}
  ],
  "edges": [
    {"id": "e1", "source": "start-1", "target": "agent-1"},
    {"id": "e2", "source": "agent-1", "target": "start-1"},
    {"id": "e3", "source": "agent-1", "target": "out-1"}
  ]
}`,
			wantErr: "开始节点",
		},
		{
			name: "output with outgoing edge",
			graph: `{
  "nodes": [
    {"id": "start-1", "type": "start", "label": "开始", "position": {"x": 0, "y": 0}, "config": {}},
    {"id": "out-1", "type": "output", "label": "输出", "position": {"x": 0, "y": 80}, "config": {"output_key": "result"}},
    {"id": "end-1", "type": "end", "label": "结束", "position": {"x": 0, "y": 160}, "config": {}}
  ],
  "edges": [
    {"id": "e1", "source": "start-1", "target": "out-1"},
    {"id": "e2", "source": "out-1", "target": "end-1"}
  ]
}`,
			wantErr: "不能有出边",
		},
		{
			name: "tool without name",
			graph: `{
  "nodes": [
    {"id": "start-1", "type": "start", "label": "开始", "position": {"x": 0, "y": 0}, "config": {}},
    {"id": "tool-1", "type": "tool", "label": "工具", "position": {"x": 0, "y": 80}, "config": {}},
    {"id": "out-1", "type": "output", "label": "输出", "position": {"x": 0, "y": 160}, "config": {"output_key": "result"}}
  ],
  "edges": [
    {"id": "e1", "source": "start-1", "target": "tool-1"},
    {"id": "e2", "source": "tool-1", "target": "out-1"}
  ]
}`,
			wantErr: "必须选择 MCP 工具",
		},
		{
			name: "condition with too many branches",
			graph: `{
  "nodes": [
    {"id": "start-1", "type": "start", "label": "开始", "position": {"x": 0, "y": 0}, "config": {}},
    {"id": "cond-1", "type": "condition", "label": "判断", "position": {"x": 0, "y": 80}, "config": {"expression": "{{inputs.message}}"}},
    {"id": "out-1", "type": "output", "label": "输出1", "position": {"x": -80, "y": 160}, "config": {"output_key": "a"}},
    {"id": "out-2", "type": "output", "label": "输出2", "position": {"x": 0, "y": 160}, "config": {"output_key": "b"}},
    {"id": "out-3", "type": "output", "label": "输出3", "position": {"x": 80, "y": 160}, "config": {"output_key": "c"}}
  ],
  "edges": [
    {"id": "e1", "source": "start-1", "target": "cond-1"},
    {"id": "e2", "source": "cond-1", "target": "out-1"},
    {"id": "e3", "source": "cond-1", "target": "out-2"},
    {"id": "e4", "source": "cond-1", "target": "out-3"}
  ]
}`,
			wantErr: "1 到 2 条出边",
		},
		{
			name: "orphan node",
			graph: `{
  "nodes": [
    {"id": "start-1", "type": "start", "label": "开始", "position": {"x": 0, "y": 0}, "config": {}},
    {"id": "out-1", "type": "output", "label": "输出", "position": {"x": 0, "y": 80}, "config": {"output_key": "result"}},
    {"id": "agent-1", "type": "agent", "label": "孤岛", "position": {"x": 200, "y": 80}, "config": {"instruction": "noop"}}
  ],
  "edges": [
    {"id": "e1", "source": "start-1", "target": "out-1"}
  ]
}`,
			wantErr: "不可达",
		},
		{
			name: "cycle",
			graph: `{
  "nodes": [
    {"id": "start-1", "type": "start", "label": "开始", "position": {"x": 0, "y": 0}, "config": {}},
    {"id": "agent-1", "type": "agent", "label": "Agent1", "position": {"x": 0, "y": 80}, "config": {"instruction": "noop", "output_key": "a1"}},
    {"id": "agent-2", "type": "agent", "label": "Agent2", "position": {"x": 0, "y": 160}, "config": {"instruction": "noop", "output_key": "a2"}},
    {"id": "out-1", "type": "output", "label": "输出", "position": {"x": 0, "y": 240}, "config": {"output_key": "result"}}
  ],
  "edges": [
    {"id": "e1", "source": "start-1", "target": "agent-1"},
    {"id": "e2", "source": "agent-1", "target": "agent-2"},
    {"id": "e3", "source": "agent-2", "target": "agent-1"},
    {"id": "e4", "source": "agent-2", "target": "out-1"}
  ]
}`,
			wantErr: "环路",
		},
		{
			name: "output without key",
			graph: `{
  "nodes": [
    {"id": "start-1", "type": "start", "label": "开始", "position": {"x": 0, "y": 0}, "config": {}},
    {"id": "out-1", "type": "output", "label": "输出", "position": {"x": 0, "y": 80}, "config": {}}
  ],
  "edges": [
    {"id": "e1", "source": "start-1", "target": "out-1"}
  ]
}`,
			wantErr: "输出变量名",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGraphJSON(context.Background(), tt.graph)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestCompileEngine_linear(t *testing.T) {
	ctx := context.Background()
	SetCheckpointDir(t.TempDir())
	g, err := parseGraph(linearStartOutputGraph())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultEngine.compile(ctx, g); err != nil {
		t.Fatalf("compile: %v", err)
	}
}

func createTestWorkflowRun(t *testing.T, db *database.DB, runID string) {
	t.Helper()
	if err := db.CreateWorkflowRun(&database.WorkflowRun{
		ID:         runID,
		WorkflowID: "test-wf",
		Status:     "running",
	}); err != nil {
		t.Fatalf("CreateWorkflowRun: %v", err)
	}
}

func TestExecuteEinoGraph_linearStartOutput(t *testing.T) {
	ctx := context.Background()
	SetCheckpointDir(t.TempDir())
	db := testWorkflowDB(t)
	createTestWorkflowRun(t, db, "run-linear")
	g, err := parseGraph(linearStartOutputGraph())
	if err != nil {
		t.Fatal(err)
	}
	state := newWorkflowLocalState(map[string]interface{}{"message": "ping"}, "run-linear")
	args := RunArgs{DB: db}
	if err := executeEinoGraph(ctx, args, "run-linear", "test-wf", 1, g, state); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := state.Outputs["result"]; got != "ping" {
		t.Fatalf("outputs[result] = %v, want ping", got)
	}
	if len(state.Executed) != 2 {
		t.Fatalf("executed nodes = %d, want 2", len(state.Executed))
	}
}

func TestExecuteEinoGraph_checkpointRestoresStartOutput(t *testing.T) {
	ctx := context.Background()
	checkpointStore, err := newFileCheckPointStore(t.TempDir())
	if err != nil {
		t.Fatalf("new checkpoint store: %v", err)
	}
	state := newWorkflowLocalState(map[string]interface{}{"message": "ping"}, "run-checkpoint")
	node := graphNode{ID: "start-1", Type: "start"}
	wf := compose.NewWorkflow[WorkflowInput, WorkflowOutput](
		compose.WithGenLocalState(func(context.Context) *WorkflowLocalState { return state }),
	)
	start := wf.AddLambdaNode("start-1", compose.InvokableLambda(func(_ context.Context, input WorkflowInput) (WorkflowNodeOutput, error) {
		result := startOutputMap(node, input.Message, input.ConversationID, input.ProjectID)
		state.NodeOutputs[node.ID] = result
		state.NodeOutputs["condition-1"] = conditionOutputMap(graphNode{ID: "condition-1", Type: "condition"}, "{{inputs.message}} == ping", true)
		state.NodeOutputs["tool-1"] = toolOutputMap(graphNode{ID: "tool-1", Type: "tool"}, "tool result", "lookup", map[string]any{"id": "1"}, "exec-1", false)
		state.NodeOutputs["agent-1"] = agentOutputMap(graphNode{ID: "agent-1", Type: "agent"}, "agent result", "chat", []string{"exec-1"})
		state.NodeOutputs["hitl-1"] = hitlOutputMap(graphNode{ID: "hitl-1", Type: "hitl"}, "completed", "approved", "continue?", "reviewer", true)
		state.NodeOutputs["output-1"] = outputNodeOutputMap(graphNode{ID: "output-1", Type: "output"}, "result", "ping")
		state.NodeOutputs["end-1"] = endOutputMap(graphNode{ID: "end-1", Type: "end"}, "done")
		state.LastOutput = result
		state.Outputs["seed"] = "preserved"
		return result, nil
	}))
	outputNode := wf.AddLambdaNode("out-1", compose.InvokableLambda(func(_ context.Context, input WorkflowNodeOutput) (WorkflowNodeOutput, error) {
		return input, nil
	}))
	start.AddInput(compose.START)
	outputNode.AddInput("start-1")
	wf.End().AddInput("out-1", compose.ToField("out-1"))
	runnable, err := wf.Compile(ctx,
		compose.WithCheckPointStore(checkpointStore),
		compose.WithInterruptAfterNodes([]string{"start-1"}),
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, err = runnable.Invoke(ctx, workflowInputFromMap(state.Inputs), compose.WithCheckPointID("run-checkpoint"))
	info, ok := compose.ExtractInterruptInfo(err)
	if !ok {
		t.Fatalf("invoke error = %v, want checkpoint interrupt", err)
	}
	restored, ok := info.State.(*WorkflowLocalState)
	if !ok {
		t.Fatalf("checkpoint state = %T, want *WorkflowLocalState", info.State)
	}
	for nodeID, wantType := range map[string]string{
		"start-1":     "StartOutput",
		"condition-1": "ConditionOutput",
		"tool-1":      "ToolOutput",
		"agent-1":     "AgentOutput",
		"hitl-1":      "HITLOutput",
		"output-1":    "OutputNodeOutput",
		"end-1":       "NodeOutputEnvelope",
	} {
		if got := fmt.Sprintf("%T", restored.NodeOutputs[nodeID]["typed"]); got != "workflow."+wantType {
			t.Fatalf("restored %s typed output = %s, want workflow.%s", nodeID, got, wantType)
		}
	}
	if got := valueFromPath("previous.message", restored); got != "ping" {
		t.Fatalf("restored previous.message = %v, want ping", got)
	}
	if got := valueFromPath("inputs.message", restored); got != "ping" {
		t.Fatalf("restored inputs.message = %v, want ping", got)
	}
	if got := valueFromPath("outputs.seed", restored); got != "preserved" {
		t.Fatalf("restored outputs.seed = %v, want preserved", got)
	}

	result, err := runnable.Invoke(ctx, WorkflowInput{}, compose.WithCheckPointID("run-checkpoint"))
	if err != nil {
		t.Fatalf("resume checkpoint: %v", err)
	}
	output, ok := result["out-1"].(map[string]any)
	if !ok {
		t.Fatalf("resumed output type = %T, want map[string]any", result["out-1"])
	}
	if got := output["output"]; got != "ping" {
		t.Fatalf("resumed output = %v, want ping", got)
	}
}

func TestExecuteEinoGraph_conditionBranch(t *testing.T) {
	ctx := context.Background()
	SetCheckpointDir(t.TempDir())
	db := testWorkflowDB(t)
	createTestWorkflowRun(t, db, "run-yes")
	createTestWorkflowRun(t, db, "run-no")
	g, err := parseGraph(conditionBranchGraph())
	if err != nil {
		t.Fatal(err)
	}

	stateYes := newWorkflowLocalState(map[string]interface{}{"message": "yes"}, "run-yes")
	if err := executeEinoGraph(ctx, RunArgs{DB: db}, "run-yes", "test-wf-branch", 1, g, stateYes); err != nil {
		t.Fatalf("execute yes: %v", err)
	}
	if got := stateYes.Outputs["branch"]; got != "yes" {
		t.Fatalf("yes branch output = %v", got)
	}

	stateNo := newWorkflowLocalState(map[string]interface{}{"message": "no"}, "run-no")
	if err := executeEinoGraph(ctx, RunArgs{DB: db}, "run-no", "test-wf-branch", 1, g, stateNo); err != nil {
		t.Fatalf("execute no: %v", err)
	}
	if got := stateNo.Outputs["branch"]; got != "no" {
		t.Fatalf("no branch output = %v", got)
	}
}

func TestRunRoleBoundWorkflow_integration(t *testing.T) {
	ctx := context.Background()
	SetCheckpointDir(t.TempDir())
	db := testWorkflowDB(t)
	graph := linearStartOutputGraph()
	if err := db.UpsertWorkflowDefinition(&database.WorkflowDefinition{
		ID:        "wf-linear",
		Name:      "线性流程",
		Version:   1,
		GraphJSON: graph,
		Enabled:   true,
	}); err != nil {
		t.Fatal(err)
	}
	role := config.RoleConfig{
		Name:           "tester",
		Enabled:        true,
		WorkflowID:     "wf-linear",
		WorkflowPolicy: "auto",
	}
	result, err := RunRoleBoundWorkflow(ctx, RunArgs{
		DB:          db,
		Logger:      zap.NewNop(),
		Role:        role,
		UserMessage: "from-role",
	})
	if err != nil {
		t.Fatalf("RunRoleBoundWorkflow: %v", err)
	}
	if result == nil || result.RunID == "" {
		t.Fatal("expected run result")
	}
}

func TestCompiledCache_reuse(t *testing.T) {
	ctx := context.Background()
	SetCheckpointDir(t.TempDir())
	InvalidateCompiledCache("cache-wf")
	g, err := parseGraph(linearStartOutputGraph())
	if err != nil {
		t.Fatal(err)
	}
	a1, err := defaultEngine.getOrCompile(ctx, "cache-wf", 1, g)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := defaultEngine.getOrCompile(ctx, "cache-wf", 1, g)
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Fatal("expected cached artifact pointer reuse")
	}
	InvalidateCompiledCache("cache-wf")
	a3, err := defaultEngine.getOrCompile(ctx, "cache-wf", 1, g)
	if err != nil {
		t.Fatal(err)
	}
	if a1 == a3 {
		t.Fatal("expected new artifact after invalidation")
	}
}
