package multiagent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp/builtin"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

func TestReductionCacheRootDir(t *testing.T) {
	got := reductionCacheRootDir("", "proj-1", "conv-1")
	want := filepath.Join("tmp", "reduction", "projects", "proj-1")
	if got != want {
		t.Fatalf("project scope: got %q want %q", got, want)
	}
	got = reductionCacheRootDir("", "", "conv-abc")
	want = filepath.Join("tmp", "reduction", "conversations", "conv-abc")
	if got != want {
		t.Fatalf("conversation scope: got %q want %q", got, want)
	}
	custom := reductionCacheRootDir("/data/cache", "p1", "c1")
	if !strings.HasSuffix(custom, filepath.Join("projects", "p1")) {
		t.Fatalf("custom base should still scope by project, got %q", custom)
	}
}

func TestBuildAgenticReductionMiddlewareClearsOldAgenticToolResult(t *testing.T) {
	ctx := context.Background()
	loc, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	root := t.TempDir()
	mw, err := buildAgenticReductionMiddleware(ctx, config.MultiAgentEinoMiddlewareConfig{
		ReductionRootDir:           root,
		ReductionMaxTokensForClear: 1,
	}, "", "conv-1", loc, nil)
	if err != nil {
		t.Fatalf("buildAgenticReductionMiddleware: %v", err)
	}
	oldText := strings.Repeat("old-tool-output-", 20)
	newText := strings.Repeat("new-tool-output-", 20)
	state := &adk.TypedChatModelAgentState[*schema.AgenticMessage]{
		Messages: []*schema.AgenticMessage{
			agenticAssistantToolCall("old-call", "execute", `{"command":"old"}`),
			agenticToolResult("old-call", "execute", oldText),
			agenticAssistantToolCall("new-call", "execute", `{"command":"new"}`),
			agenticToolResult("new-call", "execute", newText),
		},
	}
	_, out, err := mw.BeforeModelRewriteState(ctx, state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState: %v", err)
	}
	oldGot := out.Messages[1].ContentBlocks[0].FunctionToolResult.Content[0].Text.Text
	newGot := out.Messages[3].ContentBlocks[0].FunctionToolResult.Content[0].Text.Text
	if oldGot == oldText {
		t.Fatal("agentic reduction did not clear old oversized tool result")
	}
	if !strings.Contains(oldGot, "read_file") {
		t.Fatalf("cleared content should mention read_file, got %q", oldGot)
	}
	if newGot != newText {
		t.Fatalf("latest tool result should be retained, got %q", newGot)
	}
}

func agenticAssistantToolCall(callID, name, arguments string) *schema.AgenticMessage {
	return &schema.AgenticMessage{
		Role: schema.AgenticRoleTypeAssistant,
		ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.FunctionToolCall{
			CallID:    callID,
			Name:      name,
			Arguments: arguments,
		})},
	}
}

func agenticToolResult(callID, name, text string) *schema.AgenticMessage {
	return &schema.AgenticMessage{
		Role: schema.AgenticRoleTypeUser,
		ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.FunctionToolResult{
			CallID: callID,
			Name:   name,
			Content: []*schema.FunctionToolResultContentBlock{{
				Type: schema.FunctionToolResultContentBlockTypeText,
				Text: &schema.UserInputText{Text: text},
			}},
		})},
	}
}

func TestBuildAgenticReductionMiddlewareHandlesSingleAgenticToolResult(t *testing.T) {
	ctx := context.Background()
	loc, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	mw, err := buildAgenticReductionMiddleware(ctx, config.MultiAgentEinoMiddlewareConfig{
		ReductionRootDir:           t.TempDir(),
		ReductionMaxTokensForClear: 1,
	}, "", "conv-1", loc, nil)
	if err != nil {
		t.Fatalf("buildAgenticReductionMiddleware: %v", err)
	}
	state := &adk.TypedChatModelAgentState[*schema.AgenticMessage]{
		Messages: []*schema.AgenticMessage{
			{
				Role: schema.AgenticRoleTypeUser,
				ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.FunctionToolResult{
					CallID: "call-1",
					Name:   "execute",
					Content: []*schema.FunctionToolResultContentBlock{{
						Type: schema.FunctionToolResultContentBlockTypeText,
						Text: &schema.UserInputText{Text: strings.Repeat("tool-output-", 20)},
					}},
				})},
			},
		},
	}
	_, out, err := mw.BeforeModelRewriteState(ctx, state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState: %v", err)
	}
	got := out.Messages[0].ContentBlocks[0].FunctionToolResult.Content[0].Text.Text
	if got != strings.Repeat("tool-output-", 20) {
		t.Fatalf("single retained tool result should not be cleared, got %q", got)
	}
}

func TestPrependEinoAgenticMiddlewaresRespectsReductionPlacement(t *testing.T) {
	ctx := context.Background()
	loc, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	patchToolCalls := false
	mw := &config.MultiAgentEinoMiddlewareConfig{
		ReductionEnable:            true,
		ReductionRootDir:           t.TempDir(),
		ReductionMaxTokensForClear: 100,
		PatchToolCalls:             &patchToolCalls,
	}
	_, mainHandlers, _, err := prependEinoAgenticMiddlewares(ctx, mw, einoMWMain, nil, loc, "", "conv-1", "", nil)
	if err != nil {
		t.Fatalf("prepend main: %v", err)
	}
	if len(mainHandlers) != 1 {
		t.Fatalf("main handlers = %d, want reduction", len(mainHandlers))
	}
	_, subHandlers, _, err := prependEinoAgenticMiddlewares(ctx, mw, einoMWSub, nil, loc, "", "conv-1", "", nil)
	if err != nil {
		t.Fatalf("prepend sub: %v", err)
	}
	if len(subHandlers) != 0 {
		t.Fatalf("sub handlers = %d, want skipped when reduction_sub_agents=false", len(subHandlers))
	}
	mw.ReductionSubAgents = true
	_, subHandlers, _, err = prependEinoAgenticMiddlewares(ctx, mw, einoMWSub, nil, loc, "", "conv-1", "", nil)
	if err != nil {
		t.Fatalf("prepend sub enabled: %v", err)
	}
	if len(subHandlers) != 1 {
		t.Fatalf("sub handlers = %d, want reduction when reduction_sub_agents=true", len(subHandlers))
	}
}

func TestPrependEinoAgenticMiddlewaresMountsToolSearchAndPatchToolCalls(t *testing.T) {
	ctx := context.Background()
	mw := &config.MultiAgentEinoMiddlewareConfig{
		ToolSearchEnable:        true,
		ToolSearchMinTools:      20,
		ToolSearchAlwaysVisible: 5,
	}
	outTools, handlers, toolSearchActive, err := prependEinoAgenticMiddlewares(ctx, mw, einoMWMain, stubTools(25), nil, "", "conv-test", "", nil)
	if err != nil {
		t.Fatalf("prependEinoAgenticMiddlewares: %v", err)
	}
	if !toolSearchActive {
		t.Fatal("agentic tool_search should be active")
	}
	if len(outTools) != 5 {
		t.Fatalf("mounted tools = %d, want static visible tools only", len(outTools))
	}
	if len(handlers) != 2 {
		t.Fatalf("handlers = %d, want patchtoolcalls + toolsearch", len(handlers))
	}
}

type stubTool struct{ name string }

func (s stubTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: s.name}, nil
}

func TestSplitToolsForToolSearch(t *testing.T) {
	mk := func(n int) []tool.BaseTool {
		out := make([]tool.BaseTool, n)
		for i := 0; i < n; i++ {
			out[i] = stubTool{name: fmt.Sprintf("t%d", i)}
		}
		return out
	}
	static, dynamic, ok := splitToolsForToolSearch(mk(4), 3)
	if ok || len(static) != 4 || dynamic != nil {
		t.Fatalf("expected no split when len<=alwaysVisible+1, got ok=%v static=%d dynamic=%v", ok, len(static), dynamic)
	}
	static, dynamic, ok = splitToolsForToolSearch(mk(20), 5)
	if !ok || len(static) != 5 || len(dynamic) != 15 {
		t.Fatalf("expected split 5+15, got ok=%v static=%d dynamic=%d", ok, len(static), len(dynamic))
	}
}

func TestToolSearchKeepsSubsystemSchemasDeferredAndExplicitChoicesVisible(t *testing.T) {
	var all []tool.BaseTool
	for _, name := range builtin.GetAllBuiltinTools() {
		all = append(all, stubTool{name: name})
	}
	names := mergeAlwaysVisibleToolNames([]string{"  C2_SESSION  ", builtin.ToolQueryAssets})
	static, dynamic, split := splitToolsForToolSearchByNames(all, names, 12)
	if !split {
		t.Fatal("subsystem tools should be dynamically discoverable")
	}
	visible := map[string]bool{}
	for _, name := range collectToolNames(context.Background(), static) {
		visible[name] = true
	}
	if !visible[builtin.ToolC2Session] || !visible[builtin.ToolWaitToolExecution] {
		t.Fatalf("explicit selection or execution control lost: %v", visible)
	}
	if visible[builtin.ToolC2Payload] || visible[builtin.ToolManageWebshellAdd] || visible[builtin.ToolBatchTaskCreate] {
		t.Fatalf("unrelated subsystem schemas remain always-visible: %v", visible)
	}
	if len(static)+len(dynamic) != len(all) {
		t.Fatal("deferring schemas removed callable tools")
	}
	// Explicitly selecting all tools must not hide some through positional fallback.
	static, dynamic, split = splitToolsForToolSearchByNames(all, builtin.GetAllBuiltinTools(), 2)
	if split || len(static) != len(all) || len(dynamic) != 0 {
		t.Fatal("explicit always-visible choices were silently overridden")
	}
}

func TestToolSearchInstructionMatchesInstalledToolContract(t *testing.T) {
	ctx := context.Background()
	mw := &config.MultiAgentEinoMiddlewareConfig{
		ToolSearchEnable: true, ToolSearchMinTools: 20, ToolSearchAlwaysVisible: 5,
	}
	all := stubTools(25)
	static, handlers, active, err := prependEinoAgenticMiddlewares(ctx, mw, einoMWMain, all, nil, "", "test", "", nil)
	if err != nil || !active {
		t.Fatalf("tool_search not mounted: %v", err)
	}
	instruction := injectToolNamesOnlyInstruction(ctx, "base instruction", all, active)
	if strings.Contains(instruction, "regex_pattern") || !strings.Contains(instruction, "query") || !strings.Contains(instruction, "select:exact_tool_name") {
		t.Fatalf("instructions do not describe the current tool_search schema: %s", instruction)
	}
	runCtx := &adk.ChatModelAgentContext{Tools: static}
	for _, handler := range handlers {
		ctx, runCtx, err = handler.BeforeAgent(ctx, runCtx)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, mounted := range runCtx.Tools {
		info, err := mounted.Info(ctx)
		if err != nil || info == nil || info.Name != "tool_search" {
			continue
		}
		search, ok := mounted.(tool.InvokableTool)
		if !ok {
			t.Fatal("tool_search not invokable")
		}
		// Only the meta-tool runs, against fixture names; no scanner or model is invoked.
		raw, err := search.InvokableRun(ctx, `{"query":"select:t6"}`)
		if err != nil {
			t.Fatalf("documented query syntax failed: %v", err)
		}
		var result struct {
			Matches []string `json:"matches"`
		}
		if err := json.Unmarshal([]byte(raw), &result); err != nil || len(result.Matches) != 1 || result.Matches[0] != "t6" {
			t.Fatalf("unexpected installed tool_search contract: %s / %v", raw, err)
		}
		return
	}
	t.Fatal("tool_search missing from mounted tools")
}
