package multiagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type agenticStreamIndexFakeModel struct {
	chunks []*schema.AgenticMessage
}

func (m *agenticStreamIndexFakeModel) Generate(
	context.Context,
	[]*schema.AgenticMessage,
	...model.Option,
) (*schema.AgenticMessage, error) {
	return nil, nil
}

func (m *agenticStreamIndexFakeModel) Stream(
	context.Context,
	[]*schema.AgenticMessage,
	...model.Option,
) (*schema.StreamReader[*schema.AgenticMessage], error) {
	return schema.StreamReaderFromArray(m.chunks), nil
}

func agenticToolCallChunk(index int, callID, name, arguments string) *schema.AgenticMessage {
	return &schema.AgenticMessage{
		Role: schema.AgenticRoleTypeAssistant,
		ContentBlocks: []*schema.ContentBlock{schema.NewContentBlockChunk(&schema.FunctionToolCall{
			CallID: callID, Name: name, Arguments: arguments,
		}, &schema.StreamingMeta{Index: index})},
	}
}

func TestAgenticStreamIndexRepairSeparatesConflictingToolCallIDs(t *testing.T) {
	base := &agenticStreamIndexFakeModel{chunks: []*schema.AgenticMessage{
		agenticToolCallChunk(0, "call_a", "get_asset", `{"id":"`),
		agenticToolCallChunk(0, "", "", `one"}`),
		agenticToolCallChunk(0, "call_b", "query_vulnerabilities", `{"asset":"`),
		agenticToolCallChunk(0, "", "", `one"}`),
	}}

	if _, err := schema.ConcatAgenticMessages(base.chunks); err == nil {
		t.Fatal("fixture must reproduce the conflicting stream-index failure")
	}

	wrapped := newAgenticStreamIndexRepairModel(base)
	chunks := readAgenticStreamChunks(t, wrapped)
	merged, err := schema.ConcatAgenticMessages(chunks)
	if err != nil {
		t.Fatalf("ConcatAgenticMessages() error after repair = %v", err)
	}
	if len(merged.ContentBlocks) != 2 {
		t.Fatalf("content block count = %d, want 2", len(merged.ContentBlocks))
	}
	first, second := merged.ContentBlocks[0].FunctionToolCall, merged.ContentBlocks[1].FunctionToolCall
	if first == nil || first.CallID != "call_a" || first.Name != "get_asset" || first.Arguments != `{"id":"one"}` {
		t.Fatalf("first tool call = %#v", first)
	}
	if second == nil || second.CallID != "call_b" || second.Name != "query_vulnerabilities" || second.Arguments != `{"asset":"one"}` {
		t.Fatalf("second tool call = %#v", second)
	}
	if chunks[0].ContentBlocks[0].StreamingMeta.Index != 0 ||
		chunks[1].ContentBlocks[0].StreamingMeta.Index != 0 ||
		chunks[2].ContentBlocks[0].StreamingMeta.Index != 1 ||
		chunks[3].ContentBlocks[0].StreamingMeta.Index != 1 {
		t.Fatalf("repaired chunk indexes = %#v", chunks)
	}
}

func TestAgenticStreamIndexRepairKeepsValidIndexes(t *testing.T) {
	base := &agenticStreamIndexFakeModel{chunks: []*schema.AgenticMessage{
		agenticToolCallChunk(0, "call_a", "get_asset", `{}`),
		agenticToolCallChunk(1, "call_b", "query_vulnerabilities", `{}`),
	}}
	chunks := readAgenticStreamChunks(t, newAgenticStreamIndexRepairModel(base))
	if chunks[0].ContentBlocks[0].StreamingMeta.Index != 0 || chunks[1].ContentBlocks[0].StreamingMeta.Index != 1 {
		t.Fatalf("valid indexes changed: %#v", chunks)
	}
}

func TestAgenticStreamIndexRepairKeepsSameToolAndArgumentsForDistinctIDs(t *testing.T) {
	const arguments = `{"query":"same"}`
	base := &agenticStreamIndexFakeModel{chunks: []*schema.AgenticMessage{
		agenticToolCallChunk(0, "call_a", "tool_search", arguments),
		agenticToolCallChunk(0, "call_b", "tool_search", arguments),
	}}

	repaired := readAgenticStreamChunks(t, newAgenticStreamIndexRepairModel(base))
	merged, err := schema.ConcatAgenticMessages(repaired)
	if err != nil {
		t.Fatalf("ConcatAgenticMessages() error after repair = %v", err)
	}
	if len(merged.ContentBlocks) != 2 {
		t.Fatalf("content block count = %d, want both distinct calls", len(merged.ContentBlocks))
	}
	if merged.ContentBlocks[0].FunctionToolCall.CallID != "call_a" || merged.ContentBlocks[1].FunctionToolCall.CallID != "call_b" {
		t.Fatalf("distinct calls were not preserved: %#v", merged.ContentBlocks)
	}
}

func TestAgenticStreamIndexRepairKeepsManyAnonymousFragmentsInOneToolCall(t *testing.T) {
	const fragmentCount = 96
	const sourceIndex = 0

	chunks := make([]*schema.AgenticMessage, 0, fragmentCount+2)
	chunks = append(chunks, &schema.AgenticMessage{
		Role: schema.AgenticRoleTypeAssistant,
		ContentBlocks: []*schema.ContentBlock{schema.NewContentBlockChunk(
			&schema.Reasoning{Text: "inspect"}, &schema.StreamingMeta{Index: sourceIndex},
		)},
	})

	wantArguments := `{"payload":"`
	chunks = append(chunks, agenticToolCallChunk(
		sourceIndex, "call_streamed", "stream_tool", wantArguments,
	))
	for i := 0; i < fragmentCount; i++ {
		name := ""
		if i%3 == 0 {
			// Some providers repeat the function name (and type) on argument
			// deltas even though the call ID only appears on the first chunk.
			name = "stream_tool"
		}
		arguments := "x"
		if i == fragmentCount-1 {
			arguments = `"}`
		}
		wantArguments += arguments
		chunks = append(chunks, agenticToolCallChunk(sourceIndex, "", name, arguments))
	}

	if _, err := schema.ConcatAgenticMessages(chunks); err == nil {
		t.Fatal("fixture must reproduce the mixed-block source-index conflict")
	}

	repaired := readAgenticStreamChunks(t, newAgenticStreamIndexRepairModel(
		&agenticStreamIndexFakeModel{chunks: chunks},
	))
	if got := repaired[0].ContentBlocks[0].StreamingMeta.Index; got != sourceIndex {
		t.Fatalf("reasoning index = %d, want %d", got, sourceIndex)
	}
	for i, chunk := range repaired[1:] {
		block := chunk.ContentBlocks[0]
		if block.Type != schema.ContentBlockTypeFunctionToolCall {
			t.Fatalf("tool fragment %d type = %q", i, block.Type)
		}
		if got := block.StreamingMeta.Index; got != 1 {
			t.Fatalf("tool fragment %d repaired index = %d, want 1", i, got)
		}
	}

	merged, err := schema.ConcatAgenticMessages(repaired)
	if err != nil {
		t.Fatalf("ConcatAgenticMessages() error after repair = %v", err)
	}
	if len(merged.ContentBlocks) != 2 {
		t.Fatalf("content block count = %d, want reasoning plus one tool call", len(merged.ContentBlocks))
	}
	call := merged.ContentBlocks[1].FunctionToolCall
	if call == nil || call.CallID != "call_streamed" || call.Name != "stream_tool" || call.Arguments != wantArguments {
		t.Fatalf("merged agentic tool call = %#v", call)
	}

	classicChunks := make([]*schema.Message, 0, len(repaired))
	for _, chunk := range repaired {
		classicChunks = append(classicChunks, AgenticMessageToEino(chunk)...)
	}
	classic, err := schema.ConcatMessages(classicChunks)
	if err != nil {
		t.Fatalf("ConcatMessages() error after agentic conversion = %v", err)
	}
	if len(classic.ToolCalls) != 1 {
		t.Fatalf("classic tool call count = %d, want 1 (one call must not expand into %d fragments)", len(classic.ToolCalls), fragmentCount+1)
	}
	if classic.ToolCalls[0].ID != "call_streamed" || classic.ToolCalls[0].Function.Name != "stream_tool" || classic.ToolCalls[0].Function.Arguments != wantArguments {
		t.Fatalf("merged classic tool call = %#v", classic.ToolCalls[0])
	}
}

func TestAgenticStreamIndexRepairRejectsCompleteCallFloodAtLimit(t *testing.T) {
	const duplicateCount = 513
	const sourceIndex = 0
	const arguments = `{"query":"get_asset list_vulnerabilities"}`

	chunks := make([]*schema.AgenticMessage, 0, duplicateCount+1)
	chunks = append(chunks, &schema.AgenticMessage{
		Role: schema.AgenticRoleTypeAssistant,
		ContentBlocks: []*schema.ContentBlock{schema.NewContentBlockChunk(
			&schema.Reasoning{Text: "inspect"}, &schema.StreamingMeta{Index: sourceIndex},
		)},
	})
	for i := 0; i < duplicateCount; i++ {
		chunks = append(chunks, agenticToolCallChunk(
			sourceIndex,
			fmt.Sprintf("call_%03d", i),
			"tool_search",
			arguments,
		))
	}

	stream, err := newAgenticStreamIndexRepairModel(
		&agenticStreamIndexFakeModel{chunks: chunks},
	).Stream(context.Background(), nil)
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	defer stream.Close()

	toolCallChunks := 0
	for {
		chunk, recvErr := stream.Recv()
		if recvErr != nil {
			if !strings.Contains(recvErr.Error(), "distinct function tool calls") {
				t.Fatalf("Recv() error = %v, want distinct-call limit", recvErr)
			}
			break
		}
		for _, block := range chunk.ContentBlocks {
			if block != nil && block.FunctionToolCall != nil {
				toolCallChunks++
			}
		}
	}
	if toolCallChunks != maxAgenticFunctionToolCallsPerResponse {
		t.Fatalf("tool chunks emitted before rejection = %d, want %d", toolCallChunks, maxAgenticFunctionToolCallsPerResponse)
	}
}

func TestAgenticStreamIndexRepairRejectsDistinctCallFlood(t *testing.T) {
	state := newAgenticStreamIndexRepairState()
	for i := 0; i < maxAgenticFunctionToolCallsPerResponse; i++ {
		_, err := state.repairMessage(agenticToolCallChunk(
			0,
			fmt.Sprintf("call_%03d", i),
			"tool_search",
			fmt.Sprintf(`{"query":"item-%03d"}`, i),
		))
		if err != nil {
			t.Fatalf("call %d unexpectedly rejected: %v", i+1, err)
		}
	}

	_, err := state.repairMessage(agenticToolCallChunk(
		0,
		"call_over_limit",
		"tool_search",
		`{"query":"over-limit"}`,
	))
	if err == nil || !strings.Contains(err.Error(), "distinct function tool calls") {
		t.Fatalf("overflow error = %v, want distinct-call limit", err)
	}
}

func TestAgenticStreamIndexRepairKeepsUniqueCallAcrossSourceIndexDrift(t *testing.T) {
	base := &agenticStreamIndexFakeModel{chunks: []*schema.AgenticMessage{
		agenticToolCallChunk(0, "call_a", "get_asset", `{"id":"`),
		agenticToolCallChunk(7, "", "", `one"}`),
	}}

	repaired := readAgenticStreamChunks(t, newAgenticStreamIndexRepairModel(base))
	merged, err := schema.ConcatAgenticMessages(repaired)
	if err != nil {
		t.Fatalf("ConcatAgenticMessages() error after index-drift repair = %v", err)
	}
	if len(merged.ContentBlocks) != 1 {
		t.Fatalf("content block count = %d, want 1", len(merged.ContentBlocks))
	}
	call := merged.ContentBlocks[0].FunctionToolCall
	if call == nil || call.CallID != "call_a" || call.Name != "get_asset" || call.Arguments != `{"id":"one"}` {
		t.Fatalf("merged tool call = %#v", call)
	}
}

func TestAgenticStreamIndexRepairRejectsAmbiguousAnonymousFragment(t *testing.T) {
	state := newAgenticStreamIndexRepairState()
	if _, err := state.repairMessage(agenticToolCallChunk(0, "call_a", "get_asset", `{"id":"`)); err != nil {
		t.Fatalf("first call rejected: %v", err)
	}
	if _, err := state.repairMessage(agenticToolCallChunk(1, "call_b", "list_vulnerabilities", `{"status":"`)); err != nil {
		t.Fatalf("second call rejected: %v", err)
	}

	_, err := state.repairMessage(agenticToolCallChunk(9, "", "", `{"unknown":true}`))
	if err == nil || !strings.Contains(err.Error(), "ambiguous anonymous") {
		t.Fatalf("ambiguous fragment error = %v", err)
	}
}

func TestAgenticStreamIndexRepairRejectsAnonymousFragmentForReusedSourceWithTwoIncompleteCalls(t *testing.T) {
	state := newAgenticStreamIndexRepairState()
	if _, err := state.repairMessage(agenticToolCallChunk(0, "call_a", "tool_search", `{"query":"`)); err != nil {
		t.Fatalf("first call rejected: %v", err)
	}
	if _, err := state.repairMessage(agenticToolCallChunk(0, "call_b", "tool_search", `{"query":"`)); err != nil {
		t.Fatalf("second call rejected: %v", err)
	}

	_, err := state.repairMessage(agenticToolCallChunk(0, "", "", `tail"}`))
	if err == nil || !strings.Contains(err.Error(), "ambiguous anonymous") {
		t.Fatalf("same-source ambiguity error = %v", err)
	}
}

func TestAgenticStreamIndexRepairRejectsAnonymousPayloadAfterCompletedCall(t *testing.T) {
	state := newAgenticStreamIndexRepairState()
	if _, err := state.repairMessage(agenticToolCallChunk(0, "call_a", "get_asset", `{}`)); err != nil {
		t.Fatalf("completed call rejected: %v", err)
	}

	_, err := state.repairMessage(agenticToolCallChunk(9, "", "", `{"unknown":true}`))
	if err == nil || !strings.Contains(err.Error(), "orphaned anonymous") {
		t.Fatalf("orphaned fragment error = %v", err)
	}
}

func TestAgenticStreamIndexRepairChecksArgumentByteLimitBeforeRegisteringCall(t *testing.T) {
	state := newAgenticStreamIndexRepairState()
	tooLarge := strings.Repeat("x", maxAgenticToolArgumentBytesPerResponse+1)

	_, err := state.repairMessage(agenticToolCallChunk(0, "call_large", "tool_search", tooLarge))
	if err == nil || !strings.Contains(err.Error(), "bytes of function tool arguments") {
		t.Fatalf("argument-limit error = %v", err)
	}
	if len(state.toolCalls) != 0 || len(state.toolCallsByID) != 0 || state.toolArgumentBytes != 0 {
		t.Fatalf("oversized fragment mutated state: calls=%d ids=%d bytes=%d", len(state.toolCalls), len(state.toolCallsByID), state.toolArgumentBytes)
	}
}

func TestAgenticStreamIndexRepairRejectsExcessiveEmptyToolBlocks(t *testing.T) {
	state := newAgenticStreamIndexRepairState()
	for i := 0; i < maxAgenticFunctionToolBlocksPerResponse; i++ {
		if _, err := state.repairMessage(agenticToolCallChunk(0, "call_stream", "tool_search", "")); err != nil {
			t.Fatalf("block %d unexpectedly rejected: %v", i+1, err)
		}
	}

	_, err := state.repairMessage(agenticToolCallChunk(0, "call_stream", "tool_search", ""))
	if err == nil || !strings.Contains(err.Error(), "tool-call blocks") {
		t.Fatalf("block-limit error = %v", err)
	}
}

func TestAgenticStreamIndexRepairPromotesAnonymousCallWhenIDArrivesLate(t *testing.T) {
	base := &agenticStreamIndexFakeModel{chunks: []*schema.AgenticMessage{
		agenticToolCallChunk(0, "", "tool_search", `{"query":"`),
		agenticToolCallChunk(0, "call_late", "", `same"}`),
	}}

	repaired := readAgenticStreamChunks(t, newAgenticStreamIndexRepairModel(base))
	merged, err := schema.ConcatAgenticMessages(repaired)
	if err != nil {
		t.Fatalf("ConcatAgenticMessages() error after late-ID promotion = %v", err)
	}
	if len(merged.ContentBlocks) != 1 {
		t.Fatalf("content block count = %d, want 1", len(merged.ContentBlocks))
	}
	call := merged.ContentBlocks[0].FunctionToolCall
	if call == nil || call.CallID != "call_late" || call.Name != "tool_search" || call.Arguments != `{"query":"same"}` {
		t.Fatalf("late-ID tool call = %#v", call)
	}
}

func TestAgenticStreamIndexRepairPromotesCompletedAnonymousCallForLateIDMetadata(t *testing.T) {
	base := &agenticStreamIndexFakeModel{chunks: []*schema.AgenticMessage{
		agenticToolCallChunk(0, "", "tool_search", `{"query":"same"}`),
		agenticToolCallChunk(0, "call_late", "", ""),
	}}

	repaired := readAgenticStreamChunks(t, newAgenticStreamIndexRepairModel(base))
	merged, err := schema.ConcatAgenticMessages(repaired)
	if err != nil {
		t.Fatalf("ConcatAgenticMessages() error after completed late-ID promotion = %v", err)
	}
	if len(merged.ContentBlocks) != 1 {
		t.Fatalf("content block count = %d, want 1", len(merged.ContentBlocks))
	}
	call := merged.ContentBlocks[0].FunctionToolCall
	if call == nil || call.CallID != "call_late" || call.Name != "tool_search" || call.Arguments != `{"query":"same"}` {
		t.Fatalf("completed late-ID tool call = %#v", call)
	}
}

func TestAgenticStreamIndexRepairRejectsNonJSONWhitespaceAfterCompletedArguments(t *testing.T) {
	state := newAgenticStreamIndexRepairState()
	if _, err := state.repairMessage(agenticToolCallChunk(0, "call_a", "tool_search", `{}`)); err != nil {
		t.Fatalf("completed call rejected: %v", err)
	}

	_, err := state.repairMessage(agenticToolCallChunk(0, "call_a", "", "\u00a0"))
	if err == nil || !strings.Contains(err.Error(), "after the JSON object was complete") {
		t.Fatalf("non-JSON whitespace error = %v", err)
	}
}

func TestAgenticStreamIndexRepairLimitsToolBlocksWithoutStreamingMeta(t *testing.T) {
	blocks := make([]*schema.ContentBlock, 0, maxAgenticFunctionToolCallsPerResponse+1)
	for i := 0; i <= maxAgenticFunctionToolCallsPerResponse; i++ {
		blocks = append(blocks, schema.NewContentBlock(&schema.FunctionToolCall{
			CallID:    fmt.Sprintf("call_%03d", i),
			Name:      "tool_search",
			Arguments: `{}`,
		}))
	}

	state := newAgenticStreamIndexRepairState()
	_, err := state.repairMessage(&schema.AgenticMessage{
		Role:          schema.AgenticRoleTypeAssistant,
		ContentBlocks: blocks,
	})
	if err == nil || !strings.Contains(err.Error(), "distinct function tool calls") {
		t.Fatalf("non-streaming call-limit error = %v", err)
	}
}

func TestAgenticStreamIndexRepairRejectsToolNameChangeForOneID(t *testing.T) {
	state := newAgenticStreamIndexRepairState()
	if _, err := state.repairMessage(agenticToolCallChunk(0, "call_a", "get_asset", `{"id":"`)); err != nil {
		t.Fatalf("first fragment rejected: %v", err)
	}
	_, err := state.repairMessage(agenticToolCallChunk(0, "call_a", "list_vulnerabilities", `one"}`))
	if err == nil || !strings.Contains(err.Error(), "changed function tool name") {
		t.Fatalf("tool-name conflict error = %v", err)
	}
}

func TestAgenticStreamIndexRepairSeparatesBlockTypesSharingIndex(t *testing.T) {
	index := 0
	base := &agenticStreamIndexFakeModel{chunks: []*schema.AgenticMessage{
		{
			Role: schema.AgenticRoleTypeAssistant,
			ContentBlocks: []*schema.ContentBlock{schema.NewContentBlockChunk(
				&schema.Reasoning{Text: "plan"}, &schema.StreamingMeta{Index: index},
			)},
		},
		agenticToolCallChunk(index, "call_a", "get_asset", `{}`),
	}}
	chunks := readAgenticStreamChunks(t, newAgenticStreamIndexRepairModel(base))
	merged, err := schema.ConcatAgenticMessages(chunks)
	if err != nil {
		t.Fatalf("ConcatAgenticMessages() error after mixed-block repair = %v", err)
	}
	if len(merged.ContentBlocks) != 2 || merged.ContentBlocks[0].Reasoning == nil || merged.ContentBlocks[1].FunctionToolCall == nil {
		t.Fatalf("merged blocks = %#v", merged.ContentBlocks)
	}
}

func readAgenticStreamChunks(t *testing.T, chatModel model.AgenticModel) []*schema.AgenticMessage {
	t.Helper()
	stream, err := chatModel.Stream(context.Background(), nil)
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	defer stream.Close()

	var chunks []*schema.AgenticMessage
	for {
		chunk, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			return chunks
		}
		if recvErr != nil {
			t.Fatalf("Recv() error = %v", recvErr)
		}
		chunks = append(chunks, chunk)
	}
}
