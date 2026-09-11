package multiagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

const (
	// Per-response transport budgets, independent of task iteration limits.
	// A single tool call can contain thousands of small provider deltas.
	maxAgenticFunctionToolCallsPerResponse  = 1024
	maxAgenticFunctionToolBlocksPerResponse = 262144
	maxAgenticEmptyToolBlocksInSequence     = 4096
	maxAgenticToolArgumentBytesPerResponse  = 16 << 20
	maxAgenticToolCallIDBytes               = 1024
	maxAgenticToolNameBytes                 = 256
)

// agenticStreamIndexRepairModel isolates malformed block indexes emitted by
// some OpenAI-compatible streaming providers. A stream index identifies one
// logical content block; reusing it for another tool call or block type makes
// schema.ConcatAgenticMessages fail and Eino's retry layer subsequently sees
// the successful response as an empty model output.
//
// Valid streams pass through unchanged. Conflicting logical blocks receive a
// stable replacement index. Anonymous argument deltas are merged only when
// they have one unambiguous, incomplete call to attach to.
type agenticStreamIndexRepairModel struct {
	base model.AgenticModel
}

func newAgenticStreamIndexRepairModel(base model.AgenticModel) model.AgenticModel {
	if base == nil {
		return nil
	}
	return &agenticStreamIndexRepairModel{base: base}
}

func (m *agenticStreamIndexRepairModel) Generate(
	ctx context.Context,
	input []*schema.AgenticMessage,
	opts ...model.Option,
) (*schema.AgenticMessage, error) {
	return m.base.Generate(ctx, input, opts...)
}

func (m *agenticStreamIndexRepairModel) Stream(
	ctx context.Context,
	input []*schema.AgenticMessage,
	opts ...model.Option,
) (*schema.StreamReader[*schema.AgenticMessage], error) {
	stream, err := m.base.Stream(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	state := newAgenticStreamIndexRepairState()
	return schema.StreamReaderWithConvert(stream, state.repairMessage), nil
}

type agenticFunctionToolCallState struct {
	identity         string
	callID           string
	name             string
	arguments        strings.Builder
	argumentStarted  bool
	argumentClosed   bool
	argumentInString bool
	argumentEscaped  bool
	argumentStack    []byte
	complete         bool
}

type agenticStreamIndexRepairState struct {
	assignedByIdentity map[string]int
	identityByIndex    map[int]string
	toolCallsBySource  map[int][]*agenticFunctionToolCallState
	toolCallsByID      map[string]*agenticFunctionToolCallState
	toolCalls          []*agenticFunctionToolCallState
	nextFreeIndex      int
	anonymousSequence  int
	toolCallCount      int
	toolBlockCount     int
	emptyToolBlockRun  int
	toolArgumentBytes  int
}

func newAgenticStreamIndexRepairState() *agenticStreamIndexRepairState {
	return &agenticStreamIndexRepairState{
		assignedByIdentity: make(map[string]int),
		identityByIndex:    make(map[int]string),
		toolCallsBySource:  make(map[int][]*agenticFunctionToolCallState),
		toolCallsByID:      make(map[string]*agenticFunctionToolCallState),
	}
}

func (s *agenticStreamIndexRepairState) repairMessage(msg *schema.AgenticMessage) (*schema.AgenticMessage, error) {
	if msg == nil || len(msg.ContentBlocks) == 0 {
		return msg, nil
	}

	repaired := make([]*schema.ContentBlock, 0, len(msg.ContentBlocks))
	changed := false
	for _, block := range msg.ContentBlocks {
		if block == nil {
			repaired = append(repaired, block)
			continue
		}
		isFunctionToolCall := block.Type == schema.ContentBlockTypeFunctionToolCall && block.FunctionToolCall != nil
		if isFunctionToolCall {
			if err := s.accountFunctionToolBlock(block.FunctionToolCall); err != nil {
				return nil, err
			}
		}
		if block.StreamingMeta == nil {
			if isFunctionToolCall {
				if err := s.registerToolCall(); err != nil {
					return nil, err
				}
			}
			repaired = append(repaired, block)
			continue
		}

		sourceIndex := block.StreamingMeta.Index
		if sourceIndex >= s.nextFreeIndex {
			s.nextFreeIndex = sourceIndex + 1
		}

		identity, err := s.blockIdentity(block, sourceIndex)
		if err != nil {
			return nil, err
		}
		assigned := s.assignIndex(identity, sourceIndex)
		if assigned == sourceIndex {
			repaired = append(repaired, block)
			continue
		}

		cloned := *block
		cloned.StreamingMeta = &schema.StreamingMeta{Index: assigned}
		repaired = append(repaired, &cloned)
		changed = true
	}

	if !changed {
		return msg, nil
	}
	out := *msg
	out.ContentBlocks = repaired
	return &out, nil
}

func (s *agenticStreamIndexRepairState) blockIdentity(block *schema.ContentBlock, sourceIndex int) (string, error) {
	if block.Type != schema.ContentBlockTypeFunctionToolCall || block.FunctionToolCall == nil {
		return fmt.Sprintf("block:%s:%d", block.Type, sourceIndex), nil
	}

	toolCall := block.FunctionToolCall
	callID := strings.TrimSpace(toolCall.CallID)
	toolName := strings.TrimSpace(toolCall.Name)
	if callID != "" {
		call, err := s.explicitToolCall(callID, sourceIndex, toolName, toolCall.Arguments)
		if err != nil {
			return "", err
		}
		if err := updateAgenticToolCall(call, toolName, toolCall.Arguments); err != nil {
			return "", err
		}
		s.bindToolCall(sourceIndex, call)
		return call.identity, nil
	}

	call, err := s.resolveAnonymousToolCall(sourceIndex, toolName, toolCall.Arguments)
	if err != nil {
		return "", err
	}
	return call.identity, nil
}

func (s *agenticStreamIndexRepairState) accountFunctionToolBlock(toolCall *schema.FunctionToolCall) error {
	if s.toolBlockCount >= maxAgenticFunctionToolBlocksPerResponse {
		return fmt.Errorf("agentic provider stream exceeded %d function tool-call blocks in one response", maxAgenticFunctionToolBlocksPerResponse)
	}
	if toolCall.Arguments == "" && s.emptyToolBlockRun >= maxAgenticEmptyToolBlocksInSequence {
		return fmt.Errorf("agentic provider stream exceeded %d consecutive empty function tool-call blocks without argument progress", maxAgenticEmptyToolBlocksInSequence)
	}
	if len(toolCall.CallID) > maxAgenticToolCallIDBytes {
		return fmt.Errorf("agentic provider stream function tool call ID exceeded %d bytes", maxAgenticToolCallIDBytes)
	}
	if len(toolCall.Name) > maxAgenticToolNameBytes {
		return fmt.Errorf("agentic provider stream function tool name exceeded %d bytes", maxAgenticToolNameBytes)
	}
	fragment := toolCall.Arguments
	if len(fragment) > maxAgenticToolArgumentBytesPerResponse-s.toolArgumentBytes {
		return fmt.Errorf("agentic provider stream exceeded %d bytes of function tool arguments in one response", maxAgenticToolArgumentBytesPerResponse)
	}
	s.toolArgumentBytes += len(fragment)
	s.toolBlockCount++
	if fragment == "" {
		s.emptyToolBlockRun++
	} else {
		s.emptyToolBlockRun = 0
	}
	return nil
}

func (s *agenticStreamIndexRepairState) explicitToolCall(
	callID string,
	sourceIndex int,
	toolName string,
	arguments string,
) (*agenticFunctionToolCallState, error) {
	if call := s.toolCallsByID[callID]; call != nil {
		return call, nil
	}

	var anonymousCandidate *agenticFunctionToolCallState
	for _, call := range s.toolCallsBySource[sourceIndex] {
		if call.callID != "" || toolName != "" && call.name != "" && call.name != toolName {
			continue
		}
		if call.complete && !isAgenticJSONWhitespaceString(arguments) {
			continue
		}
		if anonymousCandidate != nil && anonymousCandidate != call {
			return nil, fmt.Errorf("agentic provider stream contains an ambiguous late function tool-call ID")
		}
		anonymousCandidate = call
	}
	if anonymousCandidate != nil {
		anonymousCandidate.callID = callID
		s.toolCallsByID[callID] = anonymousCandidate
		return anonymousCandidate, nil
	}

	if err := s.registerToolCall(); err != nil {
		return nil, err
	}

	call := &agenticFunctionToolCallState{
		identity: "function:id:" + callID,
		callID:   callID,
	}
	s.toolCallsByID[callID] = call
	s.toolCalls = append(s.toolCalls, call)
	return call, nil
}

func (s *agenticStreamIndexRepairState) newAnonymousToolCall() (*agenticFunctionToolCallState, error) {
	if err := s.registerToolCall(); err != nil {
		return nil, err
	}

	s.anonymousSequence++
	call := &agenticFunctionToolCallState{
		identity: fmt.Sprintf("function:anonymous-sequence:%d", s.anonymousSequence),
	}
	s.toolCalls = append(s.toolCalls, call)
	return call, nil
}

func (s *agenticStreamIndexRepairState) registerToolCall() error {
	if s.toolCallCount >= maxAgenticFunctionToolCallsPerResponse {
		return fmt.Errorf("agentic provider stream exceeded %d distinct function tool calls in one response", maxAgenticFunctionToolCallsPerResponse)
	}
	s.toolCallCount++
	return nil
}

func (s *agenticStreamIndexRepairState) resolveAnonymousToolCall(
	sourceIndex int,
	toolName string,
	arguments string,
) (*agenticFunctionToolCallState, error) {
	sourceCandidates := incompleteAgenticToolCalls(s.toolCallsBySource[sourceIndex], toolName)
	if len(sourceCandidates) > 1 {
		return nil, fmt.Errorf("agentic provider stream contains an ambiguous anonymous function tool-call fragment")
	}
	if len(sourceCandidates) == 1 {
		call := sourceCandidates[0]
		if err := updateAgenticToolCall(call, toolName, arguments); err != nil {
			return nil, err
		}
		return call, nil
	}

	candidates := incompleteAgenticToolCalls(s.toolCalls, toolName)
	if len(candidates) > 1 {
		return nil, fmt.Errorf("agentic provider stream contains an ambiguous anonymous function tool-call fragment")
	}
	if len(candidates) == 1 {
		candidate := candidates[0]
		if err := updateAgenticToolCall(candidate, toolName, arguments); err != nil {
			return nil, err
		}
		s.bindToolCall(sourceIndex, candidate)
		return candidate, nil
	}
	if len(s.toolCalls) > 1 {
		return nil, fmt.Errorf("agentic provider stream contains an ambiguous anonymous function tool-call fragment")
	}

	// Metadata-only completion chunks may drift to a different provider index.
	// They cannot create or mutate a tool invocation, so attaching one is safe
	// only when exactly one existing call matches.
	if isAgenticJSONWhitespaceString(arguments) {
		metadataCandidates := matchingAgenticToolCalls(s.toolCallsBySource[sourceIndex], toolName)
		if len(metadataCandidates) == 0 {
			metadataCandidates = matchingAgenticToolCalls(s.toolCalls, toolName)
		}
		if len(metadataCandidates) > 1 {
			return nil, fmt.Errorf("agentic provider stream contains an ambiguous anonymous function tool-call fragment")
		}
		if len(metadataCandidates) == 1 {
			metadataCandidate := metadataCandidates[0]
			s.bindToolCall(sourceIndex, metadataCandidate)
			return metadataCandidate, nil
		}
	}

	// A provider that omits the call ID can still start one call if it supplies
	// a function name. Once any call exists, starting another anonymous call is
	// indistinguishable from a malformed tail and is rejected rather than guessed.
	if len(s.toolCalls) == 0 && toolName != "" {
		call, err := s.newAnonymousToolCall()
		if err != nil {
			return nil, err
		}
		if err := updateAgenticToolCall(call, toolName, arguments); err != nil {
			return nil, err
		}
		s.bindToolCall(sourceIndex, call)
		return call, nil
	}

	return nil, fmt.Errorf("agentic provider stream contains an orphaned anonymous function tool-call fragment")
}

func incompleteAgenticToolCalls(calls []*agenticFunctionToolCallState, toolName string) []*agenticFunctionToolCallState {
	candidates := make([]*agenticFunctionToolCallState, 0, len(calls))
	for _, call := range calls {
		if call.complete || toolName != "" && call.name != "" && call.name != toolName {
			continue
		}
		candidates = append(candidates, call)
	}
	return candidates
}

func matchingAgenticToolCalls(calls []*agenticFunctionToolCallState, toolName string) []*agenticFunctionToolCallState {
	candidates := make([]*agenticFunctionToolCallState, 0, len(calls))
	for _, call := range calls {
		if toolName != "" && call.name != toolName {
			continue
		}
		candidates = append(candidates, call)
	}
	return candidates
}

func (s *agenticStreamIndexRepairState) bindToolCall(sourceIndex int, call *agenticFunctionToolCallState) {
	for _, existing := range s.toolCallsBySource[sourceIndex] {
		if existing == call {
			return
		}
	}
	s.toolCallsBySource[sourceIndex] = append(s.toolCallsBySource[sourceIndex], call)
}

func updateAgenticToolCall(call *agenticFunctionToolCallState, toolName, fragment string) error {
	if toolName != "" {
		if call.name != "" && call.name != toolName {
			return fmt.Errorf("agentic provider stream changed function tool name from %q to %q for one call ID", call.name, toolName)
		}
		call.name = toolName
	}
	if call.argumentClosed {
		if !isAgenticJSONWhitespaceString(fragment) {
			return fmt.Errorf("agentic provider stream appended function tool arguments after the JSON object was complete")
		}
		_, _ = call.arguments.WriteString(fragment)
		call.complete = call.name != ""
		return nil
	}
	_, _ = call.arguments.WriteString(fragment)
	if err := scanAgenticToolArgumentFragment(call, fragment); err != nil {
		return err
	}
	call.complete = call.name != "" && call.argumentClosed
	return nil
}

func scanAgenticToolArgumentFragment(call *agenticFunctionToolCallState, fragment string) error {
	closedInFragment := false
	for i := 0; i < len(fragment); i++ {
		character := fragment[i]
		if call.argumentClosed {
			if !isAgenticJSONWhitespace(character) {
				return fmt.Errorf("agentic provider stream appended function tool arguments after the JSON object was complete")
			}
			continue
		}
		if !call.argumentStarted {
			if isAgenticJSONWhitespace(character) {
				continue
			}
			if character != '{' {
				return fmt.Errorf("agentic provider stream function tool arguments must be a JSON object")
			}
			call.argumentStarted = true
			call.argumentStack = append(call.argumentStack, '}')
			continue
		}
		if call.argumentInString {
			if call.argumentEscaped {
				call.argumentEscaped = false
				continue
			}
			switch character {
			case '\\':
				call.argumentEscaped = true
			case '"':
				call.argumentInString = false
			}
			continue
		}

		switch character {
		case '"':
			call.argumentInString = true
		case '{':
			call.argumentStack = append(call.argumentStack, '}')
		case '[':
			call.argumentStack = append(call.argumentStack, ']')
		case '}', ']':
			if len(call.argumentStack) == 0 || call.argumentStack[len(call.argumentStack)-1] != character {
				return fmt.Errorf("agentic provider stream function tool arguments contain mismatched JSON delimiters")
			}
			call.argumentStack = call.argumentStack[:len(call.argumentStack)-1]
			if len(call.argumentStack) == 0 {
				call.argumentClosed = true
				closedInFragment = true
			}
		}
	}

	if closedInFragment {
		var object map[string]json.RawMessage
		if err := json.Unmarshal([]byte(call.arguments.String()), &object); err != nil || object == nil {
			return fmt.Errorf("agentic provider stream function tool arguments are not a valid JSON object")
		}
	}
	return nil
}

func isAgenticJSONWhitespace(character byte) bool {
	return character == ' ' || character == '\t' || character == '\r' || character == '\n'
}

func isAgenticJSONWhitespaceString(value string) bool {
	for i := 0; i < len(value); i++ {
		if !isAgenticJSONWhitespace(value[i]) {
			return false
		}
	}
	return true
}

func (s *agenticStreamIndexRepairState) assignIndex(identity string, sourceIndex int) int {
	if assigned, ok := s.assignedByIdentity[identity]; ok {
		return assigned
	}
	assigned := sourceIndex
	if owner, occupied := s.identityByIndex[assigned]; occupied && owner != identity {
		assigned = s.takeFreeIndex()
	}
	s.assignedByIdentity[identity] = assigned
	s.identityByIndex[assigned] = identity
	return assigned
}

func (s *agenticStreamIndexRepairState) takeFreeIndex() int {
	for {
		candidate := s.nextFreeIndex
		s.nextFreeIndex++
		if _, occupied := s.identityByIndex[candidate]; !occupied {
			return candidate
		}
	}
}
