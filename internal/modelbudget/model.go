package modelbudget

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"github.com/pkoukk/tiktoken-go"
)

type message interface {
	*schema.Message | *schema.AgenticMessage
}

type budgetModel[M message] struct {
	base       model.BaseModel[M]
	name       string
	maxOutput  int
	boundTools []*schema.ToolInfo
}

func (m *budgetModel[M]) UnderlyingModel() any { return m.base }

// Unwrap exposes the backend for capability checks without removing its budget
// wrapper from the actual invocation path.
func Unwrap(base any) any {
	for {
		wrapped, ok := base.(interface{ UnderlyingModel() any })
		if !ok {
			return base
		}
		base = wrapped.UnderlyingModel()
	}
}

func WrapAgentic(base model.AgenticModel, name string, maxOutput int) model.AgenticModel {
	if base == nil {
		return nil
	}
	return &budgetModel[*schema.AgenticMessage]{base: base, name: name, maxOutput: maxOutput}
}

type chatModel struct {
	*budgetModel[*schema.Message]
	chat model.ChatModel
}

func WrapChatModel(base model.ChatModel, name string, maxOutput int) model.ChatModel {
	if base == nil {
		return nil
	}
	return &chatModel{budgetModel: &budgetModel[*schema.Message]{base: base, name: name, maxOutput: maxOutput}, chat: base}
}
func (m *chatModel) BindTools(tools []*schema.ToolInfo) error {
	if err := m.chat.BindTools(tools); err != nil {
		return err
	}
	m.boundTools = append([]*schema.ToolInfo(nil), tools...)
	return nil
}

type toolCallingModel struct {
	*budgetModel[*schema.Message]
	toolModel model.ToolCallingChatModel
}

func WrapToolCalling(base model.ToolCallingChatModel, name string, maxOutput int) model.ToolCallingChatModel {
	if base == nil {
		return nil
	}
	return &toolCallingModel{budgetModel: &budgetModel[*schema.Message]{base: base, name: name, maxOutput: maxOutput}, toolModel: base}
}
func (m *toolCallingModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	base, err := m.toolModel.WithTools(tools)
	if err != nil {
		return nil, err
	}
	return &toolCallingModel{budgetModel: &budgetModel[*schema.Message]{base: base, name: m.name, maxOutput: m.maxOutput, boundTools: append([]*schema.ToolInfo(nil), tools...)}, toolModel: base}, nil
}

func (m *budgetModel[M]) prepare(ctx context.Context, input []M, opts []model.Option) (*reservation, []model.Option, error) {
	t := FromContext(ctx)
	if t == nil {
		return nil, opts, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	common := model.GetCommonOptions(&model.Options{}, opts...)
	name, maxOutput := m.name, m.maxOutput
	if common.Model != nil {
		name = *common.Model
	}
	if common.MaxTokens != nil {
		if *common.MaxTokens <= 0 {
			return nil, nil, fmt.Errorf("model output token budget must be positive")
		}
		maxOutput = *common.MaxTokens
	}
	if maxOutput <= 0 {
		maxOutput = 16384
	}
	tools := common.Tools
	if tools == nil {
		tools = m.boundTools
	}
	if common.ToolChoice != nil && *common.ToolChoice == schema.ToolChoiceForbidden {
		tools = nil
	}
	if common.AgenticToolChoice != nil && common.AgenticToolChoice.Type == schema.ToolChoiceForbidden {
		tools = nil
	}
	clean := make([]any, 0, len(input))
	for _, msg := range input {
		if v := cleanMessage(msg); v != nil {
			clean = append(clean, v)
		}
	}
	// ToolInfo pointers preserve the SDK's custom schema serialization.
	body, err := json.Marshal(struct {
		Messages []any              `json:"messages"`
		Tools    []*schema.ToolInfo `json:"tools"`
	}{clean, tools})
	if err != nil {
		return nil, nil, fmt.Errorf("estimate task token budget: %w", err)
	}
	r, output, err := t.reserve(countTokens(name, string(body))+64, maxOutput)
	if err != nil {
		return nil, nil, err
	}
	// Pass the same default/override we reserved, including when it did not shrink.
	opts = append(append([]model.Option(nil), opts...), model.WithMaxTokens(output))
	return r, opts, nil
}

func (m *budgetModel[M]) Generate(ctx context.Context, input []M, opts ...model.Option) (M, error) {
	r, callOpts, err := m.prepare(ctx, input, opts)
	if err != nil {
		var zero M
		return zero, err
	}
	if r == nil {
		return m.base.Generate(ctx, input, callOpts...)
	}
	// Release even when a backend panics; the caller retains panic handling.
	defer r.finish(0, 0, false)
	msg, err := m.base.Generate(ctx, input, callOpts...)
	u := usageOf(msg)
	if usageReported(msg, u) {
		r.finish(totalUsage(u), 0, true)
	} else {
		name := m.name
		if chosen := model.GetCommonOptions(nil, callOpts...).Model; chosen != nil {
			name = *chosen
		}
		r.finish(0, countTokens(name, outputText(msg)), false)
	}
	return msg, err
}

func (m *budgetModel[M]) Stream(ctx context.Context, input []M, opts ...model.Option) (*schema.StreamReader[M], error) {
	r, callOpts, err := m.prepare(ctx, input, opts)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return m.base.Stream(ctx, input, callOpts...)
	}
	callCtx, cancel := context.WithCancel(ctx)
	handedOff := false
	defer func() {
		if !handedOff {
			cancel()
			r.finish(0, 0, false)
		}
	}()
	source, err := m.base.Stream(callCtx, input, callOpts...)
	if err != nil || source == nil {
		if source != nil {
			source.Close()
		}
		if err == nil {
			err = fmt.Errorf("model returned a nil stream")
		}
		return nil, err
	}
	name := m.name
	if chosen := model.GetCommonOptions(nil, callOpts...).Model; chosen != nil {
		name = *chosen
	}
	reader := accountStream(ctx, callCtx, cancel, source, r, name)
	handedOff = true
	return reader, nil
}

func cleanMessage[M message](msg M) any {
	switch v := any(msg).(type) {
	case *schema.Message:
		if v == nil {
			return nil
		}
		copy := *v
		copy.ResponseMeta = nil
		copy.Extra = nil
		return &copy
	case *schema.AgenticMessage:
		if v == nil {
			return nil
		}
		copy := *v
		copy.ResponseMeta = nil
		copy.Extra = nil
		return &copy
	}
	return nil
}

func usageOf[M message](msg M) *schema.TokenUsage {
	switch v := any(msg).(type) {
	case *schema.Message:
		if v != nil && v.ResponseMeta != nil {
			return v.ResponseMeta.Usage
		}
	case *schema.AgenticMessage:
		if v != nil && v.ResponseMeta != nil {
			return v.ResponseMeta.TokenUsage
		}
	}
	return nil
}

func usageReported[M message](msg M, usage *schema.TokenUsage) bool {
	if usage == nil {
		return false
	}
	var extra map[string]any
	switch v := any(msg).(type) {
	case *schema.Message:
		if v != nil {
			extra = v.Extra
		}
	case *schema.AgenticMessage:
		if v != nil {
			extra = v.Extra
		}
	}
	if details, ok := extra["codex_usage_details"].(map[string]any); ok {
		if reported, ok := details["reported"].(bool); ok {
			return reported
		}
	}
	// Some SDKs emit an empty usage object before the final usage chunk. That
	// alone is not evidence of a measured, free model call.
	return totalUsage(usage) > 0 || usage.PromptTokenDetails.CachedTokens > 0 || usage.CompletionTokensDetails.ReasoningTokens > 0
}

func totalUsage(u *schema.TokenUsage) int {
	if u == nil {
		return 0
	}
	if u.TotalTokens > 0 {
		return u.TotalTokens
	}
	return addTokenCounts(max(u.PromptTokens, u.PromptTokenDetails.CachedTokens), max(u.CompletionTokens, u.CompletionTokensDetails.ReasoningTokens))
}

func outputText[M message](msg M) string {
	switch v := any(msg).(type) {
	case *schema.Message:
		if v == nil {
			return ""
		}
		b, _ := json.Marshal(v.ToolCalls)
		return v.Content + v.ReasoningContent + string(b)
	case *schema.AgenticMessage:
		if v == nil {
			return ""
		}
		b, _ := json.Marshal(v.ContentBlocks)
		return string(b)
	}
	return ""
}

var encodings struct {
	sync.Mutex
	byName map[string]*tiktoken.Tiktoken
}

func countTokens(name, text string) int {
	if text == "" || text == "null" {
		return 0
	}
	encodings.Lock()
	if encodings.byName == nil {
		encodings.byName = make(map[string]*tiktoken.Tiktoken)
	}
	enc, ok := encodings.byName[name]
	if !ok {
		var err error
		enc, err = tiktoken.EncodingForModel(name)
		if err != nil {
			enc, _ = tiktoken.GetEncoding("cl100k_base")
		}
		encodings.byName[name] = enc
	}
	encodings.Unlock()
	if enc == nil {
		return (len(text) + 2) / 3
	}
	return len(enc.Encode(text, nil, nil))
}
