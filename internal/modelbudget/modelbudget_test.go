package modelbudget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"github.com/pkoukk/tiktoken-go"
)

const offlineModelName = "offline-budget-test-model"
const offlineOverrideName = "offline-budget-override-model"

func TestMain(m *testing.M) {
	// tiktoken loads vocabularies from HTTP on a cold cache. Seed the explicit
	// offline fallback so none of these fake-model tests can trigger that load.
	encodings.byName = map[string]*tiktoken.Tiktoken{
		offlineModelName: nil, offlineOverrideName: nil,
	}
	os.Exit(m.Run())
}

type fakeModel[M message] struct {
	generate func(context.Context, []M, ...model.Option) (M, error)
	stream   func(context.Context, []M, ...model.Option) (*schema.StreamReader[M], error)
}

func (f *fakeModel[M]) Generate(ctx context.Context, input []M, opts ...model.Option) (M, error) {
	if f.generate != nil {
		return f.generate(ctx, input, opts...)
	}
	var zero M
	return zero, errors.New("unexpected fake Generate")
}

func (f *fakeModel[M]) Stream(ctx context.Context, input []M, opts ...model.Option) (*schema.StreamReader[M], error) {
	if f.stream != nil {
		return f.stream(ctx, input, opts...)
	}
	return nil, errors.New("unexpected fake Stream")
}

type fakeClassic struct {
	fakeModel[*schema.Message]
	bindTools func([]*schema.ToolInfo) error
	withTools func([]*schema.ToolInfo) (model.ToolCallingChatModel, error)
}

func (f *fakeClassic) BindTools(tools []*schema.ToolInfo) error {
	if f.bindTools != nil {
		return f.bindTools(tools)
	}
	return nil
}

func (f *fakeClassic) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	if f.withTools != nil {
		return f.withTools(tools)
	}
	clone := *f
	return &clone, nil
}

func budgetInput() []*schema.Message { return []*schema.Message{schema.UserMessage("hello")} }

func inputCost(t *testing.T, input []*schema.Message, tools []*schema.ToolInfo) int {
	t.Helper()
	clean := make([]any, 0, len(input))
	for _, msg := range input {
		if msg != nil {
			copy := *msg
			copy.Extra, copy.ResponseMeta = nil, nil
			clean = append(clean, &copy)
		}
	}
	body, err := json.Marshal(struct {
		Messages []any              `json:"messages"`
		Tools    []*schema.ToolInfo `json:"tools"`
	}{clean, tools})
	if err != nil {
		t.Fatal(err)
	}
	return (len(body)+2)/3 + 64
}

func usageMessage(total int) *schema.Message {
	return &schema.Message{Role: schema.Assistant, ResponseMeta: &schema.ResponseMeta{Usage: &schema.TokenUsage{TotalTokens: total}}}
}

func reportedMessage(reported bool) *schema.Message {
	msg := usageMessage(0)
	msg.Extra = map[string]any{"codex_usage_details": map[string]any{"reported": reported}}
	return msg
}

func awaitSnapshot(t *testing.T, tracker *Tracker, check func(Snapshot) bool) Snapshot {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		s := tracker.Snapshot()
		if check(s) {
			return s
		}
		select {
		case <-deadline.C:
			t.Fatalf("accounting did not settle: %+v", s)
		case <-tick.C:
		}
	}
}

func TestContextSharesTrackerWithChildrenAndRetries(t *testing.T) {
	if FromContext(nil) != nil || FromContext(WithContext(nil, 0)) != nil {
		t.Fatal("disabled/nil context should not create a tracker")
	}
	ctx := WithContext(nil, 1000)
	tracker := FromContext(ctx)
	for _, limit := range []int{0, 100, 2000} {
		if FromContext(WithContext(ctx, limit)) != tracker {
			t.Fatalf("child limit %d replaced shared tracker", limit)
		}
	}
	if tracker.Snapshot().Limit != 1000 {
		t.Fatal("child changed the parent's limit")
	}
}

func TestExceededErrorSurvivesSDKSerialization(t *testing.T) {
	err := &ExceededError{Limit: 100, Used: 90, NextInput: 20}
	for _, candidate := range []error{err, fmt.Errorf("wrapped: %w", err), errors.New("stream error: " + err.Error()), ErrExceeded} {
		if !IsExceeded(candidate) {
			t.Fatalf("budget error lost classification: %v", candidate)
		}
	}
	if !errors.Is(err, ErrExceeded) || !strings.Contains(err.Error(), exceededMarker) {
		t.Fatal("missing sentinel identity or stable error marker")
	}
	for _, candidate := range []error{nil, context.Canceled, errors.New("request timed out"), errors.New("context window exceeded")} {
		if IsExceeded(candidate) {
			t.Fatalf("misclassified error: %v", candidate)
		}
	}
}

func TestWithSnapshotRestoresSettledUsageUnderCurrentLimit(t *testing.T) {
	old := Snapshot{Limit: 500, Used: 600, Reserved: 200, Calls: 7, Estimated: true, Stopped: true}
	ctx := WithSnapshot(nil, 1000, old)
	want := Snapshot{Limit: 1000, Used: 600, Calls: 7, Estimated: true}
	if got := FromContext(ctx).Snapshot(); got != want {
		t.Fatalf("checkpoint did not restore settled usage/current limit: got=%+v want=%+v", got, want)
	}
	if got := FromContext(WithSnapshot(nil, 400, old)).Snapshot(); !got.Stopped || got.Limit != 400 || got.Used != 600 || got.Reserved != 0 {
		t.Fatalf("lowered limit failed to stop exhausted checkpoint: %+v", got)
	}
	for _, limit := range []int{0, -1} {
		if FromContext(WithSnapshot(nil, limit, old)) != nil {
			t.Fatalf("disabled current limit %d restored an old tracker", limit)
		}
	}
	if got := FromContext(WithSnapshot(ctx, 0, Snapshot{})); got != FromContext(ctx) {
		t.Fatal("resume replaced existing shared tracker")
	}
	if got := FromContext(WithSnapshot(nil, 1000, Snapshot{Used: -1, Calls: -8, Reserved: -10})).Snapshot(); got.Used != 0 || got.Calls != 0 || got.Reserved != 0 || got.Stopped {
		t.Fatalf("invalid checkpoint counters restored: %+v", got)
	}
}

func TestReservationsAreAtomicAndOnlySettledOnce(t *testing.T) {
	tracker := FromContext(WithContext(context.Background(), 1000))
	reservations := make(chan *reservation, 10)
	var denied atomic.Int32
	var workers sync.WaitGroup
	for range 10 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r, output, err := tracker.reserve(100, 100)
			if err != nil {
				if IsExceeded(err) {
					denied.Add(1)
				}
				return
			}
			if output != 100 {
				t.Errorf("reserved unexpected output %d", output)
			}
			reservations <- r
		}()
	}
	workers.Wait()
	close(reservations)
	s := tracker.Snapshot()
	if s.Reserved != 1000 || s.Calls != 5 || denied.Load() != 5 || !s.Stopped {
		t.Fatalf("concurrent reservations exceeded/underfilled budget: %+v denied=%d", s, denied.Load())
	}
	for r := range reservations {
		r.finish(150, 0, true)
		r.finish(9000, 0, true)
	}
	s = tracker.Snapshot()
	if s.Reserved != 0 || s.Used != 750 || s.Estimated {
		t.Fatalf("reservation was not settled exactly once: %+v", s)
	}
}

func TestReservationNotificationsDoNotHoldLockAndCountersSaturate(t *testing.T) {
	tracker := FromContext(WithContext(context.Background(), 1000))
	notifications := 0
	tracker.SetNotify(func(s Snapshot) {
		notifications++
		if tracker.Snapshot() != s {
			t.Error("callback snapshot differs from tracker")
		}
	})
	r, _, err := tracker.reserve(10, 10)
	if err != nil {
		t.Fatal(err)
	}
	r.finish(800, 0, true)
	r, _, err = tracker.reserve(10, 10)
	if err != nil {
		t.Fatal(err)
	}
	r.finish(50, 0, true)
	if notifications != 1 {
		t.Fatalf("near-limit warning repeated %d times", notifications)
	}
	if _, _, err := tracker.reserve(150, 1); !IsExceeded(err) || notifications != 2 {
		t.Fatalf("expected exhaustion notification, err=%v notifications=%d", err, notifications)
	}
	maxInt := int(^uint(0) >> 1)
	if got := addTokenCounts(maxInt-1, 100); got != maxInt {
		t.Fatalf("counter overflowed: %d", got)
	}
	if got := totalUsage(&schema.TokenUsage{PromptTokens: maxInt, CompletionTokens: 10}); got != maxInt {
		t.Fatalf("usage overflowed: %d", got)
	}
}

func TestGenerateOutputBudgetDefaultsOverridesAndShrinks(t *testing.T) {
	input := budgetInput()
	cost := inputCost(t, input, nil)
	for _, tc := range []struct {
		name                    string
		configured, limit, want int
		opts                    []model.Option
	}{
		{name: "configured", configured: 200, limit: 100000, want: 200},
		{name: "fallback", limit: 100000, want: 16384},
		{name: "call override", configured: 200, limit: 100000, want: 75, opts: []model.Option{model.WithMaxTokens(75)}},
		{name: "shrink", configured: 200, limit: cost + 17, want: 17},
		{name: "shrink override", configured: 200, limit: cost + 7, want: 7, opts: []model.Option{model.WithMaxTokens(100)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithContext(context.Background(), tc.limit)
			calls := 0
			backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{generate: func(ctx context.Context, _ []*schema.Message, opts ...model.Option) (*schema.Message, error) {
				calls++
				maxTokens := model.GetCommonOptions(nil, opts...).MaxTokens
				if maxTokens == nil || *maxTokens != tc.want {
					t.Fatalf("backend output limit=%v, want %d", maxTokens, tc.want)
				}
				if got := FromContext(ctx).Snapshot().Reserved; got != cost+tc.want {
					t.Fatalf("backend limit and reservation differ: %d", got)
				}
				return usageMessage(10), nil
			}}}
			wrapped := WrapChatModel(backend, offlineModelName, tc.configured)
			if _, err := wrapped.Generate(ctx, input, tc.opts...); err != nil || calls != 1 {
				t.Fatalf("Generate calls=%d err=%v", calls, err)
			}
			if got := FromContext(ctx).Snapshot(); got.Used != 10 || got.Reserved != 0 {
				t.Fatalf("unexpected final accounting: %+v", got)
			}
		})
	}
}

func TestGenerateInvalidLimitCancellationAndExhaustionNeverCallBackend(t *testing.T) {
	var calls int
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{generate: func(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
		calls++
		return usageMessage(1), nil
	}}}
	wrapped := WrapChatModel(backend, offlineModelName, 100)
	for _, invalid := range []int{0, -1} {
		ctx := WithContext(context.Background(), 1000)
		if _, err := wrapped.Generate(ctx, budgetInput(), model.WithMaxTokens(invalid)); err == nil {
			t.Fatalf("accepted invalid override %d", invalid)
		}
		if s := FromContext(ctx).Snapshot(); s.Calls != 0 || s.Reserved != 0 {
			t.Fatalf("invalid request reserved usage: %+v", s)
		}
	}
	ctx, cancel := context.WithCancel(WithContext(context.Background(), 1000))
	cancel()
	if _, err := wrapped.Generate(ctx, budgetInput()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request: %v", err)
	}
	ctx = WithContext(context.Background(), 1)
	for range 2 {
		if _, err := wrapped.Generate(ctx, budgetInput()); !IsExceeded(err) {
			t.Fatalf("missing budget rejection: %v", err)
		}
	}
	if calls != 0 || FromContext(ctx).Snapshot().Calls != 0 {
		t.Fatalf("rejected request/retry reached backend: %d", calls)
	}
}

func TestGenerateReportedUsageOnSuccessAndFailure(t *testing.T) {
	backendErr := errors.New("fake provider failed after generating")
	for _, tc := range []struct {
		name string
		msg  *schema.Message
		err  error
		want int
	}{
		{"total preferred", usageMessage(120), nil, 120},
		{"usage on error", usageMessage(150), backendErr, 150},
		{"explicit zero measured", reportedMessage(true), nil, 0},
		{"total fallback", &schema.Message{ResponseMeta: &schema.ResponseMeta{Usage: &schema.TokenUsage{PromptTokens: 80, CompletionTokens: 20, PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 60}, CompletionTokensDetails: schema.CompletionTokensDetails{ReasoningTokens: 10}}}}, nil, 100},
		{"reported detail lower bound", &schema.Message{ResponseMeta: &schema.ResponseMeta{Usage: &schema.TokenUsage{PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 60}, CompletionTokensDetails: schema.CompletionTokensDetails{ReasoningTokens: 10}}}}, nil, 70},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithContext(context.Background(), 10000)
			backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{generate: func(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
				return tc.msg, tc.err
			}}}
			got, err := WrapChatModel(backend, offlineModelName, 200).Generate(ctx, budgetInput())
			if got != tc.msg || err != tc.err {
				t.Fatal("wrapper changed backend response/error")
			}
			if s := FromContext(ctx).Snapshot(); s.Used != tc.want || s.Reserved != 0 || s.Estimated || s.Calls != 1 {
				t.Fatalf("unexpected measured usage: %+v", s)
			}
		})
	}
}

func TestGenerateUnreportedUsageIsEstimatedIncludingError(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  *schema.Message
		err  error
	}{
		{"nil response on error", nil, errors.New("connection lost")},
		{"no usage", &schema.Message{Content: "abcabcabc"}, nil},
		{"empty SDK usage", &schema.Message{Content: "abcabcabc", ResponseMeta: &schema.ResponseMeta{Usage: &schema.TokenUsage{}}}, nil},
		{"explicit unknown zero", reportedMessage(false), errors.New("partial response")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithContext(context.Background(), 10000)
			backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{generate: func(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
				return tc.msg, tc.err
			}}}
			got, err := WrapChatModel(backend, offlineModelName, 200).Generate(ctx, budgetInput(), model.WithModel(offlineOverrideName))
			if got != tc.msg || err != tc.err {
				t.Fatal("wrapper changed backend response/error")
			}
			want := inputCost(t, budgetInput(), nil) + countTokens(offlineOverrideName, outputText(tc.msg))
			if s := FromContext(ctx).Snapshot(); !s.Estimated || s.Used != want || s.Reserved != 0 {
				t.Fatalf("unreported usage not estimated: %+v want=%d", s, want)
			}
		})
	}
}

func TestDisabledBudgetForwardsUnchangedWithoutTokenization(t *testing.T) {
	const uncachedName = "must-not-load-a-vocabulary"
	response := &schema.Message{Content: "untracked response"}
	source := schema.StreamReaderFromArray([]*schema.Message{response})
	defer source.Close()
	opts := []model.Option{model.WithTemperature(0.5), model.WithMaxTokens(7)}
	check := func(got []model.Option) {
		if len(got) != len(opts) || &got[0] != &opts[0] {
			t.Error("disabled tracking rewrote call options")
		}
	}
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{
		generate: func(_ context.Context, _ []*schema.Message, got ...model.Option) (*schema.Message, error) {
			check(got)
			return response, nil
		},
		stream: func(_ context.Context, _ []*schema.Message, got ...model.Option) (*schema.StreamReader[*schema.Message], error) {
			check(got)
			return source, nil
		},
	}}
	wrapped := WrapChatModel(backend, uncachedName, 200)
	if got, err := wrapped.Generate(context.Background(), budgetInput(), opts...); err != nil || got != response {
		t.Fatalf("untracked Generate got=%v err=%v", got, err)
	}
	if got, err := wrapped.Stream(context.Background(), budgetInput(), opts...); err != nil || got != source {
		t.Fatalf("untracked Stream got=%v err=%v", got, err)
	}
	encodings.Lock()
	_, loaded := encodings.byName[uncachedName]
	encodings.Unlock()
	if loaded {
		t.Fatal("untracked response unnecessarily initialized tokenization")
	}
}

func TestGenerateConcurrentCallsCannotOverReserve(t *testing.T) {
	input := budgetInput()
	cost := inputCost(t, input, nil)
	ctx := WithContext(context.Background(), 3*(cost+20))
	tracker := FromContext(ctx)
	gate := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate) }) }
	t.Cleanup(release)
	events := make(chan bool, 10)
	var calls atomic.Int32
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{generate: func(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
		calls.Add(1)
		events <- true
		<-gate
		return usageMessage(10), nil
	}}}
	wrapped := WrapChatModel(backend, offlineModelName, 20)
	var workers sync.WaitGroup
	for range 10 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := wrapped.Generate(ctx, input); err != nil {
				if !IsExceeded(err) {
					t.Errorf("unexpected generation error: %v", err)
				}
				events <- false
			}
		}()
	}
	admitted := 0
	for range 10 {
		select {
		case entered := <-events:
			if entered {
				admitted++
			}
		case <-time.After(2 * time.Second):
			t.Fatal("calls stalled before reservation decision")
		}
	}
	if s := tracker.Snapshot(); admitted != 3 || calls.Load() != 3 || s.Reserved != s.Limit || s.Used != 0 {
		t.Fatalf("concurrent backend calls oversubscribed: %+v admitted=%d calls=%d", s, admitted, calls.Load())
	}
	release()
	workers.Wait()
	if s := tracker.Snapshot(); s.Reserved != 0 || s.Used != 30 || s.Calls != 3 {
		t.Fatalf("concurrent calls did not settle: %+v", s)
	}
}

func TestAgenticUsageAndImplementationOptionsArePreserved(t *testing.T) {
	type specificOptions struct{ Reasoning string }
	response := &schema.AgenticMessage{ResponseMeta: &schema.AgenticResponseMeta{TokenUsage: &schema.TokenUsage{TotalTokens: 37}}}
	backend := &fakeModel[*schema.AgenticMessage]{generate: func(_ context.Context, input []*schema.AgenticMessage, opts ...model.Option) (*schema.AgenticMessage, error) {
		if got := model.GetImplSpecificOptions(&specificOptions{}, opts...).Reasoning; got != "low" {
			t.Fatalf("implementation option lost: %q", got)
		}
		if maxTokens := model.GetCommonOptions(nil, opts...).MaxTokens; maxTokens == nil || *maxTokens != 100 {
			t.Fatal("agentic output budget not passed")
		}
		if len(input) != 1 || input[0].Extra["local"] != "retained" {
			t.Fatal("budget estimation mutated actual input")
		}
		return response, nil
	}}
	ctx := WithContext(context.Background(), 1000)
	wrapped := WrapAgentic(backend, offlineModelName, 100)
	input := []*schema.AgenticMessage{{Role: schema.AgenticRoleTypeUser, Extra: map[string]any{"local": "retained"}}}
	got, err := wrapped.Generate(ctx, input, model.WrapImplSpecificOptFn(func(opts *specificOptions) { opts.Reasoning = "low" }))
	if err != nil || got != response || Unwrap(wrapped) != backend || FromContext(ctx).Snapshot().Used != 37 {
		t.Fatalf("agentic wrapper got=%v err=%v snapshot=%+v", got, err, FromContext(ctx).Snapshot())
	}
}

func TestPrepareIgnoresResponseMetadataWithoutMutatingInput(t *testing.T) {
	input := budgetInput()
	input[0].ResponseMeta = &schema.ResponseMeta{Usage: &schema.TokenUsage{TotalTokens: 999999}}
	input[0].Extra = map[string]any{"not JSON encodable": make(chan int)}
	ctx := WithContext(context.Background(), 1000)
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{generate: func(_ context.Context, actual []*schema.Message, _ ...model.Option) (*schema.Message, error) {
		if actual[0] != input[0] || actual[0].Extra == nil || actual[0].ResponseMeta == nil {
			t.Fatal("estimation modified caller's message")
		}
		if got := FromContext(ctx).Snapshot().Reserved; got != inputCost(t, budgetInput(), nil)+100 {
			t.Fatalf("metadata counted as model input: %d", got)
		}
		return usageMessage(10), nil
	}}}
	if _, err := WrapChatModel(backend, offlineModelName, 100).Generate(ctx, input); err != nil {
		t.Fatal(err)
	}
}

func TestBoundToolsRemainBudgetedAndPerCallToolChoiceApplies(t *testing.T) {
	tools := []*schema.ToolInfo{{Name: "local_lookup", Desc: strings.Repeat("large tool description ", 200)}}
	input := budgetInput()
	bareCost := inputCost(t, input, nil)
	toolCost := inputCost(t, input, tools)
	var calls int
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{generate: func(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
		calls++
		return usageMessage(10), nil
	}}}
	wrapped := WrapToolCalling(backend, offlineModelName, 100)
	bound, err := wrapped.WithTools(tools)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the caller's slice must not rebind the derived model's tool list.
	tools[0] = &schema.ToolInfo{Name: "replacement"}
	ctx := WithContext(context.Background(), bareCost+100)
	if _, err := bound.Generate(ctx, input); !IsExceeded(err) || calls != 0 || toolCost <= bareCost+100 {
		t.Fatalf("WithTools bypassed schema budget: err=%v calls=%d", err, calls)
	}
	if _, err := wrapped.Generate(WithContext(context.Background(), bareCost+100), input); err != nil {
		t.Fatalf("WithTools mutated original wrapper: %v", err)
	}
	for _, option := range []model.Option{
		model.WithTools(nil),
		model.WithToolChoice(schema.ToolChoiceForbidden),
		model.WithAgenticToolChoice(&schema.AgenticToolChoice{Type: schema.ToolChoiceForbidden}),
	} {
		if _, err := bound.Generate(WithContext(context.Background(), bareCost+100), input, option); err != nil {
			t.Fatalf("per-call tool override ignored: %v", err)
		}
	}
	boundChat := WrapChatModel(backend, offlineModelName, 100)
	if err := boundChat.BindTools([]*schema.ToolInfo{{Name: "large", Desc: strings.Repeat("x", 4000)}}); err != nil {
		t.Fatal(err)
	}
	before := calls
	if _, err := boundChat.Generate(WithContext(context.Background(), bareCost+100), input); !IsExceeded(err) || calls != before {
		t.Fatal("BindTools schema bypassed the budget")
	}
	bindErr := errors.New("cannot bind tools")
	backend.bindTools = func([]*schema.ToolInfo) error { return bindErr }
	backend.withTools = func([]*schema.ToolInfo) (model.ToolCallingChatModel, error) { return nil, bindErr }
	if err := boundChat.BindTools(nil); err != bindErr {
		t.Fatal("BindTools error lost")
	}
	if _, err := wrapped.WithTools(nil); err != bindErr {
		t.Fatal("WithTools error lost")
	}
}

func TestStreamCumulativeUsageCountsOnceAndPreservesToolJSON(t *testing.T) {
	args := `{"query":"` + strings.Repeat("abcdef", 1000) + `"}`
	toolChunk := &schema.Message{ToolCalls: []schema.ToolCall{{ID: "test-call", Function: schema.FunctionCall{Name: "lookup", Arguments: args}}}}
	first, last := usageMessage(80), usageMessage(1500)
	last.ResponseMeta.Usage.PromptTokenDetails.CachedTokens = 50
	last.ResponseMeta.Usage.CompletionTokensDetails.ReasoningTokens = 100
	chunks := []*schema.Message{usageMessage(0), toolChunk, first, last, last}
	source := schema.StreamReaderFromArray(chunks)
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{stream: func(_ context.Context, _ []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
		if maxTokens := model.GetCommonOptions(nil, opts...).MaxTokens; maxTokens == nil || *maxTokens != 100 {
			t.Fatal("stream default output budget not forwarded")
		}
		return source, nil
	}}}
	ctx := WithContext(context.Background(), 1000)
	wrapped := WrapChatModel(backend, offlineModelName, 100)
	reader, err := wrapped.Stream(ctx, budgetInput())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for i, expected := range chunks {
		got, err := reader.Recv()
		if err != nil || got != expected {
			t.Fatalf("chunk %d changed: got=%v err=%v", i, got, err)
		}
	}
	if _, err := reader.Recv(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
	if s := FromContext(ctx).Snapshot(); s.Used != 1500 || s.Estimated || s.Reserved != 0 || s.Calls != 1 {
		t.Fatalf("cumulative usage double-counted: %+v", s)
	}
	if toolChunk.ToolCalls[0].Function.Arguments != args || !json.Valid([]byte(args)) {
		t.Fatal("budget truncated complete tool arguments")
	}
	if _, err := wrapped.Generate(ctx, budgetInput()); !IsExceeded(err) {
		t.Fatalf("next call not stopped after overshooting advisory output: %v", err)
	}
}

func TestStreamErrorPreservesPartialMeasuredUsage(t *testing.T) {
	backendErr := errors.New("fake stream broke")
	source, writer := schema.Pipe[*schema.Message](2)
	writer.Send(usageMessage(70), nil)
	final := usageMessage(123)
	writer.Send(final, backendErr)
	writer.Close()
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{stream: func(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
		return source, nil
	}}}
	ctx := WithContext(context.Background(), 10000)
	reader, err := WrapChatModel(backend, offlineModelName, 100).Stream(ctx, budgetInput())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.Recv(); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.Recv(); got != final || err != backendErr {
		t.Fatalf("partial error response changed: got=%v err=%v", got, err)
	}
	s := awaitSnapshot(t, FromContext(ctx), func(s Snapshot) bool { return s.Reserved == 0 })
	if s.Used != 123 || s.Estimated {
		t.Fatalf("error usage lost: %+v", s)
	}
}

func TestAgenticStreamCombinesSeparatelyReportedUsageComponents(t *testing.T) {
	start := &schema.AgenticMessage{ResponseMeta: &schema.AgenticResponseMeta{TokenUsage: &schema.TokenUsage{PromptTokens: 250, CompletionTokens: 1, TotalTokens: 251}}}
	end := &schema.AgenticMessage{ResponseMeta: &schema.AgenticResponseMeta{TokenUsage: &schema.TokenUsage{CompletionTokens: 50, TotalTokens: 50}}}
	backend := &fakeModel[*schema.AgenticMessage]{stream: func(context.Context, []*schema.AgenticMessage, ...model.Option) (*schema.StreamReader[*schema.AgenticMessage], error) {
		return schema.StreamReaderFromArray([]*schema.AgenticMessage{start, end, end}), nil
	}}
	ctx := WithContext(context.Background(), 10000)
	reader, err := WrapAgentic(backend, offlineModelName, 100).Stream(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for {
		_, err := reader.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if s := FromContext(ctx).Snapshot(); s.Used != 300 || s.Reserved != 0 || s.Estimated {
		t.Fatalf("split cumulative usage lost/double-counted components: %+v", s)
	}
}

func TestStreamUnreportedUsageAndExplicitZero(t *testing.T) {
	for _, reported := range []bool{false, true} {
		t.Run(fmt.Sprint(reported), func(t *testing.T) {
			chunk := reportedMessage(reported)
			chunk.Content = strings.Repeat("abc", 20)
			backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{stream: func(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
				return schema.StreamReaderFromArray([]*schema.Message{chunk}), nil
			}}}
			ctx := WithContext(context.Background(), 10000)
			reader, err := WrapChatModel(backend, offlineModelName, 100).Stream(ctx, budgetInput())
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if _, err := reader.Recv(); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Recv(); err != io.EOF {
				t.Fatal(err)
			}
			s := FromContext(ctx).Snapshot()
			if reported && (s.Estimated || s.Used != 0) {
				t.Fatalf("reported zero became estimate: %+v", s)
			}
			if !reported && (!s.Estimated || s.Used <= inputCost(t, budgetInput(), nil)) {
				t.Fatalf("unknown zero became free call: %+v", s)
			}
		})
	}
}

func TestStreamCloseWhileSourceIdleReleasesReservation(t *testing.T) {
	source, writer := schema.Pipe[*schema.Message](0)
	defer writer.Close() // The intentionally uncooperative fake ignores cancellation.
	var callCtx context.Context
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{stream: func(ctx context.Context, _ []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
		callCtx = ctx
		return source, nil
	}}}
	ctx := WithContext(context.Background(), 10000)
	reader, err := WrapChatModel(backend, offlineModelName, 100).Stream(ctx, budgetInput())
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	s := awaitSnapshot(t, FromContext(ctx), func(s Snapshot) bool { return s.Reserved == 0 })
	if callCtx.Err() != context.Canceled || !s.Estimated || s.Used != inputCost(t, budgetInput(), nil) {
		t.Fatalf("idle consumer close did not cancel/settle: err=%v snapshot=%+v", callCtx.Err(), s)
	}
}

func TestStreamParentCancellationWithoutReadingReleasesReservation(t *testing.T) {
	source, writer := schema.Pipe[*schema.Message](0)
	defer writer.Close()
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{stream: func(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
		return source, nil
	}}}
	ctx, cancel := context.WithCancel(WithContext(context.Background(), 10000))
	reader, err := WrapChatModel(backend, offlineModelName, 100).Stream(ctx, budgetInput())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	awaitSnapshot(t, FromContext(ctx), func(s Snapshot) bool { return s.Reserved == 0 })
	// The caller's usual defer Close must remain safe after internal cancel.
	reader.Close()
	if _, err := reader.Recv(); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not exposed to reader: %v", err)
	}
}

func TestStreamInternalHeartbeatIsNotVisible(t *testing.T) {
	source, writer := schema.Pipe[*schema.Message](1)
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{stream: func(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
		return source, nil
	}}}
	ctx := WithContext(context.Background(), 10000)
	reader, err := WrapChatModel(backend, offlineModelName, 100).Stream(ctx, budgetInput())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	actual := usageMessage(42)
	go func() {
		timer := time.NewTimer(350 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		writer.Send(actual, nil)
		writer.Close()
	}()
	if got, err := reader.Recv(); err != nil || got != actual {
		t.Fatalf("internal heartbeat leaked as a visible chunk: got=%v err=%v", got, err)
	}
	if _, err := reader.Recv(); err != io.EOF {
		t.Fatal(err)
	}
}

func TestStreamStartupFailureAndPanicReleaseReservation(t *testing.T) {
	startupErr := errors.New("stream startup failed")
	for _, tc := range []struct {
		name      string
		stream    func(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error)
		wantPanic bool
	}{
		{"error", func(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
			return nil, startupErr
		}, false},
		{"nil stream", func(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
			return nil, nil
		}, false},
		{"panic", func(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
			panic("fake panic")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithContext(context.Background(), 10000)
			backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{stream: tc.stream}}
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				if _, err := WrapChatModel(backend, offlineModelName, 100).Stream(ctx, budgetInput()); err == nil {
					t.Error("startup failure returned no error")
				}
			}()
			if panicked != tc.wantPanic {
				t.Fatalf("panic propagation=%t", panicked)
			}
			if s := FromContext(ctx).Snapshot(); s.Reserved != 0 || s.Calls != 1 || !s.Estimated || s.Used != inputCost(t, budgetInput(), nil) {
				t.Fatalf("startup failure leaked reservation: %+v", s)
			}
		})
	}
}

func TestGeneratePanicReleasesReservation(t *testing.T) {
	ctx := WithContext(context.Background(), 10000)
	backend := &fakeClassic{fakeModel: fakeModel[*schema.Message]{generate: func(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
		panic("fake panic")
	}}}
	var caught any
	func() {
		defer func() { caught = recover() }()
		_, _ = WrapChatModel(backend, offlineModelName, 100).Generate(ctx, budgetInput())
	}()
	if caught != "fake panic" {
		t.Fatalf("panic swallowed/changed: %v", caught)
	}
	if s := FromContext(ctx).Snapshot(); s.Reserved != 0 || !s.Estimated || s.Used != inputCost(t, budgetInput(), nil) {
		t.Fatalf("panic leaked reservation: %+v", s)
	}
}

func TestOutputEstimateRetainsOnlyBoundedWindow(t *testing.T) {
	estimate := outputEstimate{name: offlineModelName}
	chunk := strings.Repeat("0123456789", 10000)
	for range 50 {
		estimate.add(chunk)
		if len(estimate.pending) >= outputEstimateBufferBytes || cap(estimate.pending) > outputEstimateBufferBytes {
			t.Fatalf("unbounded retained output buffer len=%d cap=%d", len(estimate.pending), cap(estimate.pending))
		}
	}
	if got, want := estimate.total(), (len(chunk)*50+2)/3; got < want || got > want+400 {
		t.Fatalf("windowed estimate drifted too far: got=%d min=%d", got, want)
	}
}
