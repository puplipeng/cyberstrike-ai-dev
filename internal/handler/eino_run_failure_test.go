package handler

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"cyberstrike-ai/internal/multiagent"

	"github.com/cloudwego/eino/adk"
)

func TestEinoRunFailureMessagePreservesIterationLimitPartial(t *testing.T) {
	err := fmt.Errorf("run node[ChatModel] pre processor fail: %w", adk.ErrExceedMaxIterations)
	got := einoRunFailureMessage(&multiagent.RunResult{Response: "已完成前 30 轮检查。"}, err)
	if !strings.Contains(got, "已完成前 30 轮检查") {
		t.Fatalf("partial response was lost: %q", got)
	}
	if !strings.Contains(got, "任务暂停") || !strings.Contains(got, "继续") {
		t.Fatalf("missing actionable iteration-limit notice: %q", got)
	}
	if strings.Contains(got, "NodeRunError") || strings.Contains(got, "node[ChatModel]") {
		t.Fatalf("internal Eino error leaked to user: %q", got)
	}
}

func TestEinoRunFailureMessageKeepsNormalFailureShape(t *testing.T) {
	got := einoRunFailureMessage(nil, fmt.Errorf("provider unavailable"))
	if got != "执行失败: provider unavailable" {
		t.Fatalf("message = %q", got)
	}
}

func TestEinoRunFailureMessageIsIdempotentWithoutDroppingPartial(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", adk.ErrExceedMaxIterations)
	first := einoRunFailureMessage(&multiagent.RunResult{Response: "阶段结果"}, err)
	second := einoRunFailureMessage(&multiagent.RunResult{Response: first}, err)
	if second != first {
		t.Fatalf("second formatting changed content:\nfirst=%q\nsecond=%q", first, second)
	}
	if !strings.Contains(second, "阶段结果") {
		t.Fatalf("partial response was dropped: %q", second)
	}
}

func TestEinoRunFailureErrorHidesFrameworkTextAndPreservesCause(t *testing.T) {
	raw := fmt.Errorf("node path [ChatModel]: %w", adk.ErrExceedMaxIterations)
	wrapped := einoRunFailureError(raw)
	if !errors.Is(wrapped, adk.ErrExceedMaxIterations) {
		t.Fatalf("wrapped error lost cause: %v", wrapped)
	}
	if strings.Contains(wrapped.Error(), "node path") || strings.Contains(wrapped.Error(), "ChatModel") {
		t.Fatalf("wrapped error leaked framework text: %q", wrapped.Error())
	}
}
