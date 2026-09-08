package multiagent

import "strings"

// EinoRunFailureMessage formats a terminal run error for user-facing surfaces.
// When the ReAct guard stops a long run, retain the latest partial answer and
// present the stop as resumable instead of exposing Eino's node wrapper.
func EinoRunFailureMessage(result *RunResult, runErr error) string {
	clientMessage := strings.TrimSpace(EinoClientRunErrorMessage(runErr))
	if !IsEinoIterationLimitError(runErr) {
		return "执行失败: " + clientMessage
	}

	notice := "任务暂停：" + clientMessage
	if result == nil || IsEinoEmptyResponseResult(result) {
		return notice
	}
	partial := strings.TrimSpace(result.Response)
	if partial == "" {
		return notice
	}
	if strings.Contains(partial, notice) {
		return partial
	}
	return partial + "\n\n---\n\n" + notice
}
