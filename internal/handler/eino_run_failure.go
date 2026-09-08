package handler

import "cyberstrike-ai/internal/multiagent"

type einoUserFacingRunError struct {
	message string
	cause   error
}

func (e *einoUserFacingRunError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func (e *einoUserFacingRunError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// einoRunFailureMessage keeps useful partial output when an Eino run stops at
// its iteration guard. Other failures retain the existing compact error form.
func einoRunFailureMessage(result *multiagent.RunResult, runErr error) string {
	return multiagent.EinoRunFailureMessage(result, runErr)
}

func einoRunFailureError(runErr error) error {
	if runErr == nil {
		return nil
	}
	return &einoUserFacingRunError{
		message: multiagent.EinoClientRunErrorMessage(runErr),
		cause:   runErr,
	}
}
