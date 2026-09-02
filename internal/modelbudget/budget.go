// Package modelbudget limits new model calls using shared per-run accounting.
// It is not a billing meter: unreported usage is estimated, and providers can
// finish an in-flight request above its estimate or advisory output budget.
package modelbudget

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var ErrExceeded = errors.New("task token budget exhausted")

const exceededMarker = "[task_token_budget_exhausted]"

// IsExceeded also recognizes SDK errors that retain only the error text.
func IsExceeded(err error) bool {
	return err != nil && (errors.Is(err, ErrExceeded) ||
		strings.Contains(err.Error(), exceededMarker) ||
		strings.Contains(err.Error(), ErrExceeded.Error()))
}

type ExceededError struct{ Limit, Used, Reserved, NextInput int }

func (e *ExceededError) Error() string {
	return fmt.Sprintf("%s 任务 Token 预算不足：上限 %d，已用 %d，在途预留 %d，下次输入预计 %d。已停止新的模型调用，请调整任务预算后继续。", exceededMarker, e.Limit, e.Used, e.Reserved, e.NextInput)
}
func (*ExceededError) Unwrap() error { return ErrExceeded }

type Snapshot struct {
	Limit     int  `json:"limit"`
	Used      int  `json:"used"`
	Reserved  int  `json:"reserved"`
	Calls     int  `json:"calls"`
	Estimated bool `json:"estimated"`
	Stopped   bool `json:"stopped"`
}

type Tracker struct {
	mu       sync.Mutex
	snapshot Snapshot
	warned   bool
	notify   func(Snapshot)
}
type contextKey struct{}

// WithContext keeps an existing tracker when a run starts child agents/retries.
// limit<=0 disables tracking only when there is no parent tracker.
func WithContext(ctx context.Context, limit int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if FromContext(ctx) != nil || limit <= 0 {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, &Tracker{snapshot: Snapshot{Limit: limit}})
}

// WithSnapshot resumes settled usage from a persisted workflow checkpoint.
// There are no requests in flight across an HTTP resume, and the current
// configured limit takes precedence over the checkpoint's previous limit.
func WithSnapshot(ctx context.Context, limit int, snapshot Snapshot) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if FromContext(ctx) != nil || limit <= 0 {
		return ctx
	}
	used := max(snapshot.Used, 0)
	return context.WithValue(ctx, contextKey{}, &Tracker{snapshot: Snapshot{
		Limit: limit, Used: used, Calls: max(snapshot.Calls, 0),
		Estimated: snapshot.Estimated, Stopped: used >= limit,
	}})
}

func FromContext(ctx context.Context) *Tracker {
	if ctx == nil {
		return nil
	}
	t, _ := ctx.Value(contextKey{}).(*Tracker)
	return t
}

func (t *Tracker) Snapshot() Snapshot {
	if t == nil {
		return Snapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshot
}

func (t *Tracker) SetNotify(fn func(Snapshot)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.notify = fn
	t.mu.Unlock()
}

type reservation struct {
	tracker         *Tracker
	reserved, input int
	once            sync.Once
}

func (t *Tracker) reserve(input, output int) (*reservation, int, error) {
	if t == nil {
		return nil, output, nil
	}
	if input < 1 {
		input = 1
	}
	if output < 1 {
		output = 1
	}
	t.mu.Lock()
	available := max(0, t.snapshot.Limit-addTokenCounts(t.snapshot.Used, t.snapshot.Reserved))
	if available <= input {
		t.snapshot.Stopped = true
		s, fn := t.snapshot, t.notify
		t.mu.Unlock()
		if fn != nil {
			fn(s)
		}
		return nil, 0, &ExceededError{Limit: s.Limit, Used: s.Used, Reserved: s.Reserved, NextInput: input}
	}
	if output > available-input {
		output = available - input
	}
	r := &reservation{tracker: t, input: input, reserved: input + output}
	t.snapshot.Reserved += r.reserved
	t.snapshot.Calls++
	t.mu.Unlock()
	return r, output, nil
}

func (r *reservation) finish(actual, estimatedOutput int, reported bool) {
	if r == nil {
		return
	}
	r.once.Do(func() {
		t := r.tracker
		t.mu.Lock()
		t.snapshot.Reserved -= r.reserved
		if reported {
			t.snapshot.Used = addTokenCounts(t.snapshot.Used, actual)
		} else {
			t.snapshot.Used = addTokenCounts(t.snapshot.Used, addTokenCounts(r.input, estimatedOutput))
			t.snapshot.Estimated = true
		}
		s, fn := t.snapshot, t.notify
		threshold := (s.Limit/5)*4 + (s.Limit%5)*4/5
		warn := !t.warned && s.Used >= threshold
		if warn {
			t.warned = true
		}
		t.mu.Unlock()
		if warn && fn != nil {
			fn(s)
		}
	})
}

// Saturation makes malformed/very large usage fail closed rather than wrap
// around to a negative counter and allow more calls.
func addTokenCounts(a, b int) int {
	a, b = max(a, 0), max(b, 0)
	maxInt := int(^uint(0) >> 1)
	if b > maxInt-a {
		return maxInt
	}
	return a + b
}
