package modelbudget

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/cloudwego/eino/schema"
)

const outputEstimateBufferBytes = 16 * 1024

// Retain at most one small tokenization window. Boundaries can overestimate
// usage; the actual streamed response is never truncated or rewritten.
type outputEstimate struct {
	name    string
	pending []byte
	count   int
}

func (e *outputEstimate) add(text string) {
	if len(text) > 0 && e.pending == nil {
		e.pending = make([]byte, 0, outputEstimateBufferBytes)
	}
	for len(text) > 0 {
		n := min(len(text), outputEstimateBufferBytes-len(e.pending))
		e.pending = append(e.pending, text[:n]...)
		text = text[n:]
		if len(e.pending) == outputEstimateBufferBytes {
			e.count = addTokenCounts(e.count, countTokens(e.name, string(e.pending)))
			e.pending = e.pending[:0]
		}
	}
}

func (e *outputEstimate) total() int {
	return addTokenCounts(e.count, countTokens(e.name, string(e.pending)))
}

type streamAccounting struct {
	mu                 sync.Mutex
	reservation        *reservation
	estimate           outputEstimate
	actual             int
	prompt, completion int
	reported, finished bool
}

func (a *streamAccounting) observe(usage *schema.TokenUsage, reported bool, text string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.finished {
		return
	}
	if reported {
		a.reported = true
		// Some providers emit prompt usage at stream start and completion usage
		// in a later event. Combine the maxima of the two cumulative components;
		// taking only max(total) would lose one side, summing events double-counts.
		a.prompt = max(a.prompt, usage.PromptTokens, usage.PromptTokenDetails.CachedTokens)
		a.completion = max(a.completion, usage.CompletionTokens, usage.CompletionTokensDetails.ReasoningTokens)
		a.actual = max(a.actual, totalUsage(usage), addTokenCounts(a.prompt, a.completion))
		a.estimate.pending = nil
	} else if !a.reported {
		a.estimate.add(text)
	}
}

func (a *streamAccounting) finish() {
	a.mu.Lock()
	if a.finished {
		a.mu.Unlock()
		return
	}
	a.finished = true
	actual, reported, estimated := a.actual, a.reported, 0
	if !reported {
		estimated = a.estimate.total()
	}
	a.estimate.pending = nil
	a.mu.Unlock()
	a.reservation.finish(actual, estimated, reported)
}

type streamPacket[M message] struct {
	message   M
	err       error
	heartbeat bool
}

type streamRead[M message] struct {
	message M
	err     error
}

func accountStream[M message](parentCtx, callCtx context.Context, cancel context.CancelFunc, source *schema.StreamReader[M], r *reservation, name string) *schema.StreamReader[M] {
	accounting := &streamAccounting{reservation: r, estimate: outputEstimate{name: name}}
	rawReader, writer := schema.Pipe[streamPacket[M]](1)
	// Cancellation and the consumer may both close this reader. Eino's ordinary
	// Pipe.Close is not idempotent; automatic-close mode supplies its atomic guard.
	rawReader.SetAutomaticClose()
	reader := schema.StreamReaderWithConvert(rawReader, func(packet streamPacket[M]) (M, error) {
		if packet.heartbeat {
			var zero M
			return zero, schema.ErrNoValue
		}
		// Carry backend errors through the conversion result. Supplying an error
		// to Pipe.Send instead would make Eino discard its accompanying message.
		return packet.message, packet.err
	}, schema.WithOnEOF(func() (any, error) {
		if err := parentCtx.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}))
	var sourceClose sync.Once
	closeSource := func() { sourceClose.Do(source.Close) }
	stopCancellation := context.AfterFunc(callCtx, func() {
		closeSource()
		rawReader.Close() // Unblocks Send if the consumer is not reading.
		accounting.finish()
	})
	received := make(chan streamRead[M], 1)
	go func() {
		defer close(received)
		usageSeen := false
		for {
			chunk, err := source.Recv()
			usage := usageOf(chunk)
			reported := usageReported(chunk, usage)
			usageSeen = usageSeen || reported
			text := ""
			if !usageSeen {
				text = outputText(chunk)
			}
			accounting.observe(usage, reported, text)
			select {
			case received <- streamRead[M]{message: chunk, err: err}:
			case <-callCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		// Eino has no StreamReader Close callback. This internal heartbeat lets
		// Send detect a consumer Close while source.Recv is idle. The converter
		// removes it before the application or UI observes any value.
		ticker := time.NewTicker(250 * time.Millisecond)
		defer func() {
			ticker.Stop()
			stopCancellation()
			cancel()
			closeSource()
			accounting.finish()
			writer.Close()
		}()
		for {
			select {
			case <-callCtx.Done():
				return
			case receivedChunk, ok := <-received:
				if !ok || (receivedChunk.err == io.EOF && receivedChunk.message == nil) {
					return
				}
				if writer.Send(streamPacket[M]{message: receivedChunk.message, err: receivedChunk.err}, nil) || receivedChunk.err != nil {
					return
				}
			case <-ticker.C:
				if writer.Send(streamPacket[M]{heartbeat: true}, nil) {
					return
				}
			}
		}
	}()
	return reader
}
