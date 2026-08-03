package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// ErrInvalidProcessResult indicates that a processor result cannot be emitted safely.
var ErrInvalidProcessResult = errors.New("invalid audit processor result")

// FinalizedEvent is the immutable processor input after request outcome and
// configured JWT enrichment have been applied. Event retains the authoritative
// producer fields; Audit is the enriched default OpenTDF payload.
type FinalizedEvent struct {
	Verb  Verb
	Event RecordedEvent
	Audit map[string]any
}

// Emission describes one slog record produced by an audit processor.
type Emission struct {
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

// ProcessResult contains all emissions for one finalized event. Drop must be
// explicitly true to intentionally produce no output.
type ProcessResult struct {
	Emissions []Emission
	Drop      bool
}

// Processor transforms finalized audit events. Implementations may be called
// concurrently and must not mutate their input or retain aliases to it.
type Processor interface {
	Process(context.Context, FinalizedEvent) (ProcessResult, error)
}

// ProcessorFunc adapts a function to Processor.
type ProcessorFunc func(context.Context, FinalizedEvent) (ProcessResult, error)

func (f ProcessorFunc) Process(ctx context.Context, event FinalizedEvent) (ProcessResult, error) {
	return f(ctx, event)
}

type defaultProcessor struct{}

func (defaultProcessor) Process(_ context.Context, event FinalizedEvent) (ProcessResult, error) {
	return ProcessResult{Emissions: []Emission{{
		Level:   LevelAudit,
		Message: string(event.Verb),
		Attrs:   []slog.Attr{slog.Any("audit", event.Audit)},
	}}}, nil
}

func processEvent(ctx context.Context, processor Processor, event FinalizedEvent) (ProcessResult, error) {
	var result ProcessResult
	var processErr error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				processErr = fmt.Errorf("audit processor panic: %v", recovered)
				result = ProcessResult{}
			}
		}()
		result, processErr = processor.Process(context.WithoutCancel(ctx), cloneFinalizedEvent(event))
	}()
	return result, processErr
}

func validateProcessResult(result ProcessResult) error {
	if result.Drop {
		if len(result.Emissions) != 0 {
			return fmt.Errorf("%w: drop cannot include emissions", ErrInvalidProcessResult)
		}
		return nil
	}
	if len(result.Emissions) == 0 {
		return fmt.Errorf("%w: empty emissions require explicit drop", ErrInvalidProcessResult)
	}
	for idx, emission := range result.Emissions {
		if emission.Level < LevelAudit {
			return fmt.Errorf("%w: emission %d level %s is filtered by the audit handler", ErrInvalidProcessResult, idx, emission.Level)
		}
	}
	return nil
}

func cloneFinalizedEvent(event FinalizedEvent) FinalizedEvent {
	auditMap, _ := normalizeAuditValue(event.Audit).(map[string]any)
	return FinalizedEvent{
		Verb:  event.Verb,
		Event: cloneRecordedEvent(event.Event),
		Audit: auditMap,
	}
}
