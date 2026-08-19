package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

var (
	ErrInvalidEvent    = errors.New("invalid audit event")
	ErrInvalidEmission = errors.New("invalid audit encoder emissions")
	ErrEncoding        = errors.New("audit event encoding failed")
	ErrSink            = errors.New("audit sink failed")
)

// Recorder immediately records an immutable audit event. Implementations must
// return only after the configured sink has accepted or rejected the event.
type Recorder interface {
	Record(context.Context, Event) error
}

// Emission is one serialized-log input produced from a canonical event.
type Emission struct {
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

// Encoder transforms one canonical event into one or more emissions. Returning
// no emissions is invalid so an encoder cannot silently discard audit evidence.
type Encoder interface {
	Encode(context.Context, Event) ([]Emission, error)
}

// EncoderFunc adapts a function to Encoder.
type EncoderFunc func(context.Context, Event) ([]Emission, error)

func (f EncoderFunc) Encode(ctx context.Context, event Event) ([]Emission, error) {
	return f(ctx, event)
}

// Sink acknowledges handoff of one emission. Implementations may be called
// concurrently and must not retain or mutate emission values.
type Sink interface {
	Write(context.Context, Emission) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(context.Context, Emission) error

func (f SinkFunc) Write(ctx context.Context, emission Emission) error {
	return f(ctx, emission)
}

// Record snapshots and stamps an event before encoding it under a bounded
// context detached from request cancellation. Encoder failure falls back to
// the default OpenTDF emission and is still returned to the caller.
func (a *Logger) Record(ctx context.Context, event Event) error {
	snapshot, err := snapshotEvent(event)
	if err != nil {
		return err
	}
	a.stampEvent(ctx, &snapshot)

	timeout := a.recordTimeout
	if timeout <= 0 {
		timeout = defaultRecordTimeout
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	emissions, encodeErr := a.encode(recordCtx, snapshot)
	if encodeErr != nil {
		a.diagnosticLogger().ErrorContext(recordCtx,
			"audit encoder failed; emitting default event",
			slog.Any("error", encodeErr),
		)
		var fallbackErr error
		emissions, fallbackErr = a.defaultEncode(recordCtx, snapshot)
		encodeErr = errors.Join(encodeErr, fallbackErr)
	}

	return errors.Join(encodeErr, a.writeAll(recordCtx, emissions))
}

func snapshotEvent(event Event) (snapshot Event, snapshotErr error) { //nolint:nonamedreturns // recovery must replace both values
	defer func() {
		if recovered := recover(); recovered != nil {
			snapshotErr = fmt.Errorf("%w: snapshot panic: %v", ErrInvalidEvent, recovered)
		}
	}()

	encoded, err := json.Marshal(event)
	if err != nil {
		return Event{}, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&snapshot); err != nil {
		return Event{}, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}
	snapshot.Verb = event.Verb
	snapshot.ID = event.ID
	snapshot.Phase = event.Phase
	snapshot.Principal = event.Principal
	if snapshot.Verb == "" {
		return Event{}, fmt.Errorf("%w: verb is required", ErrInvalidEvent)
	}
	return snapshot, nil
}

func (a *Logger) stampEvent(ctx context.Context, event *Event) {
	data := GetAuditDataFromContext(ctx)
	event.Principal = ctxAuth.Principal{}
	if principal, ok := ctxAuth.PrincipalFromContext(ctx); ok {
		event.Principal = principal
	}
	if event.Actor.ID == "" {
		event.Actor.ID = data.ActorID
	}
	event.RequestID = data.RequestID
	event.ClientInfo.UserAgent = data.UserAgent
	event.ClientInfo.RequestIP = data.RequestIP
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.Phase == "" {
		event.Phase = PhaseCompleted
	}
	event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
}

func (a *Logger) encode(ctx context.Context, event Event) (emissions []Emission, encodeErr error) { //nolint:nonamedreturns // recovery must replace both values
	if a.encoder == nil {
		return a.defaultEncode(ctx, event)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			emissions = nil
			encodeErr = fmt.Errorf("%w: panic: %v", ErrEncoding, recovered)
		}
	}()

	encoderEvent, err := snapshotEvent(event)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncoding, err)
	}
	emissions, err = a.encoder.Encode(ctx, encoderEvent)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncoding, err)
	}
	if err := validateEmissions(emissions); err != nil {
		return nil, errors.Join(ErrEncoding, err)
	}
	return emissions, nil
}

func validateEmissions(emissions []Emission) error {
	if len(emissions) == 0 {
		return fmt.Errorf("%w: encoder returned no emissions", ErrInvalidEmission)
	}
	for idx, emission := range emissions {
		if emission.Message == "" {
			return fmt.Errorf("%w: emission %d has no message", ErrInvalidEmission, idx)
		}
	}
	return nil
}

func (a *Logger) defaultEncode(ctx context.Context, event Event) (emissions []Emission, encodeErr error) { //nolint:nonamedreturns // recovery must replace both values
	defer func() {
		if recovered := recover(); recovered != nil {
			emissions = nil
			encodeErr = fmt.Errorf("%w: default encoder panic: %v", ErrEncoding, recovered)
		}
	}()
	return []Emission{{
		Level:   LevelAudit,
		Message: string(event.Verb),
		Attrs:   []slog.Attr{slog.Any("audit", a.buildLogEntry(ctx, &event))},
	}}, nil
}

func (a *Logger) writeAll(ctx context.Context, emissions []Emission) error {
	var writeErr error
	for idx, emission := range emissions {
		if err := a.write(ctx, emission); err != nil {
			writeErr = errors.Join(writeErr, fmt.Errorf("emission %d: %w", idx, err))
		}
	}
	return writeErr
}

func (a *Logger) write(ctx context.Context, emission Emission) (writeErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			writeErr = fmt.Errorf("%w: panic: %v", ErrSink, recovered)
		}
	}()
	emission = cloneEmission(emission)

	if a.sink != nil {
		if err := a.sink.Write(ctx, emission); err != nil {
			return fmt.Errorf("%w: %w", ErrSink, err)
		}
		return nil
	}

	handler := a.logger.Handler()
	if !handler.Enabled(ctx, emission.Level) {
		return fmt.Errorf("%w: level %s is disabled", ErrSink, emission.Level)
	}
	record := slog.NewRecord(time.Now(), emission.Level, emission.Message, 0)
	record.AddAttrs(emission.Attrs...)
	if err := handler.Handle(ctx, record); err != nil {
		return fmt.Errorf("%w: %w", ErrSink, err)
	}
	return nil
}

func cloneEmission(emission Emission) Emission {
	cloned := emission
	cloned.Attrs = make([]slog.Attr, len(emission.Attrs))
	for idx, attr := range emission.Attrs {
		cloned.Attrs[idx] = cloneAttr(attr)
	}
	return cloned
}

func cloneAttr(attr slog.Attr) slog.Attr {
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		group := value.Group()
		cloned := make([]slog.Attr, len(group))
		for idx, nested := range group {
			cloned[idx] = cloneAttr(nested)
		}
		return slog.Attr{Key: attr.Key, Value: slog.GroupValue(cloned...)}
	}
	if value.Kind() == slog.KindAny {
		return slog.Any(attr.Key, normalizeAuditValue(value.Any()))
	}
	return slog.Attr{Key: attr.Key, Value: value}
}

func (a *Logger) diagnosticLogger() *slog.Logger {
	if a.diagnostics != nil {
		return a.diagnostics
	}
	return slog.Default()
}
