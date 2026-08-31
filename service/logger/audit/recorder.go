package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

var (
	ErrInvalidEvent = errors.New("invalid audit event")
	ErrProcessing   = errors.New("audit event processing failed")
)

// Recorder immediately records an immutable audit event. Implementations must
// return only after the configured processor has accepted or rejected the event.
type Recorder interface {
	Record(context.Context, Event) error
}

// Processor accepts a fully stamped event. Processors own destination-specific
// validation, fan-out, delivery, and recovery. A nil error means the event was
// accepted by the intended destination or a durable recovery path.
//
// Implementations may be called concurrently and must honor context cancellation.
type Processor interface {
	Process(context.Context, Event) error
}

// ProcessorFunc adapts a function to Processor.
type ProcessorFunc func(context.Context, Event) error

func (f ProcessorFunc) Process(ctx context.Context, event Event) error {
	return f(ctx, event)
}

// Record snapshots, stamps, and validates an event before processing it under a
// bounded context detached from request cancellation.
func (a *Logger) Record(ctx context.Context, event Event) error {
	snapshot, err := snapshotEvent(event)
	if err != nil {
		return err
	}
	a.stampEvent(ctx, &snapshot)
	if err := validateEvent(snapshot); err != nil {
		return err
	}

	timeout := a.recordTimeout
	if timeout <= 0 {
		timeout = defaultRecordTimeout
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	if err := a.process(recordCtx, snapshot); err != nil {
		a.diagnosticLogger().Error("audit processor failed", slog.Any("error", err))
		return err
	}
	return nil
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
	event.Timestamp = time.Now().Format(time.RFC3339)
}

func validateEvent(event Event) error {
	required := []struct {
		name  string
		value string
	}{
		{name: "verb", value: string(event.Verb)},
		{name: "object type", value: event.Object.Type},
		{name: "action type", value: event.Action.Type},
		{name: "action result", value: event.Action.Result},
		{name: "client platform", value: event.ClientInfo.Platform},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidEvent, field.name)
		}
	}
	if event.ID == uuid.Nil {
		return fmt.Errorf("%w: id is required", ErrInvalidEvent)
	}
	if event.Phase != PhaseAttempted && event.Phase != PhaseCompleted {
		return fmt.Errorf("%w: invalid phase %q", ErrInvalidEvent, event.Phase)
	}
	if _, err := time.Parse(time.RFC3339, event.Timestamp); err != nil {
		return fmt.Errorf("%w: invalid timestamp: %w", ErrInvalidEvent, err)
	}
	return nil
}

func (a *Logger) process(ctx context.Context, event Event) (processErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			processErr = fmt.Errorf("%w: panic: %v", ErrProcessing, recovered)
		}
	}()

	if a.processor == nil {
		return a.defaultProcess(ctx, event)
	}
	if err := a.processor.Process(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrProcessing, err)
	}
	return nil
}

func (a *Logger) defaultProcess(ctx context.Context, event Event) error {
	handler := a.logger.Handler()
	if !handler.Enabled(ctx, LevelAudit) {
		return fmt.Errorf("%w: level %s is disabled", ErrProcessing, LevelAudit)
	}
	record := slog.NewRecord(time.Now(), LevelAudit, string(event.Verb), 0)
	record.AddAttrs(slog.Any("audit", a.buildLogEntry(ctx, &event)))
	if err := handler.Handle(ctx, record); err != nil {
		return fmt.Errorf("%w: %w", ErrProcessing, err)
	}
	return nil
}

func (a *Logger) diagnosticLogger() *slog.Logger {
	if a.diagnostics != nil {
		return a.diagnostics
	}
	return slog.Default()
}
