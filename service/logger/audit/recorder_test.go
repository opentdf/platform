package audit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func canonicalTestEvent() Event {
	return Event{
		Verb:   Verb("read"),
		Object: Object{Type: "document", ID: "document-1"},
		Action: Action{Type: "read", Result: "success"},
		EventMetaData: EventMetadata{
			"owner": map[string]any{"id": "org-1"},
		},
		ClientInfo: ClientInfo{Platform: "test"},
	}
}

func quietDiagnostics() Option {
	return WithDiagnosticLogger(slog.New(slog.DiscardHandler))
}

func TestRecordUsesBoundedContextAfterRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(createTestContext(t))
	cancel()

	var processed Event
	processor := ProcessorFunc(func(ctx context.Context, event Event) error {
		require.NoError(t, ctx.Err())
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), time.Second)
		processed = event
		return nil
	})
	logger := CreateAuditLogger(*slog.Default(), WithProcessor(processor), WithRecordTimeout(time.Second))

	require.NoError(t, logger.Record(ctx, canonicalTestEvent()))
	assert.NotEqual(t, uuid.Nil, processed.ID)
	assert.Equal(t, PhaseCompleted, processed.Phase)
	assert.Equal(t, TestRequestID, processed.RequestID)
	assert.Equal(t, TestActorID, processed.Actor.ID)
	_, err := time.Parse(time.RFC3339, processed.Timestamp)
	require.NoError(t, err)
}

func TestRecordStampsItsEventCopy(t *testing.T) {
	event := canonicalTestEvent()
	var processed Event
	logger := CreateAuditLogger(*slog.Default(), WithProcessor(ProcessorFunc(
		func(_ context.Context, event Event) error {
			processed = event
			return nil
		},
	)))

	require.NoError(t, logger.Record(createTestContext(t), event))

	assert.Equal(t, uuid.Nil, event.ID)
	assert.Empty(t, event.Phase)
	assert.Empty(t, event.RequestID)
	assert.Empty(t, event.Timestamp)
	assert.NotEqual(t, uuid.Nil, processed.ID)
	assert.Equal(t, PhaseCompleted, processed.Phase)
}

func TestRecordRejectsInvalidRequiredFieldsBeforeProcessing(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "verb", mutate: func(event *Event) { event.Verb = " " }},
		{name: "object type", mutate: func(event *Event) { event.Object.Type = " " }},
		{name: "action type", mutate: func(event *Event) { event.Action.Type = " " }},
		{name: "action result", mutate: func(event *Event) { event.Action.Result = " " }},
		{name: "client platform", mutate: func(event *Event) { event.ClientInfo.Platform = " " }},
		{name: "phase", mutate: func(event *Event) { event.Phase = Phase("unknown") }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := canonicalTestEvent()
			test.mutate(&event)
			calls := 0
			logger := CreateAuditLogger(*slog.Default(), WithProcessor(ProcessorFunc(
				func(context.Context, Event) error {
					calls++
					return nil
				},
			)))

			err := logger.Record(t.Context(), event)

			require.ErrorIs(t, err, ErrInvalidEvent)
			assert.Zero(t, calls)
		})
	}
}

func TestRecordAllowsOptionalFieldsToBeEmpty(t *testing.T) {
	event := canonicalTestEvent()
	event.Object.ID = ""
	event.Actor = Actor{}
	event.EventMetaData = nil
	event.Original = nil
	event.Updated = nil

	processed := false
	logger := CreateAuditLogger(*slog.Default(), WithProcessor(ProcessorFunc(
		func(_ context.Context, event Event) error {
			processed = true
			assert.Empty(t, event.Object.ID)
			return nil
		},
	)))

	require.NoError(t, logger.Record(t.Context(), event))
	assert.True(t, processed)
}

func TestRecordReturnsProcessorErrorWithoutFallback(t *testing.T) {
	processorErr := errors.New("delivery unavailable")
	logger, buffer := createTestLogger()
	logger.processor = ProcessorFunc(func(context.Context, Event) error { return processorErr })
	logger.diagnostics = slog.New(slog.DiscardHandler)

	err := logger.Record(createTestContext(t), canonicalTestEvent())

	require.ErrorIs(t, err, ErrProcessing)
	require.ErrorIs(t, err, processorErr)
	assert.Empty(t, buffer.String())
}

func TestRecordReturnsProcessorPanic(t *testing.T) {
	logger := CreateAuditLogger(*slog.Default(), WithProcessor(ProcessorFunc(func(context.Context, Event) error {
		panic("processor panic")
	})), quietDiagnostics())

	err := logger.Record(createTestContext(t), canonicalTestEvent())

	require.ErrorIs(t, err, ErrProcessing)
	require.ErrorContains(t, err, "processor panic")
}

func TestRecordReturnsProcessorDeadline(t *testing.T) {
	processor := ProcessorFunc(func(ctx context.Context, _ Event) error {
		<-ctx.Done()
		return ctx.Err()
	})
	logger := CreateAuditLogger(*slog.Default(), WithProcessor(processor), WithRecordTimeout(time.Millisecond), quietDiagnostics())

	err := logger.Record(t.Context(), canonicalTestEvent())

	require.ErrorIs(t, err, ErrProcessing)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRecordDoesNotTrustProducerPrincipal(t *testing.T) {
	event := canonicalTestEvent()
	event.Principal = ctxAuth.Principal{Subject: "producer-supplied"}
	var processed Event
	logger := CreateAuditLogger(*slog.Default(), WithProcessor(ProcessorFunc(
		func(_ context.Context, event Event) error {
			processed = event
			return nil
		},
	)))

	require.NoError(t, logger.Record(t.Context(), event))
	assert.Empty(t, processed.Principal)
}

func TestRecordIsSafeForConcurrentUse(t *testing.T) {
	const count = 50
	var (
		mu  sync.Mutex
		ids = make(map[uuid.UUID]struct{}, count)
	)
	processor := ProcessorFunc(func(_ context.Context, event Event) error {
		mu.Lock()
		ids[event.ID] = struct{}{}
		mu.Unlock()
		return nil
	})
	logger := CreateAuditLogger(*slog.Default(), WithProcessor(processor))

	var wg sync.WaitGroup
	errs := make(chan error, count)
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- logger.Record(createTestContext(t), canonicalTestEvent())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Len(t, ids, count)
}

func TestLoggerWithRetainsAuditProcessor(t *testing.T) {
	processor := ProcessorFunc(func(context.Context, Event) error { return nil })
	logger := CreateAuditLogger(*slog.Default(), WithProcessor(processor))

	child := logger.With("namespace", "extension")

	assert.NotNil(t, child.Processor())
}

func TestDefaultProcessorPreservesLegacyWireShape(t *testing.T) {
	logger, buffer := createTestLogger()

	require.NoError(t, logger.Record(createTestContext(t), canonicalTestEvent()))
	entry, _ := extractLogEntry(t, buffer)
	payload := decodeAuditPayload(t, entry.Audit)

	assert.Equal(t, LevelAuditStr, entry.Level)
	assert.Equal(t, "read", entry.Msg)
	assert.Equal(t, "document-1", requireMap(t, payload["object"])["id"])
	assert.Equal(t, "success", requireMap(t, payload["action"])["result"])
	assert.NotContains(t, payload, "id", "recorder lifecycle ID is not part of the legacy wire payload")
	assert.NotContains(t, payload, "phase", "recorder phase is not part of the legacy wire payload")
	timestamp, ok := payload["timestamp"].(string)
	require.True(t, ok)
	_, err := time.Parse(time.RFC3339, timestamp)
	require.NoError(t, err)
}
