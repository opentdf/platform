package audit

import (
	"context"
	"encoding/json"
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
			"count": jsonNumber("9007199254740993"),
			"owner": map[string]any{"id": "org-1"},
		},
		ClientInfo: ClientInfo{Platform: "test"},
	}
}

type jsonNumber string

func (n jsonNumber) MarshalJSON() ([]byte, error) {
	return []byte(n), nil
}

func TestRecordUsesBoundedContextAfterRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(createTestContext(t))
	cancel()

	var encoded Event
	encoder := EncoderFunc(func(ctx context.Context, event Event) ([]Emission, error) {
		require.NoError(t, ctx.Err())
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), time.Second)
		encoded = event
		return []Emission{{Level: LevelAudit, Message: "encoded"}}, nil
	})
	writes := 0
	sink := SinkFunc(func(ctx context.Context, emission Emission) error {
		require.NoError(t, ctx.Err())
		assert.Equal(t, "encoded", emission.Message)
		writes++
		return nil
	})
	logger := CreateAuditLogger(*slog.Default(), WithEncoder(encoder), WithSink(sink), WithRecordTimeout(time.Second))

	err := logger.Record(ctx, canonicalTestEvent())

	require.NoError(t, err)
	assert.Equal(t, 1, writes)
	assert.NotEqual(t, uuid.Nil, encoded.ID)
	assert.Equal(t, PhaseCompleted, encoded.Phase)
	assert.Equal(t, TestRequestID, encoded.RequestID)
	assert.Equal(t, TestActorID, encoded.Actor.ID)
}

func TestRecordEncoderFailureFallsBackAndReturnsError(t *testing.T) {
	encoderErr := errors.New("conversion failed")
	encoder := EncoderFunc(func(context.Context, Event) ([]Emission, error) {
		return nil, encoderErr
	})
	var captured Emission
	sink := SinkFunc(func(_ context.Context, emission Emission) error {
		captured = emission
		return nil
	})
	logger := CreateAuditLogger(*slog.Default(), WithEncoder(encoder), WithSink(sink))

	err := logger.Record(createTestContext(t), canonicalTestEvent())

	require.ErrorIs(t, err, ErrEncoding)
	require.ErrorIs(t, err, encoderErr)
	assert.Equal(t, "read", captured.Message)
	require.Len(t, captured.Attrs, 1)
	assert.Equal(t, "audit", captured.Attrs[0].Key)
}

func TestRecordEncoderCannotMutateFallbackEvent(t *testing.T) {
	encoder := EncoderFunc(func(_ context.Context, event Event) ([]Emission, error) {
		event.Object.ID = "mutated"
		owner, ok := event.EventMetaData["owner"].(map[string]any)
		require.True(t, ok)
		owner["id"] = "mutated"
		return nil, errors.New("conversion failed")
	})
	var payload map[string]any
	sink := SinkFunc(func(_ context.Context, emission Emission) error {
		var ok bool
		payload, ok = emission.Attrs[0].Value.Any().(map[string]any)
		require.True(t, ok)
		return nil
	})
	logger := CreateAuditLogger(*slog.Default(), WithEncoder(encoder), WithSink(sink))

	err := logger.Record(createTestContext(t), canonicalTestEvent())

	require.ErrorIs(t, err, ErrEncoding)
	assert.Equal(t, "document-1", requireMap(t, payload["object"])["id"])
	assert.Equal(t, "org-1", requireMap(t, requireMap(t, payload["eventMetaData"])["owner"])["id"])
}

func TestRecordRejectsSilentEncoderDrop(t *testing.T) {
	encoder := EncoderFunc(func(context.Context, Event) ([]Emission, error) {
		return nil, nil
	})
	writes := 0
	logger := CreateAuditLogger(*slog.Default(), WithEncoder(encoder), WithSink(SinkFunc(
		func(context.Context, Emission) error {
			writes++
			return nil
		},
	)))

	err := logger.Record(createTestContext(t), canonicalTestEvent())

	require.ErrorIs(t, err, ErrInvalidEmission)
	assert.Equal(t, 1, writes, "default fallback must preserve the event")
}

func TestRecordAttemptsEveryEmissionAndReturnsSinkFailures(t *testing.T) {
	encoder := EncoderFunc(func(context.Context, Event) ([]Emission, error) {
		return []Emission{
			{Level: LevelAudit, Message: "partition-1"},
			{Level: LevelAudit, Message: "partition-2"},
		}, nil
	})
	var messages []string
	sink := SinkFunc(func(_ context.Context, emission Emission) error {
		messages = append(messages, emission.Message)
		if emission.Message == "partition-1" {
			return errors.New("first partition unavailable")
		}
		return nil
	})
	logger := CreateAuditLogger(*slog.Default(), WithEncoder(encoder), WithSink(sink))

	err := logger.Record(createTestContext(t), canonicalTestEvent())

	require.ErrorIs(t, err, ErrSink)
	assert.Equal(t, []string{"partition-1", "partition-2"}, messages)
}

func TestRecordReturnsSinkPanic(t *testing.T) {
	logger := CreateAuditLogger(*slog.Default(), WithSink(SinkFunc(func(context.Context, Emission) error {
		panic("sink panic")
	})))

	err := logger.Record(createTestContext(t), canonicalTestEvent())

	require.ErrorIs(t, err, ErrSink)
	require.ErrorContains(t, err, "sink panic")
}

func TestRecordSnapshotsCallerData(t *testing.T) {
	event := canonicalTestEvent()
	var captured Event
	logger := CreateAuditLogger(*slog.Default(), WithEncoder(EncoderFunc(
		func(_ context.Context, event Event) ([]Emission, error) {
			captured = event
			return []Emission{{Level: LevelAudit, Message: "encoded"}}, nil
		},
	)), WithSink(SinkFunc(func(context.Context, Emission) error { return nil })))

	require.NoError(t, logger.Record(createTestContext(t), event))
	event.Object.ID = "mutated"
	eventOwner, ok := event.EventMetaData["owner"].(map[string]any)
	require.True(t, ok)
	eventOwner["id"] = "mutated"

	assert.Equal(t, "document-1", captured.Object.ID)
	capturedOwner, ok := captured.EventMetaData["owner"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "org-1", capturedOwner["id"])
	capturedCount, ok := captured.EventMetaData["count"].(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", capturedCount.String())
}

func TestRecordDoesNotTrustProducerPrincipal(t *testing.T) {
	event := canonicalTestEvent()
	event.Principal = ctxAuth.Principal{Subject: "producer-supplied"}
	var captured Event
	logger := CreateAuditLogger(*slog.Default(), WithEncoder(EncoderFunc(
		func(_ context.Context, event Event) ([]Emission, error) {
			captured = event
			return []Emission{{Level: LevelAudit, Message: "encoded"}}, nil
		},
	)), WithSink(SinkFunc(func(context.Context, Emission) error { return nil })))

	require.NoError(t, logger.Record(createTestContext(t), event))

	assert.Empty(t, captured.Principal)
}

func TestRecordIsSafeForConcurrentUse(t *testing.T) {
	const count = 50
	var (
		mu  sync.Mutex
		ids = make(map[uuid.UUID]struct{}, count)
	)
	encoder := EncoderFunc(func(_ context.Context, event Event) ([]Emission, error) {
		mu.Lock()
		ids[event.ID] = struct{}{}
		mu.Unlock()
		return []Emission{{Level: LevelAudit, Message: "encoded"}}, nil
	})
	logger := CreateAuditLogger(*slog.Default(), WithEncoder(encoder), WithSink(SinkFunc(func(context.Context, Emission) error { return nil })))

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

func TestLoggerWithRetainsAuditPipeline(t *testing.T) {
	encoder := EncoderFunc(func(context.Context, Event) ([]Emission, error) {
		return []Emission{{Level: LevelAudit, Message: "encoded"}}, nil
	})
	sink := SinkFunc(func(context.Context, Emission) error { return nil })
	logger := CreateAuditLogger(*slog.Default(), WithEncoder(encoder), WithSink(sink))

	child := logger.With("namespace", "extension")

	assert.NotNil(t, child.Encoder())
	assert.NotNil(t, child.Sink())
}

func TestDefaultEncoderPreservesLegacyWireShape(t *testing.T) {
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
}
