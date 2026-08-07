package audit

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordEmitsGenericEventWithDefaultWireShape(t *testing.T) {
	event := RecordedEvent{
		Object: RecordedObject{
			Type: "external_resource",
			ID:   "resource-1",
		},
		Action: RecordedAction{
			Type:   "share",
			Result: "success",
		},
		Actor: RecordedActor{
			ID:         "actor-1",
			Attributes: []any{"member"},
		},
		EventMetaData: map[string]any{"owner": map[string]any{"id": "org-1"}},
		ClientInfo: RecordedClientInfo{
			Platform: "external-service",
		},
	}

	logEntry, _ := doWithLogger(t, nil, func(ctx context.Context, logger *Logger) {
		require.NoError(t, logger.Record(ctx, Verb("share"), event))
		event.Object.ID = "mutated"
		event.Actor.Attributes[0] = "mutated"
		owner, ok := event.EventMetaData["owner"].(map[string]any)
		require.True(t, ok)
		owner["id"] = "mutated"
	})

	require.Equal(t, "share", logEntry.Msg)
	payload := decodeAuditPayload(t, logEntry.Audit)
	require.Equal(t, "resource-1", nestedString(payload, "object", "id"))
	require.Equal(t, []any{"member"}, nestedAnySlice(payload, "actor", "attributes"))
	require.Equal(t, "org-1", nestedString(payload, "eventMetaData", "owner", "id"))
}

func TestRecordReturnsTypedErrors(t *testing.T) {
	logger, _ := createTestLogger()
	event := RecordedEvent{Object: RecordedObject{Type: "external_resource"}}

	err := logger.Record(t.Context(), Verb("read"), event)
	require.ErrorIs(t, err, ErrNoTransaction)
	require.ErrorIs(t, logger.Record(createTestContext(t), "", event), ErrInvalidEvent)

	ctx := createTestContext(t)
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok)
	tx.logClose(ctx, logger, true, nil)
	err = logger.Record(ctx, Verb("read"), event)
	require.ErrorIs(t, err, ErrTransactionClosed)

	var nilLogger *Logger
	err = nilLogger.Record(ctx, Verb("read"), event)
	require.ErrorIs(t, err, ErrInvalidEvent)
}

func TestRecordReturnsInvalidEventForPanickingValue(t *testing.T) {
	logger, _ := createTestLogger()
	ctx := createTestContext(t)
	event := RecordedEvent{EventMetaData: map[string]any{"bad": panickingJSONValue{}}}

	err := logger.Record(ctx, Verb("read"), event)
	require.ErrorIs(t, err, ErrInvalidEvent)
}

func TestRecordPreservesLargeNumericMetadata(t *testing.T) {
	logger, buffer := createTestLogger()
	ctx := createTestContext(t)
	event := RecordedEvent{EventMetaData: map[string]any{"sequence": uint64(math.MaxUint64)}}
	require.NoError(t, logger.Record(ctx, Verb("read"), event))

	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok)
	require.Equal(t, json.Number("18446744073709551615"), tx.events[0].event.EventMetaData["sequence"])
	tx.logClose(ctx, logger, true, nil)
	require.Contains(t, buffer.String(), `"sequence":18446744073709551615`)
}

type panickingJSONValue struct{}

func (panickingJSONValue) MarshalJSON() ([]byte, error) {
	panic("cannot serialize")
}

func TestRecordCancellationDoesNotMutateCaller(t *testing.T) {
	logger, buffer := createTestLogger()
	ctx := createTestContext(t)
	event := RecordedEvent{
		Action:        RecordedAction{Type: "write", Result: "success"},
		EventMetaData: map[string]any{"existing": true},
	}
	require.NoError(t, logger.Record(ctx, Verb("write"), event))

	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok)
	tx.logClose(ctx, logger, false, errors.New("request failed"))

	entry, _ := extractLogEntry(t, buffer)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(entry.Audit, &payload))
	require.Equal(t, ActionResultCancel.String(), nestedString(payload, "action", "result"))
	require.Equal(t, "request failed", nestedString(payload, "eventMetaData", "cancellation_error"))
	require.Equal(t, "success", event.Action.Result)
	_, present := event.EventMetaData["cancellation_error"]
	require.False(t, present)
}
