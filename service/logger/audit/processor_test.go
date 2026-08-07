package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/require"
)

func createProcessorTestLogger(processor Processor) (*Logger, *bytes.Buffer, *bytes.Buffer) {
	var auditBuffer bytes.Buffer
	var diagnosticBuffer bytes.Buffer
	auditHandler := slog.NewJSONHandler(&auditBuffer, &slog.HandlerOptions{
		Level:       LevelAudit,
		ReplaceAttr: ReplaceAttrAuditLevel,
	})
	diagnosticHandler := slog.NewJSONHandler(&diagnosticBuffer, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := CreateAuditLogger(
		*slog.New(auditHandler),
		WithProcessor(processor),
		WithDiagnosticLogger(slog.New(diagnosticHandler)),
	)
	return logger, &auditBuffer, &diagnosticBuffer
}

func recordedTestEvent() RecordedEvent {
	return RecordedEvent{
		Object: RecordedObject{Type: "resource", ID: "resource-1"},
		Action: RecordedAction{Type: "read", Result: "success"},
		EventMetaData: map[string]any{
			"owner": map[string]any{"id": "org-1"},
		},
	}
}

func closeRecordedEvent(t *testing.T, logger *Logger) {
	t.Helper()
	ctx := createTestContext(t)
	require.NoError(t, logger.Record(ctx, Verb("read"), recordedTestEvent()))
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok)
	tx.logClose(ctx, logger, true, nil)
}

func decodeJSONLines(t *testing.T, buffer *bytes.Buffer) []map[string]any {
	t.Helper()
	var entries []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(buffer.Bytes()))
	for scanner.Scan() {
		var entry map[string]any
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &entry))
		entries = append(entries, entry)
	}
	require.NoError(t, scanner.Err())
	return entries
}

func TestProcessorEmitsManyInOrder(t *testing.T) {
	processor := ProcessorFunc(func(_ context.Context, event FinalizedEvent) (ProcessResult, error) {
		require.Equal(t, "org-1", nestedString(event.Audit, "eventMetaData", "owner", "id"))
		return ProcessResult{Emissions: []Emission{
			{Level: LevelAudit, Message: "partition-1", Attrs: []slog.Attr{slog.String("message", "one")}},
			{Level: LevelAudit, Message: "partition-2", Attrs: []slog.Attr{slog.String("message", "two")}},
		}}, nil
	})
	logger, auditBuffer, diagnosticBuffer := createProcessorTestLogger(processor)

	closeRecordedEvent(t, logger)

	entries := decodeJSONLines(t, auditBuffer)
	require.Len(t, entries, 2)
	require.Equal(t, "partition-1", entries[0]["msg"])
	require.Equal(t, "one", entries[0]["message"])
	require.Equal(t, "partition-2", entries[1]["msg"])
	require.Equal(t, "two", entries[1]["message"])
	require.Empty(t, diagnosticBuffer.String())
}

func TestDefaultProcessorPreservesOuterWireContract(t *testing.T) {
	logger, auditBuffer, diagnosticBuffer := createProcessorTestLogger(defaultProcessor{})
	closeRecordedEvent(t, logger)

	entries := decodeJSONLines(t, auditBuffer)
	require.Len(t, entries, 1)
	require.ElementsMatch(t, []string{"time", "level", "msg", "audit"}, mapKeys(entries[0]))
	require.Equal(t, LevelAuditStr, entries[0]["level"])
	require.Equal(t, "read", entries[0]["msg"])
	require.Empty(t, diagnosticBuffer.String())
}

func TestProcessorSeparatesAuthoritativeEventFromJWTEnrichment(t *testing.T) {
	token, rawToken := createTestJWTForAudit(t)
	processor := ProcessorFunc(func(ctx context.Context, event FinalizedEvent) (ProcessResult, error) {
		require.Equal(t, "resource-1", event.Event.Object.ID)
		require.Equal(t, "jwt-user", nestedString(event.Audit, "object", "id"))
		return defaultProcessor{}.Process(ctx, event)
	})
	logger, _, diagnosticBuffer := createProcessorTestLogger(processor)
	require.NoError(t, logger.ApplyConfig(Config{JWTClaimMappings: []JWTClaimMapping{{Claim: "sub", Path: "object.id"}}}))
	ctx := ctxAuth.ContextWithAuthNInfo(createTestContext(t), nil, token, rawToken)
	require.NoError(t, logger.Record(ctx, Verb("read"), recordedTestEvent()))
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok)
	tx.logClose(ctx, logger, true, nil)
	require.Empty(t, diagnosticBuffer.String())
}

func mapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func TestProcessorExplicitDrop(t *testing.T) {
	processor := ProcessorFunc(func(context.Context, FinalizedEvent) (ProcessResult, error) {
		return ProcessResult{Drop: true}, nil
	})
	logger, auditBuffer, diagnosticBuffer := createProcessorTestLogger(processor)

	closeRecordedEvent(t, logger)

	require.Empty(t, auditBuffer.String())
	require.Empty(t, diagnosticBuffer.String())
}

func TestProcessorFailuresFallBackWithoutMutation(t *testing.T) {
	testCases := map[string]Processor{
		"error": ProcessorFunc(func(_ context.Context, event FinalizedEvent) (ProcessResult, error) {
			object, ok := event.Audit["object"].(map[string]any)
			require.True(t, ok)
			object["id"] = "mutated"
			return ProcessResult{}, errors.New("conversion failed")
		}),
		"panic": ProcessorFunc(func(context.Context, FinalizedEvent) (ProcessResult, error) {
			panic("conversion panic")
		}),
		"implicit empty": ProcessorFunc(func(context.Context, FinalizedEvent) (ProcessResult, error) {
			return ProcessResult{}, nil
		}),
		"drop with emission": ProcessorFunc(func(context.Context, FinalizedEvent) (ProcessResult, error) {
			return ProcessResult{Drop: true, Emissions: []Emission{{Level: LevelAudit}}}, nil
		}),
		"filtered level": ProcessorFunc(func(context.Context, FinalizedEvent) (ProcessResult, error) {
			return ProcessResult{Emissions: []Emission{{Level: slog.LevelError, Message: "filtered"}}}, nil
		}),
	}

	for name, processor := range testCases {
		t.Run(name, func(t *testing.T) {
			logger, auditBuffer, diagnosticBuffer := createProcessorTestLogger(processor)
			closeRecordedEvent(t, logger)

			entries := decodeJSONLines(t, auditBuffer)
			require.Len(t, entries, 1)
			require.Equal(t, "read", entries[0]["msg"])
			auditPayload, ok := entries[0]["audit"].(map[string]any)
			require.True(t, ok)
			require.Equal(t, "resource-1", nestedString(auditPayload, "object", "id"))
			require.Contains(t, diagnosticBuffer.String(), "audit processor failed; emitting default event")
		})
	}
}

func TestLoggerWithRetainsProcessor(t *testing.T) {
	processor := ProcessorFunc(func(context.Context, FinalizedEvent) (ProcessResult, error) {
		return ProcessResult{Drop: true}, nil
	})
	logger, _, _ := createProcessorTestLogger(processor)

	child := logger.With("namespace", "external")
	require.NotNil(t, child.Processor())
}
