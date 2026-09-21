package audit

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestBuiltInHelpersReturnProcessorErrors(t *testing.T) {
	processorErr := errors.New("audit destination unavailable")
	for _, tt := range []struct {
		name   string
		verb   Verb
		record func(context.Context, *Logger) error
	}{
		{"rewrap success", VerbRewrap, func(ctx context.Context, l *Logger) error { return l.RewrapSuccess(ctx, rewrapParams) }},
		{"rewrap failure", VerbRewrap, func(ctx context.Context, l *Logger) error { return l.RewrapFailure(ctx, rewrapParams) }},
		{"policy success", VerbPolicyCRUD, func(ctx context.Context, l *Logger) error { return l.PolicyCRUDSuccess(ctx, policyCRUDParams) }},
		{"policy failure", VerbPolicyCRUD, func(ctx context.Context, l *Logger) error { return l.PolicyCRUDFailure(ctx, policyCRUDParams) }},
		{"decision", VerbDecision, func(ctx context.Context, l *Logger) error { return l.GetDecision(ctx, GetDecisionEventParams{}) }},
		{"decision v2", VerbDecision, func(ctx context.Context, l *Logger) error { return l.GetDecisionV2(ctx, GetDecisionV2EventParams{}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l, output := createTestLogger()
			calls := 0
			l.processor = ProcessorFunc(func(_ context.Context, event Event) error {
				calls++
				require.Equal(t, tt.verb, event.Verb)
				return processorErr
			})
			err := tt.record(t.Context(), l)
			require.ErrorIs(t, err, processorErr)
			require.ErrorIs(t, err, ErrProcessing)
			require.Equal(t, 1, calls)
			require.Empty(t, output.String(), "no implicit fallback or duplicate delivery")
		})
	}
}

func TestPolicyHelperReturnsConstructionError(t *testing.T) {
	l, output := createTestLogger()
	params := policyCRUDParams
	params.Original = structpb.NewStringValue(string([]byte{0xff}))
	l.processor = ProcessorFunc(func(context.Context, Event) error {
		t.Fatal("invalid event must not reach processor")
		return nil
	})
	require.Error(t, l.PolicyCRUDSuccess(t.Context(), params))
	require.Empty(t, output.String())
}

func TestRewrapFailureOverridesSuccessfulAccess(t *testing.T) {
	l, output := createTestLogger()
	params := rewrapParams
	params.IsSuccess = true
	require.NoError(t, l.RewrapFailure(t.Context(), params))
	entry, _ := extractLogEntry(t, output)
	payload := decodeAuditPayload(t, entry.Audit)
	require.Equal(t, ActionResultError.String(), requireMap(t, payload["action"])["result"])
}

func TestBuiltInRecordingPreservesCanceledProducerContext(t *testing.T) {
	type ownerKey struct{}
	var processed bool
	l := CreateAuditLogger(*slog.New(slog.DiscardHandler),
		WithRecordTimeout(time.Second),
		WithProcessor(ProcessorFunc(func(ctx context.Context, event Event) error {
			processed = true
			require.NoError(t, ctx.Err())
			require.Equal(t, "resource-owner", ctx.Value(ownerKey{}))
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			require.Positive(t, time.Until(deadline))
			require.LessOrEqual(t, time.Until(deadline), time.Second)
			require.Equal(t, "producer", event.Actor.ID)
			return nil
		})))
	next := ContextServerInterceptor()(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		ctx = ContextWithActorID(context.WithValue(ctx, ownerKey{}, "resource-owner"), "producer")
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		require.NoError(t, l.PolicyCRUDSuccess(ctx, policyCRUDParams))
		require.True(t, processed, "recording must finish before the producer returns")
		return connect.NewResponse(&struct{}{}), nil
	})
	_, err := next(t.Context(), connect.NewRequest(&struct{}{}))
	require.NoError(t, err)
}

func TestCompletedEventSurvivesLaterRPCFailure(t *testing.T) {
	for _, panicLater := range []bool{false, true} {
		name := "error"
		if panicLater {
			name = "panic"
		}
		t.Run(name, func(t *testing.T) {
			l, output := createTestLogger()
			laterErr := errors.New("later operation failed")
			next := ContextServerInterceptor()(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
				require.NoError(t, l.RewrapSuccess(ctx, rewrapParams))
				require.NotEmpty(t, output.String(), "event must be emitted immediately")
				if panicLater {
					panic(laterErr)
				}
				return nil, laterErr
			})
			if panicLater {
				require.PanicsWithValue(t, laterErr, func() {
					_, _ = next(t.Context(), connect.NewRequest(&struct{}{}))
				})
			} else {
				_, err := next(t.Context(), connect.NewRequest(&struct{}{}))
				require.ErrorIs(t, err, laterErr)
			}
			entry, _ := extractLogEntry(t, output)
			payload := decodeAuditPayload(t, entry.Audit)
			require.Equal(t, ActionResultSuccess.String(), requireMap(t, payload["action"])["result"])
			require.NotContains(t, requireMap(t, payload["eventMetaData"]), "cancellation_error")
		})
	}
}
