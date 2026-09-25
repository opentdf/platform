package audit

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingProcessor is an in-memory recorder that keeps an immutable snapshot
// of every event it accepts.
type recordingProcessor struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingProcessor) Process(_ context.Context, event Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *recordingProcessor) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

func lifecycleTestLogger(t *testing.T) (*Logger, *recordingProcessor) {
	t.Helper()
	processor := &recordingProcessor{}
	return CreateAuditLogger(*slog.Default(), WithProcessor(processor), WithRecordTimeout(time.Second)), processor
}

func testRewrapParams() RewrapAuditEventParams {
	return RewrapAuditEventParams{
		TDFFormat:     TestTDFFormat,
		Algorithm:     TestAlgorithm,
		PolicyBinding: TestPolicyBinding,
		KeyID:         "test-key-id",
	}
}

// lifecycleMeta extracts the correlation block an event carries.
func lifecycleMeta(t *testing.T, event Event) map[string]any {
	t.Helper()
	require.Contains(t, event.EventMetaData, LifecycleMetaDataKey)
	return requireMap(t, event.EventMetaData[LifecycleMetaDataKey])
}

func TestBeginRewrapRecordsAttemptedBeforeWork(t *testing.T) {
	ctx := createTestContext(t)
	logger, processor := lifecycleTestLogger(t)

	lifecycle, err := logger.BeginRewrap(ctx, 0, testRewrapParams())
	require.NoError(t, err)
	require.NotNil(t, lifecycle)

	events := processor.snapshot()
	require.Len(t, events, 1, "the attempt must be recorded before any work happens")

	attempted := events[0]
	assert.Equal(t, VerbRewrap, attempted.Verb)
	assert.Equal(t, ActionResultAttempted, attempted.Action.Result)
	assert.Equal(t, ActionTypeRewrap, attempted.Action.Type)
	assert.Equal(t, TestRequestID, attempted.RequestID)
	assert.Equal(t, TestActorID, attempted.Actor.ID)

	meta := lifecycleMeta(t, attempted)
	assert.Equal(t, lifecycle.ID().String(), meta["id"])
	assert.Equal(t, string(PhaseAttempted), meta["phase"])
	assert.Equal(t, 0, meta["slot"])
	assert.NotContains(t, meta, "cancellation")
}

func TestRewrapLifecyclePairsAttemptedWithTerminal(t *testing.T) {
	ctx := createTestContext(t)
	logger, processor := lifecycleTestLogger(t)

	lifecycle, err := logger.BeginRewrap(ctx, 3, testRewrapParams())
	require.NoError(t, err)

	policy := KasPolicy{UUID: uuid.New(), Body: KasPolicyBody{
		DataAttributes: []KasAttribute{{URI: "https://example.com/attr/a/value/b"}},
	}}
	lifecycle.SetPolicy(policy)
	require.NoError(t, lifecycle.Success(ctx))

	events := processor.snapshot()
	require.Len(t, events, 2)

	attempted, completed := events[0], events[1]
	assert.Equal(t, ActionResultAttempted, attempted.Action.Result)
	assert.Equal(t, ActionResultSuccess, completed.Action.Result)

	// The attempted record is intentionally partial: the policy was not known
	// yet, and enriching the lifecycle must not rewrite what was already sent.
	assert.Equal(t, uuid.Nil.String(), attempted.Object.ID)
	assert.Equal(t, policy.UUID.String(), completed.Object.ID)
	assert.Equal(t, []string{"https://example.com/attr/a/value/b"}, completed.Object.Attributes.Attrs)

	// Both records pair on the lifecycle id, and each keeps its own event id.
	attemptedMeta := lifecycleMeta(t, attempted)
	completedMeta := lifecycleMeta(t, completed)
	assert.Equal(t, lifecycle.ID().String(), attemptedMeta["id"])
	assert.Equal(t, lifecycle.ID().String(), completedMeta["id"])
	assert.Equal(t, 3, attemptedMeta["slot"])
	assert.Equal(t, 3, completedMeta["slot"])
	assert.Equal(t, string(PhaseCompleted), completedMeta["phase"])
	assert.NotEqual(t, attempted.ID, completed.ID)
}

func TestRewrapLifecycleCloseRecordsTerminalForAbandonedAttempt(t *testing.T) {
	ctx := createTestContext(t)
	logger, processor := lifecycleTestLogger(t)

	lifecycle, err := logger.BeginRewrap(ctx, 0, testRewrapParams())
	require.NoError(t, err)

	// No explicit outcome: the handler returned early.
	require.NoError(t, lifecycle.Close(ctx))

	events := processor.snapshot()
	require.Len(t, events, 2, "an abandoned attempt must still reach a terminal record")
	assert.Equal(t, ActionResultError, events[1].Action.Result)
	assert.Equal(t, string(PhaseCompleted), lifecycleMeta(t, events[1])["phase"])
}

func TestRewrapLifecycleCloseClassifiesInterruption(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		withCtx  func(context.Context) (context.Context, context.CancelFunc)
		expected CancellationKind
	}{
		{
			name:     "client disconnect",
			withCtx:  context.WithCancel,
			expected: CancellationClientDisconnect,
		},
		{
			name: "deadline exceeded",
			withCtx: func(parent context.Context) (context.Context, context.CancelFunc) {
				return context.WithTimeout(parent, time.Nanosecond)
			},
			expected: CancellationDeadlineExceeded,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			logger, processor := lifecycleTestLogger(t)
			ctx, cancel := testCase.withCtx(createTestContext(t))

			lifecycle, err := logger.BeginRewrap(ctx, 0, testRewrapParams())
			require.NoError(t, err)

			cancel()
			<-ctx.Done()
			require.NoError(t, lifecycle.Close(ctx), "recording must survive the interruption")

			events := processor.snapshot()
			require.Len(t, events, 2)

			terminal := events[1]
			// Cancellation is a result, not a denial.
			assert.Equal(t, ActionResultCancel, terminal.Action.Result)
			assert.NotEqual(t, ActionResultFailure, terminal.Action.Result)
			assert.Equal(t, string(testCase.expected), lifecycleMeta(t, terminal)["cancellation"])
		})
	}
}

func TestRewrapLifecycleRecordsExactlyOneTerminal(t *testing.T) {
	ctx := createTestContext(t)
	logger, processor := lifecycleTestLogger(t)

	lifecycle, err := logger.BeginRewrap(ctx, 0, testRewrapParams())
	require.NoError(t, err)

	require.NoError(t, lifecycle.Success(ctx))
	require.NoError(t, lifecycle.Failure(ctx))
	require.NoError(t, lifecycle.Cancel(ctx, CancellationClientDisconnect))
	require.NoError(t, lifecycle.Close(ctx))

	events := processor.snapshot()
	require.Len(t, events, 2, "a recorded outcome must never be rewritten")
	assert.Equal(t, ActionResultSuccess, events[1].Action.Result)
}

func TestRewrapLifecycleIgnoresEnrichmentAfterTerminal(t *testing.T) {
	ctx := createTestContext(t)
	logger, processor := lifecycleTestLogger(t)

	lifecycle, err := logger.BeginRewrap(ctx, 0, testRewrapParams())
	require.NoError(t, err)
	require.NoError(t, lifecycle.Success(ctx))

	lifecycle.SetPolicy(KasPolicy{UUID: uuid.New()})

	events := processor.snapshot()
	require.Len(t, events, 2)
	assert.Equal(t, uuid.Nil.String(), events[1].Object.ID, "late enrichment must not appear anywhere")
}

func TestRewrapLifecycleEnrichmentIsRaceFree(t *testing.T) {
	ctx := createTestContext(t)
	logger, processor := lifecycleTestLogger(t)

	lifecycle, err := logger.BeginRewrap(ctx, 0, testRewrapParams())
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			lifecycle.SetPolicy(KasPolicy{UUID: uuid.New()})
		}()
		go func() {
			defer wg.Done()
			assert.NoError(t, lifecycle.Close(ctx))
		}()
	}
	wg.Wait()

	assert.Len(t, processor.snapshot(), 2, "concurrent closers must still produce one terminal record")
}

func TestRewrapLifecycleSlotsSurviveDuplicateKeyAccessObjectIDs(t *testing.T) {
	ctx := createTestContext(t)
	logger, processor := lifecycleTestLogger(t)

	// Two key access objects that are indistinguishable by their own fields.
	first, err := logger.BeginRewrap(ctx, 0, testRewrapParams())
	require.NoError(t, err)
	second, err := logger.BeginRewrap(ctx, 1, testRewrapParams())
	require.NoError(t, err)

	require.NoError(t, first.Success(ctx))
	require.NoError(t, second.Failure(ctx))

	assert.NotEqual(t, first.ID(), second.ID())

	events := processor.snapshot()
	require.Len(t, events, 4)

	slots := map[any]ActionResult{}
	for _, event := range events {
		meta := lifecycleMeta(t, event)
		if meta["phase"] == string(PhaseCompleted) {
			slots[meta["slot"]] = event.Action.Result
		}
	}
	assert.Equal(t, map[any]ActionResult{0: ActionResultSuccess, 1: ActionResultError}, slots)
}

func TestNilRewrapLifecycleIsSafe(t *testing.T) {
	ctx := createTestContext(t)
	var lifecycle *RewrapLifecycle

	assert.Equal(t, uuid.Nil, lifecycle.ID())
	assert.NotPanics(t, func() {
		lifecycle.SetPolicy(KasPolicy{UUID: uuid.New()})
	})
	require.NoError(t, lifecycle.Success(ctx))
	require.NoError(t, lifecycle.Close(ctx))
}

func TestRewrapLifecyclePreservesDefaultPayloadShape(t *testing.T) {
	ctx := createTestContext(t)
	logger, processor := lifecycleTestLogger(t)

	lifecycle, err := logger.BeginRewrap(ctx, 0, testRewrapParams())
	require.NoError(t, err)
	require.NoError(t, lifecycle.Success(ctx))

	events := processor.snapshot()
	require.Len(t, events, 2)

	payload := requireMap(t, events[1].emittedPayloadMap())
	for _, key := range []string{"object", "action", "actor", "eventMetaData", "clientInfo", "requestID", "timestamp"} {
		assert.Contains(t, payload, key)
	}

	// Lifecycle correlation rides inside eventMetaData so consumers that predate
	// it keep parsing the same top-level shape.
	meta := requireMap(t, payload["eventMetaData"])
	for _, key := range []string{"keyID", "policyBinding", "tdfFormat", "algorithm"} {
		assert.Contains(t, meta, key)
	}
	assert.Contains(t, meta, LifecycleMetaDataKey)
}
