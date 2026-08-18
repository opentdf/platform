package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cloneContextValueKey struct{}

func TestDetachCopiesContextDataAndCreatesIndependentTransaction(t *testing.T) {
	l, _ := createTestLogger()
	parent := context.WithValue(createTestContext(t), cloneContextValueKey{}, "retained")
	parent, cancel := context.WithCancel(parent)

	l.PolicyCRUDSuccess(parent, policyCRUDParams)
	cloned := l.Detach(parent)
	cancel()

	assert.Equal(t, GetAuditDataFromContext(parent), GetAuditDataFromContext(cloned))
	assert.Equal(t, "retained", cloned.Value(cloneContextValueKey{}))
	assert.Nil(t, cloned.Done())
	require.NoError(t, cloned.Err())

	parentTx := requireAuditTransaction(parent, t)
	cloneTx := requireAuditTransaction(cloned, t)
	assert.NotSame(t, parentTx, cloneTx)
	require.Len(t, parentTx.events, 1)
	assert.Empty(t, cloneTx.events)

	require.PanicsWithValue(t,
		"cannot buffer an audit event on a detached transaction; use Logger.LogPolicyCRUD",
		func() { l.PolicyCRUDFailure(cloned, policyCRUDParams) },
	)
	require.Len(t, parentTx.events, 1)
	assert.Empty(t, cloneTx.events)
}

func TestLogPolicyCRUDEmitsOnceAndParentCloseDoesNotDuplicate(t *testing.T) {
	l, buf := createTestLogger()
	parent := createTestContext(t)
	cloned := l.Detach(parent)

	l.LogPolicyCRUD(cloned, true, policyCRUDParams)
	payloads := decodeAuditPayloads(t, buf)
	require.Len(t, payloads, 1)
	assert.Equal(t, "success", requireMap(t, payloads[0]["action"])["result"])
	assert.Empty(t, requireAuditTransaction(parent, t).events)
	assert.Empty(t, requireAuditTransaction(cloned, t).events)

	requireAuditTransaction(parent, t).logClose(parent, l, true, nil)
	require.Len(t, decodeAuditPayloads(t, buf), 1)
}

func TestLogPolicyCRUDMatchesBufferedSchema(t *testing.T) {
	tests := []struct {
		name      string
		isSuccess bool
	}{
		{name: "success", isSuccess: true},
		{name: "failure", isSuccess: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bufferedLogger, bufferedOutput := createTestLogger()
			bufferedCtx := createTestContext(t)
			if test.isSuccess {
				bufferedLogger.PolicyCRUDSuccess(bufferedCtx, policyCRUDParams)
			} else {
				bufferedLogger.PolicyCRUDFailure(bufferedCtx, policyCRUDParams)
			}
			requireAuditTransaction(bufferedCtx, t).logClose(bufferedCtx, bufferedLogger, true, nil)

			immediateLogger, immediateOutput := createTestLogger()
			immediateCtx := immediateLogger.Detach(createTestContext(t))
			immediateLogger.LogPolicyCRUD(immediateCtx, test.isSuccess, policyCRUDParams)

			bufferedPayloads := decodeAuditPayloads(t, bufferedOutput)
			immediatePayloads := decodeAuditPayloads(t, immediateOutput)
			require.Len(t, bufferedPayloads, 1)
			require.Len(t, immediatePayloads, 1)
			delete(bufferedPayloads[0], "timestamp")
			delete(immediatePayloads[0], "timestamp")
			assert.Equal(t, bufferedPayloads[0], immediatePayloads[0])
		})
	}
}

func TestLogPolicyCRUDUsesJWTEnrichmentFromClonedContext(t *testing.T) {
	l, buf := createTestLogger()
	require.NoError(t, l.ApplyConfig(Config{JWTClaimMappings: []JWTClaimMapping{
		{Claim: "sub", Path: "eventMetaData.requester.sub"},
		{Claim: "realm_access.roles", Path: "eventMetaData.requester.roles"},
	}}))
	token, rawToken := createTestJWTForAudit(t)
	parent, cancel := context.WithCancel(ctxAuth.ContextWithAuthNInfo(createTestContext(t), nil, token, rawToken))
	cloned := l.Detach(parent)
	cancel()

	l.LogPolicyCRUD(cloned, true, policyCRUDParams)
	payloads := decodeAuditPayloads(t, buf)
	require.Len(t, payloads, 1)
	eventMetadata := requireMap(t, payloads[0]["eventMetaData"])
	requester := requireMap(t, eventMetadata["requester"])
	assert.Equal(t, "jwt-user", requester["sub"])
	assert.Equal(t, []any{"admin", "user"}, requester["roles"])
}

func TestDetachWithoutParentUsesDefaultAttribution(t *testing.T) {
	l, buf := createTestLogger()
	cloned := l.Detach(t.Context())

	data := GetAuditDataFromContext(cloned)
	assert.Equal(t, defaultNone, data.ActorID)
	assert.Equal(t, defaultNone, data.UserAgent)
	assert.Equal(t, defaultNone, data.RequestIP)
	require.NotNil(t, requireAuditTransaction(cloned, t))

	l.LogPolicyCRUD(cloned, true, policyCRUDParams)
	payloads := decodeAuditPayloads(t, buf)
	require.Len(t, payloads, 1)
	assert.Equal(t, "00000000-0000-0000-0000-000000000000", payloads[0]["requestID"])
}

func TestLogPolicyCRUDWithoutDetachedContextDoesNotEmit(t *testing.T) {
	l, buf := createTestLogger()

	l.LogPolicyCRUD(t.Context(), false, policyCRUDParams)
	assert.Empty(t, decodeAuditPayloads(t, buf))

	l.LogPolicyCRUD(createTestContext(t), false, policyCRUDParams)
	assert.Empty(t, decodeAuditPayloads(t, buf))
}

func decodeAuditPayloads(t *testing.T, logBuffer *bytes.Buffer) []map[string]any {
	t.Helper()

	decoder := json.NewDecoder(bytes.NewReader(logBuffer.Bytes()))
	payloads := make([]map[string]any, 0)
	for decoder.More() {
		var entry logEntryStructure
		require.NoError(t, decoder.Decode(&entry))
		payloads = append(payloads, decodeAuditPayload(t, entry.Audit))
	}
	return payloads
}

func requireAuditTransaction(ctx context.Context, t *testing.T) *auditTransaction {
	t.Helper()
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok)
	require.NotNil(t, tx)
	return tx
}

func requireMap(t *testing.T, value any) map[string]any {
	t.Helper()
	mapped, ok := value.(map[string]any)
	require.True(t, ok)
	return mapped
}
