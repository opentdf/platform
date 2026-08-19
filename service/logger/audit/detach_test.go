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

func TestDetachPreservesValuesAndIgnoresCancellation(t *testing.T) {
	l, _ := createTestLogger()
	parent := context.WithValue(createTestContext(t), cloneContextValueKey{}, "retained")
	parent, cancel := context.WithCancel(parent)
	cloned := l.Detach(parent)
	cancel()

	assert.Equal(t, GetAuditDataFromContext(parent), GetAuditDataFromContext(cloned))
	assert.Equal(t, "retained", cloned.Value(cloneContextValueKey{}))
	assert.Nil(t, cloned.Done())
	require.NoError(t, cloned.Err())
}

func TestLogPolicyCRUDEmitsWithoutDetachedContext(t *testing.T) {
	l, buf := createTestLogger()
	l.LogPolicyCRUD(createTestContext(t), true, policyCRUDParams)

	payloads := decodeAuditPayloads(t, buf)
	require.Len(t, payloads, 1)
	assert.Equal(t, "success", requireMap(t, payloads[0]["action"])["result"])
}

func TestLogPolicyCRUDMatchesCompatibilityWrapperSchema(t *testing.T) {
	tests := []struct {
		name      string
		isSuccess bool
	}{
		{name: "success", isSuccess: true},
		{name: "failure", isSuccess: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapperLogger, wrapperOutput := createTestLogger()
			wrapperCtx := createTestContext(t)
			if test.isSuccess {
				wrapperLogger.PolicyCRUDSuccess(wrapperCtx, policyCRUDParams)
			} else {
				wrapperLogger.PolicyCRUDFailure(wrapperCtx, policyCRUDParams)
			}

			immediateLogger, immediateOutput := createTestLogger()
			immediateLogger.LogPolicyCRUD(createTestContext(t), test.isSuccess, policyCRUDParams)

			wrapperPayloads := decodeAuditPayloads(t, wrapperOutput)
			immediatePayloads := decodeAuditPayloads(t, immediateOutput)
			require.Len(t, wrapperPayloads, 1)
			require.Len(t, immediatePayloads, 1)
			delete(wrapperPayloads[0], "timestamp")
			delete(immediatePayloads[0], "timestamp")
			assert.Equal(t, wrapperPayloads[0], immediatePayloads[0])
		})
	}
}

func TestLogPolicyCRUDUsesJWTEnrichmentAfterCancellation(t *testing.T) {
	l, buf := createTestLogger()
	require.NoError(t, l.ApplyConfig(Config{JWTClaimMappings: []JWTClaimMapping{
		{Claim: "sub", Path: "eventMetaData.requester.sub"},
		{Claim: "realm_access.roles", Path: "eventMetaData.requester.roles"},
	}}))
	token, rawToken := createTestJWTForAudit(t)
	parent, cancel := context.WithCancel(ctxAuth.ContextWithAuthNInfo(createTestContext(t), nil, token, rawToken))
	cancel()

	l.LogPolicyCRUD(parent, true, policyCRUDParams)
	payloads := decodeAuditPayloads(t, buf)
	require.Len(t, payloads, 1)
	eventMetadata := requireMap(t, payloads[0]["eventMetaData"])
	requester := requireMap(t, eventMetadata["requester"])
	assert.Equal(t, "jwt-user", requester["sub"])
	assert.Equal(t, []any{"admin", "user"}, requester["roles"])
}

func TestLogPolicyCRUDWithoutRequestContextUsesDefaultAttribution(t *testing.T) {
	l, buf := createTestLogger()
	l.LogPolicyCRUD(t.Context(), true, policyCRUDParams)

	payloads := decodeAuditPayloads(t, buf)
	require.Len(t, payloads, 1)
	assert.Equal(t, "00000000-0000-0000-0000-000000000000", payloads[0]["requestID"])
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

func requireMap(t *testing.T, value any) map[string]any {
	t.Helper()
	mapped, ok := value.(map[string]any)
	require.True(t, ok)
	return mapped
}
