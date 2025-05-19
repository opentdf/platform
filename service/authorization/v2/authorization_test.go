package authorization

import (
	"errors"
	"testing"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRollupSingleResourceDecision(t *testing.T) {
	tests := []struct {
		name            string
		permitted       bool
		decisions       []*access.Decision
		expectedResult  *authzV2.GetDecisionResponse
		expectedError   error
		errorMsgContain string
	}{
		{
			name:      "should return permit decision when permitted is true",
			permitted: true,
			decisions: []*access.Decision{
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							ResourceID: "resource-123",
						},
					},
				},
			},
			expectedResult: &authzV2.GetDecisionResponse{
				Decision: &authzV2.ResourceDecision{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-123",
				},
			},
			expectedError: nil,
		},
		{
			name:      "should return deny decision when permitted is false",
			permitted: false,
			decisions: []*access.Decision{
				{
					Access: true, // This is intentionally different from permitted to verify permitted takes precedence
					Results: []access.ResourceDecision{
						{
							ResourceID: "resource-123",
						},
					},
				},
			},
			expectedResult: &authzV2.GetDecisionResponse{
				Decision: &authzV2.ResourceDecision{
					Decision:            authzV2.Decision_DECISION_DENY,
					EphemeralResourceId: "resource-123",
				},
			},
			expectedError: nil,
		},
		{
			name:            "should return error when no decisions are provided",
			permitted:       true,
			decisions:       []*access.Decision{},
			expectedResult:  nil,
			expectedError:   errors.New("no decisions returned"),
			errorMsgContain: "no decisions returned",
		},
		{
			name:      "should return error when decision has no results",
			permitted: true,
			decisions: []*access.Decision{
				{
					Access:  true,
					Results: []access.ResourceDecision{},
				},
			},
			expectedResult:  nil,
			expectedError:   errors.New("no decision results returned"),
			errorMsgContain: "no decision results returned",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rollupSingleResourceDecision(tc.permitted, tc.decisions)

			if tc.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsgContain)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func TestRollupMultiResourceDecision(t *testing.T) {
	tests := []struct {
		name            string
		decisions       []*access.Decision
		expectedResult  []*authzV2.ResourceDecision
		expectedError   error
		errorMsgContain string
	}{
		{
			name: "should return multiple permit decisions",
			decisions: []*access.Decision{
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							Passed:     true,
							ResourceID: "resource-123",
						},
					},
				},
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							Passed:     true,
							ResourceID: "resource-456",
						},
					},
				},
			},
			expectedResult: []*authzV2.ResourceDecision{
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-123",
				},
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-456",
				},
			},
			expectedError: nil,
		},
		{
			name: "should return mix of permit and deny decisions",
			decisions: []*access.Decision{
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							Passed:     true,
							ResourceID: "resource-123",
						},
					},
				},
				{
					Access: false,
					Results: []access.ResourceDecision{
						{
							Passed:     false,
							ResourceID: "resource-456",
						},
					},
				},
			},
			expectedResult: []*authzV2.ResourceDecision{
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-123",
				},
				{
					Decision:            authzV2.Decision_DECISION_DENY,
					EphemeralResourceId: "resource-456",
				},
			},
			expectedError: nil,
		},
		{
			name: "should return error when decision has no results",
			decisions: []*access.Decision{
				{
					Access:  true,
					Results: []access.ResourceDecision{},
				},
			},
			expectedResult:  nil,
			expectedError:   errors.New("no decision results returned"),
			errorMsgContain: "no decision results returned",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rollupMultiResourceDecision(tc.decisions)

			if tc.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsgContain)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func TestRollupMultiResourceDecisionSimple(t *testing.T) {
	// This test checks the minimal viable structure to pass through rollupMultiResourceDecision
	decision := &access.Decision{
		Access: true,
		Results: []access.ResourceDecision{
			{
				Passed:     true,
				ResourceID: "resource-123",
			},
		},
	}

	decisions := []*access.Decision{decision}

	result, err := rollupMultiResourceDecision(decisions)

	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "resource-123", result[0].GetEphemeralResourceId())
	assert.Equal(t, authzV2.Decision_DECISION_PERMIT, result[0].GetDecision())
}

func TestRollupMultiResourceDecisionWithNilChecks(t *testing.T) {
	t.Run("nil decisions array", func(t *testing.T) {
		var decisions []*access.Decision
		_, err := rollupMultiResourceDecision(decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no decisions returned")
	})

	t.Run("nil decision in array", func(t *testing.T) {
		decisions := []*access.Decision{nil}
		_, err := rollupMultiResourceDecision(decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil decision at index 0")
	})

	t.Run("nil Results field", func(t *testing.T) {
		decisions := []*access.Decision{
			{
				Access:  true,
				Results: nil,
			},
		}
		_, err := rollupMultiResourceDecision(decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no decision results returned")
	})
}

func TestRollupSingleResourceDecisionWithNilChecks(t *testing.T) {
	t.Run("nil decisions array", func(t *testing.T) {
		var decisions []*access.Decision
		_, err := rollupSingleResourceDecision(true, decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no decisions returned")
	})

	t.Run("nil decision in array", func(t *testing.T) {
		decisions := []*access.Decision{nil}
		_, err := rollupSingleResourceDecision(true, decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil decision at index 0")
	})

	t.Run("nil Results field", func(t *testing.T) {
		decisions := []*access.Decision{
			{
				Access:  true,
				Results: nil,
			},
		}
		_, err := rollupSingleResourceDecision(true, decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no decision results returned")
	})
}
