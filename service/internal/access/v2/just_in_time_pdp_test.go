package access

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/internal/access/v2/obligations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testObligation1FQN = "https://example.org/obligation/attr1/value/obl1"
	testObligation2FQN = "https://example.org/obligation/attr2/value/obl2"
	testObligation3FQN = "https://example.org/obligation/attr3/value/obl3"

	testResource1ID   = "resource1"
	testResource2ID   = "resource2"
	testResource3ID   = "resource3"
	testResource1Name = "Resource One"
	testResource2Name = "Resource Two"
	testResource3Name = "Resource Three"

	testAttr1ValueFQN = "https://example.org/attr/attr1/value/val1"
)

func mkResourceDecision(id, name string, entitled bool, dataRules ...DataRuleResult) ResourceDecision {
	return ResourceDecision{
		Entitled:        entitled,
		ResourceID:      id,
		ResourceName:    name,
		DataRuleResults: dataRules,
	}
}

func mkExpectedResourceDecision(id, name string, entitled, obligationsSatisfied, passed bool, obligations []string, dataRules ...DataRuleResult) ResourceDecision {
	return ResourceDecision{
		Entitled:                    entitled,
		ObligationsSatisfied:        obligationsSatisfied,
		Passed:                      passed,
		ResourceID:                  id,
		ResourceName:                name,
		RequiredObligationValueFQNs: obligations,
		DataRuleResults:             dataRules,
	}
}

func mkPerResourceDecision(satisfied bool, obligationFQNs ...string) obligations.PerResourceDecision {
	return obligations.PerResourceDecision{
		ObligationsSatisfied:        satisfied,
		RequiredObligationValueFQNs: obligationFQNs,
	}
}

func assertResourceDecision(t *testing.T, expected, actual ResourceDecision, idx int, prefix string) {
	t.Helper()
	assert.Equal(t, expected.Entitled, actual.Entitled, "%s resource %d: Entitled mismatch", prefix, idx)
	assert.Equal(t, expected.ObligationsSatisfied, actual.ObligationsSatisfied, "%s resource %d: ObligationsSatisfied mismatch", prefix, idx)
	assert.Equal(t, expected.Passed, actual.Passed, "%s resource %d: Passed mismatch", prefix, idx)
	assert.Equal(t, expected.ResourceID, actual.ResourceID, "%s resource %d: ResourceID mismatch", prefix, idx)
	assert.Equal(t, expected.ResourceName, actual.ResourceName, "%s resource %d: ResourceName mismatch", prefix, idx)
	assert.Equal(t, expected.RequiredObligationValueFQNs, actual.RequiredObligationValueFQNs, "%s resource %d: RequiredObligationValueFQNs mismatch", prefix, idx)
	assert.Equal(t, expected.DataRuleResults, actual.DataRuleResults, "%s resource %d: DataRuleResults mismatch", prefix, idx)
}

func Test_getResourceDecisionsWithObligations(t *testing.T) {
	tests := []struct {
		name                   string
		decision               *Decision
		obligationDecision     obligations.ObligationPolicyDecision
		expectedDecision       *Decision
		expectedAuditDecisions []ResourceDecision
	}{
		{
			name: "entitled: true, obligations: none",
			decision: &Decision{
				Results: []ResourceDecision{
					mkResourceDecision(testResource1ID, testResource1Name, true),
					mkResourceDecision(testResource2ID, testResource2Name, true),
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs:            []string{},
				RequiredObligationValueFQNsPerResource: []obligations.PerResourceDecision{{}, {}},
			},
			expectedDecision: &Decision{
				Results: []ResourceDecision{
					mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
					mkExpectedResourceDecision(testResource2ID, testResource2Name, true, true, true, nil),
				},
			},
			expectedAuditDecisions: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
				mkExpectedResourceDecision(testResource2ID, testResource2Name, true, true, true, nil),
			},
		},
		{
			name: "entitled: true, obligations: required and satisfied",
			decision: &Decision{
				Results: []ResourceDecision{mkResourceDecision(testResource1ID, testResource1Name, true)},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:                true,
				RequiredObligationValueFQNs:            []string{testObligation1FQN},
				RequiredObligationValueFQNsPerResource: []obligations.PerResourceDecision{mkPerResourceDecision(true, testObligation1FQN)},
			},
			expectedDecision: &Decision{
				Results: []ResourceDecision{mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN})},
			},
			expectedAuditDecisions: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}),
			},
		},
		{
			name: "entitled: false, obligations: required and satisfied",
			decision: &Decision{
				Results: []ResourceDecision{mkResourceDecision(testResource1ID, testResource1Name, false)},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:                true,
				RequiredObligationValueFQNs:            []string{testObligation1FQN},
				RequiredObligationValueFQNsPerResource: []obligations.PerResourceDecision{mkPerResourceDecision(true, testObligation1FQN)},
			},
			expectedDecision: &Decision{
				Results: []ResourceDecision{mkExpectedResourceDecision(testResource1ID, testResource1Name, false, true, false, nil)},
			},
			expectedAuditDecisions: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, false, true, false, []string{testObligation1FQN}),
			},
		},
		{
			name: "entitled: true, obligations: required and not satisfied",
			decision: &Decision{
				Results: []ResourceDecision{mkResourceDecision(testResource1ID, testResource1Name, true)},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:                false,
				RequiredObligationValueFQNs:            []string{testObligation1FQN},
				RequiredObligationValueFQNsPerResource: []obligations.PerResourceDecision{mkPerResourceDecision(false, testObligation1FQN)},
			},
			expectedDecision: &Decision{
				Results: []ResourceDecision{mkExpectedResourceDecision(testResource1ID, testResource1Name, true, false, false, []string{testObligation1FQN})},
			},
			expectedAuditDecisions: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, false, false, []string{testObligation1FQN}),
			},
		},
		{
			name: "multiple resources: mixed entitlement and obligation states",
			decision: &Decision{
				Results: []ResourceDecision{
					mkResourceDecision(testResource1ID, testResource1Name, true),
					mkResourceDecision(testResource2ID, testResource2Name, false),
					mkResourceDecision(testResource3ID, testResource3Name, true),
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:     false,
				RequiredObligationValueFQNs: []string{testObligation1FQN, testObligation2FQN},
				RequiredObligationValueFQNsPerResource: []obligations.PerResourceDecision{
					mkPerResourceDecision(true, testObligation1FQN),
					mkPerResourceDecision(false, testObligation2FQN),
					mkPerResourceDecision(false, testObligation2FQN),
				},
			},
			expectedDecision: &Decision{
				Results: []ResourceDecision{
					mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}),
					mkExpectedResourceDecision(testResource2ID, testResource2Name, false, false, false, nil),
					mkExpectedResourceDecision(testResource3ID, testResource3Name, true, false, false, []string{testObligation2FQN}),
				},
			},
			expectedAuditDecisions: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}),
				mkExpectedResourceDecision(testResource2ID, testResource2Name, false, false, false, []string{testObligation2FQN}),
				mkExpectedResourceDecision(testResource3ID, testResource3Name, true, false, false, []string{testObligation2FQN}),
			},
		},
		{
			name: "entitled: true, obligations: satisfied and multiple per resource",
			decision: &Decision{
				Results: []ResourceDecision{mkResourceDecision(testResource1ID, testResource1Name, true)},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:     true,
				RequiredObligationValueFQNs: []string{testObligation1FQN, testObligation2FQN, testObligation3FQN},
				RequiredObligationValueFQNsPerResource: []obligations.PerResourceDecision{
					mkPerResourceDecision(true, testObligation1FQN, testObligation2FQN, testObligation3FQN),
				},
			},
			expectedDecision: &Decision{
				Results: []ResourceDecision{
					mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN, testObligation2FQN, testObligation3FQN}),
				},
			},
			expectedAuditDecisions: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN, testObligation2FQN, testObligation3FQN}),
			},
		},
		{
			name: "no resources",
			decision: &Decision{
				Results: []ResourceDecision{},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs:            []string{},
				RequiredObligationValueFQNsPerResource: []obligations.PerResourceDecision{},
			},
			expectedDecision: &Decision{
				Results: []ResourceDecision{},
			},
			expectedAuditDecisions: []ResourceDecision{},
		},
		{
			name: "entitled: true, obligations: required, data rules preserved",
			decision: &Decision{
				Results: []ResourceDecision{
					mkResourceDecision(testResource1ID, testResource1Name, true, DataRuleResult{
						Passed:            true,
						ResourceValueFQNs: []string{testAttr1ValueFQN},
						Attribute:         &policy.Attribute{Name: "attr1"},
					}),
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:                true,
				RequiredObligationValueFQNs:            []string{testObligation1FQN},
				RequiredObligationValueFQNsPerResource: []obligations.PerResourceDecision{mkPerResourceDecision(true, testObligation1FQN)},
			},
			expectedDecision: &Decision{
				Results: []ResourceDecision{
					mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}, DataRuleResult{
						Passed:            true,
						ResourceValueFQNs: []string{testAttr1ValueFQN},
						Attribute:         &policy.Attribute{Name: "attr1"},
					}),
				},
			},
			expectedAuditDecisions: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}, DataRuleResult{
					Passed:            true,
					ResourceValueFQNs: []string{testAttr1ValueFQN},
					Attribute:         &policy.Attribute{Name: "attr1"},
				}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultDecision, auditDecisions := getResourceDecisionsWithObligations(tt.decision, tt.obligationDecision)

			require.NotNil(t, resultDecision)
			require.Len(t, resultDecision.Results, len(tt.expectedDecision.Results))

			for i := range resultDecision.Results {
				assertResourceDecision(t, tt.expectedDecision.Results[i], resultDecision.Results[i], i, "decision")
			}

			require.Len(t, auditDecisions, len(tt.expectedAuditDecisions))
			for i := range auditDecisions {
				assertResourceDecision(t, tt.expectedAuditDecisions[i], auditDecisions[i], i, "audit")
			}
		})
	}
}

func Test_getResourceDecisionsWithObligations_ImmutabilityCheck(t *testing.T) {
	originalDecision := &Decision{
		Results: []ResourceDecision{mkResourceDecision(testResource1ID, testResource1Name, true)},
	}

	obligationDecision := obligations.ObligationPolicyDecision{
		AllObligationsSatisfied:                false,
		RequiredObligationValueFQNs:            []string{testObligation1FQN},
		RequiredObligationValueFQNsPerResource: []obligations.PerResourceDecision{mkPerResourceDecision(false, testObligation1FQN)},
	}

	resultDecision, auditDecisions := getResourceDecisionsWithObligations(originalDecision, obligationDecision)

	require.Len(t, resultDecision.Results, 1)
	assert.False(t, resultDecision.Results[0].Passed)
	assert.True(t, resultDecision.Results[0].Entitled)
	assert.False(t, resultDecision.Results[0].ObligationsSatisfied)
	assert.Equal(t, []string{testObligation1FQN}, resultDecision.Results[0].RequiredObligationValueFQNs)

	require.Len(t, auditDecisions, 1)
	assert.Equal(t, resultDecision.Results[0], auditDecisions[0])

	// Modifying the returned decision's obligation list should not affect the audit snapshot
	resultDecision.Results[0].RequiredObligationValueFQNs = append(resultDecision.Results[0].RequiredObligationValueFQNs, testObligation2FQN)

	assert.Len(t, auditDecisions[0].RequiredObligationValueFQNs, 1)
	assert.Equal(t, testObligation1FQN, auditDecisions[0].RequiredObligationValueFQNs[0])
	assert.Len(t, resultDecision.Results[0].RequiredObligationValueFQNs, 2)
}
