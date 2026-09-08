package cukes

import (
	"testing"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestScaleDecisionValidatesEachResourceRegardlessOfOrder(t *testing.T) {
	expected := map[string]authz.Decision{"resource0": authz.Decision_DECISION_PERMIT, "resource1": authz.Decision_DECISION_DENY}
	valid := &authz.GetDecisionMultiResourceResponse{ResourceDecisions: []*authz.ResourceDecision{
		{EphemeralResourceId: "resource1", Decision: authz.Decision_DECISION_DENY},
		{EphemeralResourceId: "resource0", Decision: authz.Decision_DECISION_PERMIT},
	}}
	require.NoError(t, validateScaleDecision(valid, expected))
	tests := []struct {
		name   string
		change func(*authz.GetDecisionMultiResourceResponse)
	}{
		{"incorrect deny", func(r *authz.GetDecisionMultiResourceResponse) {
			r.GetResourceDecisions()[0].Decision = authz.Decision_DECISION_PERMIT
		}},
		{"duplicate resource", func(r *authz.GetDecisionMultiResourceResponse) {
			r.GetResourceDecisions()[0].EphemeralResourceId = "resource0"
		}},
		{"unknown resource", func(r *authz.GetDecisionMultiResourceResponse) {
			r.GetResourceDecisions()[0].EphemeralResourceId = "unknown"
		}},
		{"missing resource", func(r *authz.GetDecisionMultiResourceResponse) { r.ResourceDecisions = r.GetResourceDecisions()[:1] }},
		{"unexpected obligations", func(r *authz.GetDecisionMultiResourceResponse) {
			r.GetResourceDecisions()[1].RequiredObligations = []string{"unexpected"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := proto.CloneOf(valid)
			tc.change(response)
			require.Error(t, validateScaleDecision(response, expected))
		})
	}
	require.Error(t, validateScaleDecision(nil, expected))
}

func TestScaleCasesRejectMissingTable(t *testing.T) {
	_, err := parseAuthorizationScaleCases(nil)
	require.Error(t, err)
}
