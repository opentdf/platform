package access

import (
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/require"
)

func TestHierarchyEntitlementsRemainDecisionScoped(t *testing.T) {
	const definition = "https://scale.example/attr/clearance"
	high := &policy.Value{Fqn: definition + "/value/high"}
	low := &policy.Value{Fqn: definition + "/value/low"}
	attr := &policy.Attribute{Fqn: definition, Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, Values: []*policy.Value{high, low}}
	mapping := &policy.SubjectMapping{Id: "high-read", AttributeValue: high, SubjectConditionSet: clientIDInConditionSet("authorized"), Actions: []*policy.Action{{Name: "read"}}}
	log := slog.New(slog.DiscardHandler)
	l := &logger.Logger{Logger: log, Audit: audit.CreateAuditLogger(*log)}
	pdp, err := NewPolicyDecisionPoint(t.Context(), l, []*policy.Attribute{attr}, []*policy.SubjectMapping{mapping}, nil, false, false)
	require.NoError(t, err)
	for _, tc := range []struct {
		client string
		action string
		permit bool
	}{
		{"authorized", "read", true},
		{"authorized", "write", false},
		{"unauthorized", "read", false},
		{"authorized", "read", true},
	} {
		resources := append(attrValueResource(high.GetFqn()), attrValueResource(low.GetFqn())...)
		decision, _, err := pdp.GetDecision(t.Context(), entityRepWithClientID(tc.client), &policy.Action{Name: tc.action}, resources)
		require.NoError(t, err)
		require.Equal(t, tc.permit, decision.AllPermitted, "%s/%s", tc.client, tc.action)
		for _, result := range decision.Results {
				require.Equal(t, tc.permit, result.Entitled)
		}
	}
}
