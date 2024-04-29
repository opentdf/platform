package access

import (
	"context"
	"errors"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	otdf "github.com/opentdf/platform/sdk"
)

const (
	ErrPolicyDissemInvalid     = Error("policy dissem invalid")
	ErrDecisionUnexpected      = Error("authorization decision unexpected")
	ErrDecisionCountUnexpected = Error("authorization decision count unexpected")
)

func canAccess(ctx context.Context, entity *authorization.Entity, policy Policy, sdk *otdf.SDK) (bool, error) {
	if len(policy.Body.Dissem) > 0 {
		dissemAccess, err := checkDissems(policy.Body.Dissem, entity)
		if err != nil {
			return false, err
		}
		return dissemAccess, nil
	}
	if policy.Body.DataAttributes != nil {
		attrAccess, err := checkAttributes(ctx, policy.Body.DataAttributes, entity, sdk)
		if err != nil {
			return false, err
		}
		return attrAccess, nil
	}
	// if no dissem and no attributes then allow
	return true, nil
}

func checkDissems(dissems []string, ent *authorization.Entity) (bool, error) {
	if ent.GetEmailAddress() == "" {
		return false, ErrPolicyDissemInvalid
	}
	if len(dissems) == 0 || contains(dissems, ent.GetEmailAddress()) {
		return true, nil
	}
	return false, nil
}

func checkAttributes(ctx context.Context, dataAttrs []Attribute, ent *authorization.Entity, sdk *otdf.SDK) (bool, error) {
	ec := authorization.EntityChain{Entities: make([]*authorization.Entity, 0)}
	ec.Entities = append(ec.GetEntities(), ent)
	ras := []*authorization.ResourceAttribute{{
		AttributeValueFqns: make([]string, 0),
	}}
	for _, attr := range dataAttrs {
		ras[0].AttributeValueFqns = append(ras[0].GetAttributeValueFqns(), attr.URI)
	}
	in := authorization.GetDecisionsRequest{
		DecisionRequests: []*authorization.DecisionRequest{
			{
				Actions: []*policy.Action{
					{Value: &policy.Action_Standard{Standard: policy.Action_STANDARD_ACTION_DECRYPT}},
				},
				EntityChains:       []*authorization.EntityChain{&ec},
				ResourceAttributes: ras,
			},
		},
	}
	dr, err := sdk.Authorization.GetDecisions(ctx, &in)
	if err != nil {
		slog.ErrorContext(ctx, "Error received from GetDecisions", "err", err)
		return false, errors.Join(ErrDecisionUnexpected, err)
	}
	if len(dr.GetDecisionResponses()) != 1 {
		slog.ErrorContext(ctx, ErrDecisionCountUnexpected.Error(), "count", len(dr.GetDecisionResponses()))
		return false, ErrDecisionCountUnexpected
	}
	if dr.GetDecisionResponses()[0].GetDecision() == authorization.DecisionResponse_DECISION_PERMIT {
		return true, nil
	}
	return false, nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
