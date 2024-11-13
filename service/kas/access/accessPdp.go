package access

import (
	"context"
	"errors"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	ErrPolicyDissemInvalid     = Error("policy dissem invalid")
	ErrDecisionUnexpected      = Error("authorization decision unexpected")
	ErrDecisionCountUnexpected = Error("authorization decision count unexpected")
)

func (p *Provider) canAccess(ctx context.Context, token *authorization.Token, policy Policy) (bool, error) {
	if len(policy.Body.Dissem) > 0 {
		// TODO: Move dissems check to the getdecisions endpoint
		p.Logger.Error("Dissems check is not enabled in v2 platform kas")
	}
	if len(policy.Body.DataAttributes) > 0 {
		attrAccess, err := p.checkAttributes(ctx, policy.Body.DataAttributes, token)
		if err != nil {
			return false, err
		}
		return attrAccess, nil
	}
	// if no dissem and no attributes then allow
	return true, nil
}

func (p *Provider) checkAttributes(ctx context.Context, dataAttrs []Attribute, ent *authorization.Token) (bool, error) {
	ras := []*authorization.ResourceAttribute{{
		AttributeValueFqns: make([]string, 0),
	}}

	for _, attr := range dataAttrs {
		ras[0].AttributeValueFqns = append(ras[0].GetAttributeValueFqns(), attr.URI)
	}
	in := authorization.GetDecisionsByTokenRequest{
		DecisionRequests: []*authorization.TokenDecisionRequest{
			{
				Actions: []*policy.Action{
					{Value: &policy.Action_Standard{Standard: policy.Action_STANDARD_ACTION_DECRYPT}},
				},
				Tokens:             []*authorization.Token{ent},
				ResourceAttributes: ras,
			},
		},
	}
	dr, err := p.SDK.Authorization.GetDecisionsByToken(ctx, &in)
	if err != nil {
		p.Logger.ErrorContext(ctx, "Error received from GetDecisionsByToken", "err", err)
		return false, errors.Join(ErrDecisionUnexpected, err)
	}
	if len(dr.GetDecisionResponses()) != 1 {
		p.Logger.ErrorContext(ctx, ErrDecisionCountUnexpected.Error(), "count", len(dr.GetDecisionResponses()))
		return false, ErrDecisionCountUnexpected
	}
	if dr.GetDecisionResponses()[0].GetDecision() == authorization.DecisionResponse_DECISION_PERMIT {
		return true, nil
	}
	return false, nil
}
