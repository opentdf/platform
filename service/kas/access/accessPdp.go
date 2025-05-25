package access

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/tracing"
)

const (
	ErrPolicyDissemInvalid     = Error("policy dissem invalid")
	ErrDecisionUnexpected      = Error("authorization decision unexpected")
	ErrDecisionCountUnexpected = Error("authorization decision count unexpected")
)

type PDPAccessResult struct {
	Access bool
	Error  error
	Policy *Policy
}

func (p *Provider) canAccess(ctx context.Context, token *authorization.Token, policies []*Policy) ([]PDPAccessResult, error) {
	var res []PDPAccessResult
	var rasList []*authorization.ResourceAttribute
	idPolicyMap := make(map[string]*Policy)
	for i, policy := range policies {
		if len(policy.Body.Dissem) > 0 {
			// TODO: Move dissems check to the getdecisions endpoint
			p.Logger.Error("Dissems check is not enabled in v2 platform kas")
		}
		if len(policy.Body.DataAttributes) > 0 {
			id := fmt.Sprintf("rewrap-%d", i)
			ras := &authorization.ResourceAttribute{ResourceAttributesId: id}
			for _, attr := range policy.Body.DataAttributes {
				ras.AttributeValueFqns = append(ras.AttributeValueFqns, attr.URI)
			}
			rasList = append(rasList, ras)
			idPolicyMap[id] = policy
		} else {
			res = append(res, PDPAccessResult{Access: true, Policy: policy})
		}
	}

	ctx, span := p.Start(ctx, "checkAttributes")
	defer span.End()

	dr, err := p.checkAttributes(ctx, rasList, token)
	if err != nil {
		return nil, err
	}

	for _, resp := range dr.GetDecisionResponses() {
		policy, ok := idPolicyMap[resp.GetResourceAttributesId()]
		if !ok { // this really should not happen
			continue
		}
		res = append(res, PDPAccessResult{Policy: policy, Access: resp.GetDecision() == authorization.DecisionResponse_DECISION_PERMIT})
	}

	return res, nil
}

func (p *Provider) checkAttributes(ctx context.Context, ras []*authorization.ResourceAttribute, ent *authorization.Token) (*authorization.GetDecisionsByTokenResponse, error) {
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

	ctx = tracing.InjectTraceContext(ctx)
	dr, err := p.SDK.Authorization.GetDecisionsByToken(ctx, &in)
	if err != nil {
		p.Logger.ErrorContext(ctx, "Error received from GetDecisionsByToken", "err", err)
		return nil, errors.Join(ErrDecisionUnexpected, err)
	}
	return dr, nil
}
