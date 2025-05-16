package access

import (
	"context"
	"errors"
	"strconv"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/opentdf/platform/service/tracing"
)

const (
	ErrPolicyDissemInvalid     = Error("policy dissem invalid")
	ErrDecisionUnexpected      = Error("authorization decision unexpected")
	ErrDecisionCountUnexpected = Error("authorization decision count unexpected")
)

var decryptAction = &policy.Action{
	Name: actions.ActionNameRead,
}

type PDPAccessResult struct {
	Access bool
	Error  error
	Policy *Policy
}

func (p *Provider) canAccess(ctx context.Context, token *entity.Token, policies []*Policy) ([]PDPAccessResult, error) {
	var res []PDPAccessResult
	resources := make([]*authzV2.Resource, 0, len(policies))
	idPolicyMap := make(map[string]*Policy)
	for i, policy := range policies {
		if len(policy.Body.Dissem) > 0 {
			// TODO: Move dissems check to the getdecisions endpoint
			p.Logger.Error("Dissems check is not enabled in v2 platform kas")
		}
		if len(policy.Body.DataAttributes) > 0 {
			id := "rewrap-" + strconv.Itoa(i)
			attrValueFqns := make([]string, 0, len(policy.Body.DataAttributes))
			for _, attr := range policy.Body.DataAttributes {
				attrValueFqns = append(attrValueFqns, attr.URI)
			}
			resources[i] = &authzV2.Resource{
				EphemeralId: id,
				Resource: &authzV2.Resource_AttributeValues_{
					AttributeValues: &authzV2.Resource_AttributeValues{
						Fqns: attrValueFqns,
					},
				},
			}
			idPolicyMap[id] = policy
		} else {
			res = append(res, PDPAccessResult{Access: true, Policy: policy})
		}
	}

	// @security
	// TODO: is this accurate?
	if len(resources) == 0 {
		p.Logger.DebugContext(ctx, "No resources to check")
		return res, nil
	}

	ctx, span := p.Start(ctx, "checkAttributes")
	defer span.End()

	dr, err := p.checkAttributes(ctx, resources, token)
	if err != nil {
		return nil, err
	}

	for _, decision := range dr.GetResourceDecisions() {
		policy, ok := idPolicyMap[decision.GetEphemeralResourceId()]
		if !ok { // this really should not happen
			continue
		}
		res = append(res, PDPAccessResult{Policy: policy, Access: decision.GetDecision() == authzV2.Decision_DECISION_PERMIT})
	}

	return res, nil
}

func (p *Provider) checkAttributes(ctx context.Context, resources []*authzV2.Resource, ent *entity.Token) (*authzV2.GetDecisionMultiResourceResponse, error) {
	req := &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_Token{Token: ent},
		},
		Action:    decryptAction,
		Resources: resources,
	}

	ctx = tracing.InjectTraceContext(ctx)
	dr, err := p.SDK.AuthorizationV2.GetDecisionMultiResource(ctx, req)
	if err != nil {
		p.Logger.ErrorContext(ctx, "Error received from GetDecisionMultiResource", "err", err)
		return nil, errors.Join(ErrDecisionUnexpected, err)
	}
	return dr, nil
}
