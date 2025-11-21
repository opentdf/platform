package access

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
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
	var resources []*authzV2.Resource
	idPolicyMap := make(map[string]*Policy)
	var requester string

	needsDissemCheck := false
	for _, policy := range policies {
		if len(policy.Body.Dissem) > 0 {
			needsDissemCheck = true
			break
		}
	}

	if needsDissemCheck {
		subject, err := extractSubject(token.GetJwt())
		if err != nil {
			return nil, errors.Join(ErrPolicyDissemInvalid, err)
		}
		requester = subject
	}
	for i, policy := range policies {
		if len(policy.Body.Dissem) > 0 {
			if !dissemAllowed(policy.Body.Dissem, requester) {
				res = append(res, PDPAccessResult{Access: false, Policy: policy})
				continue
			}
		}
		if len(policy.Body.DataAttributes) > 0 {
			id := "rewrap-" + strconv.Itoa(i)
			attrValueFqns := make([]string, len(policy.Body.DataAttributes))
			for idx, attr := range policy.Body.DataAttributes {
				attrValueFqns[idx] = attr.URI
			}
			resources = append(resources, &authzV2.Resource{
				EphemeralId: id,
				Resource: &authzV2.Resource_AttributeValues_{
					AttributeValues: &authzV2.Resource_AttributeValues{
						Fqns: attrValueFqns,
					},
				},
			})
			idPolicyMap[id] = policy
		} else {
			res = append(res, PDPAccessResult{Access: true, Policy: policy})
		}
	}

	// If no data attributes were found in any policies, return early with the results
	// instead of roundtripping to get a decision on no resources
	if len(resources) == 0 {
		p.Logger.DebugContext(ctx, "no resources to check")
		return res, nil
	}

	ctx, span := p.Start(ctx, "checkAttributes")
	defer span.End()

	resourceDecisions, err := p.checkAttributes(ctx, resources, token)
	if err != nil {
		return nil, err
	}

	for _, decision := range resourceDecisions {
		policy, ok := idPolicyMap[decision.GetEphemeralResourceId()]
		if !ok { // this really should not happen
			p.Logger.WarnContext(ctx, "unexpected ephemeral resource id not mapped to a policy")
			continue
		}
		res = append(res, PDPAccessResult{Policy: policy, Access: decision.GetDecision() == authzV2.Decision_DECISION_PERMIT})
	}

	return res, nil
}

func extractSubject(rawToken string) (string, error) {
	tok, err := jwt.ParseString(rawToken, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return "", err
	}

	if sub, ok := tok.Get("sub"); ok {
		if asString, ok := sub.(string); ok && asString != "" {
			return asString, nil
		}
	}

	if email, ok := tok.Get("email"); ok {
		if asString, ok := email.(string); ok && asString != "" {
			return asString, nil
		}
	}

	return "", errors.New("missing subject")
}

func dissemAllowed(dissems []string, subject string) bool {
	if subject == "" {
		return false
	}
	for _, d := range dissems {
		if strings.EqualFold(d, subject) {
			return true
		}
	}
	return false
}

// checkAttributes makes authorization service GetDecision requests to check access to resources
func (p *Provider) checkAttributes(ctx context.Context, resources []*authzV2.Resource, ent *entity.Token) ([]*authzV2.ResourceDecision, error) {
	ctx = tracing.InjectTraceContext(ctx)

	// If only one resource, prefer singular endpoint
	if len(resources) == 1 {
		req := &authzV2.GetDecisionRequest{
			EntityIdentifier: &authzV2.EntityIdentifier{
				Identifier: &authzV2.EntityIdentifier_Token{Token: ent},
			},
			Action:   decryptAction,
			Resource: resources[0],
		}
		dr, err := p.SDK.AuthorizationV2.GetDecision(ctx, req)
		if err != nil {
			p.Logger.ErrorContext(ctx, "error received from GetDecision")
			return nil, errors.Join(ErrDecisionUnexpected, err)
		}
		return []*authzV2.ResourceDecision{dr.GetDecision()}, nil
	}

	// If more than one resource, use the optimized bulk endpoint
	req := &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_Token{Token: ent},
		},
		Action:    decryptAction,
		Resources: resources,
	}

	dr, err := p.SDK.AuthorizationV2.GetDecisionMultiResource(ctx, req)
	if err != nil {
		p.Logger.ErrorContext(ctx, "error received from GetDecisionMultiResource")
		return nil, errors.Join(ErrDecisionUnexpected, err)
	}
	return dr.GetResourceDecisions(), nil
}
