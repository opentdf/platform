package access

import (
	"context"
	"errors"
	"github.com/opentdf/platform/protocol/go/policy"
	otdf "github.com/opentdf/platform/sdk"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/authorization"
	attrs "github.com/virtru/access-pdp/attributes"
)

const (
	ErrPolicyDissemInvalid     = Error("policy dissem invalid")
	ErrDecisionUnexpected      = Error("authorization decision unexpected")
	ErrDecisionCountUnexpected = Error("authorization decision count unexpected")
)

func canAccess(ctx context.Context, entity authorization.Entity, policy Policy, sdk *otdf.SDK) (bool, error) {
	if len(policy.Body.Dissem) > 0 {
		dissemAccess, err := checkDissems(policy.Body.Dissem, entity)
		if err != nil {
			return false, err
		}
		if dissemAccess {
			return true, nil
		} else {
			return false, nil
		}
	}
	attrAccess, err := checkAttributes(ctx, policy.Body.DataAttributes, entity, sdk)
	if err != nil {
		return false, err
	}
	if attrAccess {
		return true, nil
	} else {
		return false, nil
	}
}

func checkDissems(dissems []string, ent authorization.Entity) (bool, error) {
	if ent.GetEmailAddress() == "" {
		return false, ErrPolicyDissemInvalid
	}
	if len(dissems) == 0 || contains(dissems, ent.GetEmailAddress()) {
		return true, nil
	}
	return false, nil
}

func checkAttributes(ctx context.Context, dataAttrs []Attribute, ent authorization.Entity, sdk *otdf.SDK) (bool, error) {
	ec := authorization.EntityChain{Entities: make([]*authorization.Entity, 0)}
	ec.Entities = append(ec.Entities, &ent)
	ras := []*authorization.ResourceAttribute{{
		AttributeFqns: make([]string, 0),
	}}
	for _, attr := range dataAttrs {
		ras[0].AttributeFqns = append(ras[0].AttributeFqns, attr.URI)
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
	if len(dr.DecisionResponses) != 1 {
		slog.ErrorContext(ctx, ErrDecisionCountUnexpected.Error(), "count", len(dr.DecisionResponses))
		return false, ErrDecisionCountUnexpected
	}
	if dr.DecisionResponses[0].Decision == authorization.DecisionResponse_DECISION_PERMIT {
		return true, nil
	}
	return false, nil
}

func convertAttrsToAttrInstances(attributes []Attribute) ([]attrs.AttributeInstance, error) {
	instances := make([]attrs.AttributeInstance, len(attributes))
	for i, attr := range attributes {
		instance, err := attrs.ParseInstanceFromURI(attr.URI)
		if err != nil {
			return nil, errors.Join(ErrPolicyDataAttributeParse, err)
		}
		instances[i] = instance
	}
	return instances, nil
}

func convertEntitlementsToEntityAttrMap(entitlements []Entitlement) (map[string][]attrs.AttributeInstance, error) {
	entityAttrMap := make(map[string][]attrs.AttributeInstance)
	for _, entitlement := range entitlements {
		instances, err := convertAttrsToAttrInstances(entitlement.EntityAttributes)
		if err != nil {
			return nil, err
		}
		entityAttrMap[entitlement.EntityID] = instances
	}
	return entityAttrMap, nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
