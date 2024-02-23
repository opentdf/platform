package access

import (
	"context"
	"errors"
	"log/slog"

	attrs "github.com/virtru/access-pdp/attributes"
	accessPdp "github.com/virtru/access-pdp/pdp"
)

const (
	ErrPolicyDissemInvalid = Error("policy dissem invalid")
	ErrDecisionUnexpected  = Error("access policy decision unexpected")
)

func canAccess(ctx context.Context, entityID string, policy Policy, claims ClaimsObject, attrDefs []attrs.AttributeDefinition) (bool, error) {
	dissemAccess, err := checkDissems(policy.Body.Dissem, entityID)
	if err != nil {
		return false, err
	}
	attrAccess, err := checkAttributes(ctx, policy.Body.DataAttributes, claims.Entitlements, attrDefs)
	if err != nil {
		return false, err
	}
	if dissemAccess && attrAccess {
		return true, nil
	} else {
		return false, nil
	}
}

func checkDissems(dissems []string, entityID string) (bool, error) {
	if entityID == "" {
		return false, ErrPolicyDissemInvalid
	}
	if len(dissems) == 0 || contains(dissems, entityID) {
		return true, nil
	}
	return false, nil
}

func checkAttributes(ctx context.Context, dataAttrs []Attribute, entitlements []Entitlement, attrDefs []attrs.AttributeDefinition) (bool, error) {
	// convert data and entitty attrs to attrs.AttributeInstance
	dataAttrInstances, err := convertAttrsToAttrInstances(dataAttrs)
	if err != nil {
		return false, err
	}
	entityAttrMap, err := convertEntitlementsToEntityAttrMap(entitlements)
	if err != nil {
		return false, err
	}

	accessPDP := accessPdp.NewAccessPDPWithSlog(slog.Default())

	decisions, err := accessPDP.DetermineAccess(dataAttrInstances, entityAttrMap, attrDefs, &ctx)
	if err != nil {
		slog.WarnContext(ctx, "Error recieved from accessPDP", "err", err)
		return false, errors.Join(ErrDecisionUnexpected, err)
	}
	// check the decisions
	for _, decision := range decisions {
		if !decision.Access {
			return false, nil
		}
	}
	return true, nil
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
