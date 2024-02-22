package access

import (
	"context"
	"errors"
	"log/slog"

	accesspdp "github.com/opentdf/platform/internal/access"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
)

const (
	ErrPolicyDissemInvalid = Error("policy dissem invalid")
	ErrDecisionUnexpected  = Error("access policy decision unexpected")
)

func canAccess(ctx context.Context, entityID string, policy Policy, claims ClaimsObject, attrDefs []attr.Attribute) (bool, error) {
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

func checkAttributes(ctx context.Context, dataAttrs []Attribute, entitlements []Entitlement, attrDefs []attr.Attribute) (bool, error) {
	// convert data and entitty attrs to accesspdp.AttributeInstance
	dataAttrInstances, err := convertAttrsToAttrInstances(dataAttrs)
	if err != nil {
		return false, err
	}
	entityAttrMap, err := convertEntitlementsToEntityAttrMap(entitlements)
	if err != nil {
		return false, err
	}

	accessPDP := accesspdp.NewPdp()

	decisions, err := accessPDP.DetermineAccess(ctx, dataAttrInstances, entityAttrMap, attrDefs)
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

func convertAttrsToAttrInstances(attributes []Attribute) ([]accesspdp.AttributeInstance, error) {
	instances := make([]accesspdp.AttributeInstance, len(attributes))
	for i, attr := range attributes {
		instance, err := accesspdp.ParseInstanceFromURI(attr.URI)
		if err != nil {
			return nil, errors.Join(ErrPolicyDataAttributeParse, err)
		}
		instances[i] = instance
	}
	return instances, nil
}

func convertEntitlementsToEntityAttrMap(entitlements []Entitlement) (map[string][]accesspdp.AttributeInstance, error) {
	entityAttrMap := make(map[string][]accesspdp.AttributeInstance)
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
