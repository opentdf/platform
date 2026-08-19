package attributes

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type objectLimitCounter interface {
	CountAttributeDefinitions(context.Context, string) (int64, error)
	CountAttributeValues(context.Context, string) (int64, error)
	CountObligationTriggersForAttributeDefinition(context.Context, string) (policydb.PolicyObjectCount, error)
}

func (s *AttributesService) enforceCreateAttributeLimits(ctx context.Context, client objectLimitCounter, req *attributes.CreateAttributeRequest) error {
	limits := s.config.ObjectLimits
	if limits.AttributeDefinitions > 0 {
		count, err := client.CountAttributeDefinitions(ctx, req.GetNamespaceId())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeAttributeDefinitions, limits.AttributeDefinitions, count, 1); err != nil {
			return err
		}
	}
	return policyconfig.EnforceObjectLimit(
		policyconfig.ObjectTypeAttributeValuesPerDefinition,
		limits.AttributeValuesPerDefinition,
		0,
		len(req.GetValues()),
	)
}

func (s *AttributesService) enforceCreateAttributeValueLimits(ctx context.Context, client objectLimitCounter, req *attributes.CreateAttributeValueRequest) error {
	limits := s.config.ObjectLimits
	if limits.AttributeValuesPerDefinition > 0 {
		count, err := client.CountAttributeValues(ctx, req.GetAttributeId())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeAttributeValuesPerDefinition, limits.AttributeValuesPerDefinition, count, 1); err != nil {
			return err
		}
	}
	if limits.ObligationTriggers == 0 || len(req.GetObligationTriggers()) == 0 {
		return nil
	}
	count, err := client.CountObligationTriggersForAttributeDefinition(ctx, req.GetAttributeId())
	if err != nil {
		return err
	}
	return policyconfig.EnforceObjectLimit(
		policyconfig.ObjectTypeObligationTriggers,
		limits.ObligationTriggers,
		count.Count,
		len(req.GetObligationTriggers()),
	)
}
