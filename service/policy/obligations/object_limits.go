package obligations

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type objectLimitCounter interface {
	CountObligationDefinitions(context.Context, string, string) (int64, error)
	CountObligationValues(context.Context, string, string) (int64, error)
	CountObligationTriggersForAttributeValues(context.Context, []*common.IdFqnIdentifier) ([]policydb.PolicyObjectCount, error)
}

func (s *Service) enforceCreateObligationLimits(ctx context.Context, client objectLimitCounter, req *obligations.CreateObligationRequest) error {
	limits := s.config.ObjectLimits
	if limits.ObligationDefinitions > 0 {
		count, err := client.CountObligationDefinitions(ctx, req.GetNamespaceId(), req.GetNamespaceFqn())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeObligationDefinitions, limits.ObligationDefinitions, count, 1); err != nil {
			return err
		}
	}
	return policyconfig.EnforceObjectLimit(
		policyconfig.ObjectTypeObligationValuesPerDefinition,
		limits.ObligationValuesPerDefinition,
		0,
		len(req.GetValues()),
	)
}

func (s *Service) enforceCreateObligationValueLimits(ctx context.Context, client objectLimitCounter, req *obligations.CreateObligationValueRequest) error {
	limits := s.config.ObjectLimits
	if limits.ObligationValuesPerDefinition > 0 {
		count, err := client.CountObligationValues(ctx, req.GetObligationId(), req.GetObligationFqn())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeObligationValuesPerDefinition, limits.ObligationValuesPerDefinition, count, 1); err != nil {
			return err
		}
	}
	if limits.ObligationTriggers == 0 || len(req.GetTriggers()) == 0 {
		return nil
	}
	values := make([]*common.IdFqnIdentifier, 0, len(req.GetTriggers()))
	for _, trigger := range req.GetTriggers() {
		values = append(values, trigger.GetAttributeValue())
	}
	return enforceObligationTriggerLimits(ctx, client, limits.ObligationTriggers, values)
}

func (s *Service) enforceAddObligationTriggerLimit(ctx context.Context, client objectLimitCounter, req *obligations.AddObligationTriggerRequest) error {
	limit := s.config.ObjectLimits.ObligationTriggers
	if limit == 0 {
		return nil
	}
	return enforceObligationTriggerLimits(ctx, client, limit, []*common.IdFqnIdentifier{req.GetAttributeValue()})
}

func enforceObligationTriggerLimits(ctx context.Context, client objectLimitCounter, limit int64, values []*common.IdFqnIdentifier) error {
	counts, err := client.CountObligationTriggersForAttributeValues(ctx, values)
	if err != nil {
		return err
	}
	for _, count := range counts {
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeObligationTriggers, limit, count.Count, int(count.Added)); err != nil {
			return err
		}
	}
	return nil
}
