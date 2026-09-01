package obligations

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	policyconfig "github.com/opentdf/platform/service/policy/config"
)

type objectLimitCounter interface {
	CountObligationDefinitions(context.Context, string, string) (int64, error)
	CountObligationValues(context.Context, string, string) (int64, error)
	CountObligationTriggersForAttributeValue(context.Context, *common.IdFqnIdentifier, string) (int64, error)
	CountActionsWithMissingNames(context.Context, string, string, []string) (int64, int64, error)
	GetAttributeValueNamespaceID(context.Context, *common.IdFqnIdentifier) (string, error)
}

type triggerAddition struct {
	action *common.IdNameIdentifier
	value  *common.IdFqnIdentifier
}

func (s *Service) enforceCreateObligationLimits(ctx context.Context, client objectLimitCounter, req *obligations.CreateObligationRequest) error {
	limits := s.config.MaxObjectCounts
	if limits.ObligationDefinitionsPerNamespace > 0 {
		count, err := client.CountObligationDefinitions(ctx, req.GetNamespaceId(), req.GetNamespaceFqn())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeObligationDefinitionsPerNamespace, limits.ObligationDefinitionsPerNamespace, count, 1); err != nil {
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
	limits := s.config.MaxObjectCounts
	if limits.ObligationValuesPerDefinition > 0 {
		count, err := client.CountObligationValues(ctx, req.GetObligationId(), req.GetObligationFqn())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeObligationValuesPerDefinition, limits.ObligationValuesPerDefinition, count, 1); err != nil {
			return err
		}
	}
	if len(req.GetTriggers()) == 0 {
		return nil
	}
	additions := make([]triggerAddition, 0, len(req.GetTriggers()))
	for _, trigger := range req.GetTriggers() {
		additions = append(additions, triggerAddition{action: trigger.GetAction(), value: trigger.GetAttributeValue()})
	}
	return s.enforceObligationTriggerLimits(ctx, client, additions, "")
}

func (s *Service) enforceAddObligationTriggerLimit(ctx context.Context, client objectLimitCounter, req *obligations.AddObligationTriggerRequest) error {
	return s.enforceObligationTriggerLimits(ctx, client, []triggerAddition{{action: req.GetAction(), value: req.GetAttributeValue()}}, "")
}

func (s *Service) enforceUpdateObligationValueLimits(ctx context.Context, client objectLimitCounter, req *obligations.UpdateObligationValueRequest) error {
	if len(req.GetTriggers()) == 0 {
		return nil
	}
	additions := make([]triggerAddition, 0, len(req.GetTriggers()))
	for _, trigger := range req.GetTriggers() {
		additions = append(additions, triggerAddition{action: trigger.GetAction(), value: trigger.GetAttributeValue()})
	}
	return s.enforceObligationTriggerLimits(ctx, client, additions, req.GetId())
}

func (s *Service) enforceObligationTriggerLimits(ctx context.Context, client objectLimitCounter, additions []triggerAddition, excludedObligationValueID string) error {
	limits := s.config.MaxObjectCounts
	type addition struct {
		value *common.IdFqnIdentifier
		count int
	}
	triggersByValue := make(map[string]addition, len(additions))
	for _, added := range additions {
		key := added.value.GetId()
		if key == "" {
			key = added.value.GetFqn()
		}
		item := triggersByValue[key]
		item.value = added.value
		item.count++
		triggersByValue[key] = item
	}
	if limits.ObligationTriggersPerAttributeValue > 0 {
		for _, item := range triggersByValue {
			count, err := client.CountObligationTriggersForAttributeValue(ctx, item.value, excludedObligationValueID)
			if err != nil {
				return err
			}
			if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeObligationTriggersPerAttributeValue, limits.ObligationTriggersPerAttributeValue, count, item.count); err != nil {
				return err
			}
		}
	}

	if limits.ActionsPerNamespace == 0 {
		return nil
	}
	actionNamesByNamespace := make(map[string][]string)
	valueNamespaces := make(map[string]string, len(triggersByValue))
	for _, added := range additions {
		if added.action.GetId() != "" || added.action.GetName() == "" {
			continue
		}
		valueKey := added.value.GetId()
		if valueKey == "" {
			valueKey = added.value.GetFqn()
		}
		namespaceID, ok := valueNamespaces[valueKey]
		if !ok {
			var err error
			namespaceID, err = client.GetAttributeValueNamespaceID(ctx, added.value)
			if err != nil {
				return err
			}
			valueNamespaces[valueKey] = namespaceID
		}
		actionNamesByNamespace[namespaceID] = append(actionNamesByNamespace[namespaceID], added.action.GetName())
	}
	for namespaceID, actionNames := range actionNamesByNamespace {
		current, missing, err := client.CountActionsWithMissingNames(ctx, namespaceID, "", actionNames)
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeActionsPerNamespace, limits.ActionsPerNamespace, current, int(missing)); err != nil {
			return err
		}
	}
	return nil
}
