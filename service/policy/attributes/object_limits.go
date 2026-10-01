package attributes

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
	policyconfig "github.com/opentdf/platform/service/policy/config"
)

type objectLimitCounter interface {
	GetCountAttributeDefinitions(context.Context, string) (int64, error)
	GetCountAttributeValues(context.Context, string) (int64, error)
	GetCountSubjectConditionSets(context.Context, string, string) (int64, error)
	GetCountActionsWithNewAdditions(context.Context, string, string, []string) (int64, int64, error)
	GetAttributeDefinitionNamespaceID(context.Context, string) (string, error)
}

func (s *AttributesService) enforceCreateAttributeLimits(ctx context.Context, client objectLimitCounter, req *attributes.CreateAttributeRequest) error {
	limits := s.config.MaxObjectCounts
	if limits.AttributeDefinitionsPerNamespace > 0 {
		count, err := client.GetCountAttributeDefinitions(ctx, req.GetNamespaceId())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeAttributeDefinitionsPerNamespace, limits.AttributeDefinitionsPerNamespace, count, 1); err != nil {
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
	limits := s.config.MaxObjectCounts
	if limits.AttributeValuesPerDefinition > 0 {
		count, err := client.GetCountAttributeValues(ctx, req.GetAttributeId())
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeAttributeValuesPerDefinition, limits.AttributeValuesPerDefinition, count, 1); err != nil {
			return err
		}
	}
	if err := policyconfig.EnforceObjectLimit(
		policyconfig.ObjectTypeSubjectMappingsPerAttributeValue,
		limits.SubjectMappingsPerAttributeValue,
		0,
		len(req.GetSubjectMappings()),
	); err != nil {
		return err
	}
	if err := policyconfig.EnforceObjectLimit(
		policyconfig.ObjectTypeObligationTriggersPerAttributeValue,
		limits.ObligationTriggersPerAttributeValue,
		0,
		len(req.GetObligationTriggers()),
	); err != nil {
		return err
	}

	// Nested mappings and triggers may create condition sets and actions with the value.
	newConditionSets := 0
	actionNames := make([]string, 0)
	for _, mapping := range req.GetSubjectMappings() {
		if mapping.GetExistingSubjectConditionSetId() == "" && mapping.GetNewSubjectConditionSet() != nil {
			newConditionSets++
		}
		for _, action := range mapping.GetActions() {
			if action.GetId() == "" && action.GetName() != "" {
				actionNames = append(actionNames, action.GetName())
			}
		}
	}
	for _, trigger := range req.GetObligationTriggers() {
		if action := trigger.GetAction(); action.GetId() == "" && action.GetName() != "" {
			actionNames = append(actionNames, action.GetName())
		}
	}

	checkConditionSets := limits.SubjectConditionSetsPerNamespace > 0 && newConditionSets > 0
	checkActions := limits.ActionsPerNamespace > 0 && len(actionNames) > 0
	if !checkConditionSets && !checkActions {
		return nil
	}

	namespaceID, err := client.GetAttributeDefinitionNamespaceID(ctx, req.GetAttributeId())
	if err != nil {
		return err
	}
	if checkConditionSets {
		count, err := client.GetCountSubjectConditionSets(ctx, namespaceID, "")
		if err != nil {
			return err
		}
		if err := policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeSubjectConditionSetsPerNamespace, limits.SubjectConditionSetsPerNamespace, count, newConditionSets); err != nil {
			return err
		}
	}
	if checkActions {
		current, additions, err := client.GetCountActionsWithNewAdditions(ctx, namespaceID, "", actionNames)
		if err != nil {
			return err
		}
		return policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeActionsPerNamespace, limits.ActionsPerNamespace, current, int(additions))
	}
	return nil
}
