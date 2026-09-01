package db

import (
	"context"

	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/common"
)

func (c PolicyDBClient) CountAttributeDefinitions(ctx context.Context, namespaceID string) (int64, error) {
	return c.queries.countAttributeDefinitions(ctx, namespaceID)
}

func (c PolicyDBClient) CountAttributeValues(ctx context.Context, attributeDefinitionID string) (int64, error) {
	return c.queries.countAttributeValues(ctx, attributeDefinitionID)
}

func (c PolicyDBClient) GetResourceMappingGroupCount(ctx context.Context, namespaceID, namespaceFQN string) (string, int64, error) {
	result, err := c.queries.getResourceMappingGroupCount(ctx, getResourceMappingGroupCountParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
	return result.NamespaceID, result.ObjectCount, err
}

func (c PolicyDBClient) CountResourceMappings(ctx context.Context, attributeValueID string) (int64, error) {
	return c.queries.countResourceMappings(ctx, attributeValueID)
}

func (c PolicyDBClient) CountSubjectMappings(ctx context.Context, attributeValueID string) (int64, error) {
	return c.queries.countSubjectMappings(ctx, attributeValueID)
}

func (c PolicyDBClient) CountSubjectConditionSets(ctx context.Context, namespaceID, namespaceFQN string) (int64, error) {
	return c.queries.countSubjectConditionSets(ctx, countSubjectConditionSetsParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
}

func (c PolicyDBClient) CountObligationDefinitions(ctx context.Context, namespaceID, namespaceFQN string) (int64, error) {
	return c.queries.countObligationDefinitions(ctx, countObligationDefinitionsParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
}

func (c PolicyDBClient) CountObligationValues(ctx context.Context, obligationID, obligationFQN string) (int64, error) {
	namespaceFQN, obligationName := identifier.BreakOblFQN(obligationFQN)
	return c.queries.countObligationValues(ctx, countObligationValuesParams{
		ObligationID:   pgtypeUUID(obligationID),
		NamespaceFqn:   pgtypeText(namespaceFQN),
		ObligationName: pgtypeText(obligationName),
	})
}

func (c PolicyDBClient) CountObligationTriggersForAttributeValue(ctx context.Context, value *common.IdFqnIdentifier, excludedObligationValueID string) (int64, error) {
	return c.queries.countObligationTriggersForAttributeValue(ctx, countObligationTriggersForAttributeValueParams{
		AttributeValueID:          pgtypeUUID(value.GetId()),
		AttributeValueFqn:         pgtypeText(value.GetFqn()),
		ExcludedObligationValueID: pgtypeUUID(excludedObligationValueID),
	})
}

func (c PolicyDBClient) CountActions(ctx context.Context, namespaceID, namespaceFQN string) (int64, error) {
	return c.queries.countActions(ctx, countActionsParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
}

func (c PolicyDBClient) CountActionsWithMissingNames(ctx context.Context, namespaceID, namespaceFQN string, actionNames []string) (int64, int64, error) {
	counts, err := c.queries.countActionsWithMissingNames(ctx, countActionsWithMissingNamesParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
		ActionNames:  actionNames,
	})
	return counts.CurrentCount, counts.MissingCount, err
}

func (c PolicyDBClient) GetAttributeDefinitionNamespaceID(ctx context.Context, attributeDefinitionID string) (string, error) {
	return c.queries.getAttributeDefinitionNamespaceID(ctx, attributeDefinitionID)
}

func (c PolicyDBClient) GetAttributeValueNamespaceID(ctx context.Context, value *common.IdFqnIdentifier) (string, error) {
	return c.queries.getAttributeValueNamespaceID(ctx, getAttributeValueNamespaceIDParams{
		AttributeValueID:  pgtypeUUID(value.GetId()),
		AttributeValueFqn: pgtypeText(value.GetFqn()),
	})
}
