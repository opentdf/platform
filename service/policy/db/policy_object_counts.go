package db

import (
	"context"

	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/service/pkg/db"
)

func (c PolicyDBClient) GetCountAttributeDefinitions(ctx context.Context, namespaceID string) (int64, error) {
	return c.queries.countAttributeDefinitions(ctx, namespaceID)
}

func (c PolicyDBClient) GetCountAttributeValues(ctx context.Context, attributeDefinitionID string) (int64, error) {
	return c.queries.countAttributeValues(ctx, attributeDefinitionID)
}

func (c PolicyDBClient) GetCountResourceMappingGroups(ctx context.Context, namespaceID, namespaceFQN string) (string, int64, error) {
	result, err := c.queries.getResourceMappingGroupCount(ctx, getResourceMappingGroupCountParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
	return result.NamespaceID, result.ObjectCount, db.WrapIfKnownInvalidQueryErr(err)
}

func (c PolicyDBClient) GetCountResourceMappings(ctx context.Context, attributeValueID string) (int64, error) {
	return c.queries.countResourceMappings(ctx, attributeValueID)
}

func (c PolicyDBClient) GetCountSubjectMappings(ctx context.Context, attributeValueID string) (int64, error) {
	return c.queries.countSubjectMappings(ctx, attributeValueID)
}

func (c PolicyDBClient) GetCountSubjectConditionSets(ctx context.Context, namespaceID, namespaceFQN string) (int64, error) {
	count, err := c.queries.countSubjectConditionSets(ctx, countSubjectConditionSetsParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
	return count, db.WrapIfKnownInvalidQueryErr(err)
}

func (c PolicyDBClient) GetCountObligationDefinitions(ctx context.Context, namespaceID, namespaceFQN string) (int64, error) {
	return c.queries.countObligationDefinitions(ctx, countObligationDefinitionsParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
}

func (c PolicyDBClient) GetCountObligationValues(ctx context.Context, obligationID, obligationFQN string) (int64, error) {
	namespaceFQN, obligationName := identifier.BreakOblFQN(obligationFQN)
	return c.queries.countObligationValues(ctx, countObligationValuesParams{
		ObligationID:   pgtypeUUID(obligationID),
		NamespaceFqn:   pgtypeText(namespaceFQN),
		ObligationName: pgtypeText(obligationName),
	})
}

// GetCountObligationTriggersForAttributeValue returns the canonical attribute value ID
// with its trigger count so callers can combine additions that identify the same value
// by different identifier forms.
func (c PolicyDBClient) GetCountObligationTriggersForAttributeValue(ctx context.Context, value *common.IdFqnIdentifier, excludedObligationValueID string) (string, int64, error) {
	result, err := c.queries.countObligationTriggersForAttributeValue(ctx, countObligationTriggersForAttributeValueParams{
		AttributeValueID:          pgtypeUUID(value.GetId()),
		AttributeValueFqn:         pgtypeText(value.GetFqn()),
		ExcludedObligationValueID: pgtypeUUID(excludedObligationValueID),
	})
	return result.AttributeValueID, result.ObjectCount, db.WrapIfKnownInvalidQueryErr(err)
}

func (c PolicyDBClient) GetCountActions(ctx context.Context, namespaceID, namespaceFQN string) (int64, error) {
	count, err := c.queries.countActions(ctx, countActionsParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
	})
	return count, db.WrapIfKnownInvalidQueryErr(err)
}

// GetCountActionsWithNewAdditions returns the current action count and the number of
// distinct supplied names that would create actions in the target namespace.
func (c PolicyDBClient) GetCountActionsWithNewAdditions(ctx context.Context, namespaceID, namespaceFQN string, actionNames []string) (int64, int64, error) {
	counts, err := c.queries.countActionsWithMissingNames(ctx, countActionsWithMissingNamesParams{
		NamespaceID:  pgtypeUUID(namespaceID),
		NamespaceFqn: pgtypeText(namespaceFQN),
		ActionNames:  actionNames,
	})
	return counts.CurrentCount, counts.MissingCount, db.WrapIfKnownInvalidQueryErr(err)
}

func (c PolicyDBClient) GetAttributeDefinitionNamespaceID(ctx context.Context, attributeDefinitionID string) (string, error) {
	namespaceID, err := c.queries.getAttributeDefinitionNamespaceID(ctx, attributeDefinitionID)
	return namespaceID, db.WrapIfKnownInvalidQueryErr(err)
}

func (c PolicyDBClient) GetAttributeValueNamespaceID(ctx context.Context, value *common.IdFqnIdentifier) (string, error) {
	namespaceID, err := c.queries.getAttributeValueNamespaceID(ctx, getAttributeValueNamespaceIDParams{
		AttributeValueID:  pgtypeUUID(value.GetId()),
		AttributeValueFqn: pgtypeText(value.GetFqn()),
	})
	return namespaceID, db.WrapIfKnownInvalidQueryErr(err)
}
