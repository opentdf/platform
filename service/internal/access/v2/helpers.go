package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/opentdf/platform/lib/identifier"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrInvalidSubjectMapping          = errors.New("access: invalid subject mapping")
	ErrInvalidAttributeDefinition     = errors.New("access: invalid attribute definition")
	ErrInvalidRegisteredResource      = errors.New("access: invalid registered resource")
	ErrInvalidRegisteredResourceValue = errors.New("access: invalid registered resource value")
)

// getDefinition parses the value FQN and uses it to retrieve the definition from the provided definitions canmap
func getDefinition(valueFQN string, allDefinitionsByDefFQN map[string]*policy.Attribute) (*policy.Attribute, error) {
	parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](valueFQN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attribute value FQN [%s]: %w", valueFQN, err)
	}
	def := &identifier.FullyQualifiedAttribute{
		Namespace: parsed.Namespace,
		Name:      parsed.Name,
	}

	definition, ok := allDefinitionsByDefFQN[def.FQN()]
	if !ok {
		return nil, fmt.Errorf("definition not found for FQN: %s", def.FQN())
	}
	return definition, nil
}

// getFilteredEntitleableAttributes filters the entitleable attributes to only those that are in the optional matched subject mappings
func getFilteredEntitleableAttributes(
	matchedSubjectMappings []*policy.SubjectMapping,
	allEntitleableAttributesByValueFQN map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
) (map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	filtered := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)

	for _, sm := range matchedSubjectMappings {
		mappedValue := sm.GetAttributeValue()
		mappedValueFQN := mappedValue.GetFqn()

		if _, ok := allEntitleableAttributesByValueFQN[mappedValueFQN]; !ok {
			return nil, fmt.Errorf("invalid attribute value FQN in optional matched subject mappings: %w", ErrInvalidSubjectMapping)
		}
		// Take subject mapping's attribute value and its definition from memory
		attributeAndValue, ok := allEntitleableAttributesByValueFQN[mappedValueFQN]
		if !ok {
			return nil, fmt.Errorf("attribute value not found in memory: %s", mappedValueFQN)
		}
		parentDefinition := attributeAndValue.GetAttribute()

		// Create a copy of the value with the subject mapping
		valueWithMapping := &policy.Value{
			Fqn:             mappedValue.GetFqn(),
			Value:           mappedValue.GetValue(),
			SubjectMappings: []*policy.SubjectMapping{sm},
		}

		mapped := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value:     valueWithMapping,
			Attribute: parentDefinition,
		}

		// If this value already exists in the filtered map, append the subject mapping
		if existing, exists := filtered[mappedValueFQN]; exists {
			existing.Value.SubjectMappings = append(existing.Value.SubjectMappings, sm)
		} else {
			filtered[mappedValueFQN] = mapped
		}
	}

	return filtered, nil
}

// populateLowerValuesIfHierarchy populates the lower values if the attribute is of type hierarchy
func populateLowerValuesIfHierarchy(
	valueFQN string,
	entitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entitledActions *authz.EntityEntitlements_ActionsList,
	entitledActionsPerAttributeValueFqn map[string]*authz.EntityEntitlements_ActionsList,
) error {
	attributeAndValue, ok := entitleableAttributes[valueFQN]
	if !ok {
		return fmt.Errorf("attribute value not found in memory: %s", valueFQN)
	}
	definition := attributeAndValue.GetAttribute()
	if definition == nil {
		return fmt.Errorf("attribute is nil: %w", ErrInvalidAttributeDefinition)
	}
	if definition.GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		return nil
	}

	lower := false
	entitledActionsSet := make(map[string]*policy.Action)
	for _, action := range entitledActions.GetActions() {
		entitledActionsSet[action.GetName()] = action
	}
	for _, value := range definition.GetValues() {
		if lower {
			alreadyEntitledActions, exists := entitledActionsPerAttributeValueFqn[value.GetFqn()]
			if !exists {
				entitledActionsPerAttributeValueFqn[value.GetFqn()] = entitledActions
			} else {
				// Ensure the actions are unique
				mergedActions := mergeDeduplicatedActions(entitledActionsSet, alreadyEntitledActions.GetActions())

				merged := &authz.EntityEntitlements_ActionsList{
					Actions: mergedActions,
				}

				entitledActionsPerAttributeValueFqn[value.GetFqn()] = merged
			}
		}
		if value.GetFqn() == valueFQN {
			lower = true
		}
	}

	return nil
}

// populateHigherValuesIfHierarchy sets the higher values if the attribute is of type hierarchy to
// the decisionable attributes map
func populateHigherValuesIfHierarchy(
	ctx context.Context,
	l *logger.Logger,
	valueFQN string,
	definition *policy.Attribute,
	allEntitleableAttributesByValueFQN map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	decisionableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
) error {
	if definition == nil {
		return fmt.Errorf("attribute is nil: %w", ErrInvalidAttributeDefinition)
	}
	if definition.GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		return nil
	}

	for _, value := range definition.GetValues() {
		if value.GetFqn() == valueFQN {
			break
		}
		// Pull the value from the lookup store holding subject mappings
		fullValue, ok := allEntitleableAttributesByValueFQN[value.GetFqn()]
		if !ok {
			l.WarnContext(ctx,
				"value FQN of hierarchy attribute not found available for lookup, may not have had subject mappings associated or provided",
				slog.String("value_fqn", value.GetFqn()),
			)
			continue
		}
		decisionableAttributes[value.GetFqn()] = &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value:     fullValue.GetValue(),
			Attribute: definition,
		}
	}

	return nil
}

// Deduplicate and merge two lists of actions
func mergeDeduplicatedActions(actionsSet map[string]*policy.Action, actionsToMerge ...[]*policy.Action) []*policy.Action {
	// Add or override with actions to merge
	for _, actionList := range actionsToMerge {
		for _, action := range actionList {
			actionsSet[action.GetName()] = action
		}
	}

	// Convert map back to slice
	merged := make([]*policy.Action, 0, len(actionsSet))
	for _, action := range actionsSet {
		merged = append(merged, action)
	}

	return merged
}

func getResourceDecisionableAttributes(
	ctx context.Context,
	logger *logger.Logger,
	accessibleRegisteredResourceValues map[string]*policy.RegisteredResourceValue,
	entitleableAttributesByValueFQN map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	allAttributesByDefinitionFQN map[string]*policy.Attribute,
	// action *policy.Action,
	resources []*authz.Resource,
) (map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	var (
		decisionableAttributes = make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)
		attrValueFQNs          = make([]string, 0)
	)

	// Parse attribute value FQNs from various resource types
	for idx, resource := range resources {
		// Assign indexed ephemeral ID for resource if not already set
		if resource.GetEphemeralId() == "" {
			resource.EphemeralId = "resource-" + strconv.Itoa(idx)
		}

		switch resource.GetResource().(type) {
		case *authz.Resource_RegisteredResourceValueFqn:
			regResValueFQN := strings.ToLower(resource.GetRegisteredResourceValueFqn())
			regResValue, found := accessibleRegisteredResourceValues[regResValueFQN]
			if !found {
				return nil, fmt.Errorf("resource registered resource value FQN not found in memory [%s]: %w", regResValueFQN, ErrInvalidResource)
			}

			for _, aav := range regResValue.GetActionAttributeValues() {
				attrValueFQNs = append(attrValueFQNs, aav.GetAttributeValue().GetFqn())
			}

		case *authz.Resource_AttributeValues_:
			for idx, attrValueFQN := range resource.GetAttributeValues().GetFqns() {
				// lowercase each resource attribute value FQN for case consistent map key lookups
				attrValueFQN = strings.ToLower(attrValueFQN)
				resource.GetAttributeValues().Fqns[idx] = attrValueFQN

				attrValueFQNs = append(attrValueFQNs, attrValueFQN)
			}

		default:
			// default should never happen as we validate above
			return nil, fmt.Errorf("invalid resource type [%T]: %w", resource.GetResource(), ErrInvalidResource)
		}
	}

	// determine decisionable attributes based on the attribute value FQNs
	for _, attrValueFQN := range attrValueFQNs {
		// If same value FQN more than once, skip (dedupe)
		if _, ok := decisionableAttributes[attrValueFQN]; ok {
			continue
		}

		attributeAndValue, ok := entitleableAttributesByValueFQN[attrValueFQN]
		if !ok {
			// TODO: this logic requires a provisioned Virtru org namespace, definition and FQN record in the database
			// TODO: add provisioning scripts for test orgs in dev/staging and decide how to provision for production
			// Try to find the definition by extracting partial FQN for adhoc attributes
			parentDefinition, err := getDefinition(attrValueFQN, allAttributesByDefinitionFQN)
			if err != nil {
				return nil, fmt.Errorf("resource attribute value FQN not found in memory and no definition found [%s]: %w", attrValueFQN, err)
			}

			// Extract the value part from the FQN
			// FQN format: https://<namespace>/attr/<name>/value/<value>
			lastSlashIdx := strings.LastIndex(attrValueFQN, "/")
			valueStr := ""
			if lastSlashIdx != -1 {
				valueStr = attrValueFQN[lastSlashIdx+1:]
			}

			// Create synthetic AttributeAndValue for adhoc attribute
			syntheticValue := &policy.Value{
				Fqn:   attrValueFQN,
				Value: valueStr,
			}

			attributeAndValue = &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Value:     syntheticValue,
				Attribute: parentDefinition,
			}
		}

		decisionableAttributes[attrValueFQN] = attributeAndValue
		err := populateHigherValuesIfHierarchy(ctx, logger, attrValueFQN, attributeAndValue.GetAttribute(), entitleableAttributesByValueFQN, decisionableAttributes)
		if err != nil {
			return nil, fmt.Errorf("error populating higher hierarchy attribute values: %w", err)
		}
	}

	return decisionableAttributes, nil
}
