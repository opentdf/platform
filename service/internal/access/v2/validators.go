package access

import (
	"errors"
	"fmt"
	"strings"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
)

var (
	ErrInvalidAction                = errors.New("access: invalid action")
	ErrInvalidEntityChain           = errors.New("access: invalid entity chain")
	ErrInvalidEntitledFQNsToActions = errors.New("access: invalid entitled FQNs to actions")
)

// validateGetDecision validates the input parameters for GetDecision:
//
//   - entityRepresentation: must not be nil
//   - action: must not be nil
//   - resources: must not be nil and must contain at least one resource
func validateGetDecision(entityRepresentation *entityresolutionV2.EntityRepresentation, action *policy.Action, resources []*authzV2.Resource) error {
	if err := validateEntityRepresentations([]*entityresolutionV2.EntityRepresentation{entityRepresentation}); err != nil {
		return fmt.Errorf("invalid entity representation: %w", err)
	}
	if action.GetName() == "" {
		return fmt.Errorf("action required with name: %w", ErrInvalidAction)
	}
	if len(resources) == 0 {
		return fmt.Errorf("resources are empty: %w", ErrInvalidResource)
	}
	for _, resource := range resources {
		if resource == nil {
			return fmt.Errorf("resource is nil: %w", ErrInvalidResource)
		}
	}
	return nil
}

// validateSubjectMapping validates the subject mapping is valid for an entitlement decision
//
// subjectMapping:
//
//   - must not be nil
//   - must have a non-empty attribute value
//   - must have a non-empty attribute value FQN
//   - must have a non-empty actions
func validateSubjectMapping(subjectMapping *policy.SubjectMapping) error {
	if subjectMapping == nil {
		return fmt.Errorf("subject mapping is nil: %w", ErrInvalidSubjectMapping)
	}
	if subjectMapping.GetAttributeValue() == nil {
		return fmt.Errorf("subject mapping's attribute value is nil: %w", ErrInvalidSubjectMapping)
	}
	if subjectMapping.GetAttributeValue().GetFqn() == "" {
		return fmt.Errorf("subject mapping's attribute value FQN is empty: %w", ErrInvalidSubjectMapping)
	}
	if subjectMapping.GetActions() == nil {
		return fmt.Errorf("subject mapping's actions are nil: %w", ErrInvalidSubjectMapping)
	}
	return nil
}

// validateAttribute validates the attribute is valid for an entitlement decision
//
// attribute:
//
//   - must not be nil
//   - must have a non-empty FQN
//   - must have non-empty values
//   - must have non-empty values FQNs
func validateAttribute(attribute *policy.Attribute) error {
	if attribute == nil {
		return fmt.Errorf("attribute is nil: %w", ErrInvalidAttributeDefinition)
	}
	if attribute.GetFqn() == "" {
		return fmt.Errorf("attribute FQN is empty: %w", ErrInvalidAttributeDefinition)
	}
	if len(attribute.GetValues()) == 0 {
		return fmt.Errorf("attribute values are empty: %w", ErrInvalidAttributeDefinition)
	}
	for _, value := range attribute.GetValues() {
		if value == nil {
			return fmt.Errorf("attribute value is nil: %w", ErrInvalidAttributeDefinition)
		}
		if !strings.HasPrefix(value.GetFqn(), attribute.GetFqn()) {
			return fmt.Errorf("attribute value FQN must be of definition FQN: %w", ErrInvalidAttributeDefinition)
		}
	}
	if attribute.GetRule() == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED {
		return fmt.Errorf("attribute rule is unspecified: %w", ErrInvalidAttributeDefinition)
	}
	return nil
}

// validateEntityRepresentations validates the entity representations are valid for an entitlement decision
//
//   - entityRepresentations: must have at least one non-nil entity representation
func validateEntityRepresentations(entityRepresentations []*entityresolutionV2.EntityRepresentation) error {
	if len(entityRepresentations) == 0 {
		return fmt.Errorf("empty entity chain: %w", ErrInvalidEntityChain)
	}
	for _, entity := range entityRepresentations {
		if entity == nil {
			return fmt.Errorf("entity is nil: %w", ErrInvalidEntityChain)
		}
	}

	return nil
}

// validateOneResourceDecision validates the parameters for an access decision on a resource
//
//   - accessibleAttributeValues: must not be nil
//   - entitlements: must not be nil
//   - action: must not be nil
//   - resource: must not be nil
func validateGetResourceDecision(
	accessibleAttributeValues map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resource *authzV2.Resource,
) error {
	if entitlements == nil {
		return fmt.Errorf("entitled FQNs to actions are nil: %w", ErrInvalidEntitledFQNsToActions)
	}
	if action.GetName() == "" {
		return fmt.Errorf("action name required: %w", ErrInvalidAction)
	}
	if resource.GetResource() == nil {
		return fmt.Errorf("resource is nil: %w", ErrInvalidResource)
	}
	if len(accessibleAttributeValues) == 0 {
		return fmt.Errorf("accessible attribute values are empty: %w", ErrMissingRequiredPolicy)
	}
	return nil
}
