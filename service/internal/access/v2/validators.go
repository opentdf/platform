package access

import (
	"fmt"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
)

// validateGetDecision validates the input parameters for GetDecision:
//
//   - entityChain: must not be nil and must contain at least one entity
//   - action: must not be nil
//   - resources: must not be nil and must contain at least one resource
func validateGetDecision(entityChain *authz.EntityChain, action *policy.Action, resources []*authz.Resource) error {
	if entityChain == nil {
		return fmt.Errorf("entity chain is nil: %w", ErrInvalidEntityChain)
	}
	if len(entityChain.GetEntities()) == 0 {
		return fmt.Errorf("entity chain is empty: %w", ErrInvalidEntityChain)
	}
	if action == nil {
		return fmt.Errorf("action is nil: %w", ErrInvalidAction)
	}
	if len(resources) == 0 {
		return fmt.Errorf("resources are empty: %w", ErrInvalidResourceType)
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
		if value.GetFqn() == "" {
			return fmt.Errorf("attribute value FQN is empty: %w", ErrInvalidAttributeDefinition)
		}
	}
	return nil
}

// validateEntityRepresentations validates the entity representations are valid for an entitlement decision
//
//   - entityRepresentations: must have at least one non-nil entity representation
func validateEntityRepresentations(entityRepresentations []*entityresolution.EntityRepresentation) error {
	if entityRepresentations == nil || len(entityRepresentations) == 0 {
		return fmt.Errorf("empty entity chain: %w", ErrInvalidEntityChain)
	}
	for _, entity := range entityRepresentations {
		if entity == nil {
			return fmt.Errorf("entity is nil: %w", ErrInvalidEntityChain)
		}
	}

	return nil
}
