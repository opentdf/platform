package dynamicentitlement

import (
	"strings"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
)

// DefinitionValueEntitlementMapping is the spike's purpose-built primitive — Option B,
// "new primitive". It raises condition-set authority to the AttributeDefinition: a
// single mapping resolves entitlement for every concrete value FQN under the definition.
//
// Compared with Option A (reuse_subjectmapping.go) it carries exactly the four fields
// the dynamic case needs and nothing it does not: there is no static
// subject_external_values to overload, and the operator field is typed to the dynamic
// operators only, so an admin cannot author a nonsensical static/dynamic mix. This is
// the model the ADR sketched as DefinitionValueEntitlementMapping.
type DefinitionValueEntitlementMapping struct {
	// AttributeDefinitionFQN is the parent definition this mapping is scoped to,
	// e.g. "https://hospital.co/attr/mrn".
	AttributeDefinitionFQN string
	// Selector is the flattened entity-representation selector, e.g. ".medicalRecordNumber"
	// or ".patientAssignments[]" for an array field.
	Selector string
	// Operator is the dynamic comparison applied between the selector result and the
	// resource value segment (initially ResourceValueIn).
	Operator DynamicOperator
	// Actions are granted on the concrete value FQN when the comparison matches.
	Actions []*policy.Action
	// Canonicalizer optionally overrides DefaultCanonicalizer.
	Canonicalizer Canonicalizer
}

var _ Mapping = (*DefinitionValueEntitlementMapping)(nil)

// DefinitionFQN implements Mapping.
func (m *DefinitionValueEntitlementMapping) DefinitionFQN() string {
	return strings.ToLower(m.AttributeDefinitionFQN)
}

// EntitledActions implements Mapping: it resolves the selector against the entity and,
// on a match, returns the mapped actions for the given resource value segment.
func (m *DefinitionValueEntitlementMapping) EntitledActions(entity flattening.Flattened, segment string) ([]*policy.Action, error) {
	matched, err := evaluateDynamicMatch(m.Operator, entity, m.Selector, segment, m.Canonicalizer)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, nil
	}
	return m.Actions, nil
}
