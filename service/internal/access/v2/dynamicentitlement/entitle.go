package dynamicentitlement

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
)

// Mapping is the common behavior shared by all three option shapes
// (DefinitionScopedSubjectMapping, DefinitionValueEntitlementMapping,
// DynamicRuleDefinition). Implementing one interface across all three lets the driver
// and the tests treat them uniformly, which is what makes the options directly
// comparable.
type Mapping interface {
	// DefinitionFQN returns the lowercased parent attribute definition FQN the mapping
	// is scoped to.
	DefinitionFQN() string
	// EntitledActions returns the actions entitled on a resource value segment for a
	// single flattened entity representation, or nil when there is no match.
	EntitledActions(entity flattening.Flattened, segment string) ([]*policy.Action, error)
}

var (
	// ErrHierarchyUnsupported indicates dynamic entitlement was requested for a
	// HIERARCHY definition, which requires statically ordered values.
	ErrHierarchyUnsupported = errors.New("dynamicentitlement: HIERARCHY rule is incompatible with dynamic value entitlement")
	// ErrCoexistence indicates a definition has both a value-level (static) subject
	// mapping and a dynamic mapping, which the ADR forbids.
	ErrCoexistence = errors.New("dynamicentitlement: a definition cannot have both a value-level subject mapping and a dynamic mapping")
)

// Entitle resolves the set of actions entitled to an entity on a single concrete
// resource value FQN, across all supplied dynamic mappings scoped to that value's parent
// definition. Mappings scoped to other definitions are ignored, which keeps entitlement
// from leaking across definitions/namespaces that happen to share a value segment
// (the pass-through-value collision concern raised by @jakedoublev).
func Entitle(mappings []Mapping, entityRep *entityresolution.EntityRepresentation, resourceValueFQN string) ([]*policy.Action, error) {
	defFQN, segment, err := parseResourceValue(resourceValueFQN)
	if err != nil {
		return nil, err
	}
	if err := validateValueSegment(segment); err != nil {
		return nil, err
	}

	flats, err := flattenEntity(entityRep)
	if err != nil {
		return nil, err
	}

	actionsByName := map[string]*policy.Action{}
	for _, m := range mappings {
		if !strings.EqualFold(m.DefinitionFQN(), defFQN) {
			continue
		}
		for _, flat := range flats {
			acts, err := m.EntitledActions(flat, segment)
			if err != nil {
				return nil, err
			}
			for _, a := range acts {
				actionsByName[strings.ToLower(a.GetName())] = a
			}
		}
	}
	return sortedActions(actionsByName), nil
}

// Decide applies a definition's combination rule across one or more concrete resource
// value FQNs under a single definition and reports whether action is granted. It mirrors
// the production PDP rules in service/internal/access/v2/evaluate.go (anyOfRule /
// allOfRule) so the spike exercises multi-value resources (ADR decision-flow step 6).
//
// RuleDynamic combines as ANY_OF (see the conflation note on DynamicRuleDefinition).
// RuleHierarchy is rejected outright.
func Decide(mappings []Mapping, entityRep *entityresolution.EntityRepresentation, rule AttributeRule, action string, resourceValueFQNs []string) (bool, error) {
	if len(resourceValueFQNs) == 0 {
		return false, nil
	}

	switch rule {
	case RuleAnyOf, RuleDynamic:
		for _, fqn := range resourceValueFQNs {
			ok, err := actionEntitled(mappings, entityRep, action, fqn)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case RuleAllOf:
		for _, fqn := range resourceValueFQNs {
			ok, err := actionEntitled(mappings, entityRep, action, fqn)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case RuleHierarchy:
		return false, ErrHierarchyUnsupported
	case RuleUnspecified:
		return false, errors.New("dynamicentitlement: unspecified rule")
	default:
		return false, fmt.Errorf("dynamicentitlement: unsupported rule: %s", rule)
	}
}

func actionEntitled(mappings []Mapping, entityRep *entityresolution.EntityRepresentation, action, resourceValueFQN string) (bool, error) {
	acts, err := Entitle(mappings, entityRep, resourceValueFQN)
	if err != nil {
		return false, err
	}
	for _, a := range acts {
		if strings.EqualFold(a.GetName(), action) {
			return true, nil
		}
	}
	return false, nil
}

// ValidateNoCoexistence enforces the ADR's API rule that a definition cannot carry both
// a value-level (static) subject mapping and a dynamic mapping. A real implementation
// would enforce this in the policy service CRUD layer; here it is a standalone check so
// the rule can be exercised by tests.
func ValidateNoCoexistence(definitionFQN string, hasValueLevelSubjectMapping bool, dynamicMappings []Mapping) error {
	if !hasValueLevelSubjectMapping {
		return nil
	}
	for _, m := range dynamicMappings {
		if strings.EqualFold(m.DefinitionFQN(), strings.ToLower(definitionFQN)) {
			return fmt.Errorf("%w: %s", ErrCoexistence, strings.ToLower(definitionFQN))
		}
	}
	return nil
}

// ValidateRule rejects rules that are incompatible with dynamic value entitlement.
func ValidateRule(rule AttributeRule) error {
	if rule == RuleHierarchy {
		return ErrHierarchyUnsupported
	}
	return nil
}

func flattenEntity(er *entityresolution.EntityRepresentation) ([]flattening.Flattened, error) {
	var out []flattening.Flattened
	for _, props := range er.GetAdditionalProps() {
		f, err := flattening.Flatten(props.AsMap())
		if err != nil {
			return nil, fmt.Errorf("flattening entity representation: %w", err)
		}
		out = append(out, f)
	}
	return out, nil
}

func sortedActions(byName map[string]*policy.Action) []*policy.Action {
	if len(byName) == 0 {
		return nil
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*policy.Action, 0, len(names))
	for _, n := range names {
		out = append(out, byName[n])
	}
	return out
}
