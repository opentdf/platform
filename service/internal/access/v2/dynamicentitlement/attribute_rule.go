package dynamicentitlement

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
)

// AttributeRule mirrors the conceptual attribute-definition rule set
// (policy.AttributeRuleTypeEnum: ANY_OF / ALL_OF / HIERARCHY) extended with RuleDynamic
// for Option C, "a different attribute rule".
//
// A definition marked RuleDynamic entitles its values by selector match rather than by
// static per-value subject mappings. RuleAnyOf / RuleAllOf / RuleHierarchy are also
// modeled here because the driver needs a combination rule when a single resource
// carries multiple values under one definition (see entitle.go Decide).
type AttributeRule int

const (
	RuleUnspecified AttributeRule = iota
	RuleAnyOf
	RuleAllOf
	RuleHierarchy
	RuleDynamic
)

func (r AttributeRule) String() string {
	switch r {
	case RuleAnyOf:
		return "ANY_OF"
	case RuleAllOf:
		return "ALL_OF"
	case RuleHierarchy:
		return "HIERARCHY"
	case RuleDynamic:
		return "DYNAMIC"
	case RuleUnspecified:
		return "UNSPECIFIED"
	default:
		return fmt.Sprintf("AttributeRule(%d)", int(r))
	}
}

// DynamicRuleDefinition is Option C. Rather than a separate mapping object, the
// AttributeDefinition itself carries the dynamic intent (Rule == RuleDynamic) plus the
// selector/operator/actions inline.
//
// Modeling dynamic as a rule VALUE surfaces a structural tension captured in ADR 0005:
// the rule slot already encodes how multiple values on one definition COMBINE
// (ANY_OF / ALL_OF / HIERARCHY). Spending that slot on RuleDynamic — which describes how
// values are ENTITLED — conflates two orthogonal axes, so a dynamic definition can no
// longer also state its combination semantics. Here, RuleDynamic combines as ANY_OF by
// default (see Decide).
type DynamicRuleDefinition struct {
	AttributeDefinitionFQN string
	Rule                   AttributeRule // expected RuleDynamic
	Selector               string
	Operator               DynamicOperator
	Actions                []*policy.Action
	Canonicalizer          Canonicalizer
}

var _ Mapping = (*DynamicRuleDefinition)(nil)

// DefinitionFQN implements Mapping.
func (d *DynamicRuleDefinition) DefinitionFQN() string {
	return strings.ToLower(d.AttributeDefinitionFQN)
}

// EntitledActions implements Mapping. It only entitles when the definition is actually
// marked RuleDynamic, demonstrating that the rule value gates the behavior.
func (d *DynamicRuleDefinition) EntitledActions(entity flattening.Flattened, segment string) ([]*policy.Action, error) {
	if d.Rule != RuleDynamic {
		return nil, nil
	}
	matched, err := evaluateDynamicMatch(d.Operator, entity, d.Selector, segment, d.Canonicalizer)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, nil
	}
	return d.Actions, nil
}
