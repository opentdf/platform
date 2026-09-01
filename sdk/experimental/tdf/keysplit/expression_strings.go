// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package keysplit

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
)

// minAttributeParts is the number of pieces an attribute value FQN
// splits into around "/value/".
const minAttributeParts = 2

// String returns a human-readable representation of the boolean expression
func (e *BooleanExpression) String() string {
	if len(e.Clauses) == 0 {
		return "∅"
	}

	var parts []string
	for _, clause := range e.Clauses {
		parts = append(parts, clause.String())
	}
	return strings.Join(parts, " & ")
}

// String returns a human-readable representation of an attribute clause
func (c *AttributeClause) String() string {
	if len(c.Values) == 0 {
		return c.Definition.GetFqn()
	}

	ruleName := ruleToString(c.Rule)

	if len(c.Values) == 1 {
		return c.Values[0].GetFqn()
	}

	// Multiple values - show as rule application
	var valueNames []string
	for _, v := range c.Values {
		// Extract just the value part from FQN
		parts := strings.Split(v.GetFqn(), "/value/")
		if len(parts) == minAttributeParts {
			if unescaped, err := url.PathUnescape(parts[1]); err == nil {
				valueNames = append(valueNames, unescaped)
			} else {
				valueNames = append(valueNames, parts[1])
			}
		} else {
			valueNames = append(valueNames, v.GetFqn())
		}
	}

	return fmt.Sprintf("%s(%s: {%s})",
		ruleName,
		c.Definition.GetFqn(),
		strings.Join(valueNames, ", "))
}

// ruleToString converts attribute rule enum to string
func ruleToString(rule policy.AttributeRuleTypeEnum) string {
	switch rule {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		return "allOf"
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
		return "anyOf"
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		return "hierarchy"
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
		return "unspecified"
	default:
		return "unknown"
	}
}
