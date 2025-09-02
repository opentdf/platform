package keysplit

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	expectedFQNMatches = 4 // Full match + 3 capture groups (authority, attr name, attr value)
	minAttributeParts  = 2 // Minimum parts when splitting attribute rule
)

// Package-level regex for performance - compiled once and reused
var attributeFQNRegex = regexp.MustCompile(`^(https?://[\w.:/-]+)/attr/([^/\s]*)/value/([^/\s]*)$`)

// buildBooleanExpression groups attribute values by their definition and creates clauses
func buildBooleanExpression(values []*policy.Value) (*BooleanExpression, error) {
	if len(values) == 0 {
		return &BooleanExpression{
			Clauses: []AttributeClause{},
		}, nil
	}

	// Group values by their attribute definition FQN
	clauseMap := make(map[string]*AttributeClause)
	var sortedFQNs []string

	for _, value := range values {
		def := value.GetAttribute()
		if def == nil {
			return nil, fmt.Errorf("%w: attribute definition missing for value %s",
				ErrMissingDefinition, value.GetFqn())
		}

		// Validate the attribute FQN format
		if err := validateAttributeFQN(value.GetFqn()); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidAttributeFQN, err)
		}

		defFQN := def.GetFqn()
		if clause, exists := clauseMap[defFQN]; exists {
			// Add value to existing clause
			clause.Values = append(clause.Values, value)
		} else {
			// Create new clause for this attribute definition
			clauseMap[defFQN] = &AttributeClause{
				Definition: def,
				Values:     []*policy.Value{value},
				Rule:       def.GetRule(),
			}
			sortedFQNs = append(sortedFQNs, defFQN)
		}

		slog.Debug("added value to boolean expression",
			slog.String("value_fqn", value.GetFqn()),
			slog.String("def_fqn", defFQN),
			slog.String("rule", def.GetRule().String()))
	}

	// Sort FQNs for deterministic ordering
	sort.Strings(sortedFQNs)

	// Convert to ordered list of clauses
	expr := &BooleanExpression{
		Clauses: make([]AttributeClause, 0, len(clauseMap)),
	}

	for _, fqn := range sortedFQNs {
		clause := clauseMap[fqn]

		// Validate the attribute rule
		if err := validateAttributeRule(clause.Rule); err != nil {
			return nil, fmt.Errorf("%w: %w for attribute %s", ErrInvalidRule, err, fqn)
		}

		expr.Clauses = append(expr.Clauses, *clause)
	}

	slog.Debug("built boolean expression",
		slog.Int("num_clauses", len(expr.Clauses)),
		slog.String("expression", expr.String()))

	return expr, nil
}

// validateAttributeFQN ensures the FQN follows the expected format
func validateAttributeFQN(fqn string) error {
	if fqn == "" {
		return errors.New("FQN is empty")
	}

	// Check for attribute value FQN format: https://domain/attr/name/value/value
	matches := attributeFQNRegex.FindStringSubmatch(fqn)

	if len(matches) < expectedFQNMatches {
		return fmt.Errorf("invalid FQN format: %s", fqn)
	}

	authority := matches[1]
	attrName := matches[2]
	attrValue := matches[3]

	// Validate URL parts
	if authority == "" || attrName == "" || attrValue == "" {
		return fmt.Errorf("FQN has empty components: %s", fqn)
	}

	// Validate URL encoding
	if _, err := url.PathUnescape(attrName); err != nil {
		return fmt.Errorf("invalid attribute name encoding: %s", attrName)
	}
	if _, err := url.PathUnescape(attrValue); err != nil {
		return fmt.Errorf("invalid attribute value encoding: %s", attrValue)
	}

	return nil
}

// validateAttributeRule checks if the attribute rule is supported
func validateAttributeRule(rule policy.AttributeRuleTypeEnum) error {
	switch rule {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		return nil
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
		return nil
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		return nil
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
		// Treat as allOf
		return nil
	default:
		return fmt.Errorf("unsupported rule type: %s", rule.String())
	}
}

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
