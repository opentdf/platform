package multistrategy

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// StrategyMatcher handles strategy selection based on JWT context
type StrategyMatcher struct {
	strategies []types.MappingStrategy
}

// NewStrategyMatcher creates a new strategy matcher
func NewStrategyMatcher(strategies []types.MappingStrategy) *StrategyMatcher {
	return &StrategyMatcher{
		strategies: strategies,
	}
}

// SelectStrategy selects the first strategy that matches the JWT claims
func (sm *StrategyMatcher) SelectStrategy(_ context.Context, claims types.JWTClaims) (*types.MappingStrategy, error) {
	for _, strategy := range sm.strategies {
		if sm.matchesConditions(claims, strategy.Conditions) {
			return &strategy, nil
		}
	}

	return nil, types.NewStrategyError("no matching strategy found", map[string]interface{}{
		"available_strategies": len(sm.strategies),
		"entity_map":           extractClaimNames(claims),
	})
}

// SelectStrategies returns all strategies that match the JWT claims in configuration order
func (sm *StrategyMatcher) SelectStrategies(_ context.Context, claimsMap types.JWTClaims) ([]*types.MappingStrategy, error) {
	var matchingStrategies []*types.MappingStrategy

	for _, strategy := range sm.strategies {
		if sm.matchesConditions(claimsMap, strategy.Conditions) {
			matchingStrategies = append(matchingStrategies, &strategy)
		}
	}

	if len(matchingStrategies) == 0 {
		return nil, types.NewStrategyError("no matching strategy found", map[string]interface{}{
			"available_strategies": len(sm.strategies),
			"entity_map":           extractClaimNames(claimsMap),
		})
	}

	return matchingStrategies, nil
}

// matchesConditions checks if JWT claims match strategy conditions
func (sm *StrategyMatcher) matchesConditions(claimsMap types.JWTClaims, conditions types.StrategyConditions) bool {
	for _, claimCondition := range conditions.JWTClaims {
		if !sm.matchesClaimCondition(claimsMap, claimCondition) {
			return false
		}
	}
	return true
}

// matchesClaimCondition checks if a specific claim condition is met
func (sm *StrategyMatcher) matchesClaimCondition(claims types.JWTClaims, condition types.JWTClaimCondition) bool {
	claimValue, exists := claims[condition.Claim]

	switch condition.Operator {
	case "exists":
		return exists && claimValue != nil

	case "equals":
		if !exists || claimValue == nil {
			return false
		}
		return sm.valueEqualsIgnoreCase(claimValue, condition.Values)

	case "contains":
		if !exists || claimValue == nil {
			return false
		}
		return sm.valueContainsIgnoreCase(claimValue, condition.Values)

	case "regex":
		if !exists || claimValue == nil {
			return false
		}
		return sm.valueMatchesRegex(claimValue, condition.Values)

	default:
		// Unknown operator - fail safe
		return false
	}
}

// valueEqualsIgnoreCase checks if claim value equals any of the expected values (case-insensitive)
func (sm *StrategyMatcher) valueEqualsIgnoreCase(claimValue interface{}, expectedValues []string) bool {
	claimStr := sm.interfaceToString(claimValue)
	if claimStr == "" {
		return false
	}

	for _, expected := range expectedValues {
		if strings.EqualFold(claimStr, expected) {
			return true
		}
	}
	return false
}

// valueContainsIgnoreCase checks if claim value contains any of the expected values (case-insensitive)
func (sm *StrategyMatcher) valueContainsIgnoreCase(claimValue interface{}, expectedValues []string) bool {
	// Handle string values
	if claimStr := sm.interfaceToString(claimValue); claimStr != "" {
		lowerClaim := strings.ToLower(claimStr)
		for _, expected := range expectedValues {
			if strings.Contains(lowerClaim, strings.ToLower(expected)) {
				return true
			}
		}
	}

	// Handle array values (e.g., audience claim)
	if claimArray, ok := claimValue.([]interface{}); ok {
		for _, arrayItem := range claimArray {
			if itemStr := sm.interfaceToString(arrayItem); itemStr != "" {
				lowerItem := strings.ToLower(itemStr)
				for _, expected := range expectedValues {
					if strings.Contains(lowerItem, strings.ToLower(expected)) {
						return true
					}
				}
			}
		}
	}

	return false
}

// valueMatchesRegex checks if claim value matches any of the regex patterns
func (sm *StrategyMatcher) valueMatchesRegex(claimValue interface{}, patterns []string) bool {
	claimStr := sm.interfaceToString(claimValue)
	if claimStr == "" {
		return false
	}

	for _, pattern := range patterns {
		if matched, err := regexp.MatchString(pattern, claimStr); err == nil && matched {
			return true
		}
	}
	return false
}

// interfaceToString safely converts interface{} to string
func (sm *StrategyMatcher) interfaceToString(value interface{}) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		// For other types, use string representation
		return strings.TrimSpace(strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
			strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%v", v), "[", ""), "]", ""),
			"{", ""), "}", ""), " ", "")))
	}
}

// extractClaimNames extracts claim names from JWT for debugging
func extractClaimNames(claims types.JWTClaims) []string {
	names := make([]string, 0, len(claims))
	for name := range claims {
		names = append(names, name)
	}
	return names
}
