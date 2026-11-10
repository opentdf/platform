package internal

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/entity"
)

const (
	// Test constants for flexible assertions
	maxDisplayCount     = 5
	minDisplayCount     = 3
	pairDisplayCount    = 2
	pairMinDisplayCount = 2
)

// FlexibleEntityChainExpectation provides range-based and conditional expectations
type FlexibleEntityChainExpectation struct {
	EphemeralID             string
	MinEntityCount          int      // At least this many entities
	MaxEntityCount          int      // At most this many entities (0 = no limit)
	RequiredEntityTypes     []string // Must contain these entity types
	RequiredClaims          []string // Must contain these claim keys
	RequiredCategories      []string // Must contain these categories
	ForbiddenClaims         []string // Must NOT contain these claim keys
	AllowImplementationGaps bool     // Accept implementation differences
}

// FlexibleChainValidationRule provides comprehensive validation
type FlexibleChainValidationRule struct {
	Description         string
	Expectations        []FlexibleEntityChainExpectation
	AllowPartialSuccess bool // Some chains can fail if others succeed
	MinSuccessCount     int  // Minimum number of successful chains
}

// ValidateEntityChainFlexible performs flexible validation with detailed reporting
func ValidateEntityChainFlexible(chains []*entity.EntityChain, rule FlexibleChainValidationRule) error {
	if len(chains) == 0 {
		return errors.New("no entity chains returned")
	}

	var validationErrors []string
	successCount := 0

	// Create a map for quick chain lookup
	chainMap := make(map[string]*entity.EntityChain)
	for _, chain := range chains {
		chainMap[chain.GetEphemeralId()] = chain
	}

	// Validate each expected chain
	for _, expectation := range rule.Expectations {
		chain, exists := chainMap[expectation.EphemeralID]
		if !exists {
			errMsg := fmt.Sprintf("Chain %s: not found in results", expectation.EphemeralID)
			validationErrors = append(validationErrors, errMsg)
			continue
		}

		if err := validateSingleChain(chain, expectation); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("Chain %s: %v", expectation.EphemeralID, err))
		} else {
			successCount++
		}
	}

	// Check success requirements
	if rule.MinSuccessCount > 0 && successCount < rule.MinSuccessCount {
		return fmt.Errorf("insufficient successful chains: %d < %d required. Errors: %s",
			successCount, rule.MinSuccessCount, strings.Join(validationErrors, "; "))
	}

	if !rule.AllowPartialSuccess && len(validationErrors) > 0 {
		return fmt.Errorf("validation failures: %s", strings.Join(validationErrors, "; "))
	}

	return nil
}

// validateSingleChain validates a single chain against expectations
func validateSingleChain(chain *entity.EntityChain, expectation FlexibleEntityChainExpectation) error {
	entityCount := len(chain.GetEntities())

	// Validate entity count
	if entityCount < expectation.MinEntityCount {
		return fmt.Errorf("entity count %d < minimum %d", entityCount, expectation.MinEntityCount)
	}

	if expectation.MaxEntityCount > 0 && entityCount > expectation.MaxEntityCount {
		return fmt.Errorf("entity count %d > maximum %d", entityCount, expectation.MaxEntityCount)
	}

	// Collect entity types and claims from all entities
	entityTypes := make(map[string]bool)
	allClaims := make(map[string]bool)
	categories := make(map[string]bool)

	for _, ent := range chain.GetEntities() {
		// Determine entity type based on the oneof field
		entityType := ""
		switch {
		case ent.GetEmailAddress() != "":
			entityType = "email"
		case ent.GetUserName() != "":
			entityType = "username"
		case ent.GetClientId() != "":
			entityType = "client"
		case ent.GetClaims() != nil:
			entityType = "claims"
		}

		if entityType != "" {
			entityTypes[entityType] = true
		}

		// Get category
		categories[ent.GetCategory().String()] = true

		// Extract claims from standard entity fields
		if ent.GetUserName() != "" {
			allClaims["username"] = true
		}
		if ent.GetEmailAddress() != "" {
			allClaims["email"] = true
		}
		if ent.GetClientId() != "" {
			allClaims["client_id"] = true
		}
	}

	// Validate required entity types
	if !expectation.AllowImplementationGaps {
		for _, requiredType := range expectation.RequiredEntityTypes {
			if !entityTypes[requiredType] {
				return fmt.Errorf("missing required entity type: %s", requiredType)
			}
		}
	}

	// Validate required claims
	for _, requiredClaim := range expectation.RequiredClaims {
		if !allClaims[requiredClaim] {
			return fmt.Errorf("missing required claim: %s", requiredClaim)
		}
	}

	// Validate required categories
	for _, requiredCategory := range expectation.RequiredCategories {
		if !categories[requiredCategory] {
			return fmt.Errorf("missing required category: %s", requiredCategory)
		}
	}

	// Validate forbidden claims
	for _, forbiddenClaim := range expectation.ForbiddenClaims {
		if allClaims[forbiddenClaim] {
			return fmt.Errorf("found forbidden claim: %s", forbiddenClaim)
		}
	}

	return nil
}

// Helper functions to create common expectations

// ExpectBasicUserChain creates expectation for a user-based entity chain
func ExpectBasicUserChain(ephemeralID string) FlexibleEntityChainExpectation {
	return FlexibleEntityChainExpectation{
		EphemeralID:             ephemeralID,
		MinEntityCount:          1,
		MaxEntityCount:          maxDisplayCount, // Reasonable upper bound
		RequiredClaims:          []string{"username", "email"},
		RequiredCategories:      []string{"CATEGORY_SUBJECT"},
		AllowImplementationGaps: true,
	}
}

// ExpectClientChain creates expectation for a client-based entity chain
func ExpectClientChain(ephemeralID string) FlexibleEntityChainExpectation {
	return FlexibleEntityChainExpectation{
		EphemeralID:             ephemeralID,
		MinEntityCount:          1,
		MaxEntityCount:          minDisplayCount,
		RequiredClaims:          []string{"client_id"},
		RequiredCategories:      []string{"CATEGORY_SUBJECT"},
		AllowImplementationGaps: true,
	}
}

// ExpectEnvironmentChain creates expectation for environment entities
func ExpectEnvironmentChain(ephemeralID string) FlexibleEntityChainExpectation {
	return FlexibleEntityChainExpectation{
		EphemeralID:             ephemeralID,
		MinEntityCount:          1,
		MaxEntityCount:          pairDisplayCount,
		RequiredCategories:      []string{"CATEGORY_ENVIRONMENT"},
		AllowImplementationGaps: true,
	}
}

// ExpectMultiStrategyChain creates expectation for multi-strategy entity resolution
func ExpectMultiStrategyChain(ephemeralID string, expectedStrategies int) FlexibleEntityChainExpectation {
	return FlexibleEntityChainExpectation{
		EphemeralID:             ephemeralID,
		MinEntityCount:          expectedStrategies,                       // One entity per strategy
		MaxEntityCount:          expectedStrategies * pairMinDisplayCount, // Allow for additional entities
		RequiredCategories:      []string{"CATEGORY_SUBJECT", "CATEGORY_ENVIRONMENT"},
		AllowImplementationGaps: true,
	}
}

// CreateFlexibleValidationFromLegacy converts legacy validation rules to flexible ones
func CreateFlexibleValidationFromLegacy(legacyRules []EntityChainValidationRule) FlexibleChainValidationRule {
	expectations := make([]FlexibleEntityChainExpectation, len(legacyRules))

	for i, legacy := range legacyRules {
		expectations[i] = FlexibleEntityChainExpectation{
			EphemeralID:             legacy.EphemeralID,
			MinEntityCount:          legacy.EntityCount,
			MaxEntityCount:          legacy.EntityCount, // Strict match for legacy
			RequiredEntityTypes:     legacy.EntityTypes,
			RequiredCategories:      legacy.EntityCategories,
			AllowImplementationGaps: !legacy.RequireConsistentOrdering,
		}
	}

	return FlexibleChainValidationRule{
		Description:         "Converted from legacy validation",
		Expectations:        expectations,
		AllowPartialSuccess: false, // Legacy was strict
		MinSuccessCount:     len(expectations),
	}
}
