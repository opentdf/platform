package keysplit

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/policy"
)

// createSplitPlan applies boolean logic and attribute rules to determine split assignments
func createSplitPlan(expr *BooleanExpression, defaultKAS string) ([]SplitAssignment, error) {
	if len(expr.Clauses) == 0 {
		return createDefaultSplitPlan(defaultKAS), nil
	}

	var assignments []SplitAssignment

	for _, clause := range expr.Clauses {
		clauseAssignments, err := processBooleanClause(clause)
		if err != nil {
			return nil, fmt.Errorf("failed to process clause for %s: %w",
				clause.Definition.GetFqn(), err)
		}
		assignments = append(assignments, clauseAssignments...)
	}

	if len(assignments) == 0 {
		slog.Debug("no assignments found from attributes, using default KAS",
			slog.String("default_kas", defaultKAS))
		return createDefaultSplitPlan(defaultKAS), nil
	}

	// Optimize the split assignments (remove duplicates, merge compatible splits)
	optimized := optimizeSplitAssignments(assignments)

	slog.Debug("created split plan",
		slog.Int("original_assignments", len(assignments)),
		slog.Int("optimized_assignments", len(optimized)))

	return optimized, nil
}

// processBooleanClause handles a single attribute clause based on its rule
func processBooleanClause(clause AttributeClause) ([]SplitAssignment, error) {
	switch clause.Rule {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		return processAllOfClause(clause)
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
		return processAnyOfClause(clause)
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		return processHierarchyClause(clause)
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
		// Treat unspecified as allOf
		return processAllOfClause(clause)
	default:
		return nil, fmt.Errorf("%w: unsupported rule %s", ErrInvalidRule, clause.Rule.String())
	}
}

// processAllOfClause creates separate splits for each value (all must be satisfied)
func processAllOfClause(clause AttributeClause) ([]SplitAssignment, error) {
	var assignments []SplitAssignment

	for _, value := range clause.Values {
		grant, err := resolveAttributeGrants(value)
		if err != nil {
			slog.Debug("skipping value without grants in allOf clause",
				slog.String("fqn", value.GetFqn()),
				slog.Any("error", err))
			continue
		}

		// Each value gets its own split in allOf
		splitID := generateSplitID()
		assignment := SplitAssignment{
			SplitID: splitID,
			KASURLs: extractKASURLs(grant.KASGrants),
			Keys:    extractKASKeys(grant.KASGrants),
		}

		assignments = append(assignments, assignment)

		slog.Debug("created allOf split",
			slog.String("fqn", value.GetFqn()),
			slog.String("split_id", splitID),
			slog.Any("kas_urls", assignment.KASURLs))
	}

	return assignments, nil
}

// processAnyOfClause creates a single split shared by all values (any can satisfy)
func processAnyOfClause(clause AttributeClause) ([]SplitAssignment, error) {
	allKAS := make(map[string]*policy.SimpleKasPublicKey)
	var allURLs []string
	hasValidGrants := false

	// Collect KAS servers from all values
	for _, value := range clause.Values {
		grant, err := resolveAttributeGrants(value)
		if err != nil {
			slog.Debug("skipping value without grants in anyOf clause",
				slog.String("fqn", value.GetFqn()),
				slog.Any("error", err))
			continue
		}

		hasValidGrants = true
		for _, kg := range grant.KASGrants {
			if _, exists := allKAS[kg.URL]; !exists {
				allKAS[kg.URL] = kg.PublicKey
				allURLs = append(allURLs, kg.URL)
			}
		}
	}

	if !hasValidGrants {
		slog.Debug("no valid grants found in anyOf clause, will fall back to default KAS",
			slog.String("def_fqn", clause.Definition.GetFqn()))
		return []SplitAssignment{}, nil // Return empty assignments, not error
	}

	// All values share the same split
	splitID := generateSplitID()
	assignment := SplitAssignment{
		SplitID: splitID,
		KASURLs: allURLs,
		Keys:    allKAS,
	}

	slog.Debug("created anyOf split",
		slog.String("def_fqn", clause.Definition.GetFqn()),
		slog.String("split_id", splitID),
		slog.Int("num_values", len(clause.Values)),
		slog.Any("kas_urls", allURLs))

	return []SplitAssignment{assignment}, nil
}

// processHierarchyClause handles hierarchy rule (ordered preference)
func processHierarchyClause(clause AttributeClause) ([]SplitAssignment, error) {
	// For now, treat hierarchy similar to anyOf but with value ordering
	// The hierarchy logic from the original granter.go could be enhanced here
	slog.Debug("processing hierarchy clause (treating as anyOf)",
		slog.String("def_fqn", clause.Definition.GetFqn()),
		slog.Int("num_values", len(clause.Values)))

	return processAnyOfClause(clause)
}

// extractKASURLs gets all KAS URLs from grants
func extractKASURLs(grants []KASGrant) []string {
	var urls []string
	for _, grant := range grants {
		urls = append(urls, grant.URL)
	}
	sort.Strings(urls) // Ensure deterministic ordering
	return urls
}

// extractKASKeys gets all KAS public keys from grants
func extractKASKeys(grants []KASGrant) map[string]*policy.SimpleKasPublicKey {
	keys := make(map[string]*policy.SimpleKasPublicKey)
	for _, grant := range grants {
		if grant.PublicKey != nil {
			keys[grant.URL] = grant.PublicKey
		}
	}
	return keys
}

// optimizeSplitAssignments reduces the split plan to a minimal set
func optimizeSplitAssignments(assignments []SplitAssignment) []SplitAssignment {
	if len(assignments) <= 1 {
		return assignments
	}

	// Group assignments by their KAS URL sets
	kasSetMap := make(map[string][]SplitAssignment)

	for _, assignment := range assignments {
		kasSet := createKASSetKey(assignment.KASURLs)
		kasSetMap[kasSet] = append(kasSetMap[kasSet], assignment)
	}

	var optimized []SplitAssignment

	// Merge assignments with identical KAS sets
	for kasSet, group := range kasSetMap {
		if len(group) == 1 {
			// Single assignment - keep as is
			optimized = append(optimized, group[0])
		} else {
			// Multiple assignments with same KAS set - merge into one
			merged := mergeAssignments(group)
			slog.Debug("merged assignments",
				slog.String("kas_set", kasSet),
				slog.Int("original_count", len(group)),
				slog.String("merged_split_id", merged.SplitID))
			optimized = append(optimized, merged)
		}
	}

	// Sort for deterministic ordering
	sort.Slice(optimized, func(i, j int) bool {
		return optimized[i].SplitID < optimized[j].SplitID
	})

	return optimized
}

// createKASSetKey creates a deterministic key for a set of KAS URLs
func createKASSetKey(kasURLs []string) string {
	sorted := make([]string, len(kasURLs))
	copy(sorted, kasURLs)
	sort.Strings(sorted)
	return fmt.Sprintf("%v", sorted)
}

// mergeAssignments combines multiple assignments with the same KAS set
func mergeAssignments(assignments []SplitAssignment) SplitAssignment {
	if len(assignments) == 0 {
		return SplitAssignment{}
	}
	if len(assignments) == 1 {
		return assignments[0]
	}

	// Use the first assignment as base
	merged := assignments[0]

	// Merge all public keys
	for _, assignment := range assignments[1:] {
		for kasURL, key := range assignment.Keys {
			if _, exists := merged.Keys[kasURL]; !exists {
				merged.Keys[kasURL] = key
			}
		}
	}

	return merged
}

// createDefaultSplitPlan creates a single split for the default KAS
func createDefaultSplitPlan(defaultKAS string) []SplitAssignment {
	if defaultKAS == "" {
		return nil
	}

	// Single default KAS - no split ID needed since there's only one split
	return []SplitAssignment{{
		SplitID: "",
		KASURLs: []string{defaultKAS},
		Keys:    make(map[string]*policy.SimpleKasPublicKey), // No keys available for default
	}}
}

// generateSplitID creates a unique identifier for a split
func generateSplitID() string {
	return uuid.New().String()
}
