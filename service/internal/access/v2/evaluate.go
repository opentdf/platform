package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrInvalidResource              = errors.New("access: invalid resource")
	ErrFQNNotFound                  = errors.New("access: FQN not found")
	ErrDefinitionNotFound           = errors.New("access: definition not found for FQN")
	ErrFailedEvaluation             = errors.New("access: failed to evaluate definition")
	ErrMissingRequiredSpecifiedRule = errors.New("access: AttributeDefinition rule cannot be unspecified")
	ErrUnrecognizedRule             = errors.New("access: unrecognized AttributeDefinition rule")
)

// getResourceDecision evaluates the access decision for a single resource, driving the flows
// between entitlement checks for the different types of resources
func getResourceDecision(
	ctx context.Context,
	l *logger.Logger,
	accessibleAttributeValues map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	accessibleRegisteredResourceValues map[string]*policy.RegisteredResourceValue,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resource *authz.Resource,
	namespacedPolicy bool,
) (*ResourceDecision, error) {
	var (
		resourceID                 = resource.GetEphemeralId()
		registeredResourceValueFQN string
		resourceAttributeValues    *authz.Resource_AttributeValues
		failure                    = &ResourceDecision{
			Entitled:     false,
			ResourceID:   resourceID,
			ResourceName: resourceID,
		}
	)
	if err := validateGetResourceDecision(entitlements, action, resource); err != nil {
		return nil, err
	}

	l.DebugContext(
		ctx,
		"getting decision on one resource",
		slog.Any("resource", resource.GetResource()),
	)

	switch resource.GetResource().(type) {
	case *authz.Resource_RegisteredResourceValueFqn:
		registeredResourceValueFQN = strings.ToLower(resource.GetRegisteredResourceValueFqn())
		l = l.With("registered_resource_value_fqn", registeredResourceValueFQN)
		failure.ResourceName = registeredResourceValueFQN

		regResValue, found := accessibleRegisteredResourceValues[registeredResourceValueFQN]
		if !found {
			l.WarnContext(
				ctx,
				"registered resource value not found - denying access",
			)
			return failure, nil
		}
		l.DebugContext(
			ctx,
			"registered_resource_value",
			slog.Any("action_attribute_values", regResValue.GetActionAttributeValues()),
		)

		resourceAttributeValues = &authz.Resource_AttributeValues{
			Fqns: make([]string, 0),
		}
		for _, aav := range regResValue.GetActionAttributeValues() {
			aavAttrValueFQN := aav.GetAttributeValue().GetFqn()
			precheckNamespaceID := ""
			precheckNamespacedPolicy := false
			// First, check whether the request action identity (id or name[/namespace])
			// could match this AAV action at all. This lightweight pre-check is used to
			// decide whether strict mode must fail closed when namespace context is
			// missing for this candidate AAV.
			matchesRequestIdentity := isRequestedActionMatch(ctx, l, action, precheckNamespaceID, aav.GetAction(), precheckNamespacedPolicy)
			requiredNamespaceID := ""
			if attrAndValue, ok := accessibleAttributeValues[aavAttrValueFQN]; ok {
				requiredNamespaceID = attrAndValue.GetAttribute().GetNamespace().GetId()
			} else if namespacedPolicy && matchesRequestIdentity {
				// Strict namespaced policy: if this AAV is otherwise a candidate for the
				// requested action but we cannot resolve the attribute-value namespace,
				// deny rather than silently skipping evaluation.
				l.TraceContext(
					ctx,
					"strict namespaced-policy mode: unable to resolve namespace for RR action-attribute-value; denying access",
					slog.String("attribute_value_fqn", aavAttrValueFQN),
				)
				return failure, nil
			}

			// skip evaluating attribute rules on any action-attribute-values without the requested action
			if !isRequestedActionMatch(ctx, l, action, requiredNamespaceID, aav.GetAction(), namespacedPolicy) {
				continue
			}

			if !slices.Contains(resourceAttributeValues.GetFqns(), aavAttrValueFQN) {
				resourceAttributeValues.Fqns = append(resourceAttributeValues.Fqns, aavAttrValueFQN)
			}
		}

		// if no relevant attributes from action-attribute-values with the requested action,
		// indicates a failure before attribute definition rule evaluation
		if len(resourceAttributeValues.GetFqns()) == 0 {
			l.WarnContext(ctx, "registered resource value missing action-attribute-values for requested action")
			return failure, nil
		}

	case *authz.Resource_AttributeValues_:
		resourceAttributeValues = resource.GetAttributeValues()

	default:
		return nil, fmt.Errorf("unsupported resource type: %w", ErrInvalidResource)
	}

	// Cannot entitle any resource
	if len(accessibleAttributeValues) == 0 {
		l.WarnContext(ctx, "resource is not able to be entitled", slog.Any("resource", resource.GetResource()))
		return failure, nil
	}

	return evaluateResourceAttributeValues(ctx, l, resourceAttributeValues, resourceID, registeredResourceValueFQN, action, entitlements, accessibleAttributeValues, namespacedPolicy)
}

// evaluateResourceAttributeValues evaluates a list of attribute values against the action and entitlements
// and lowercases the FQNs to ensure case-insensitive matching
func evaluateResourceAttributeValues(
	ctx context.Context,
	l *logger.Logger,
	resourceAttributeValues *authz.Resource_AttributeValues,
	resourceID string,
	resourceName string,
	action *policy.Action,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	accessibleAttributeValues map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	namespacedPolicy bool,
) (*ResourceDecision, error) {
	// Group value FQNs by parent definition
	definitionFqnToValueFqns := make(map[string][]string)
	definitionsLookup := make(map[string]*policy.Attribute)
	notFoundFQNs := make([]string, 0)

	for _, valueFQN := range resourceAttributeValues.GetFqns() {
		attributeAndValue, ok := accessibleAttributeValues[valueFQN]
		if !ok {
			notFoundFQNs = append(notFoundFQNs, valueFQN)
			continue
		}
		definition := attributeAndValue.GetAttribute()
		definitionFqnToValueFqns[definition.GetFqn()] = append(definitionFqnToValueFqns[definition.GetFqn()], valueFQN)
		definitionsLookup[definition.GetFqn()] = definition
	}

	// If ANY FQNs are missing, DENY the resource
	if len(notFoundFQNs) > 0 {
		l.WarnContext(ctx, "attribute value FQN(s) not found - denying access to resource",
			slog.Any("not_found_fqns", notFoundFQNs),
			slog.String("resource_id", resourceID))
		result := &ResourceDecision{
			Entitled:   false,
			ResourceID: resourceID,
		}
		if resourceName != "" {
			result.ResourceName = resourceName
		}
		return result, nil
	}

	// Evaluate each definition by rule, resource attributes, action, and entitlements
	passed := true
	dataRuleResults := make([]DataRuleResult, 0)

	for defFQN, resourceValueFQNs := range definitionFqnToValueFqns {
		definition := definitionsLookup[defFQN]
		if definition == nil {
			return nil, fmt.Errorf("%w: %s", ErrDefinitionNotFound, defFQN)
		}

		dataRuleResult, err := evaluateDefinition(ctx, l, entitlements, action, resourceValueFQNs, definition, namespacedPolicy)
		if err != nil {
			return nil, errors.Join(ErrFailedEvaluation, err)
		}
		if !dataRuleResult.Passed {
			passed = false
		}

		dataRuleResults = append(dataRuleResults, *dataRuleResult)
	}

	// Return results in the appropriate structure
	result := &ResourceDecision{
		Entitled:        passed,
		ResourceID:      resourceID,
		DataRuleResults: dataRuleResults,
	}
	if resourceName != "" {
		result.ResourceName = resourceName
	}
	return result, nil
}

func evaluateDefinition(
	ctx context.Context,
	l *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
	attrDefinition *policy.Attribute,
	namespacedPolicy bool,
) (*DataRuleResult, error) {
	var entitlementFailures []EntitlementFailure
	requiredNamespaceID := attrDefinition.GetNamespace().GetId()

	l = l.With("definitionRule", attrDefinition.GetRule().String())
	l = l.With("definitionFQN", attrDefinition.GetFqn())

	l.DebugContext(
		ctx,
		"evaluating definition",
		slog.Any("resource_value_fqns", resourceValueFQNs),
	)

	switch attrDefinition.GetRule() {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		entitlementFailures = allOfRuleScoped(ctx, l, entitlements, action, resourceValueFQNs, requiredNamespaceID, namespacedPolicy)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
		entitlementFailures = anyOfRuleScoped(ctx, l, entitlements, action, resourceValueFQNs, requiredNamespaceID, namespacedPolicy)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		entitlementFailures = hierarchyRuleScoped(ctx, l, entitlements, action, resourceValueFQNs, attrDefinition, requiredNamespaceID, namespacedPolicy)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
		return nil, fmt.Errorf("%w: %s, rule: %s", ErrMissingRequiredSpecifiedRule, attrDefinition.GetFqn(), attrDefinition.GetRule().String())
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnrecognizedRule, attrDefinition.GetRule().String())
	}

	passed := len(entitlementFailures) == 0
	simpleAttribute := &policy.Attribute{
		Id:   attrDefinition.GetId(),
		Fqn:  attrDefinition.GetFqn(),
		Rule: attrDefinition.GetRule(),
	}
	result := &DataRuleResult{
		Passed:            passed,
		Attribute:         simpleAttribute,
		ResourceValueFQNs: resourceValueFQNs,
	}
	l.DebugContext(ctx, "definition evaluation result", slog.Bool("passed", passed))
	if !passed {
		result.EntitlementFailures = entitlementFailures
	}
	return result, nil
}

// allOfRule validates that:
// 1. For each resource attribute value FQN, the action is entitled
// 2. If any FQN is not entitled, or the FQN is missing the requested action, the rule fails
func allOfRule(
	ctx context.Context,
	l *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
) []EntitlementFailure {
	// Legacy wrapper: evaluate without strict namespace constraints.
	return allOfRuleScoped(ctx, l, entitlements, action, resourceValueFQNs, "", false)
}

func allOfRuleScoped(
	ctx context.Context,
	l *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
	requiredNamespaceID string,
	namespacedPolicy bool,
) []EntitlementFailure {
	actionName := action.GetName()
	failures := make([]EntitlementFailure, 0, len(resourceValueFQNs)) // Pre-allocate for efficiency

	// Single loop through all resource value FQNs
	for _, valueFQN := range resourceValueFQNs {
		hasEntitlement := false

		// Check if this FQN has the entitled action
		if entitledActions, ok := entitlements[valueFQN]; ok {
			for _, entitledAction := range entitledActions {
				if isRequestedActionMatch(ctx, l, action, requiredNamespaceID, entitledAction, namespacedPolicy) {
					hasEntitlement = true
					break
				}
			}
		}

		// If no entitlement found for this FQN, add to failures immediately
		if !hasEntitlement {
			failures = append(failures, EntitlementFailure{
				AttributeValueFQN: valueFQN,
				ActionName:        actionName,
			})
		}
	}

	return failures
}

// anyOfRule validates that:
// 1. At least one resource attribute value FQN has the action entitled
// 2. If none of the FQNs are found the entitlements, the rule fails
// 3. If none of the matching FQNs in the entitlements contain the requested action, the rule fails
func anyOfRule(
	ctx context.Context,
	l *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
) []EntitlementFailure {
	// Legacy wrapper: evaluate without strict namespace constraints.
	return anyOfRuleScoped(ctx, l, entitlements, action, resourceValueFQNs, "", false)
}

func anyOfRuleScoped(
	ctx context.Context,
	l *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
	requiredNamespaceID string,
	namespacedPolicy bool,
) []EntitlementFailure {
	// No resources to check
	if len(resourceValueFQNs) == 0 {
		return nil
	}

	actionName := action.GetName()
	anyEntitlementFound := false
	entitlementFailures := make([]EntitlementFailure, 0, len(resourceValueFQNs))

	// Single loop through all resource value FQNs
	for _, valueFQN := range resourceValueFQNs {
		foundEntitlementForThisFQN := false

		entitledActions, ok := entitlements[valueFQN]
		if ok {
			for _, entitledAction := range entitledActions {
				if isRequestedActionMatch(ctx, l, action, requiredNamespaceID, entitledAction, namespacedPolicy) {
					foundEntitlementForThisFQN = true
					anyEntitlementFound = true
					break
				}
			}
		}

		if !foundEntitlementForThisFQN {
			entitlementFailures = append(entitlementFailures, EntitlementFailure{
				AttributeValueFQN: valueFQN,
				ActionName:        actionName,
			})
		}
	}

	// Rule is satisfied if at least one FQN has the entitled action
	if anyEntitlementFound {
		return nil
	}
	return entitlementFailures
}

// hierarchyRule validates that:
// 1. The user has entitlement to the specified action on the highest value FQN in the hierarchy or any hierarchically higher value
// 2. The highest value FQN is determined by the lowest index in the hierarchy definition
// 3. If the highest value FQN or any higher value has the required entitlement, the rule passes with no failures
// 4. If no hierarchically relevant FQN has the required entitlement, the rule fails with all missing entitlements
func hierarchyRule(
	ctx context.Context,
	l *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
	attrDefinition *policy.Attribute,
) []EntitlementFailure {
	// Legacy wrapper: evaluate without strict namespace constraints.
	return hierarchyRuleScoped(ctx, l, entitlements, action, resourceValueFQNs, attrDefinition, "", false)
}

func hierarchyRuleScoped(
	ctx context.Context,
	l *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
	attrDefinition *policy.Attribute,
	requiredNamespaceID string,
	namespacedPolicy bool,
) []EntitlementFailure {
	// No resources to check
	if len(resourceValueFQNs) == 0 {
		return nil
	}

	actionName := action.GetName()
	attrValues := attrDefinition.GetValues()

	// Create a lookup map for the attribute value indices - O(n) where n is the number of values in the attribute
	valueFQNToIndex := make(map[string]int, len(attrValues))
	for idx, value := range attrValues {
		valueFQNToIndex[value.GetFqn()] = idx
	}

	// Find the lowest indexed value FQN (highest in hierarchy) - O(m) where m is the number of resource values
	lowestValueFQNIndex := len(attrValues)
	for _, valueFQN := range resourceValueFQNs {
		if idx, exists := valueFQNToIndex[valueFQN]; exists && idx < lowestValueFQNIndex {
			lowestValueFQNIndex = idx
		}
	}

	// Check if the entitlements contain any values with index <= lowestValueFQNIndex
	// This checks the requested value and any hierarchically higher values in a single pass - O(e) where e is entitlements count
	for entitlementFQN, entitledActions := range entitlements {
		// Check if this entitlement FQN has a valid index in the hierarchy
		if idx, exists := valueFQNToIndex[entitlementFQN]; exists && idx <= lowestValueFQNIndex {
			// Check if the required action is entitled
			for _, entitledAction := range entitledActions {
				if isRequestedActionMatch(ctx, l, action, requiredNamespaceID, entitledAction, namespacedPolicy) {
					l.DebugContext(ctx, "hierarchy rule satisfied",
						slog.Group("entitled_by_value",
							slog.String("FQN", entitlementFQN),
							slog.Int("index", idx),
						),
						slog.Group("resource_highest_hierarchy_value",
							slog.String("FQN", attrValues[lowestValueFQNIndex].GetFqn()),
							slog.Int("index", lowestValueFQNIndex),
						),
					)
					return nil // Found an entitled action at or above the hierarchy level, no failures
				}
			}
		}
	}

	// The rule was not satisfied - collect failures - O(m) where m is the number of resource values
	entitlementFailures := make([]EntitlementFailure, 0, len(resourceValueFQNs))
	for _, valueFQN := range resourceValueFQNs {
		foundValue := false
		if entitledActions, ok := entitlements[valueFQN]; ok {
			for _, entitledAction := range entitledActions {
				if isRequestedActionMatch(ctx, l, action, requiredNamespaceID, entitledAction, namespacedPolicy) {
					foundValue = true
					break
				}
			}
		}

		if !foundValue {
			entitlementFailures = append(entitlementFailures, EntitlementFailure{
				AttributeValueFQN: valueFQN,
				ActionName:        actionName,
			})
		}
	}

	return entitlementFailures
}

func isRequestedActionMatch(ctx context.Context, l *logger.Logger, requestedAction *policy.Action, requiredNamespaceID string, entitledAction *policy.Action, namespacedPolicy bool) bool {
	if requestedAction == nil || entitledAction == nil {
		return false
	}

	// Action identity precedence for matching:
	// 1) request action id (if present) is authoritative,
	// 2) otherwise name (case-insensitive),
	// 3) optional request namespace (id or fqn) further narrows matches.
	// Note: API validation still requires request action name today; this logic
	// defines matcher behavior when additional identity fields are present.
	if requestedAction.GetId() != "" {
		if requestedAction.GetId() != entitledAction.GetId() {
			return false
		}
	} else {
		if requestedAction.GetName() == "" || !strings.EqualFold(requestedAction.GetName(), entitledAction.GetName()) {
			return false
		}
	}

	// If the caller explicitly provides a request action namespace, always enforce
	// that identity constraint regardless of namespacedPolicy mode.
	if requestNamespace := requestedAction.GetNamespace(); requestNamespace != nil && (requestNamespace.GetId() != "" || requestNamespace.GetFqn() != "") {
		entitledNamespace := entitledAction.GetNamespace()
		if entitledNamespace == nil {
			l.TraceContext(ctx, "action match request namespace mismatch",
				slog.String("requested_action_namespace_id", requestNamespace.GetId()),
			)
			return false
		}
		if requestNamespace.GetId() != "" && entitledNamespace.GetId() != requestNamespace.GetId() {
			l.TraceContext(ctx, "action match request namespace mismatch",
				slog.String("requested_action_namespace_id", requestNamespace.GetId()),
				slog.String("candidate_namespace_id", entitledNamespace.GetId()),
			)
			return false
		}
		if requestNamespace.GetId() == "" && requestNamespace.GetFqn() != "" && !strings.EqualFold(entitledNamespace.GetFqn(), requestNamespace.GetFqn()) {
			l.TraceContext(ctx, "action match request namespace mismatch",
				slog.String("requested_action_namespace_fqn", requestNamespace.GetFqn()),
				slog.String("candidate_namespace_fqn", entitledNamespace.GetFqn()),
			)
			return false
		}
	}

	if !namespacedPolicy {
		return true
	}

	// Strict namespaced-policy mode requires a resolved target namespace from
	// the resource/definition context and a namespaced entitled action.
	if requiredNamespaceID == "" {
		l.TraceContext(ctx, "action match strict namespace mismatch",
			slog.String("required_namespace_id", requiredNamespaceID),
		)
		return false
	}

	entitledNamespace := entitledAction.GetNamespace()
	if entitledNamespace == nil || entitledNamespace.GetId() == "" {
		l.TraceContext(ctx, "action match strict namespace mismatch",
			slog.String("required_namespace_id", requiredNamespaceID),
		)
		return false
	}
	if entitledNamespace.GetId() != requiredNamespaceID {
		l.TraceContext(ctx, "action match strict namespace mismatch",
			slog.String("required_namespace_id", requiredNamespaceID),
			slog.String("candidate_namespace_id", entitledNamespace.GetId()),
		)
		return false
	}

	return true
}
