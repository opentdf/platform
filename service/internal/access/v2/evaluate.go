package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/opentdf/platform/lib/identifier"
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
		requiredNamespaceFqn       *identifier.FullyQualifiedAttribute
		resourceAttributeValues    *authz.Resource_AttributeValues
		failure                    = &ResourceDecision{
			Entitled:     false,
			ResourceID:   resourceID,
			ResourceName: resourceID,
		}
	)
	if err := validateGetResourceDecision(entitlements, action, resource, namespacedPolicy); err != nil {
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

		if namespacedPolicy {
			// the parsing is validated in the validator, so ignoring error here
			parsed, _ := identifier.Parse[*identifier.FullyQualifiedRegisteredResourceValue](registeredResourceValueFQN)
			requiredNamespaceFqn = &identifier.FullyQualifiedAttribute{Namespace: parsed.Namespace}
		}

		resourceAttributeValues = &authz.Resource_AttributeValues{
			Fqns: make([]string, 0),
		}
		for _, aav := range regResValue.GetActionAttributeValues() {
			aavAttrValueFQN := aav.GetAttributeValue().GetFqn()
			// If namespaced policies are enabled, enforce that the attribute value FQN is in the same namespace as the registered resource value and extract the namespace ID for later checks.
			// This is a fail safe, as RR and attr NS match should be enforced on creation and update of registered resources
			// This ensures that only attribute values from the correct namespace are considered in the evaluation.
			if namespacedPolicy {
				parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](aavAttrValueFQN)
				if err != nil {
					return nil, fmt.Errorf("invalid attribute value FQN [%s]: %w", aavAttrValueFQN, ErrInvalidResource)
				}
				if parsed.Namespace != requiredNamespaceFqn.Namespace {
					return nil, fmt.Errorf("attribute value FQN [%s] namespace [%s] does not match RR namespace [%s]: %w", aavAttrValueFQN, parsed.Namespace, requiredNamespaceFqn.FQN(), ErrInvalidResource)
				}
			}

			// skip evaluating attribute rules on any action-attribute-values without the requested action
			if !isRequestedActionMatch(ctx, l, action,
				func() string {
					if requiredNamespaceFqn != nil && requiredNamespaceFqn.Namespace != "" {
						return requiredNamespaceFqn.FQN()
					}
					return ""
				}(), aav.GetAction(),
				namespacedPolicy) {
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
	namespaceFQN := attrDefinition.GetNamespace().GetFqn()

	l = l.With("definitionRule", attrDefinition.GetRule().String())
	l = l.With("definitionFQN", attrDefinition.GetFqn())

	l.DebugContext(
		ctx,
		"evaluating definition",
		slog.Any("resource_value_fqns", resourceValueFQNs),
	)

	switch attrDefinition.GetRule() {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		entitlementFailures = allOfRule(ctx, l, entitlements, action, resourceValueFQNs, namespaceFQN, namespacedPolicy)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
		entitlementFailures = anyOfRule(ctx, l, entitlements, action, resourceValueFQNs, namespaceFQN, namespacedPolicy)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		entitlementFailures = hierarchyRule(ctx, l, entitlements, action, resourceValueFQNs, attrDefinition, namespaceFQN, namespacedPolicy)

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
	requiredNamespaceFQN string,
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
				if isRequestedActionMatch(ctx, l, action, requiredNamespaceFQN, entitledAction, namespacedPolicy) {
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
	requiredNamespaceFQN string,
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
				if isRequestedActionMatch(ctx, l, action, requiredNamespaceFQN, entitledAction, namespacedPolicy) {
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
	requiredNamespaceFQN string,
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
				if isRequestedActionMatch(ctx, l, action, requiredNamespaceFQN, entitledAction, namespacedPolicy) {
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
				if isRequestedActionMatch(ctx, l, action, requiredNamespaceFQN, entitledAction, namespacedPolicy) {
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

// This function checks if there are any conflicts between two actions based on their IDs and namespaces, and determines which action to prefer in case of a conflict.
// This is used when merging actions from different sources (e.g., direct entitlements and subject mapping) to ensure deterministic behavior.
// The requestedAction is the action from the access request, and the entitledAction is the action from the entitlements.
// The requiredNamespaceID and namespacedPolicy parameters are used to enforce namespace constraints if strict namespaced policies are enabled.
func isRequestedActionMatch(ctx context.Context, l *logger.Logger, requestedAction *policy.Action, requiredNamespaceFQN string, entitledAction *policy.Action, namespacedPolicy bool) bool {
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
		// the requested action has a namespace, so enforce that the entitled action also has a
		// namespace and that they match on id if provided, otherwise fqn (case-insensitive)
		entitledNamespace := entitledAction.GetNamespace()
		if entitledNamespace == nil {
			// the entitled action is missing a namespace while the request action has one,
			// so this is a mismatch and we should not consider this a match
			l.TraceContext(ctx, "action match request namespace mismatch",
				slog.String("requested_action_namespace_id", requestNamespace.GetId()),
			)
			return false
		}
		if requestNamespace.GetId() != "" && entitledNamespace.GetId() != requestNamespace.GetId() {
			// the requested action namespace has an id and it does not match the entitled action namespace id,
			// so this is a mismatch and we should not consider this a match
			l.TraceContext(ctx, "action match request namespace mismatch",
				slog.String("requested_action_namespace_id", requestNamespace.GetId()),
				slog.String("candidate_namespace_id", entitledNamespace.GetId()),
			)
			return false
		}
		if requestNamespace.GetId() == "" && requestNamespace.GetFqn() != "" && !strings.EqualFold(entitledNamespace.GetFqn(), requestNamespace.GetFqn()) {
			// the requested action namespace has an FQN and it does not match the entitled action namespace FQN,
			// so this is a mismatch and we should not consider this a match
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
	if requiredNamespaceFQN == "" {
		// we are in strict namespaced policy mode but do not have a required namespace from the resource context
		// this should not happen, it should be caught upstream
		l.TraceContext(ctx, "action match strict namespace mismatch, required_namespace is empty")
		return false
	}

	entitledNamespace := entitledAction.GetNamespace()
	if entitledNamespace == nil || entitledNamespace.GetId() == "" {
		// the entitled action is missing a namespace while strict namespaced policy mode requires it
		l.TraceContext(ctx, "action match strict namespace mismatch",
			slog.String("required_namespace", requiredNamespaceFQN),
		)
		return false
	}
	if entitledNamespace.GetFqn() != requiredNamespaceFQN {
		// the entitled action namespace FQN does not match the required namespace FQN from the resource context
		l.TraceContext(ctx, "action match strict namespace mismatch",
			slog.String("required_namespace", requiredNamespaceFQN),
			slog.String("candidate_namespace", entitledNamespace.GetFqn()),
		)
		return false
	}

	return true
}
