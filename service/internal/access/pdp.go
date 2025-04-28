package access

import (
	"context"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
)

// Pdp represents the Policy Decision Point component.
type Pdp struct {
	logger *logger.Logger
}

// NewPdp creates a new Policy Decision Point instance.
func NewPdp(l *logger.Logger) *Pdp {
	return &Pdp{
		logger: l,
	}
}

// DetermineAccess will take data Attribute Values, entities mapped entityId to Attribute Value FQNs, and data AttributeDefinitions,
// compare every data Attribute against every entity's set of Attribute Values, generating a rolled-up decision
// result for each entity, as well as a detailed breakdown of every data comparison.
func (pdp *Pdp) DetermineAccess(
	ctx context.Context,
	dataAttributes []*policy.Value,
	entityAttributeSets map[string][]string,
	attributeDefinitions []*policy.Attribute,
) (map[string]*Decision, error) {
	pdp.logger.DebugContext(ctx, "DetermineAccess")

	// TODO: behavior if dataAttributes is empty?

	dataAttrValsByDefinition, err := pdp.groupDataAttributesByDefinition(ctx, dataAttributes)
	if err != nil {
		return nil, err
	}

	fqnToDefinitionMap, err := pdp.mapFqnToDefinitions(attributeDefinitions)
	if err != nil {
		return nil, err
	}

	return pdp.evaluateAttributes(ctx, dataAttrValsByDefinition, fqnToDefinitionMap, entityAttributeSets)
}

func (pdp *Pdp) groupDataAttributesByDefinition(ctx context.Context, dataAttributes []*policy.Value) (map[string][]*policy.Value, error) {
	dataAttrValsByDefinition, err := GroupValuesByDefinition(dataAttributes)
	if err != nil {
		pdp.logger.ErrorContext(ctx, fmt.Sprintf("error grouping data attributes by definition: %s", err.Error()))
		return nil, err
	}
	return dataAttrValsByDefinition, nil
}

func (pdp *Pdp) mapFqnToDefinitions(attributeDefinitions []*policy.Attribute) (map[string]*policy.Attribute, error) {
	fqnToDefinitionMap := make(map[string]*policy.Attribute, len(attributeDefinitions))
	for _, attr := range attributeDefinitions {
		fqnToDefinitionMap[attr.Fqn] = attr
	}
	return fqnToDefinitionMap, nil
}

func (pdp *Pdp) evaluateAttributes(
	ctx context.Context,
	dataAttrValsByDefinition map[string][]*policy.Value,
	fqnToDefinitionMap map[string]*policy.Attribute,
	entityAttributeSets map[string][]string,
) (map[string]*Decision, error) {
	decisions := make(map[string]*Decision)

	for definitionFqn, distinctValues := range dataAttrValsByDefinition {
		pdp.logger.DebugContext(ctx, "Evaluating data attribute fqn", "fqn:", definitionFqn)

		attrDefinition, ok := fqnToDefinitionMap[definitionFqn]
		if !ok {
			return nil, fmt.Errorf("expected an Attribute Definition under the FQN %s", definitionFqn)
		}

		entityRuleDecision, err := pdp.evaluateRule(ctx, attrDefinition, distinctValues, entityAttributeSets)
		if err != nil {
			return nil, err
		}

		pdp.rollUpDecisions(entityRuleDecision, attrDefinition, decisions)
	}

	return decisions, nil
}

func (pdp *Pdp) evaluateRule(
	ctx context.Context,
	attrDefinition *policy.Attribute,
	distinctValues []*policy.Value,
	entityAttributeSets map[string][]string,
) (map[string]DataRuleResult, error) {
	switch attrDefinition.GetRule() {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		pdp.logger.DebugContext(ctx, "Evaluating under allOf", "name", attrDefinition.GetFqn())
		return pdp.allOfRule(ctx, distinctValues, entityAttributeSets)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
		pdp.logger.DebugContext(ctx, "Evaluating under anyOf", "name", attrDefinition.GetFqn())
		return pdp.anyOfRule(ctx, distinctValues, entityAttributeSets)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		pdp.logger.DebugContext(ctx, "Evaluating under hierarchy", "name", attrDefinition.GetFqn())
		return pdp.hierarchyRule(ctx, distinctValues, entityAttributeSets, attrDefinition.GetValues())

	default:
		return nil, fmt.Errorf("unrecognized AttributeDefinition rule: %s", attrDefinition.GetRule())
	}
}

func (pdp *Pdp) rollUpDecisions(
	entityRuleDecision map[string]DataRuleResult,
	attrDefinition *policy.Attribute,
	decisions map[string]*Decision,
) {
	for entityID, ruleResult := range entityRuleDecision {
		entityDecision := decisions[entityID]
		ruleResult.RuleDefinition = attrDefinition

		if entityDecision == nil {
			decisions[entityID] = &Decision{
				Access:  ruleResult.Passed,
				Results: []DataRuleResult{ruleResult},
			}
		} else {
			entityDecision.Access = entityDecision.Access && ruleResult.Passed
			entityDecision.Results = append(entityDecision.Results, ruleResult)
		}
	}
}

// allOfRule evaluates data attributes against entity attributes using the "all of" rule.
// All data attributes must be found in the entity's attributes to grant access.
func (pdp *Pdp) allOfRule(
	ctx context.Context,
	dataAttrValuesOfOneDefinition []*policy.Value,
	entityAttributeValueFqns map[string][]string,
) (map[string]DataRuleResult, error) {
	// Early return for empty data attributes
	if len(dataAttrValuesOfOneDefinition) == 0 {
		return map[string]DataRuleResult{}, nil
	}

	// Get the definition FQN just once from the first value
	attrDefFqn, err := GetDefinitionFqnFromValue(dataAttrValuesOfOneDefinition[0])
	if err != nil {
		return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
	}

	pdp.logger.DebugContext(ctx, "Evaluating allOf decision", "attribute definition FQN", attrDefFqn)

	// Pre-allocate the result map with the expected size
	ruleResultsByEntity := make(map[string]DataRuleResult, len(entityAttributeValueFqns))

	// Pre-process data attributes for fast lookup
	dataAttrValsFqns := make([]string, len(dataAttrValuesOfOneDefinition))
	for i, dataAttrVal := range dataAttrValuesOfOneDefinition {
		dataAttrValsFqns[i] = strings.ToLower(dataAttrVal.GetFqn())
	}

	// Process each entity
	for entityID, entityAttrValFqns := range entityAttributeValueFqns {
		// Group entity attributes by definition only once per entity
		entityAttrGroup, err := GroupValueFqnsByDefinition(entityAttrValFqns)
		if err != nil {
			return nil, fmt.Errorf("error grouping entity attribute values by definition: %s", err.Error())
		}

		// Get the relevant entity attributes for this definition
		entityAttrsForDef := entityAttrGroup[attrDefFqn]

		// Quick check: if entity has fewer attributes than required, fail fast
		if len(entityAttrsForDef) < len(dataAttrValuesOfOneDefinition) {
			valueFailures := make([]ValueFailure, len(dataAttrValuesOfOneDefinition))
			for i, dataAttrVal := range dataAttrValuesOfOneDefinition {
				valueFailures[i] = ValueFailure{
					DataAttribute: dataAttrVal,
					Message: fmt.Sprintf("AllOf not satisfied for data attr %s with value %s and entity %s - insufficient entity attributes",
						attrDefFqn, dataAttrVal.GetValue(), entityID),
				}
			}

			ruleResultsByEntity[entityID] = DataRuleResult{
				Passed:        false,
				ValueFailures: valueFailures,
			}
			continue
		}

		// Create a set of entity FQNs for O(1) lookups
		entityFqnSet := make(map[string]struct{}, len(entityAttrsForDef))
		for _, fqn := range entityAttrsForDef {
			entityFqnSet[strings.ToLower(fqn)] = struct{}{}
		}

		// Default to success, then check each requirement
		entityPassed := true
		var valueFailures []ValueFailure

		// Check each data attribute value
		for i, dataAttrVal := range dataAttrValuesOfOneDefinition {
			// O(1) lookup in the set using pre-computed lowercase FQN
			if _, found := entityFqnSet[dataAttrValsFqns[i]]; !found {
				entityPassed = false
				denialMsg := fmt.Sprintf("AllOf not satisfied for data attr %s with value %s and entity %s",
					attrDefFqn, dataAttrVal.GetValue(), entityID)
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: dataAttrVal,
					Message:       denialMsg,
				})
			}
		}

		// Only create the result object once we know the final state
		ruleResultsByEntity[entityID] = DataRuleResult{
			Passed:        entityPassed,
			ValueFailures: valueFailures,
		}

		// Log success at debug level
		if entityPassed {
			pdp.logger.DebugContext(ctx, "allOf rule passed", "entity", entityID)
		}
	}

	return ruleResultsByEntity, nil
}

// anyOfRule evaluates data attributes against entity attributes using the "any of" rule.
// At least one data attribute must be found in the entity's attributes to grant access.
func (pdp *Pdp) anyOfRule(
	ctx context.Context,
	dataAttrValuesOfOneDefinition []*policy.Value,
	entityAttributeValueFqns map[string][]string,
) (map[string]DataRuleResult, error) {
	// Early return for empty data attributes
	if len(dataAttrValuesOfOneDefinition) == 0 {
		return map[string]DataRuleResult{}, nil
	}

	// Get the definition FQN just once from the first value
	attrDefFqn, err := GetDefinitionFqnFromValue(dataAttrValuesOfOneDefinition[0])
	if err != nil {
		return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
	}

	// Pre-allocate the result map with the expected size
	ruleResultsByEntity := make(map[string]DataRuleResult, len(entityAttributeValueFqns))

	// Pre-process data attributes for fast lookup
	dataAttrValsFqns := make([]string, len(dataAttrValuesOfOneDefinition))
	for i, dataAttrVal := range dataAttrValuesOfOneDefinition {
		dataAttrValsFqns[i] = strings.ToLower(dataAttrVal.GetFqn())
	}

	// Process each entity
	for entityID, entityAttrValFqns := range entityAttributeValueFqns {
		// Group entity attributes by definition only once per entity
		entityAttrGroup, err := GroupValueFqnsByDefinition(entityAttrValFqns)
		if err != nil {
			return nil, fmt.Errorf("error grouping entity attribute values by definition: %s", err.Error())
		}

		// Get the relevant entity attributes for this definition
		entityAttrsForDef := entityAttrGroup[attrDefFqn]

		// Quick path: no attributes of this type for this entity
		if len(entityAttrsForDef) == 0 {
			// All data attributes fail
			valueFailures := make([]ValueFailure, len(dataAttrValuesOfOneDefinition))
			for i, dataAttrVal := range dataAttrValuesOfOneDefinition {
				valueFailures[i] = ValueFailure{
					DataAttribute: dataAttrVal,
					Message:       fmt.Sprintf("anyOf not satisfied for data attr %s with value %s and entity %s - no matching entity attributes", attrDefFqn, dataAttrVal.GetValue(), entityID),
				}
			}

			ruleResultsByEntity[entityID] = DataRuleResult{
				Passed:        false,
				ValueFailures: valueFailures,
			}
			continue
		}

		// Create a set of entity FQNs for O(1) lookups
		entityFqnSet := make(map[string]struct{}, len(entityAttrsForDef))
		for _, fqn := range entityAttrsForDef {
			entityFqnSet[strings.ToLower(fqn)] = struct{}{}
		}

		// Check for any matches using efficient loop
		entityPassed := false
		var matchedDataAttr *policy.Value
		var unmatched []*policy.Value

		for i, dataAttrVal := range dataAttrValuesOfOneDefinition {
			if _, found := entityFqnSet[dataAttrValsFqns[i]]; found {
				entityPassed = true
				matchedDataAttr = dataAttrVal
				break
			}
			unmatched = append(unmatched, dataAttrVal)
		}

		var valueFailures []ValueFailure
		if !entityPassed && len(unmatched) > 0 {
			valueFailures = make([]ValueFailure, len(unmatched))
			for i, dataAttrVal := range unmatched {
				valueFailures[i] = ValueFailure{
					DataAttribute: dataAttrVal,
					Message:       fmt.Sprintf("anyOf not satisfied for data attr %s with value %s and entity %s", attrDefFqn, dataAttrVal.GetValue(), entityID),
				}
			}
		}

		// Only log detailed diagnostic information at debug level
		if entityPassed && matchedDataAttr != nil {
			pdp.logger.DebugContext(ctx, "anyOf rule passed",
				"entity", entityID,
				"matched_value", matchedDataAttr.GetValue())
		}

		ruleResultsByEntity[entityID] = DataRuleResult{
			Passed:        entityPassed,
			ValueFailures: valueFailures,
		}
	}

	return ruleResultsByEntity, nil
}

// hierarchyRule evaluates data attributes against entity attributes using the hierarchy rule.
// Entity attributes must have equal or higher rank than the data attribute to grant access.
func (pdp *Pdp) hierarchyRule(
	ctx context.Context,
	dataAttrValuesOfOneDefinition []*policy.Value,
	entityAttributeValueFqns map[string][]string,
	order []*policy.Value,
) (map[string]DataRuleResult, error) {
	// Pre-allocate result map with expected capacity
	ruleResultsByEntity := make(map[string]DataRuleResult, len(entityAttributeValueFqns))

	// Find highest ranked data attribute value once
	highestDataAttrVal, err := pdp.getHighestRankedInstanceFromDataAttributes(ctx, order, dataAttrValuesOfOneDefinition)
	if err != nil {
		return nil, fmt.Errorf("error getting highest ranked instance from data attributes: %s", err.Error())
	}

	if highestDataAttrVal == nil {
		pdp.logger.WarnContext(ctx, "No data attribute value found that matches attribute definition allowed values!")

		// If no highest data attribute, all entities are denied access
		for entityID := range entityAttributeValueFqns {
			denialMsg := fmt.Sprintf("Hierarchy - No data values found exist in attribute definition, entity %s is denied", entityID)
			ruleResultsByEntity[entityID] = DataRuleResult{
				Passed: false,
				ValueFailures: []ValueFailure{{
					DataAttribute: nil,
					Message:       denialMsg,
				}},
			}
		}
		return ruleResultsByEntity, nil
	}

	// Get data attribute definition FQN once
	attrDefFqn, err := GetDefinitionFqnFromValue(highestDataAttrVal)
	if err != nil {
		return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
	}

	// Create index map for order values for faster lookups
	orderIndexMap := make(map[string]int, len(order))
	for idx, val := range order {
		orderIndexMap[val.GetValue()] = idx
		if val.GetFqn() != "" {
			orderIndexMap[val.GetFqn()] = idx
		}
	}

	// Get data value index once
	dvIndex, err := getOrderOfValue(order, highestDataAttrVal, pdp.logger)
	if err != nil {
		return nil, err
	}

	pdp.logger.DebugContext(ctx, "Hierarchy evaluation",
		"attribute definition FQN", attrDefFqn,
		"value", highestDataAttrVal.GetValue(),
		"rank", dvIndex)

	// Process each entity
	for entityID, entityAttrs := range entityAttributeValueFqns {
		entityAttrGroup, err := GroupValueFqnsByDefinition(entityAttrs)
		if err != nil {
			return nil, fmt.Errorf("error grouping entity attribute values by definition: %s", err.Error())
		}

		// Get only the relevant attributes for this definition
		relevantEntityAttrs := entityAttrGroup[attrDefFqn]

		passed := false
		var valueFailures []ValueFailure

		// Check if entity has sufficient rank
		if len(relevantEntityAttrs) > 0 {
			passed, err = entityHasSufficientRank(orderIndexMap, dvIndex, relevantEntityAttrs)
			if err != nil {
				return nil, err
			}
		}

		if !passed {
			denialMsg := fmt.Sprintf("Hierarchy - Entity: %s hierarchy values rank below data value: %s",
				entityID, highestDataAttrVal.GetValue())
			valueFailures = append(valueFailures, ValueFailure{
				DataAttribute: highestDataAttrVal,
				Message:       denialMsg,
			})
		}

		ruleResultsByEntity[entityID] = DataRuleResult{
			Passed:        passed,
			ValueFailures: valueFailures,
		}
	}

	return ruleResultsByEntity, nil
}

// entityHasSufficientRank checks if entity has attributes with high enough rank
func entityHasSufficientRank(
	orderIndexMap map[string]int,
	dataValueIndex int,
	entityAttrs []string,
) (bool, error) {
	for _, entityAttr := range entityAttrs {
		// Extract the value from the FQN (last part after /value/)
		parts := strings.Split(entityAttr, "/value/")
		if len(parts) != 2 {
			continue
		}

		entityValue := parts[1]

		// Check if the entity value exists in the order map
		if idx, exists := orderIndexMap[entityValue]; exists {
			// If entity rank is equal or higher (lower index), access is granted
			if idx <= dataValueIndex {
				return true, nil
			}
		}

		// Check by full FQN as a fallback
		if idx, exists := orderIndexMap[entityAttr]; exists {
			if idx <= dataValueIndex {
				return true, nil
			}
		}
	}

	return false, nil
}

// getHighestRankedInstanceFromDataAttributes finds the data attribute with the highest rank in the hierarchy.
// Performance optimized version that uses direct lookups and minimizes iterations.
func (pdp *Pdp) getHighestRankedInstanceFromDataAttributes(
	ctx context.Context,
	order []*policy.Value,
	dataAttributeGroup []*policy.Value,
) (*policy.Value, error) {
	if len(dataAttributeGroup) == 0 || len(order) == 0 {
		return nil, nil
	}

	// Special case: if there's only one data attribute, just check if it's valid
	if len(dataAttributeGroup) == 1 {
		dataAttr := dataAttributeGroup[0]
		dataValue := dataAttr.GetValue()

		// Simple linear scan for a single item
		for _, orderVal := range order {
			if orderVal.GetValue() == dataValue {
				return dataAttr, nil
			}
		}
		return nil, nil
	}

	// Create a map for O(1) lookups of value indices
	orderMap := make(map[string]int, len(order))
	for i, val := range order {
		orderMap[val.GetValue()] = i
	}

	// Start with the first valid value as the highest
	highestDVIndex := len(order)
	var highestRankedInstance *policy.Value

	for _, dataAttr := range dataAttributeGroup {
		val := dataAttr.GetValue()

		// Use map lookup instead of linear scanning
		idx, exists := orderMap[val]
		if !exists {
			continue
		}

		// If we found a higher rank (lower index), update our result
		if idx < highestDVIndex {
			highestDVIndex = idx
			highestRankedInstance = dataAttr

			// Early return if we found the highest possible rank (index 0)
			if idx == 0 {
				return dataAttr, nil
			}
		}
	}

	return highestRankedInstance, nil
}

// getIsValueFoundInFqnValuesSet checks if a Value is present in a set of FQN strings.
func getIsValueFoundInFqnValuesSet(
	v *policy.Value,
	fqns []string,
	l *logger.Logger,
) bool {
	valFqn := v.GetFqn()
	if valFqn == "" {
		l.Error(fmt.Sprintf("Unexpected empty FQN for value %+v", v))
		return false
	}

	for _, fqn := range fqns {
		if strings.EqualFold(valFqn, fqn) {
			return true
		}
	}

	return false
}

// entityRankGreaterThanOrEqualToDataRank compares entity attribute ranks against data attribute rank.
func entityRankGreaterThanOrEqualToDataRank(
	order []*policy.Value,
	dataAttribute *policy.Value,
	entityAttrValueFqnsGroup []string,
	log *logger.Logger,
) (bool, error) {
	// Get data attribute index once
	dvIndex, err := getOrderOfValue(order, dataAttribute, log)
	if err != nil {
		return false, err
	}

	// Extract data attribute definition FQN once
	dataAttrDefFqn, err := GetDefinitionFqnFromValue(dataAttribute)
	if err != nil {
		return false, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
	}

	// Pre-compute a map for faster order lookup
	orderMap := make(map[string]int, len(order))
	for i, v := range order {
		orderMap[v.GetValue()] = i
		if v.GetFqn() != "" {
			orderMap[v.GetFqn()] = i
		}
	}

	// Process all entity attributes at once
	for _, entityAttributeFqn := range entityAttrValueFqnsGroup {
		entityAttrDefFqn, err := GetDefinitionFqnFromValueFqn(entityAttributeFqn)
		if err != nil {
			return false, fmt.Errorf("error getting definition FQN from entity attribute value: %s", err.Error())
		}

		// Only process relevant attributes
		if dataAttrDefFqn == entityAttrDefFqn {
			// Extract value part directly from FQN for faster comparison
			parts := strings.Split(entityAttributeFqn, "/value/")
			if len(parts) != 2 {
				continue
			}
			entityValue := parts[1]

			// Check if entity value exists in order map
			if idx, exists := orderMap[entityValue]; exists {
				if idx <= dvIndex {
					return true, nil
				}
			} else if idx, exists := orderMap[entityAttributeFqn]; exists {
				if idx <= dvIndex {
					return true, nil
				}
			} else {
				// Fallback to manual lookup only when necessary
				evIndex, err := getOrderOfValueByFqn(order, entityAttributeFqn)
				if err != nil {
					return false, err
				}

				if evIndex == -1 {
					continue
				}

				if evIndex <= dvIndex {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// getOrderOfValue finds the index of a value in the ordered list.
func getOrderOfValue(
	order []*policy.Value,
	v *policy.Value,
	log *logger.Logger,
) (int, error) {
	val := v.GetValue()
	if val == "" {
		log.Debug("empty 'value' in value, falling back to FQN")
		return getOrderOfValueByFqn(order, v.GetFqn())
	}

	// More efficient linear scan
	for idx, orderVal := range order {
		if orderVal.GetValue() == val {
			return idx, nil
		}
	}

	return -1, nil
}

// getOrderOfValueByFqn finds the index of a value FQN in the ordered list.
func getOrderOfValueByFqn(order []*policy.Value, valFqn string) (int, error) {
	for idx := range order {
		orderValFqn := order[idx].GetFqn()

		if orderValFqn == "" {
			defFqn, err := GetDefinitionFqnFromValue(order[idx])
			if err != nil {
				return -1, fmt.Errorf("error getting definition FQN from value: %s", err.Error())
			}

			orderVal := order[idx].GetValue()
			if orderVal == "" {
				return -1, fmt.Errorf("unexpected empty value %+v in order at index %d", order[idx], idx)
			}

			orderValFqn = fmt.Sprintf("%s/value/%s", defFqn, orderVal)
		}

		if orderValFqn == valFqn {
			return idx, nil
		}
	}

	return -1, nil
}

// === Structures ===

// Decision represents the overall access decision for an entity.
type Decision struct {
	Access  bool             `json:"access" example:"false"`
	Results []DataRuleResult `json:"entity_rule_result"`
}

// DataRuleResult represents the result of evaluating one rule for an entity.
type DataRuleResult struct {
	Passed         bool              `json:"passed" example:"false"`
	RuleDefinition *policy.Attribute `json:"rule_definition"`
	ValueFailures  []ValueFailure    `json:"value_failures"`
}

// ValueFailure represents a specific failure when evaluating a data attribute.
type ValueFailure struct {
	DataAttribute *policy.Value `json:"data_attribute"`
	Message       string        `json:"message" example:"Criteria NOT satisfied for entity: {entity_id} - lacked attribute value: {attribute}"`
}

// === Utilities for FQN/Definitions ===

// GroupValuesByDefinition groups policy values by their attribute definition FQNs.
func GroupValuesByDefinition(values []*policy.Value) (map[string][]*policy.Value, error) {
	groupings := make(map[string][]*policy.Value)

	for _, v := range values {
		if v.GetAttribute() != nil {
			defFqn := v.GetAttribute().GetFqn()
			if defFqn != "" {
				groupings[defFqn] = append(groupings[defFqn], v)
				continue
			}
		}

		defFqn, err := GetDefinitionFqnFromValueFqn(v.GetFqn())
		if err != nil {
			return nil, err
		}

		groupings[defFqn] = append(groupings[defFqn], v)
	}

	return groupings, nil
}

// GroupValueFqnsByDefinition groups value FQN strings by their attribute definition FQNs.
// Performance optimized version that minimizes allocations.
func GroupValueFqnsByDefinition(valueFqns []string) (map[string][]string, error) {
	// Pre-allocate with estimated capacity
	groupings := make(map[string][]string, min(len(valueFqns), 10))

	// First pass: count occurrences to pre-allocate slices
	counts := make(map[string]int, min(len(valueFqns), 10))
	for _, v := range valueFqns {
		defFqn, err := GetDefinitionFqnFromValueFqn(v)
		if err != nil {
			return nil, err
		}
		counts[defFqn]++
	}

	// Pre-allocate slices with exact sizes
	for defFqn, count := range counts {
		groupings[defFqn] = make([]string, 0, count)
	}

	// Second pass: populate the slices
	for _, v := range valueFqns {
		defFqn, err := GetDefinitionFqnFromValueFqn(v)
		if err != nil {
			return nil, err
		}
		groupings[defFqn] = append(groupings[defFqn], v)
	}

	return groupings, nil
}

// Helper function to return the smaller of two integers (for Go versions < 1.21)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetDefinitionFqnFromValue extracts the definition FQN from a policy value.
func GetDefinitionFqnFromValue(v *policy.Value) (string, error) {
	if v.GetAttribute() != nil && v.GetAttribute().GetFqn() != "" {
		return v.GetAttribute().GetFqn(), nil
	}
	return GetDefinitionFqnFromValueFqn(v.GetFqn())
}

// GetDefinitionFqnFromValueFqn extracts the definition FQN from a value FQN string.
// This is a performance-critical function, optimized for minimal allocations.
func GetDefinitionFqnFromValueFqn(valueFqn string) (string, error) {
	if valueFqn == "" {
		return "", fmt.Errorf("unexpected empty value FQN in GetDefinitionFqnFromValueFqn")
	}

	const suffix = "/value/"
	idx := strings.LastIndex(valueFqn, suffix)
	if idx == -1 {
		return "", fmt.Errorf("value FQN (%s) is of unknown format with no '/value/' segment", valueFqn)
	}

	// Return substring directly without additional allocations
	return valueFqn[:idx], nil
}

// GetDefinitionFqnFromDefinition constructs the FQN for an attribute definition.
func GetDefinitionFqnFromDefinition(def *policy.Attribute) (string, error) {
	fqn := def.GetFqn()
	if fqn != "" {
		return fqn, nil
	}

	ns := def.GetNamespace()
	if ns == nil {
		return "", fmt.Errorf("attribute definition has unexpectedly nil namespace")
	}

	nsName := ns.GetName()
	if nsName == "" {
		return "", fmt.Errorf("attribute definition's Namespace has unexpectedly empty name")
	}

	nsFqn := ns.GetFqn()
	attr := def.GetName()
	if attr == "" {
		return "", fmt.Errorf("attribute definition has unexpectedly empty name")
	}

	if nsFqn != "" {
		return fmt.Sprintf("%s/attr/%s", nsFqn, attr), nil
	}

	return fmt.Sprintf("https://%s/attr/%s", nsName, attr), nil
}
