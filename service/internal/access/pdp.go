package access

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/arkavo-org/opentdf-platform/protocol/go/policy"
)

type Pdp struct{}

func NewPdp() *Pdp {
	return &Pdp{}
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
	slog.DebugContext(ctx, "DetermineAccess")
	// Group all the Data Attribute Values by their Definitions (that is, "<namespace>/attr/<attrname>").
	// Definitions contain the rule logic for how to evaluate the data Attribute Values as a group (i.e. ANY_OF/ALL_OF/HIERARCHY).
	//
	// For example, we may have one group for the Definition FQN "https://namespace.org/attr/MyAttr"
	// with two Attribute Values on the data:
	// - "https://namespace.org/attr/MyAttr/value/Value1")
	// - "https://namespace.org/attr/MyAttr/value/Value2")
	dataAttrValsByDefinition, err := GroupValuesByDefinition(dataAttributes)
	if err != nil {
		slog.Error(fmt.Sprintf("error grouping data attributes by definition: %s", err.Error()))
		return nil, err
	}

	// Unlike with Values, there should only be *one* Attribute Definition per FQN (e.g "https://namespace.org/attr/MyAttr")
	fqnToDefinitionMap, err := GetFqnToDefinitionMap(attributeDefinitions)
	if err != nil {
		slog.Error(fmt.Sprintf("error grouping attribute definitions by FQN: %s", err.Error()))
		return nil, err
	}

	decisions := make(map[string]*Decision)
	// Go through all the grouped data values under each definition FQN
	for definitionFqn, distinctValues := range dataAttrValsByDefinition {
		slog.DebugContext(ctx, "Evaluating data attribute fqn", definitionFqn, slog.Any("values", distinctValues))
		attrDefinition, ok := fqnToDefinitionMap[definitionFqn]
		if !ok {
			return nil, fmt.Errorf("expected an Attribute Definition under the FQN %s", definitionFqn)
		}

		// If GroupBy is set, determine which entities (out of the set of entities and their respective Values)
		// will be considered for evaluation under this Definition's Rule.
		//
		// If GroupBy is not set, then we always consider all entities for evaluation under a Rule
		//
		// If this rule simply does not apply to a given entity ID as defined by the Attribute Definition we have,
		// and the entity Values that entity ID has, then that entity ID passed (or skipped) this rule.
		var (
			entityRuleDecision map[string]DataRuleResult
			err                error
		)
		switch attrDefinition.GetRule() {
		case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
			slog.DebugContext(ctx, "Evaluating under allOf", "name", definitionFqn, "values", distinctValues)
			entityRuleDecision, err = pdp.allOfRule(ctx, distinctValues, entityAttributeSets)
		case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
			slog.DebugContext(ctx, "Evaluating under anyOf", "name", definitionFqn, "values", distinctValues)
			entityRuleDecision, err = pdp.anyOfRule(ctx, distinctValues, entityAttributeSets)
		case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
			slog.DebugContext(ctx, "Evaluating under hierarchy", "name", definitionFqn, "values", distinctValues)
			entityRuleDecision, err = pdp.hierarchyRule(ctx, distinctValues, entityAttributeSets, attrDefinition.GetValues())
		case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
			return nil, fmt.Errorf("unset AttributeDefinition rule: %s", attrDefinition.GetRule())
		default:
			return nil, fmt.Errorf("unrecognized AttributeDefinition rule: %s", attrDefinition.GetRule())
		}
		if err != nil {
			return nil, fmt.Errorf("error evaluating rule: %s", err.Error())
		}

		// Roll up the per-data-rule decisions for each entity considered for this rule into the overall decision
		for entityId, ruleResult := range entityRuleDecision {
			entityDecision := decisions[entityId]

			ruleResult.RuleDefinition = attrDefinition
			// If we do not yet have an overall decision for this entity, initialize the map
			// with entityId as key and a Decision object as value
			if entityDecision == nil {
				decisions[entityId] = &Decision{
					Access:  ruleResult.Passed,
					Results: []DataRuleResult{ruleResult},
				}
			} else {
				// An overall Decision already exists for this entity, so update it with the new information
				// from the last rule evaluation -
				// boolean AND the new rule result for this entity and this rule with the existing access
				// result for this entity and the previous rules
				// to make sure we flip the overall access correctly, e.g if existing overall result is
				// TRUE and this new rule result is FALSE, then overall result flips to FALSE.
				// If it was previously FALSE it stays FALSE, etc
				entityDecision.Access = entityDecision.Access && ruleResult.Passed
				// Append the current rule result to the list of rule results.
				entityDecision.Results = append(entityDecision.Results, ruleResult)
			}
		}
	}

	return decisions, nil
}

// AllOf the Data Attribute Values should be present in AllOf the Entity's entityAttributeValue sets
// Accepts
// - a set of data Attribute Values with the same FQN
// - a map of entity Attribute Values keyed by entity ID
// Returns a map of DataRuleResults keyed by Subject
func (pdp *Pdp) allOfRule(ctx context.Context, dataAttrValuesOfOneDefinition []*policy.Value, entityAttributeValueFqns map[string][]string) (map[string]DataRuleResult, error) {
	ruleResultsByEntity := make(map[string]DataRuleResult)

	// All of the data Attribute Values in the arg have the same Definition FQN
	def, err := GetDefinitionFqnFromValue(dataAttrValuesOfOneDefinition[0])
	if err != nil {
		return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
	}
	slog.DebugContext(ctx, "Evaluating allOf decision", "attribute definition FQN", def)

	// Go through every entity's attributeValues set...
	for entityId, entityAttrVals := range entityAttributeValueFqns {
		var valueFailures []ValueFailure
		// Default to DENY
		entityPassed := false

		groupedEntityAttrValsByDefinition, err := GroupValueFqnsByDefinition(entityAttrVals)
		if err != nil {
			return nil, fmt.Errorf("error grouping entity attribute values by definition: %s", err.Error())
		}

		// For every unique data Attribute Value in the set sharing the same FQN...
		for dvIndex, dataAttrVal := range dataAttrValuesOfOneDefinition {
			attrDefFqn, err := GetDefinitionFqnFromValue(dataAttrVal)
			if err != nil {
				return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
			}
			slog.DebugContext(ctx, "Evaluating allOf decision for data attr %s with value %s", attrDefFqn, dataAttrVal.GetValue())
			// See if
			// 1. there exists an entity Attribute Value in the set of Attribute Values
			// with the same FQN as the data Attribute Value in question
			// 2. It has the same VALUE as the data Attribute Value in question
			found := getIsValueFoundInFqnValuesSet(dataAttrValuesOfOneDefinition[dvIndex], groupedEntityAttrValsByDefinition[attrDefFqn])

			// If we did not find the data Attribute Value FQN + value in the entity Attribute Value set,
			// then prepare a ValueFailure for that data Attribute Value for this entity
			if !found {
				denialMsg := fmt.Sprintf("AllOf not satisfied for data attr %s with value %s and entity %s", attrDefFqn, dataAttrVal.GetValue(), entityId)
				slog.WarnContext(ctx, denialMsg)
				// Append the ValueFailure to the set of entity value failures
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: dataAttrValuesOfOneDefinition[dvIndex],
					Message:       denialMsg,
				})
			}
		}

		// If we have no value failures, we are good - entity passes this rule
		if len(valueFailures) == 0 {
			entityPassed = true
		}
		ruleResultsByEntity[entityId] = DataRuleResult{
			Passed:        entityPassed,
			ValueFailures: valueFailures,
		}
	}

	return ruleResultsByEntity, nil
}

// AnyOf the Data Attribute Values can be present in AnyOf the Entity's Attribute Value FQN sets
// Accepts
// - a set of data Attribute Values with the same FQN
// - a map of entity Attribute Values keyed by entity ID
// Returns a map of DataRuleResults keyed by Subject entity ID
func (pdp *Pdp) anyOfRule(ctx context.Context, dataAttrValuesOfOneDefinition []*policy.Value, entityAttributeValueFqns map[string][]string) (map[string]DataRuleResult, error) {
	ruleResultsByEntity := make(map[string]DataRuleResult)

	// All of the data Attribute Values in the arg have the same Definition FQN
	attrDefFqn, err := GetDefinitionFqnFromValue(dataAttrValuesOfOneDefinition[0])
	if err != nil {
		return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
	}
	slog.DebugContext(ctx, "Evaluating anyOf decision", "attribute definition FQN", attrDefFqn)

	// Go through every entity's Attribute Value set...
	for entityId, entityAttrValFqns := range entityAttributeValueFqns {
		var valueFailures []ValueFailure
		// Default to DENY
		entityPassed := false

		entityAttrGroup, err := GroupValueFqnsByDefinition(entityAttrValFqns)
		if err != nil {
			return nil, fmt.Errorf("error grouping entity attribute values by definition: %s", err.Error())
		}

		// For every unique data Attribute Value in this set of data Attribute Value sharing the same FQN...
		for dvIndex, dataAttrVal := range dataAttrValuesOfOneDefinition {
			slog.DebugContext(ctx, "Evaluating anyOf decision", "attribute definition FQN", attrDefFqn, "value", dataAttrVal.GetValue())
			// See if there exists an entity Attribute Value in the set of Attribute Values
			// with the same FQN as the data Attribute Value in question
			found := getIsValueFoundInFqnValuesSet(dataAttrVal, entityAttrGroup[attrDefFqn])

			// If we did not find the data Attribute Value FQN + value in the entity Attribute Value set,
			// then prepare a ValueFailure for that data Attribute Value and value, for this entity
			if !found {
				denialMsg := fmt.Sprintf("anyOf not satisfied for data attr %s with value %s and entity %s - anyOf is permissive, so this doesn't mean overall failure", attrDefFqn, dataAttrVal.GetValue(), entityId)
				slog.WarnContext(ctx, denialMsg)
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: dataAttrValuesOfOneDefinition[dvIndex],
					Message:       denialMsg,
				})
			}
		}

		// AnyOf - IF there were fewer value failures for this entity, for this Attribute Value FQN,
		// then there are distict data values, for this Attribute Value FQN, THEN this entity must
		// possess AT LEAST ONE of the values in its entity Attribute Value group,
		// and we have satisfied AnyOf
		if len(valueFailures) < len(dataAttrValuesOfOneDefinition) {
			slog.DebugContext(ctx, "anyOf satisfied", "attribute definition FQN", attrDefFqn, "entityId", entityId)
			entityPassed = true
		}
		ruleResultsByEntity[entityId] = DataRuleResult{
			Passed:        entityPassed,
			ValueFailures: valueFailures,
		}
	}

	return ruleResultsByEntity, nil
}

// Hierarchy rule compares the HIGHEST (that is, numerically lowest index) data Attribute Value for a given Attribute Value FQN
// with the LOWEST (that is, numerically highest index) entity value for a given Attribute Value FQN.
//
// If multiple data values (that is, Attribute Values) for a given hierarchy AttributeDefinition are present for the same FQN, the highest will be chosen and
// the others ignored.
//
// If multiple entity Attribute Values for a hierarchy AttributeDefinition are present for the same FQN, the lowest will be chosen,
// and the others ignored.
func (pdp *Pdp) hierarchyRule(ctx context.Context, dataAttrValuesOfOneDefinition []*policy.Value, entityAttributeValueFqns map[string][]string, order []*policy.Value) (map[string]DataRuleResult, error) {
	ruleResultsByEntity := make(map[string]DataRuleResult)

	highestDataAttrVal, err := pdp.getHighestRankedInstanceFromDataAttributes(ctx, order, dataAttrValuesOfOneDefinition)
	if err != nil {
		return nil, fmt.Errorf("error getting highest ranked instance from data attributes: %s", err.Error())
	}
	if highestDataAttrVal == nil {
		slog.WarnContext(ctx, "No data attribute value found that matches attribute definition allowed values! All entity access will be rejected!")
	} else {
		slog.DebugContext(ctx, "Highest ranked hierarchy value on data attributes found", "value", highestDataAttrVal)
	}
	// All the data Attribute Values in the arg have the same FQN.

	// Go through every entity's Attribute Value set...
	for entityId, entityAttrs := range entityAttributeValueFqns {
		// Default to DENY
		entityPassed := false
		valueFailures := []ValueFailure{}

		// Group entity Attribute Values by FQN...
		entityAttrGroup, err := GroupValueFqnsByDefinition(entityAttrs)
		if err != nil {
			return nil, fmt.Errorf("error grouping entity attribute values by definition: %s", err.Error())
		}

		if highestDataAttrVal != nil {
			attrDefFqn, err := GetDefinitionFqnFromValue(highestDataAttrVal)
			if err != nil {
				return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
			}
			// For every unique data Attribute Value in this set of data Attribute Values sharing the same FQN...
			slog.DebugContext(ctx, "Evaluating hierarchy decision", "attribute definition fqn", attrDefFqn, "value", highestDataAttrVal.GetValue())

			// Compare the (one or more) Attribute Values for this FQN to the (one) data Attribute Value, and see which is "higher".
			passed, err := entityRankGreaterThanOrEqualToDataRank(order, highestDataAttrVal, entityAttrGroup[attrDefFqn])
			if err != nil {
				return nil, fmt.Errorf("error comparing entity rank to data rank: %s", err.Error())
			}
			entityPassed = passed

			// If the rank of the data Attribute Value is higher than the highest entity Attribute Value, then FAIL.
			if !entityPassed {
				denialMsg := fmt.Sprintf("Hierarchy - Entity: %s hierarchy values rank below data hierarchy value of %s", entityId, highestDataAttrVal.GetValue())
				slog.WarnContext(ctx, denialMsg)

				// Since there is only one data value we (ultimately) consider in a HierarchyRule, we will only ever
				// have one ValueFailure per entity at most
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: highestDataAttrVal,
					Message:       denialMsg,
				})
			}
			// It's possible we couldn't FIND a highest data value - because none of the data values are in the set of valid attribute definition values!
			// If this happens, we can't do a comparison, and access will be denied for every entity for this data attribute instance
		} else {
			// If every data attribute value we're comparing against is invalid (that is, none of them exist in the attribute definition)
			// then we must fail and return a nil instance.
			denialMsg := fmt.Sprintf("Hierarchy - No data values found exist in attribute definition, no hierarchy comparison possible, entity %s is denied", entityId)
			slog.WarnContext(ctx, denialMsg)
			valueFailures = append(valueFailures, ValueFailure{
				DataAttribute: nil,
				Message:       denialMsg,
			})
		}
		ruleResultsByEntity[entityId] = DataRuleResult{
			Passed:        entityPassed,
			ValueFailures: valueFailures,
		}
	}

	return ruleResultsByEntity, nil
}

// It is possible that a data policy may have more than one Hierarchy value for the same data attribute definition
// name, e.g.:
// - "https://namespace.org/attr/MyHierarchyAttr/value/Value1"
// - "https://namespace.org/attr/MyHierarchyAttr/value/Value2"
// Since by definition hierarchy comparisons have to be one-data-value-to-many-entity-values, this won't work.
// So, in a scenario where there are multiple data values to choose from, grab the "highest" ranked value
// present in the set of data Attribute Values, and use that as the point of comparison, ignoring the "lower-ranked" data values.
// If we find a data value that does not exist in the attribute definition's list of valid values, we will skip it
// If NONE of the data values exist in the attribute definitions list of valid values, return a nil instance
func (pdp *Pdp) getHighestRankedInstanceFromDataAttributes(ctx context.Context, order []*policy.Value, dataAttributeGroup []*policy.Value) (*policy.Value, error) {
	// For hierarchy, convention is 0 == most privileged, 1 == less privileged, etc
	// So initialize with the LEAST privileged rank in the defined order
	highestDVIndex := len(order) - 1
	var highestRankedInstance *policy.Value
	for _, dataAttr := range dataAttributeGroup {
		foundRank, err := getOrderOfValue(order, dataAttr)
		if err != nil {
			return nil, fmt.Errorf("error getting order of value: %s", err.Error())
		}
		if foundRank == -1 {
			msg := fmt.Sprintf("Data value %s is not in %s and is not a valid value for this attribute - ignoring this invalid value and continuing to look for a valid one...", dataAttr.GetValue(), order)
			slog.WarnContext(ctx, msg)
			// If this isnt a valid data value, skip this iteration and look at the next one - maybe it is?
			// If none of them are valid, we should return a nil instance
			continue
		}
		slog.DebugContext(ctx, "Found data", "rank", foundRank, "value", dataAttr.GetValue(), "maxRank", highestDVIndex)
		// If this rank is a "higher rank" (that is, a lower index) than the last one,
		// (or it is the same rank, to handle cases where the lowest is the only)
		// it becomes the new high watermark rank.
		if foundRank <= highestDVIndex {
			slog.DebugContext(ctx, "Updating rank!")
			highestDVIndex = foundRank
			gotAttr := dataAttr
			highestRankedInstance = gotAttr
		}
	}
	return highestRankedInstance, nil
}

// Check for a match of a singular Attribute Value in a set of Attribute Value FQNs
func getIsValueFoundInFqnValuesSet(v *policy.Value, fqns []string) bool {
	valFqn := v.GetFqn()
	if valFqn == "" {
		slog.Error(fmt.Sprintf("Unexpected empty FQN for value %+v", v))
		return false
	}
	for _, fqn := range fqns {
		if valFqn == fqn {
			return true
		}
	}
	return false
}

// Given set of ordered/ranked values, a data singular Attribute Value, and a set of entity Attribute Values,
// determine if the entity Attribute Values include a ranked value that equals or exceeds
// the rank of the data Attribute Value.
// For hierarchy, convention is 0 == most privileged, 1 == less privileged, etc
func entityRankGreaterThanOrEqualToDataRank(order []*policy.Value, dataAttribute *policy.Value, entityAttrValueFqnsGroup []string) (bool, error) {
	// default to least-perm
	result := false
	dvIndex, err := getOrderOfValue(order, dataAttribute)
	if err != nil {
		return false, err
	}
	// Compute the rank of the entity Attribute Value against the rank of the data Attribute Value
	// While, for hierarchy, we only ever have a singular data value we're checking
	// for a given data Attribute Value FQN,
	// we may have *several* entity values for a given entity Attribute Value FQN -
	// so if an entity has multiple values that can be compared for the hierarchy rule,
	// we check all of them and go with the value that has the least-significant index when deciding access
	for _, entityAttributeFqn := range entityAttrValueFqnsGroup {
		// Ideally, the caller will have already ensured all the entity Attribute Values we've been provided
		// have the same FQN as the data Attribute Value we're comparing against,
		// but if they haven't for some reason only consider matching entity Attribute Values
		dataAttrDefFqn, err := GetDefinitionFqnFromValue(dataAttribute)
		if err != nil {
			return false, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
		}
		entityAttrDefFqn, err := GetDefinitionFqnFromValueFqn(entityAttributeFqn)
		if err != nil {
			return false, fmt.Errorf("error getting definition FQN from entity attribute value: %s", err.Error())
		}
		if dataAttrDefFqn == entityAttrDefFqn {
			evIndex, err := getOrderOfValueByFqn(order, entityAttributeFqn)
			if err != nil {
				return false, err
			}
			// If the entity value isn't IN the order at all,
			// then set it's rank to one below the lowest rank in the current
			// order so it will always fail
			if evIndex == -1 {
				evIndex = len(order) + 1
			}
			// If, at any point, we find an entity Attribute Value that is below the data Attribute Value in rank,
			// (that is, numerically greater than the data rank)
			// (or if the data value itself is < 0, indicating it's not actually part of the defined order)
			// then we must immediately assume failure for this entity
			// and return.
			if evIndex > dvIndex || dvIndex == -1 {
				result = false
				return result, nil
			} else if evIndex <= dvIndex {
				result = true
			}
		}
	}
	return result, nil
}

// Given a set of ordered/ranked values and a singular Attribute Value, return the
// rank #/index of the singular Attribute Value. If the value is not found, return -1.
// For hierarchy, convention is 0 == most privileged, 1 == less privileged, etc.
func getOrderOfValue(order []*policy.Value, v *policy.Value) (int, error) {
	val := v.GetValue()
	valFqn := v.GetFqn()
	if val == "" {
		slog.Debug(fmt.Sprintf("Unexpected empty 'value' in value: %+v, falling back to FQN", v))
		return getOrderOfValueByFqn(order, valFqn)
	}

	for idx := range order {
		orderVal := order[idx].GetValue()
		if orderVal == "" {
			return -1, fmt.Errorf("unexpected empty value %+v in order at index %d", order[idx], idx)
		}
		if orderVal == val {
			return idx, nil
		}
	}

	// If we did not find the right index, return -1
	return -1, nil
}

// Given a set of ordered/ranked values and a singular Attribute Value, return the
// rank #/index of the singular Attribute Value. If the value is not found, return -1.
// For hierarchy, convention is 0 == most privileged, 1 == less privileged, etc
func getOrderOfValueByFqn(order []*policy.Value, valFqn string) (int, error) {
	for idx := range order {
		orderValFqn := order[idx].GetFqn()
		// We should have this, but if not, rebuild it from the value
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

// A Decision represents the overall access decision for a specific entity,
// - that is, the aggregate result of comparing entity Attribute Values to every data Attribute Value.
type Decision struct {
	// The important bit - does this entity Have Access or not, for this set of data attribute values
	// This will be TRUE if, for *every* DataRuleResult in Results, EntityRuleResult.Passed == TRUE
	// Otherwise, it will be false
	Access bool `json:"access" example:"false"`
	// Results will contain at most 1 DataRuleResult for each data Attribute Value.
	// e.g. if we compare an entity's Attribute Values against 5 data Attribute Values,
	// then there will be 5 rule results, each indicating whether this entity "passed" validation
	// for that data Attribute Value or not.
	//
	// If an entity was skipped for a particular rule evaluation because of a GroupBy clause
	// on the AttributeDefinition for a given data Attribute Value, however, then there may be
	// FEWER DataRuleResults then there are DataRules
	//
	// e.g. there are 5 data Attribute Values, and two entities each with a set of Attribute Values,
	// the definition for one of those data Attribute Values has a GroupBy clause that excludes the second entity
	//-> the first entity will have 5 DataRuleResults with Passed = true
	//-> the second entity will have 4 DataRuleResults Passed = true
	//-> both will have Access == true.
	Results []DataRuleResult `json:"entity_rule_result"`
}

// DataRuleResult represents the rule-level (or AttributeDefinition-level) decision for a specific entity -
// the result of comparing entity Attribute Values to a single data AttributeDefinition/rule (with potentially many values)
//
// There may be multiple "instances" (that is, Attribute Values) of a single AttributeDefinition on both data and entities,
// each with a different value.
type DataRuleResult struct {
	// Indicates whether, for this specific data AttributeDefinition, an entity satisfied
	// the rule conditions (allof/anyof/hierarchy)
	Passed bool `json:"passed" example:"false"`
	// Contains the AttributeDefinition of the data attribute rule this result represents
	RuleDefinition *policy.Attribute `json:"rule_definition"`
	// May contain 0 or more ValueFailure types, depending on the RuleDefinition and which (if any)
	// data Attribute Values/values the entity failed against
	//
	// For an AllOf rule, there should be no value failures if Passed=TRUE
	// For an AnyOf rule, there should be fewer entity value failures than
	// there are data attribute values in total if Passed=TRUE
	// For a Hierarchy rule, there should be either no value failures if Passed=TRUE,
	// or exactly one value failure if Passed=FALSE
	ValueFailures []ValueFailure `json:"value_failures"`
}

// ValueFailure indicates, for a given entity and data Attribute Value, which data values
// (aka specific data Attribute Value) the entity "failed" on.
//
// There may be multiple "instances" (that is, Attribute Values) of a single AttributeDefinition on both data and entities,
// each with a different value.
//
// A ValueFailure does not necessarily mean the requirements for an AttributeDefinition were not or will not be met,
// it is purely informational - there will be one value failure, per entity, per rule, per value the entity lacks -
// it is up to the rule itself (anyof/allof/hierarchy) to translate this into an overall failure or not.
type ValueFailure struct {
	// The data attribute w/value that "caused" the denial
	DataAttribute *policy.Value `json:"data_attribute"`
	// Optional denial message
	Message string `json:"message" example:"Criteria NOT satisfied for entity: {entity_id} - lacked attribute value: {attribute}"`
}

// GroupDefinitionsByFqn takes a slice of Attribute Definitions and returns them as a map:
// FQN -> Attribute Definition
func GetFqnToDefinitionMap(attributeDefinitions []*policy.Attribute) (map[string]*policy.Attribute, error) {
	grouped := make(map[string]*policy.Attribute)
	for _, def := range attributeDefinitions {
		a, err := GetDefinitionFqnFromDefinition(def)
		if err != nil {
			return nil, err
		}
		if v, ok := grouped[a]; ok {
			// TODO: is this really an error case, or is logging a warning okay?
			slog.Warn(fmt.Sprintf("duplicate Attribute Definition FQN %s found when building FQN map: %v and %v, which may indicate an issue", a, v, def))
		}
		grouped[a] = def
	}
	return grouped, nil
}

// Groups Attribute Values by their parent Attribute Definition FQN
func GroupValuesByDefinition(values []*policy.Value) (map[string][]*policy.Value, error) {
	groupings := make(map[string][]*policy.Value)
	for _, v := range values {
		// If the parent Definition & its FQN are not nil, rely on them
		if v.GetAttribute() != nil {
			defFqn := v.GetAttribute().GetFqn()
			if defFqn != "" {
				groupings[defFqn] = append(groupings[defFqn], v)
				continue
			}
		}
		// Otherwise derive the grouping relation from the FQNs
		defFqn, err := GetDefinitionFqnFromValueFqn(v.GetFqn())
		if err != nil {
			return nil, err
		}
		groupings[defFqn] = append(groupings[defFqn], v)
	}
	return groupings, nil
}

func GroupValueFqnsByDefinition(valueFqns []string) (map[string][]string, error) {
	groupings := make(map[string][]string)
	for _, v := range valueFqns {
		defFqn, err := GetDefinitionFqnFromValueFqn(v)
		if err != nil {
			return nil, err
		}
		groupings[defFqn] = append(groupings[defFqn], v)
	}
	return groupings, nil
}

func GetDefinitionFqnFromValue(v *policy.Value) (string, error) {
	if v.GetAttribute() != nil {
		return GetDefinitionFqnFromDefinition(v.GetAttribute())
	}
	return GetDefinitionFqnFromValueFqn(v.GetFqn())
}

// Splits off the Value from the FQN to get the parent Definition FQN:
//
//	Input: https://<namespace>/attr/<attr name>/value/<value>
//	Output: https://<namespace>/attr/<attr name>
func GetDefinitionFqnFromValueFqn(valueFqn string) (string, error) {
	if valueFqn == "" {
		return "", fmt.Errorf("unexpected empty value FQN in GetDefinitionFqnFromValueFqn")
	}
	idx := strings.LastIndex(valueFqn, "/value/")
	if idx == -1 {
		return "", fmt.Errorf("value FQN (%s) is of unknown format with no '/value/' segment", valueFqn)
	}
	defFqn := valueFqn[:idx]
	if defFqn == "" {
		return "", fmt.Errorf("value FQN (%s) is of unknown format with no known parent Definition", valueFqn)
	}
	return defFqn, nil
}

func GetDefinitionFqnFromDefinition(def *policy.Attribute) (string, error) {
	// see if its FQN is already supplied
	fqn := def.GetFqn()
	if fqn != "" {
		return fqn, nil
	}
	// otherwise build it from the namespace and name
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
	// Namespace FQN contains 'https://' scheme prefix, but Namespace Name does not
	if nsFqn != "" {
		return fmt.Sprintf("%s/attr/%s", nsFqn, attr), nil
	}
	return fmt.Sprintf("https://%s/attr/%s", nsName, attr), nil
}
