//nolint:sloglint // v1 PDP will be deprecated soon
package access

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
)

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

	if len(dataAttributes) == 0 {
		pdp.logger.DebugContext(ctx, "No data attributes provided")
		return nil, errors.New("no data attributes provided")
	}

	if len(attributeDefinitions) == 0 {
		pdp.logger.DebugContext(ctx, "No attribute definitions provided")
		return nil, errors.New("no attribute definitions provided")
	}

	dataAttrValsByDefinition, err := pdp.groupDataAttributesByDefinition(ctx, dataAttributes)
	if err != nil {
		return nil, err
	}

	fqnToDefinitionMap, err := pdp.mapFqnToDefinitions(ctx, attributeDefinitions)
	if err != nil {
		return nil, err
	}

	return pdp.evaluateAttributes(ctx, dataAttrValsByDefinition, fqnToDefinitionMap, entityAttributeSets)
}

// groups provided values
func (pdp *Pdp) groupDataAttributesByDefinition(ctx context.Context, dataAttributes []*policy.Value) (map[string][]*policy.Value, error) {
	groupings := make(map[string][]*policy.Value)

	for _, v := range dataAttributes {
		if v.GetAttribute() != nil {
			defFqn := v.GetAttribute().GetFqn()
			if defFqn != "" {
				groupings[defFqn] = append(groupings[defFqn], v)
				continue
			}
		}

		defFqn, err := GetDefinitionFqnFromValueFqn(v.GetFqn())
		if err != nil {
			pdp.logger.ErrorContext(ctx, "error getting definition FQN from value: "+err.Error())
			return nil, err
		}

		groupings[defFqn] = append(groupings[defFqn], v)
	}

	return groupings, nil
}

// maps defintion FQN to definition object
func (pdp *Pdp) mapFqnToDefinitions(ctx context.Context, attributeDefinitions []*policy.Attribute) (map[string]*policy.Attribute, error) {
	grouped := make(map[string]*policy.Attribute)

	for _, def := range attributeDefinitions {
		defFQN, err := GetDefinitionFqnFromDefinition(def)
		if err != nil {
			return nil, err
		}

		if v, ok := grouped[defFQN]; ok {
			pdp.logger.Warn(fmt.Sprintf("duplicate Attribute Definition FQN %s found when building FQN map which may indicate an issue", defFQN))
			pdp.logger.TraceContext(ctx, "duplicate attribute definitions found are: ", "attr1", v, "attr2", def)
		}

		grouped[defFQN] = def
	}

	return grouped, nil
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

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
		return nil, fmt.Errorf("AttributeDefinition rule cannot be unspecified: %s, rule: %v", attrDefinition.GetFqn(), attrDefinition.GetRule())
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
	ruleResultsByEntity := make(map[string]DataRuleResult)

	if len(dataAttrValuesOfOneDefinition) == 0 {
		return ruleResultsByEntity, nil
	}

	def, err := GetDefinitionFqnFromValue(dataAttrValuesOfOneDefinition[0])
	if err != nil {
		return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
	}

	pdp.logger.DebugContext(ctx, "Evaluating allOf decision", "attribute definition FQN", def)
	pdp.logger.TraceContext(ctx, "Attribute values for", "attribute definition FQN", def, "values", dataAttrValuesOfOneDefinition)

	for entityID, entityAttrVals := range entityAttributeValueFqns {
		var valueFailures []ValueFailure
		entityPassed := true

		groupedEntityAttrValsByDefinition, err := GroupValueFqnsByDefinition(entityAttrVals)
		if err != nil {
			return nil, fmt.Errorf("error grouping entity attribute values by definition: %s", err.Error())
		}

		for _, dataAttrVal := range dataAttrValuesOfOneDefinition {
			attrDefFqn, err := GetDefinitionFqnFromValue(dataAttrVal)
			if err != nil {
				return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
			}

			pdp.logger.DebugContext(ctx, "Evaluating allOf decision", "data attr fqn", attrDefFqn, "value", dataAttrVal.GetValue())

			found := getIsValueFoundInFqnValuesSet(dataAttrVal, groupedEntityAttrValsByDefinition[attrDefFqn], pdp.logger)
			if !found {
				denialMsg := fmt.Sprintf("AllOf not satisfied for data attr %s with value %s and entity %s", attrDefFqn, dataAttrVal.GetValue(), entityID)
				pdp.logger.WarnContext(ctx, denialMsg)
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: dataAttrVal,
					Message:       denialMsg,
				})
				entityPassed = false
			}
		}

		ruleResultsByEntity[entityID] = DataRuleResult{
			Passed:        entityPassed,
			ValueFailures: valueFailures,
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
	ruleResultsByEntity := make(map[string]DataRuleResult)

	if len(dataAttrValuesOfOneDefinition) == 0 {
		return ruleResultsByEntity, nil
	}

	attrDefFqn, err := GetDefinitionFqnFromValue(dataAttrValuesOfOneDefinition[0])
	if err != nil {
		return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
	}

	pdp.logger.DebugContext(ctx, "Evaluating anyOf decision", "attribute definition FQN", attrDefFqn)
	pdp.logger.TraceContext(ctx, "Attribute values for", "attribute definition FQN", attrDefFqn, "values", dataAttrValuesOfOneDefinition)

	for entityID, entityAttrValFqns := range entityAttributeValueFqns {
		var valueFailures []ValueFailure
		entityPassed := false

		entityAttrGroup, err := GroupValueFqnsByDefinition(entityAttrValFqns)
		if err != nil {
			return nil, fmt.Errorf("error grouping entity attribute values by definition: %s", err.Error())
		}

		for _, dataAttrVal := range dataAttrValuesOfOneDefinition {
			pdp.logger.DebugContext(ctx, "Evaluating anyOf decision", "attribute definition FQN", attrDefFqn, "value", dataAttrVal.GetValue())

			found := getIsValueFoundInFqnValuesSet(dataAttrVal, entityAttrGroup[attrDefFqn], pdp.logger)
			if found {
				entityPassed = true
			} else {
				denialMsg := fmt.Sprintf("anyOf not satisfied for data attr %s with value %s and entity %s - anyOf is permissive, so this doesn't mean overall failure", attrDefFqn, dataAttrVal.GetValue(), entityID)
				pdp.logger.DebugContext(ctx, denialMsg)
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: dataAttrVal,
					Message:       denialMsg,
				})
			}
		}

		if entityPassed {
			pdp.logger.DebugContext(ctx, "anyOf satisfied", "attribute definition FQN", attrDefFqn, "entityId", entityID)
		} else {
			pdp.logger.WarnContext(ctx, "anyOf not satisfied", "attribute definition FQN", attrDefFqn, "entityId", entityID)
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
	ruleResultsByEntity := make(map[string]DataRuleResult)

	highestDataAttrVal, err := pdp.getHighestRankedInstanceFromDataAttributes(ctx, order, dataAttrValuesOfOneDefinition, pdp.logger)
	if err != nil {
		return nil, fmt.Errorf("error getting highest ranked instance from data attributes: %s", err.Error())
	}

	if highestDataAttrVal == nil {
		pdp.logger.WarnContext(ctx, "No data attribute value found that matches attribute definition allowed values! All entity access will be rejected!")
	} else {
		pdp.logger.DebugContext(ctx, "Highest ranked hierarchy value on data attributes found", "value", highestDataAttrVal.GetValue())
	}

	for entityID, entityAttrs := range entityAttributeValueFqns {
		valueFailures := []ValueFailure{}
		entityPassed := false

		entityAttrGroup, err := GroupValueFqnsByDefinition(entityAttrs)
		if err != nil {
			return nil, fmt.Errorf("error grouping entity attribute values by definition: %s", err.Error())
		}

		if highestDataAttrVal != nil {
			attrDefFqn, err := GetDefinitionFqnFromValue(highestDataAttrVal)
			if err != nil {
				return nil, fmt.Errorf("error getting definition FQN from data attribute value: %s", err.Error())
			}

			pdp.logger.DebugContext(ctx, "Evaluating hierarchy decision", "attribute definition fqn", attrDefFqn, "value", highestDataAttrVal.GetValue())
			pdp.logger.TraceContext(ctx, "Value obj", "value", highestDataAttrVal.GetValue(), "obj", highestDataAttrVal)

			passed, err := entityRankGreaterThanOrEqualToDataRank(order, highestDataAttrVal, entityAttrGroup[attrDefFqn], pdp.logger)
			if err != nil {
				return nil, fmt.Errorf("error comparing entity rank to data rank: %s", err.Error())
			}
			entityPassed = passed

			if !entityPassed {
				denialMsg := fmt.Sprintf("Hierarchy - Entity: %s hierarchy values rank below data hierarchy value of %s", entityID, highestDataAttrVal.GetValue())
				pdp.logger.WarnContext(ctx, denialMsg)
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: highestDataAttrVal,
					Message:       denialMsg,
				})
			}
		} else {
			denialMsg := fmt.Sprintf("Hierarchy - No data values found exist in attribute definition, no hierarchy comparison possible, entity %s is denied", entityID)
			pdp.logger.WarnContext(ctx, denialMsg)
			valueFailures = append(valueFailures, ValueFailure{
				DataAttribute: nil,
				Message:       denialMsg,
			})
		}

		ruleResultsByEntity[entityID] = DataRuleResult{
			Passed:        entityPassed,
			ValueFailures: valueFailures,
		}
	}

	return ruleResultsByEntity, nil
}

// getHighestRankedInstanceFromDataAttributes finds the data attribute with the highest rank in the hierarchy.
func (pdp *Pdp) getHighestRankedInstanceFromDataAttributes(
	ctx context.Context,
	order []*policy.Value,
	dataAttributeGroup []*policy.Value,
	logger *logger.Logger,
) (*policy.Value, error) {
	highestDVIndex := len(order) - 1
	var highestRankedInstance *policy.Value

	for _, dataAttr := range dataAttributeGroup {
		foundRank, err := getOrderOfValue(order, dataAttr, logger)
		if err != nil {
			return nil, fmt.Errorf("error getting order of value: %s", err.Error())
		}

		if foundRank == -1 {
			msg := fmt.Sprintf("Data value %s is not in %s and is not a valid value for this attribute - ignoring this invalid value and continuing to look for a valid one...", dataAttr.GetValue(), order)
			pdp.logger.WarnContext(ctx, msg)
			continue
		}

		pdp.logger.DebugContext(ctx, "Found data", "rank", foundRank, "value", dataAttr.GetValue(), "maxRank", highestDVIndex)
		if foundRank <= highestDVIndex {
			pdp.logger.DebugContext(ctx, "Updating rank!")
			highestDVIndex = foundRank
			highestRankedInstance = dataAttr
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
	result := false

	dvIndex, err := getOrderOfValue(order, dataAttribute, log)
	if err != nil {
		return false, err
	}

	for _, entityAttributeFqn := range entityAttrValueFqnsGroup {
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

			if evIndex == -1 {
				evIndex = len(order) + 1
			}

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

// getOrderOfValue finds the index of a value in the ordered list.
func getOrderOfValue(
	order []*policy.Value,
	v *policy.Value,
	log *logger.Logger,
) (int, error) {
	val := v.GetValue()
	valFqn := v.GetFqn()

	if val == "" {
		log.Debug(fmt.Sprintf("Unexpected empty 'value' in value: %+v, falling back to FQN", v))
		return getOrderOfValueByFqn(order, valFqn)
	}

	for idx, orderVal := range order {
		currentVal := orderVal.GetValue()
		if currentVal == "" {
			return -1, fmt.Errorf("unexpected empty value %+v in order at index %d", orderVal, idx)
		}

		if currentVal == val {
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

// === Utilities for FQN/Definitions ===

// GroupValueFqnsByDefinition groups value FQN strings by their attribute definition FQNs.
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

// GetDefinitionFqnFromValue extracts the definition FQN from a policy value.
func GetDefinitionFqnFromValue(v *policy.Value) (string, error) {
	if v.GetAttribute() != nil {
		return GetDefinitionFqnFromDefinition(v.GetAttribute())
	}
	return GetDefinitionFqnFromValueFqn(v.GetFqn())
}

// GetDefinitionFqnFromValueFqn extracts the definition FQN from a value FQN string.
func GetDefinitionFqnFromValueFqn(valueFqn string) (string, error) {
	if valueFqn == "" {
		return "", errors.New("unexpected empty value FQN in GetDefinitionFqnFromValueFqn")
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

// GetDefinitionFqnFromDefinition constructs the FQN for an attribute definition.
func GetDefinitionFqnFromDefinition(def *policy.Attribute) (string, error) {
	fqn := def.GetFqn()
	if fqn != "" {
		return fqn, nil
	}

	ns := def.GetNamespace()
	if ns == nil {
		return "", errors.New("attribute definition has unexpectedly nil namespace")
	}

	nsName := ns.GetName()
	if nsName == "" {
		return "", errors.New("attribute definition's Namespace has unexpectedly empty name")
	}

	nsFqn := ns.GetFqn()
	attr := def.GetName()
	if attr == "" {
		return "", errors.New("attribute definition has unexpectedly empty name")
	}

	if nsFqn != "" {
		return fmt.Sprintf("%s/attr/%s", nsFqn, attr), nil
	}

	return fmt.Sprintf("https://%s/attr/%s", nsName, attr), nil
}
