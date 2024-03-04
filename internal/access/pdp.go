package access

import (
	"context"
	"fmt"
	"log/slog"

	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
)

type Pdp struct {
}

func NewPdp() *Pdp {
	return &Pdp{}
}

// DetermineAccess will take data AttributeInstances, data AttributeDefinitions, and entity attributeInstance sets, and
// compare every data attributeInstance against every entity's attributeInstance set, generating a rolled-up decision
// result for each entity, as well as a detailed breakdown of every data attributeInstance comparison.
func (pdp *Pdp) DetermineAccess(
	ctx context.Context,
	dataAttributes []attributeInstance,
	entityAttributeSets map[string][]attributeInstance,
	attributeDefinitions []*attrs.Attribute,
) (map[string]*Decision, error) {
	slog.DebugContext(ctx, "DetermineAccess")
	// Cluster (e.g. group) all the Data AttributeInstances by CanonicalName (that is, "<namespace>/attr/<attrname>")
	// AttributeInstances in the same cluster/group (keyed by CanonicalName) will be different "instances" of the same attribute,
	// potentially with different values.
	//
	// (e.g. we may have one cluster keyed by "https://authority.org/attr/MyAttr"
	// with two attributes having different values inside that cluster:
	// - "https://authority.org/attr/MyAttr/value/Value1")
	// - "https://authority.org/attr/MyAttr/value/Value2")
	clusteredDataAttrs := ClusterByCanonicalNameAI(dataAttributes)
	// Similarly, cluster (e.g. group) all the previously-fetched AttributeDefinitions (one definition per Data attributeInstance)
	// by CanonicalName (that is, "<namespace>/attr/<attrname>")
	//
	// Unlike with AttributeInstances, there should only be *one* AttributeDefinition per CanonicalName (e.g "https://authority.org/attr/MyAttr")
	clusteredDefinitions := ClusterByCanonicalNameAD(attributeDefinitions)

	decisions := make(map[string]*Decision)
	// Go through all the clustered data attrs by canonical name
	for canonicalName, distinctValues := range clusteredDataAttrs {
		slog.DebugContext(ctx, "Evaluating data attribute", "name", canonicalName)
		// Correctness check - we should only have been given 1 AttributeDefinition for per attribute CanonicalName
		// If not, then calling code is broken, so complain.
		if len(clusteredDefinitions[canonicalName]) != 1 {
			return nil, fmt.Errorf("expected 1 AttributeDefinition per attribute CanonicalName %s", canonicalName)
		}
		// For every canonical name we have a cluster for in the data attr set,
		// look up its AttributeDefinition (again, should be exactly 1)
		attrDefinition := clusteredDefinitions[canonicalName][0]

		// If GroupBy is set, determine which entities (out of the set of entities and their respective AttributeInstances)
		// will be considered for evaluation under this rule definition.
		//
		// If GroupBy is not set, then we always consider all entities for evaluation under a rule definition
		//
		// If this rule simply does not apply to a given entity ID as defined by the AttributeDefinition we have,
		// and the entity AttributeInstances that entity ID has, then that entity ID passed (or skipped) this rule.
		filteredEntities := entityAttributeSets
		var entityRuleDecision map[string]DataRuleResult
		switch attrDefinition.Rule {
		case attrs.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
			slog.DebugContext(ctx, "Evaluating under allOf", "name", canonicalName, "values", distinctValues)
			entityRuleDecision = pdp.allOfRule(ctx, distinctValues, filteredEntities)
		case attrs.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
			slog.DebugContext(ctx, "Evaluating under anyOf", "name", canonicalName, "values", distinctValues)
			entityRuleDecision = pdp.anyOfRule(ctx, distinctValues, filteredEntities)
		case attrs.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
			slog.DebugContext(ctx, "Evaluating under hierarchy", "name", canonicalName, "values", distinctValues)
			entityRuleDecision = pdp.hierarchyRule(ctx, distinctValues, filteredEntities, attrDefinition.Values)
		case attrs.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
			return nil, fmt.Errorf("unset AttributeDefinition rule: %s", attrDefinition.Rule)
		default:
			return nil, fmt.Errorf("unrecognized AttributeDefinition rule: %s", attrDefinition.Rule)
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

// AllOf the Data attributeInstance CanonicalName+Value pairs should be present in AllOf the Entity's attributeInstance sets
// Accepts
// - a set of data AttributeInstances with the same canonical name
// - a map of entity AttributeInstances keyed by entity ID
// Returns a map of DataRuleResults keyed by EntityID
func (pdp *Pdp) allOfRule(ctx context.Context, dataAttrsBySingleCanonicalName []attributeInstance, entityAttributes map[string][]attributeInstance) map[string]DataRuleResult {
	ruleResultsByEntity := make(map[string]DataRuleResult)

	//All of the data AttributeInstances in the arg have the same canonical name.
	slog.DebugContext(ctx, "Evaluating all-of decision", "name", dataAttrsBySingleCanonicalName[0].GetCanonicalName())

	//Go through every entity's attributeInstance set...
	for entityId, entityAttrs := range entityAttributes {
		var valueFailures []ValueFailure
		//Default to DENY
		entityPassed := false
		//Cluster entity AttributeInstances by canonical name...
		entityAttrCluster := ClusterByCanonicalNameAI(entityAttrs)

		//For every unique data attributeInstance (that is, unique data attribute value) in this set of data AttributeInstances sharing the same canonical name...
		for dvIndex, dataAttrVal := range dataAttrsBySingleCanonicalName {
			dvCanonicalName := dataAttrVal.GetCanonicalName()
			slog.DebugContext(ctx, "Evaluating all-of decision for data attr %s with value %s", dvCanonicalName, dataAttrVal.Value)
			//See if
			// 1. there exists an entity attributeInstance in the set of AttributeInstances
			// with the same canonical name as the data attributeInstance in question
			// 2. It has the same VALUE as the data attributeInstance in question
			found := findInstanceValueInClusterAI(&dataAttrsBySingleCanonicalName[dvIndex], entityAttrCluster[dvCanonicalName])

			denialMsg := ""
			//If we did not find the data attributeInstance canonical name + value in the entity attributeInstance set,
			//then prepare a ValueFailure for that data attributeInstance (that is, attribute value), for this entity
			if !found {
				denialMsg = fmt.Sprintf("AllOf not satisfied for canonical data attr+value %s and entity %s", dataAttrVal, entityId)
				slog.WarnContext(ctx, denialMsg)
				//Append the ValueFailure to the set of entity value failures
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: &dataAttrsBySingleCanonicalName[dvIndex],
					Message:       denialMsg,
				})
			}
		}

		//If we have no value failures, we are good - entity passes this rule
		if len(valueFailures) == 0 {
			entityPassed = true
		}
		ruleResultsByEntity[entityId] = DataRuleResult{
			Passed:        entityPassed,
			ValueFailures: valueFailures,
		}

	}

	return ruleResultsByEntity
}

// AnyOf the Data attributeInstance CanonicalName+Value pairs can be present in AnyOf the Entity's attributeInstance sets
// Accepts
// - a set of data AttributeInstances with the same canonical name
// - a map of entity AttributeInstances keyed by entity ID
// Returns a map of DataRuleResults keyed by EntityID
func (pdp *Pdp) anyOfRule(ctx context.Context, dataAttrsBySingleCanonicalName []attributeInstance, entityAttributes map[string][]attributeInstance) map[string]DataRuleResult {
	ruleResultsByEntity := make(map[string]DataRuleResult)

	dvCanonicalName := dataAttrsBySingleCanonicalName[0].GetCanonicalName()
	// All the data AttributeInstances in the arg have the same canonical name.
	slog.DebugContext(ctx, "Evaluating anyOf decision", "attr", dvCanonicalName)

	// Go through every entity's attributeInstance set...
	for entityId, entityAttrs := range entityAttributes {
		var valueFailures []ValueFailure
		//Default to DENY
		entityPassed := false
		//Cluster entity AttributeInstances by canonical name...
		entityAttrCluster := ClusterByCanonicalNameAI(entityAttrs)

		//For every unique data attributeInstance (that is, value) in this set of data attributeInstance sharing the same canonical name...
		for dvIndex, dataAttrVal := range dataAttrsBySingleCanonicalName {
			slog.DebugContext(ctx, "Evaluating anyOf decision", "attr", dvCanonicalName, "value", dataAttrVal.Value)
			//See if
			// 1. there exists an entity attributeInstance in the set of AttributeInstances
			// with the same canonical name as the data attributeInstance in question
			// 2. It has the same VALUE as the data attributeInstance in question
			found := findInstanceValueInClusterAI(&dataAttrsBySingleCanonicalName[dvIndex], entityAttrCluster[dvCanonicalName])

			denialMsg := ""
			//If we did not find the data attributeInstance canonical name + value in the entity attributeInstance set,
			//then prepare a ValueFailure for that data attributeInstance and value, for this entity
			if !found {
				denialMsg = fmt.Sprintf("anyOf not satisfied for canonical data attr+value %s and entity %s - anyOf is permissive, so this doesn't mean overall failure", dataAttrVal, entityId)
				slog.WarnContext(ctx, denialMsg)
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: &dataAttrsBySingleCanonicalName[dvIndex],
					Message:       denialMsg,
				})
			}
		}

		//AnyOf - IF there were fewer value failures for this entity, for this attributeInstance canonical name,
		//then there are distict data values, for this attributeInstance canonical name, THEN this entity must
		//possess AT LEAST ONE of the values in its entity attributeInstance cluster,
		//and we have satisfied AnyOf
		if len(valueFailures) < len(dataAttrsBySingleCanonicalName) {
			slog.DebugContext(ctx, "anyOf satisfied for canonical data", "attr", dvCanonicalName, "entityId", entityId)
			entityPassed = true
		}
		ruleResultsByEntity[entityId] = DataRuleResult{
			Passed:        entityPassed,
			ValueFailures: valueFailures,
		}

	}

	return ruleResultsByEntity
}

// Hierarchy rule compares the HIGHEST (that is, numerically lowest index) data attributeInstance (that is, value) for a given attributeInstance canonical name
// with the LOWEST (that is, numerically highest index) entity value for a given attributeInstance canonical name.
//
// If multiple data values (that is, AttributeInstances) for a given hierarchy AttributeDefinition are present for the same canonical name, the highest will be chosen and
// the others ignored.
//
// If multiple entity AttributeInstances (that is, values) for a hierarchy AttributeDefinition are present for the same canonical name, the lowest will be chosen,
// and the others ignored.
func (pdp *Pdp) hierarchyRule(ctx context.Context, dataAttrsBySingleCanonicalName []attributeInstance, entityAttributes map[string][]attributeInstance, order []*attrs.Value) map[string]DataRuleResult {
	ruleResultsByEntity := make(map[string]DataRuleResult)

	highestDataInstance := pdp.getHighestRankedInstanceFromDataAttributes(ctx, order, dataAttrsBySingleCanonicalName)
	if highestDataInstance == nil {
		slog.WarnContext(ctx, "No data attribute value found that matches attribute definition allowed values! All entity access will be rejected!")
	} else {
		slog.DebugContext(ctx, "Highest ranked hierarchy value on data attributes found", "value", highestDataInstance)
	}
	// All the data AttributeInstances in the arg have the same canonical name.

	// Go through every entity's attributeInstance set...
	for entityId, entityAttrs := range entityAttributes {
		// Default to DENY
		entityPassed := false
		valueFailures := []ValueFailure{}
		// Cluster entity AttributeInstances by canonical name...
		entityAttrCluster := ClusterByCanonicalNameAI(entityAttrs)

		if highestDataInstance != nil {
			dvCanonicalName := highestDataInstance.GetCanonicalName()
			// For every unique data attributeInstance (that is, value) in this set of data AttributeInstances sharing the same canonical name...
			slog.DebugContext(ctx, "Evaluating hierarchy decision", "name", dvCanonicalName, "value", highestDataInstance.Value)

			// Compare the (one or more) AttributeInstances (that is, values) for this canonical name to the (one) data attributeInstance, and see which is "higher".
			entityPassed = entityRankGreaterThanOrEqualToDataRank(order, highestDataInstance, entityAttrCluster[dvCanonicalName])

			// If the rank of the data attributeInstance (that is, value) is higher than the highest entity attributeInstance, then FAIL.
			if !entityPassed {
				denialMsg := fmt.Sprintf("Hierarchy - Entity: %s hierarchy values rank below data hierarchy value of %s", entityId, highestDataInstance.Value)
				slog.WarnContext(ctx, denialMsg)

				// Since there is only one data value we (ultimately) consider in a HierarchyRule, we will only ever
				// have one ValueFailure per entity at most
				valueFailures = append(valueFailures, ValueFailure{
					DataAttribute: highestDataInstance,
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

	return ruleResultsByEntity
}

// the purpose of a GroupBy property on an AttributeDefinition is to indicate which entities should be included in a rule evaluation, and which
// entities should not be included. This function will check every entity's AttributeInstances, and filter out the entities
// that lack the GroupBy attributeInstance, returning a new, reduced set of entities that all have the
// GroupBy attributeInstance.
func (pdp *Pdp) groupByFilterEntityAttributeInstances(ctx context.Context, entityAttributes map[string][]attributeInstance, groupBy *attrs.Attribute) map[string][]attributeInstance {
	slog.DebugContext(ctx, "Filtering out entities with groupby", "groupby", groupBy)

	filteredEntitySet := make(map[string][]attributeInstance)

	//Go through every entity's attributeInstance set...
	for entityId, entityAttrs := range entityAttributes {
		slog.DebugContext(ctx, "Filtering entity with groupby", "entityId", entityId, "groupBy", groupBy)
		//If this entity has the groupBy attributeInstance within its set of AttributeInstances
		if findInstanceValueInCluster(groupBy, entityAttrs) {
			//Then it will be included in the map of filtered entities.
			filteredEntitySet[entityId] = entityAttrs
		}
		//otherwise, it will be left out of consideration.
	}

	return filteredEntitySet
}

// It is possible that a data policy may have more than one Hierarchy value for the same data attribute canonical
// name, e.g.:
// - "https://authority.org/attr/MyHierarchyAttr/value/Value1"
// - "https://authority.org/attr/MyHierarchyAttr/value/Value2"
// Since by definition hierarchy comparisons have to be one-data-value-to-many-entity-values, this won't work.
// So, in a scenario where there are multiple data values to choose from, grab the "highest" ranked value
// present in the set of data AttributeInstances, and use that as the point of comparison, ignoring the "lower-ranked" data values.
// If we find a data value that does not exist in the attribute definition's list of valid values, we will skip it
// If NONE of the data values exist in the attribute definitions list of valid values, return a nil instance
func (pdp *Pdp) getHighestRankedInstanceFromDataAttributes(ctx context.Context, order []*attrs.Value, dataAttributeCluster []attributeInstance) *attributeInstance {
	// For hierarchy, convention is 0 == most privileged, 1 == less privileged, etc
	// So initialize with the LEAST privileged rank in the defined order
	highestDVIndex := len(order) - 1
	var highestRankedInstance *attributeInstance
	for _, dataAttr := range dataAttributeCluster {
		foundRank := getOrderOfValue(order, dataAttr.Value)
		if foundRank == -1 {
			msg := fmt.Sprintf("Data value %s is not in %s and is not a valid value for this attribute - ignoring this invalid value and continuing to look for a valid one...", dataAttr.Value, order)
			slog.WarnContext(ctx, msg)
			//If this isnt a valid data value, skip this iteration and look at the next one - maybe it is?
			//If none of them are valid, we should return a nil instance
			continue
		}
		slog.DebugContext(ctx, "Found data", "rank", foundRank, "value", dataAttr.Value, "maxRank", highestDVIndex)
		//If this rank is a "higher rank" (that is, a lower index) than the last one,
		//(or it is the same rank, to handle cases where the lowest is the only)
		//it becomes the new high watermark rank.
		if foundRank <= highestDVIndex {
			slog.DebugContext(ctx, "Updating rank!")
			highestDVIndex = foundRank
			gotAttr := dataAttr
			highestRankedInstance = &gotAttr
		}
	}
	return highestRankedInstance
}

// Given a single attributeInstance, and an arbitrary set of AttributeInstances,
// look through that set of instances for an instance whose value and canonical name matches the single instance
func findInstanceValueInCluster(instance *attrs.Attribute, cluster []attributeInstance) bool {
	for i := range cluster {
		if cluster[i].Value == instance.String() && cluster[i].GetCanonicalName() == GetCanonicalNameADV(instance) {
			return true
		}
	}
	return false
}

func findInstanceValueInClusterAI(a *attributeInstance, instances []attributeInstance) bool {
	for _, ai := range instances {
		if ai.Value == a.Value && ai.GetCanonicalName() == GetCanonicalName(*a) {
			return true
		}
	}
	return false
}

// Given set of ordered/ranked values, a data singular attributeInstance, and a set of entity AttributeInstances,
// determine if the entity AttributeInstances include a ranked value that equals or exceeds
// the rank of the data attributeInstance value.
// For hierarchy, convention is 0 == most privileged, 1 == less privileged, etc
func entityRankGreaterThanOrEqualToDataRank(order []*attrs.Value, dataAttribute *attributeInstance, entityAttributeCluster []attributeInstance) bool {
	//default to least-perm
	result := false
	dvIndex := getOrderOfValue(order, dataAttribute.Value)
	// Compute the rank of the entity AttributeInstance value against the rank of the data attributeInstance value
	// While, for hierarchy, we only ever have a singular data value we're checking
	// for a given data attributeInstance canonical name,
	// we may have *several* entity values for a given entity attributeInstance canonical name -
	// so if an entity has multiple values that can be compared for the hierarchy rule,
	// we check all of them and go with the value that has the least-significant index when deciding access
	for _, entityAttribute := range entityAttributeCluster {
		//Ideally, the caller will have already ensured all the entity attributeInstance we've been provided
		//have the same canonical name as the data attributeInstance we're comparing against,
		// but if they haven't for some reason only consider matching entity attributeInstance
		if dataAttribute.GetCanonicalName() == entityAttribute.GetCanonicalName() {
			evIndex := getOrderOfValue(order, entityAttribute.Value)
			//If the entity value isn't IN the order at all,
			//then set it's rank to one below the lowest rank in the current
			// order so it will always fail
			if evIndex == -1 {
				evIndex = len(order) + 1
			}
			//If, at any point, we find an entity attributeInstance value that is below the data attributeInstance value in rank,
			// (that is, numerically greater than the data rank)
			// (or if the data value itself is < 0, indicating it's not actually part of the defined order)
			//then we must immediately assume failure for this entity
			//and return.
			if evIndex > dvIndex || dvIndex == -1 {
				result = false
				return result
			} else if evIndex <= dvIndex {
				result = true
			}
		}
	}
	return result
}

// Given a set of ordered/ranked values and a singular attributeInstance,
// return the rank #/index of the singular attributeInstance
func getOrderOfValue(order []*attrs.Value, value string) int {
	//For hierarchy, convention is 0 == most privileged, 1 == less privileged, etc
	dvIndex := -1 // -1 == Not Found in the set - this should always be a failure.
	for index := range order {
		if order[index].Value == value {
			dvIndex = index
		}
	}

	//We either found the right index, or we return -1
	return dvIndex
}

// A Decision represents the overall access decision for a specific entity,
// - that is, the aggregate result of comparing entity AttributeInstances to every data attributeInstance.
type Decision struct {
	//The important bit - does this entity Have Access or not, for this set of data attribute values
	//This will be TRUE if, for *every* DataRuleResult in Results, EntityRuleResult.Passed == TRUE
	//Otherwise, it will be false
	Access bool `json:"access" example:"false"`
	//Results will contain at most 1 DataRuleResult for each data attributeInstance.
	//e.g. if we compare an entity's AttributeInstances against 5 data AttributeInstances,
	//then there will be 5 rule results, each indicating whether this entity "passed" validation
	//for that data attributeInstance or not.
	//
	//If an entity was skipped for a particular rule evaluation because of a GroupBy clause
	//on the AttributeDefinition for a given data attributeInstance, however, then there may be
	// FEWER DataRuleResults then there are DataRules
	//
	//e.g. there are 5 data AttributeInstances, and two entities each with a set of AttributeInstances,
	//the definition for one of those data AttributeInstances has a GroupBy clause that excludes the second entity
	//-> the first entity will have 5 DataRuleResults with Passed = true
	//-> the second entity will have 4 DataRuleResults Passed = true
	//-> both will have Access == true.
	Results []DataRuleResult `json:"entity_rule_result"`
}

// DataRuleResult represents the rule-level (or AttributeDefinition-level) decision for a specific entity -
// the result of comparing entity AttributeInstances to a single data AttributeDefinition/rule (with potentially many values)
//
// There may be multiple "instances" (that is, AttributeInstances) of a single AttributeDefinition on both data and entities,
// each with a different value.
type DataRuleResult struct {
	//Indicates whether, for this specific data AttributeDefinition, an entity satisfied
	//the rule conditions (allof/anyof/hierarchy)
	Passed bool `json:"passed" example:"false"`
	//Contains the AttributeDefinition of the data attribute rule this result represents
	RuleDefinition *attrs.Attribute `json:"rule_definition"`
	//May contain 0 or more ValueFailure types, depending on the RuleDefinition and which (if any)
	//data AttributeInstances/values the entity failed against
	//
	//For an AllOf rule, there should be no value failures if Passed=TRUE
	//For an AnyOf rule, there should be fewer entity value failures than
	//there are data attribute values in total if Passed=TRUE
	//For a Hierarchy rule, there should be either no value failures if Passed=TRUE,
	//or exactly one value failure if Passed=FALSE
	ValueFailures []ValueFailure `json:"value_failures"`
}

// ValueFailure indicates, for a given entity and data attributeInstance, which data values
// (aka specific data attributeInstance) the entity "failed" on.
//
// There may be multiple "instances" (that is, AttributeInstances) of a single AttributeDefinition on both data and entities,
// each with a different value.
//
// A ValueFailure does not necessarily mean the requirements for an AttributeDefinition were not or will not be met,
// it is purely informational - there will be one value failure, per entity, per rule, per value the entity lacks -
// it is up to the rule itself (anyof/allof/hierarchy) to translate this into an overall failure or not.
type ValueFailure struct {
	//The data attribute w/value that "caused" the denial
	DataAttribute *attributeInstance `json:"data_attribute"`
	//Optional denial message
	Message string `json:"message" example:"Criteria NOT satisfied for entity: {entity_id} - lacked attribute value: {attribute}"`
}

// Clusterable is an interface that either AttributeInstances or AttributeDefinitions can implement,
// to support easily "clustering" or grouping a slice of either by their shared CanonicalName or Authority.
type Clusterable interface {
	// GetCanonicalName Returns the canonical URI representation of this clusterable thing, in the format
	//  <scheme>://<hostname>/attr/<name>
	GetCanonicalName() string
	// GetAuthority Returns the authority of this clusterable thing, in the format
	//  <scheme>://<hostname>
	GetAuthority() string
	GroupBy() *attributeInstance
	Rule() attrs.AttributeRuleTypeEnum
	Order() []string
}

// ClusterByAuthority takes a slice of Clusterables, and returns them as a map,
// where the map is keyed by each unique Authorities (e.g. 'https://myauthority.org') found in the slice of Clusterables
func ClusterByAuthority[attrCluster Clusterable](attrs []attrCluster) map[string][]attrCluster {
	clusters := make(map[string][]attrCluster)

	for _, instance := range attrs {
		clusters[instance.GetAuthority()] = append(clusters[instance.GetAuthority()], instance)
	}

	return clusters
}

// ClusterByCanonicalName takes a slice of Clusterable (attributeInstance OR AttributeDefinition),
// and returns them as a map, where the map is keyed by each unique CanonicalName
// (e.g. Authority+Name, 'https://myauthority.org/attr/<name>') found in the slice of Clusterables
func ClusterByCanonicalName(attrs []Clusterable) map[string][]Clusterable {
	clusters := make(map[string][]Clusterable)

	for _, instance := range attrs {
		clusters[instance.GetCanonicalName()] = append(clusters[instance.GetCanonicalName()], instance)
	}

	return clusters
}

// ClusterByCanonicalNameAD takes a slice of Clusterable (attributeInstance OR AttributeDefinition),
// and returns them as a map, where the map is keyed by each unique CanonicalName
// (e.g. Authority+Name, 'https://myauthority.org/attr/<name>') found in the slice of Clusterables
func ClusterByCanonicalNameAD(ads []*attrs.Attribute) map[string][]*attrs.Attribute {
	clusters := make(map[string][]*attrs.Attribute)
	// FIXME
	for _, instance := range ads {
		a := GetCanonicalNameADV(instance)
		clusters[a] = append(clusters[a], instance)
	}

	return clusters
}

func ClusterByCanonicalNameAI(attributes []attributeInstance) map[string][]attributeInstance {
	clusters := make(map[string][]attributeInstance)
	for _, a := range attributes {
		clusters[a.GetCanonicalName()] = append(clusters[a.GetCanonicalName()], a)
	}
	return clusters
}

// GetCanonicalName Returns the canonical URI representation of this AttributeDefinition:
//
//	<scheme>://<hostname>/attr/<name>
func GetCanonicalName(ai attributeInstance) string {
	return fmt.Sprintf("%s/attr/%s",
		ai.Authority,
		ai.Name,
	)
}

func GetCanonicalNameADV(instance *attrs.Attribute) string {
	return fmt.Sprintf("%s/attr/%s",
		instance.Namespace.Name,
		instance.Name,
	)
}

// GetAuthority Returns the authority of this AttributeDefinition:
//
//	<scheme>://<hostname>
func GetAuthority(attrdef attributeInstance) string {
	return attrdef.Authority
}
