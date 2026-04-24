package namespacedpolicy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
)

type registeredResourceValueCanonical struct {
	Value                 string   `json:"value"`
	ActionAttributeValues []string `json:"action_attribute_values"`
}
type canonicalSubjectSetEntry struct {
	ConditionGroups []canonicalConditionGroupEntry `json:"condition_groups"`
}

type canonicalConditionGroupEntry struct {
	Conditions      []canonicalConditionEntry `json:"conditions"`
	BooleanOperator int32                     `json:"boolean_operator"`
}

type canonicalConditionEntry struct {
	Selector string   `json:"selector"`
	Operator int32    `json:"operator"`
	Values   []string `json:"values"`
}

type canonicalRequestContextEntry struct {
	ClientID string `json:"client_id"`
}

func actionCanonicalEqual(source, target *policy.Action) bool {
	s := canonicalActionName(source)
	return s != "" && s == canonicalActionName(target)
}

func subjectConditionSetCanonicalEqual(source, target *policy.SubjectConditionSet) bool {
	s := canonicalSubjectConditionSet(source)
	return s != "" && s == canonicalSubjectConditionSet(target)
}

func subjectMappingCanonicalEqual(source, target *policy.SubjectMapping) bool {
	s := canonicalSubjectMapping(source)
	return s != "" && s == canonicalSubjectMapping(target)
}

func obligationTriggerCanonicalEqual(source, target *policy.ObligationTrigger) bool {
	s := canonicalObligationTrigger(source)
	return s != "" && s == canonicalObligationTrigger(target)
}

func registeredResourceCanonicalEqual(source, target *policy.RegisteredResource) bool {
	s := canonicalRegisteredResource(source)
	return s != "" && s == canonicalRegisteredResource(target)
}

func canonicalActionName(action *policy.Action) string {
	if action == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(action.GetName()))
}

// canonicalSubjectConditionSet produces a deterministic string key from the
// semantically meaningful fields of a SubjectConditionSet. We extract into
// plain Go types and sort at every level rather than relying on protobuf
// serialization (protojson.Marshal, proto.Marshal with Deterministic: true),
// because neither guarantees stable output across library versions or builds.
// Canonical comparison is only performed within a single planning run, but
// explicit field extraction makes the stability guarantee self-evident.
func canonicalSubjectConditionSet(scs *policy.SubjectConditionSet) string {
	if scs == nil || len(scs.GetSubjectSets()) == 0 {
		return ""
	}

	sets := make([]canonicalSubjectSetEntry, 0, len(scs.GetSubjectSets()))
	for _, ss := range scs.GetSubjectSets() {
		if ss == nil {
			continue
		}
		sets = append(sets, normalizeSubjectSet(ss))
	}
	if len(sets) == 0 {
		return ""
	}
	sortByJSON(sets)

	encoded, err := json.Marshal(sets)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func canonicalSubjectMapping(mapping *policy.SubjectMapping) string {
	if mapping == nil {
		return ""
	}

	payload := struct {
		AttributeValueFQN string   `json:"attribute_value_fqn"`
		ActionNames       []string `json:"action_names"`
		SubjectSetKey     string   `json:"subject_condition_set"`
	}{
		AttributeValueFQN: strings.TrimSpace(mapping.GetAttributeValue().GetFqn()),
		ActionNames:       canonicalActionNames(mapping.GetActions()),
		SubjectSetKey:     canonicalSubjectConditionSet(mapping.GetSubjectConditionSet()),
	}
	if payload.AttributeValueFQN == "" || payload.SubjectSetKey == "" {
		return ""
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func canonicalObligationTrigger(trigger *policy.ObligationTrigger) string {
	if trigger == nil {
		return ""
	}

	payload := struct {
		AttributeValueFQN  string `json:"attribute_value_fqn"`
		ActionName         string `json:"action_name"`
		ObligationValueFQN string `json:"obligation_value_fqn"`
		Context            string `json:"context"`
	}{
		AttributeValueFQN:  strings.TrimSpace(trigger.GetAttributeValue().GetFqn()),
		ActionName:         canonicalActionName(trigger.GetAction()),
		ObligationValueFQN: strings.TrimSpace(trigger.GetObligationValue().GetFqn()),
		Context:            canonicalObligationTriggerContext(trigger.GetContext()),
	}
	if payload.AttributeValueFQN == "" || payload.ActionName == "" || payload.ObligationValueFQN == "" {
		return ""
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(encoded)
}

// canonicalObligationTriggerContext produces a deterministic string key from
// RequestContext fields. See canonicalSubjectConditionSet for rationale on
// avoiding protobuf serialization.
func canonicalObligationTriggerContext(contexts []*policy.RequestContext) string {
	if len(contexts) == 0 {
		return ""
	}

	entries := make([]canonicalRequestContextEntry, 0, len(contexts))
	for _, rc := range contexts {
		if rc == nil || rc.GetPep() == nil {
			continue
		}
		entries = append(entries, canonicalRequestContextEntry{
			ClientID: strings.TrimSpace(rc.GetPep().GetClientId()),
		})
	}

	if len(entries) == 0 {
		return ""
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].ClientID < entries[j].ClientID
	})

	encoded, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func normalizeSubjectSet(ss *policy.SubjectSet) canonicalSubjectSetEntry {
	groups := make([]canonicalConditionGroupEntry, 0, len(ss.GetConditionGroups()))
	for _, cg := range ss.GetConditionGroups() {
		if cg == nil {
			continue
		}
		groups = append(groups, normalizeConditionGroup(cg))
	}
	sortByJSON(groups)
	return canonicalSubjectSetEntry{ConditionGroups: groups}
}

func normalizeConditionGroup(cg *policy.ConditionGroup) canonicalConditionGroupEntry {
	conditions := make([]canonicalConditionEntry, 0, len(cg.GetConditions()))
	for _, c := range cg.GetConditions() {
		if c == nil {
			continue
		}
		values := append([]string(nil), c.GetSubjectExternalValues()...)
		sort.Strings(values)
		conditions = append(conditions, canonicalConditionEntry{
			Selector: strings.TrimSpace(c.GetSubjectExternalSelectorValue()),
			Operator: int32(c.GetOperator()),
			Values:   values,
		})
	}
	sort.SliceStable(conditions, func(i, j int) bool {
		if conditions[i].Selector != conditions[j].Selector {
			return conditions[i].Selector < conditions[j].Selector
		}
		if conditions[i].Operator != conditions[j].Operator {
			return conditions[i].Operator < conditions[j].Operator
		}
		return strings.Join(conditions[i].Values, ",") < strings.Join(conditions[j].Values, ",")
	})
	return canonicalConditionGroupEntry{
		Conditions:      conditions,
		BooleanOperator: int32(cg.GetBooleanOperator()),
	}
}

func sortByJSON[T any](items []T) {
	type keyedItem struct {
		value T
		key   string
	}

	keyed := make([]keyedItem, 0, len(items))
	for _, item := range items {
		k, _ := json.Marshal(item)
		keyed = append(keyed, keyedItem{
			value: item,
			key:   string(k),
		})
	}

	sort.SliceStable(keyed, func(i, j int) bool {
		return keyed[i].key < keyed[j].key
	})
	for i := range keyed {
		items[i] = keyed[i].value
	}
}

// TODO: Revisit this. Probably can be simpler.
func canonicalRegisteredResource(resource *policy.RegisteredResource) string {
	if resource == nil {
		return ""
	}

	values := make([]registeredResourceValueCanonical, 0, len(resource.GetValues()))
	for _, value := range resource.GetValues() {
		if value == nil {
			continue
		}

		aavs := make([]string, 0, len(value.GetActionAttributeValues()))
		for _, aav := range value.GetActionAttributeValues() {
			if aav == nil {
				continue
			}
			key := fmt.Sprintf("%s|%s", canonicalActionName(aav.GetAction()), strings.TrimSpace(aav.GetAttributeValue().GetFqn()))
			if key == "|" {
				continue
			}
			aavs = append(aavs, key)
		}
		sort.Strings(aavs)

		values = append(values, registeredResourceValueCanonical{
			Value:                 strings.ToLower(strings.TrimSpace(value.GetValue())),
			ActionAttributeValues: aavs,
		})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Value == values[j].Value {
			return strings.Join(values[i].ActionAttributeValues, ",") < strings.Join(values[j].ActionAttributeValues, ",")
		}
		return values[i].Value < values[j].Value
	})

	payload := struct {
		Name   string                             `json:"name"`
		Values []registeredResourceValueCanonical `json:"values"`
	}{
		Name:   strings.ToLower(strings.TrimSpace(resource.GetName())),
		Values: values,
	}
	if payload.Name == "" {
		return ""
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func canonicalActionNames(actions []*policy.Action) []string {
	names := make([]string, 0, len(actions))
	for _, action := range actions {
		if name := canonicalActionName(action); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
