package namespacedpolicy

import (
	"github.com/opentdf/platform/protocol/go/policy"
)

// reduceDependencies filters dependency-backed candidate slices in place on the
// provided Retrieved. Callers should assume retrieved.Candidates is modified.
func reduceDependencies(retrieved *Retrieved, scopes scopeSet) {
	if retrieved == nil {
		return
	}

	retrieved.Candidates.Actions = reduceActions(scopes, retrieved.Candidates)
	retrieved.Candidates.SubjectConditionSets = reduceSubjectConditionSets(scopes, retrieved.Candidates)
}

func reduceActions(scopes scopeSet, candidates Candidates) []*policy.Action {
	if !scopes.requiresActions() || scopes.has(ScopeActions) {
		return candidates.Actions
	}

	required := make(map[string]struct{})

	if scopes.has(ScopeSubjectMappings) {
		for _, mapping := range candidates.SubjectMappings {
			for _, action := range mapping.GetActions() {
				if id := action.GetId(); id != "" {
					required[id] = struct{}{}
				}
			}
		}
	}

	if scopes.has(ScopeRegisteredResources) {
		for _, resource := range candidates.RegisteredResources {
			if _, ok := registeredResourceNamespaceRef(resource); !ok {
				continue
			}
			for _, value := range resource.GetValues() {
				for _, aav := range value.GetActionAttributeValues() {
					if id := aav.GetAction().GetId(); id != "" {
						required[id] = struct{}{}
					}
				}
			}
		}
	}

	if scopes.has(ScopeObligationTriggers) {
		for _, trigger := range candidates.ObligationTriggers {
			if id := trigger.GetAction().GetId(); id != "" {
				required[id] = struct{}{}
			}
		}
	}

	return filterActions(candidates.Actions, required)
}

// Determine if a registered resource can be derived to one namespace based on
// whether or not the attribute values are all under one namespace.
func registeredResourceNamespaceRef(resource *policy.RegisteredResource) (*policy.Namespace, bool) {
	if resource == nil {
		return nil, false
	}

	var observed *policy.Namespace
	for _, value := range resource.GetValues() {
		for _, aav := range value.GetActionAttributeValues() {
			namespace := namespaceFromAttributeValue(aav.GetAttributeValue())
			if namespaceRefKey(namespace) == "" {
				return nil, false
			}
			if observed == nil {
				observed = namespace
				continue
			}
			if !sameNamespace(observed, namespace) {
				return nil, false
			}
		}
	}

	return observed, observed != nil
}

func reduceSubjectConditionSets(scopes scopeSet, candidates Candidates) []*policy.SubjectConditionSet {
	if !scopes.requiresSubjectConditionSets() || scopes.has(ScopeSubjectConditionSets) {
		return candidates.SubjectConditionSets
	}

	required := make(map[string]struct{})
	for _, mapping := range candidates.SubjectMappings {
		if id := mapping.GetSubjectConditionSet().GetId(); id != "" {
			required[id] = struct{}{}
		}
	}

	return filterSubjectConditionSets(candidates.SubjectConditionSets, required)
}

func filterActions(actions []*policy.Action, required map[string]struct{}) []*policy.Action {
	if len(required) == 0 {
		return nil
	}

	filtered := make([]*policy.Action, 0, len(actions))
	for _, action := range actions {
		if action == nil {
			continue
		}
		if _, ok := required[action.GetId()]; ok {
			filtered = append(filtered, action)
		}
	}

	return filtered
}

func filterSubjectConditionSets(sets []*policy.SubjectConditionSet, required map[string]struct{}) []*policy.SubjectConditionSet {
	if len(required) == 0 {
		return nil
	}

	filtered := make([]*policy.SubjectConditionSet, 0, len(sets))
	for _, scs := range sets {
		if scs == nil {
			continue
		}
		if _, ok := required[scs.GetId()]; ok {
			filtered = append(filtered, scs)
		}
	}

	return filtered
}
