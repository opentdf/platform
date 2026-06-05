package namespacedpolicy

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrEmptyPlannerScope = errors.New("at least one migration scope is required")
	ErrInvalidScope      = errors.New("invalid migration scope")
)

type Scope string

const (
	ScopeActions              Scope = "actions"
	ScopeSubjectConditionSets Scope = "subject-condition-sets"
	ScopeSubjectMappings      Scope = "subject-mappings"
	ScopeRegisteredResources  Scope = "registered-resources"
	ScopeObligationTriggers   Scope = "obligation-triggers"
)

var supportedScopes = []Scope{
	ScopeActions,
	ScopeSubjectConditionSets,
	ScopeSubjectMappings,
	ScopeRegisteredResources,
	ScopeObligationTriggers,
}

func ParseScopes(csv string) ([]Scope, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, ErrEmptyPlannerScope
	}

	scopes, err := normalizeScopes(splitScopes(csv))
	if err != nil {
		return nil, err
	}

	return scopes.ordered(), nil
}

func splitScopes(csv string) []Scope {
	rawScopes := strings.Split(csv, ",")
	scopes := make([]Scope, 0, len(rawScopes))
	for _, raw := range rawScopes {
		scopes = append(scopes, Scope(strings.TrimSpace(raw)))
	}

	return scopes
}

func normalizeScopes(scopes []Scope) (scopeSet, error) {
	if len(scopes) == 0 {
		return nil, ErrEmptyPlannerScope
	}

	requested := make(scopeSet, len(supportedScopes))
	for _, scope := range scopes {
		if scope == "" {
			return nil, ErrEmptyPlannerScope
		}
		if !isSupportedScope(scope) {
			return nil, fmt.Errorf("%w: %s", ErrInvalidScope, scope)
		}
		requested[scope] = struct{}{}
	}

	return requested, nil
}

func expandScopes(scopes scopeSet) scopeSet {
	if len(scopes) == 0 {
		return scopes
	}

	expanded := make(scopeSet, len(supportedScopes))
	for scope := range scopes {
		expanded[scope] = struct{}{}
	}

	if expanded.has(ScopeSubjectMappings) {
		expanded[ScopeActions] = struct{}{}
		expanded[ScopeSubjectConditionSets] = struct{}{}
	}
	if expanded.has(ScopeRegisteredResources) {
		expanded[ScopeActions] = struct{}{}
	}
	if expanded.has(ScopeObligationTriggers) {
		expanded[ScopeActions] = struct{}{}
	}

	return expanded
}

type scopeSet map[Scope]struct{}

func (s scopeSet) ordered() []Scope {
	ordered := make([]Scope, 0, len(s))
	for _, scope := range supportedScopes {
		if s.has(scope) {
			ordered = append(ordered, scope)
		}
	}

	return ordered
}

func (s scopeSet) has(scope Scope) bool {
	_, ok := s[scope]
	return ok
}

func (s scopeSet) requiresActions() bool {
	return s.has(ScopeActions) || s.has(ScopeSubjectMappings) || s.has(ScopeRegisteredResources) || s.has(ScopeObligationTriggers)
}

func (s scopeSet) requiresSubjectConditionSets() bool {
	return s.has(ScopeSubjectConditionSets) || s.has(ScopeSubjectMappings)
}

func (s scopeSet) requiresSubjectMappings() bool {
	return s.has(ScopeActions) || s.has(ScopeSubjectConditionSets) || s.has(ScopeSubjectMappings)
}

func (s scopeSet) requiresRegisteredResources() bool {
	return s.has(ScopeActions) || s.has(ScopeRegisteredResources)
}

func (s scopeSet) requiresObligationTriggers() bool {
	return s.has(ScopeActions) || s.has(ScopeObligationTriggers)
}

func isSupportedScope(scope Scope) bool {
	for _, supported := range supportedScopes {
		if scope == supported {
			return true
		}
	}
	return false
}
