package namespacedpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseScopesNormalizesAndOrders(t *testing.T) {
	t.Parallel()

	scopes, err := ParseScopes(" registered-resources, actions, subject-mappings, actions ")
	require.NoError(t, err)

	assert.Equal(t, []Scope{
		ScopeActions,
		ScopeSubjectMappings,
		ScopeRegisteredResources,
	}, scopes)
}

func TestParseScopesRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		err   error
	}{
		{
			name:  "empty csv",
			input: "   ",
			err:   ErrEmptyPlannerScope,
		},
		{
			name:  "empty entry",
			input: "actions,",
			err:   ErrEmptyPlannerScope,
		},
		{
			name:  "invalid scope",
			input: "actions,widgets",
			err:   ErrInvalidScope,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseScopes(tt.input)
			require.ErrorIs(t, err, tt.err)
		})
	}
}

func TestExpandScopesAddsRequiredDependencies(t *testing.T) {
	t.Parallel()

	requested, err := normalizeScopes([]Scope{ScopeSubjectMappings, ScopeObligationTriggers})
	require.NoError(t, err)

	assert.Equal(t, []Scope{
		ScopeActions,
		ScopeSubjectConditionSets,
		ScopeSubjectMappings,
		ScopeObligationTriggers,
	}, expandScopes(requested).ordered())
}
