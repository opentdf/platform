package namespacedpolicy

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHuhInteractiveReviewerResolvesConflictingRegisteredResource(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			leftNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			leftNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{leftNamespace, rightNamespace},
			Pagination: emptyPageResponse(),
		},
	}
	prompter := &testInteractivePrompter{
		selectValue: namespaceSelectionValue(leftNamespace),
	}
	reviewer := NewHuhInteractiveReviewer(handler, prompter)
	resolved := &ResolvedTargets{
		Scopes: []Scope{ScopeRegisteredResources},
		RegisteredResources: []*ResolvedRegisteredResource{
			{
				Source: testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
						),
						testActionAttributeValue(
							"action-2",
							"encrypt",
							testAttributeValue("https://example.org/attr/classification/value/restricted", rightNamespace),
						),
					),
					&policy.RegisteredResourceValue{
						Value: "shared",
					},
				),
				Unresolved: &Unresolved{
					Reason:  UnresolvedReasonRegisteredResourceConflictingNamespaces,
					Message: "could not determine target namespace: registered resource spans multiple target namespaces",
				},
			},
		},
	}

	err := reviewer.Review(t.Context(), resolved, []*policy.Namespace{leftNamespace, rightNamespace})
	require.NoError(t, err)

	require.Equal(t, 1, prompter.selectCalls)
	require.NotNil(t, prompter.lastSelectPrompt)
	assert.Equal(t, "Registered resource (name: documents, id: resource-1) spans multiple target namespaces.", prompter.lastSelectPrompt.Title)
	require.Len(t, prompter.lastSelectPrompt.Options, 3)

	require.Len(t, resolved.RegisteredResources, 1)
	resource := resolved.RegisteredResources[0]
	require.NotNil(t, resource)
	assert.Nil(t, resource.Unresolved)
	assert.True(t, resource.NeedsCreate)
	assert.Nil(t, resource.AlreadyMigrated)
	require.True(t, sameNamespace(leftNamespace, resource.Namespace))
	require.Len(t, resource.Source.GetValues(), 2)
	require.Len(t, resource.Source.GetValues()[0].GetActionAttributeValues(), 1)
	assert.Equal(t, "action-1", resource.Source.GetValues()[0].GetActionAttributeValues()[0].GetAction().GetId())
	assert.Empty(t, resource.Source.GetValues()[1].GetActionAttributeValues())

	require.Len(t, resolved.Actions, 1)
	action := resolved.Actions[0]
	require.NotNil(t, action.Source)
	assert.Equal(t, "action-1", action.Source.GetId())
	require.Len(t, action.Results, 1)
	assert.True(t, sameNamespace(leftNamespace, action.Results[0].Namespace))
	assert.True(t, action.Results[0].NeedsCreate)
}

func TestHuhInteractiveReviewerSkipsActionResolutionWhenFilteredResourceAlreadyExists(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}

	filteredExisting := testRegisteredResource(
		"resource-existing",
		"documents",
		testRegisteredResourceValue(
			"prod",
			testActionAttributeValue(
				"action-existing",
				"decrypt",
				testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
			),
		),
		&policy.RegisteredResourceValue{Value: "shared"},
	)

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			leftNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			leftNamespace.GetId(): {
				Resources:  []*policy.RegisteredResource{filteredExisting},
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{leftNamespace, rightNamespace},
			Pagination: emptyPageResponse(),
		},
	}
	reviewer := NewHuhInteractiveReviewer(handler, &testInteractivePrompter{
		selectValue: namespaceSelectionValue(leftNamespace),
	})
	resolved := &ResolvedTargets{
		Scopes: []Scope{ScopeRegisteredResources},
		RegisteredResources: []*ResolvedRegisteredResource{
			{
				Source: testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
						),
						testActionAttributeValue(
							"action-2",
							"encrypt",
							testAttributeValue("https://example.org/attr/classification/value/restricted", rightNamespace),
						),
					),
					&policy.RegisteredResourceValue{Value: "shared"},
				),
				Unresolved: &Unresolved{
					Reason: UnresolvedReasonRegisteredResourceConflictingNamespaces,
				},
			},
		},
	}

	err := reviewer.Review(t.Context(), resolved, []*policy.Namespace{leftNamespace, rightNamespace})
	require.NoError(t, err)

	resource := resolved.RegisteredResources[0]
	require.NotNil(t, resource)
	assert.Nil(t, resource.Unresolved)
	assert.False(t, resource.NeedsCreate)
	require.NotNil(t, resource.AlreadyMigrated)
	assert.Equal(t, filteredExisting.GetId(), resource.AlreadyMigrated.GetId())
	assert.Empty(t, resolved.Actions)
}

func TestHuhInteractiveReviewerReusesPreviouslyResolvedActionForDuplicateBindings(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			leftNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			leftNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{leftNamespace, rightNamespace},
			Pagination: emptyPageResponse(),
		},
	}
	reviewer := NewHuhInteractiveReviewer(handler, &testInteractivePrompter{
		selectValue: namespaceSelectionValue(leftNamespace),
	})
	resolved := &ResolvedTargets{
		Scopes: []Scope{ScopeRegisteredResources},
		RegisteredResources: []*ResolvedRegisteredResource{
			{
				Source: testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
						),
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/internal", leftNamespace),
						),
						testActionAttributeValue(
							"action-2",
							"encrypt",
							testAttributeValue("https://example.org/attr/classification/value/restricted", rightNamespace),
						),
					),
				),
				Unresolved: &Unresolved{
					Reason: UnresolvedReasonRegisteredResourceConflictingNamespaces,
				},
			},
		},
	}

	err := reviewer.Review(t.Context(), resolved, []*policy.Namespace{leftNamespace, rightNamespace})
	require.NoError(t, err)

	require.Len(t, resolved.RegisteredResources, 1)
	reviewedResource := resolved.RegisteredResources[0]
	require.NotNil(t, reviewedResource)
	require.True(t, sameNamespace(leftNamespace, reviewedResource.Namespace))
	require.Len(t, reviewedResource.Source.GetValues(), 1)
	require.Len(t, reviewedResource.Source.GetValues()[0].GetActionAttributeValues(), 2)

	require.Len(t, resolved.Actions, 1)
	resolvedAction := resolved.Actions[0]
	require.NotNil(t, resolvedAction.Source)
	assert.Equal(t, "action-1", resolvedAction.Source.GetId())
	require.Len(t, resolvedAction.Results, 1)
	duplicateBindingActionResult := resolvedAction.Results[0]
	assert.True(t, sameNamespace(leftNamespace, duplicateBindingActionResult.Namespace))
	assert.True(t, duplicateBindingActionResult.NeedsCreate)
	assert.Nil(t, duplicateBindingActionResult.AlreadyMigrated)
}

func TestEnsureRegisteredResourceActionResolutionReusesExistingNamespaceResult(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	resolved := &ResolvedTargets{
		Actions: []*ResolvedAction{
			{
				Source: &policy.Action{
					Id:   "action-1",
					Name: "decrypt",
				},
				Results: []*ResolvedActionResult{
					{
						Namespace:   namespace,
						NeedsCreate: true,
					},
				},
			},
		},
	}

	err := ensureRegisteredResourceActionResolution(
		resolved,
		namespace,
		&policy.Action{Id: "action-1", Name: "decrypt"},
		&resolver{
			existing: &ExistingTargets{},
		},
	)
	require.NoError(t, err)

	require.Len(t, resolved.Actions, 1)
	require.Len(t, resolved.Actions[0].Results, 1)
}

func TestEnsureRegisteredResourceActionResolutionCreatesNewActionResolution(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	sourceAction := &policy.Action{
		Id:   "action-1",
		Name: "decrypt_custom",
	}
	resolved := &ResolvedTargets{}

	err := ensureRegisteredResourceActionResolution(
		resolved,
		namespace,
		sourceAction,
		&resolver{
			existing: newExistingTargets(),
		},
	)
	require.NoError(t, err)

	require.Len(t, resolved.Actions, 1)
	resolvedAction := resolved.Actions[0]
	require.NotNil(t, resolvedAction.Source)
	assert.NotSame(t, sourceAction, resolvedAction.Source)
	assert.Equal(t, sourceAction.GetId(), resolvedAction.Source.GetId())
	assert.Equal(t, sourceAction.GetName(), resolvedAction.Source.GetName())

	require.Len(t, resolvedAction.Results, 1)
	createdActionResult := resolvedAction.Results[0]
	assert.True(t, sameNamespace(namespace, createdActionResult.Namespace))
	assert.True(t, createdActionResult.NeedsCreate)
	assert.Nil(t, createdActionResult.AlreadyMigrated)
	assert.Nil(t, createdActionResult.ExistingStandard)
}

func TestEnsureRegisteredResourceActionResolutionAppendsMissingNamespaceResult(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}
	sourceAction := &policy.Action{
		Id:   "action-1",
		Name: "decrypt_custom",
	}
	existingMigratedAction := &policy.Action{
		Id:   "action-existing",
		Name: "decrypt_custom",
	}
	resolved := &ResolvedTargets{
		Actions: []*ResolvedAction{
			{
				Source: sourceAction,
				Results: []*ResolvedActionResult{
					{
						Namespace:   leftNamespace,
						NeedsCreate: true,
					},
				},
			},
		},
	}
	actionResolver := &resolver{
		existing: newExistingTargets(),
	}
	actionResolver.existing.CustomActions[rightNamespace.GetId()] = []*policy.Action{existingMigratedAction}

	err := ensureRegisteredResourceActionResolution(
		resolved,
		rightNamespace,
		sourceAction,
		actionResolver,
	)
	require.NoError(t, err)

	require.Len(t, resolved.Actions, 1)
	resolvedAction := resolved.Actions[0]
	require.Len(t, resolvedAction.Results, 2)

	existingNamespaceActionResult := resolvedAction.Results[0]
	assert.True(t, sameNamespace(leftNamespace, existingNamespaceActionResult.Namespace))
	assert.True(t, existingNamespaceActionResult.NeedsCreate)

	appendedActionResult := resolvedAction.Results[1]
	assert.True(t, sameNamespace(rightNamespace, appendedActionResult.Namespace))
	assert.False(t, appendedActionResult.NeedsCreate)
	assert.Same(t, existingMigratedAction, appendedActionResult.AlreadyMigrated)
	assert.Nil(t, appendedActionResult.ExistingStandard)
}

func TestEnsureRegisteredResourceActionResolutionResolvesStandardActionTarget(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	sourceAction := &policy.Action{
		Id:   "action-1",
		Name: "read",
	}
	existingStandardAction := &policy.Action{
		Id:        "action-standard",
		Name:      "read",
		Namespace: namespace,
	}
	actionResolver := &resolver{
		existing: newExistingTargets(),
	}
	actionResolver.existing.StandardActions[namespace.GetId()] = []*policy.Action{existingStandardAction}
	resolved := &ResolvedTargets{}

	err := ensureRegisteredResourceActionResolution(
		resolved,
		namespace,
		sourceAction,
		actionResolver,
	)
	require.NoError(t, err)

	require.Len(t, resolved.Actions, 1)
	require.Len(t, resolved.Actions[0].Results, 1)
	standardActionResult := resolved.Actions[0].Results[0]
	assert.True(t, sameNamespace(namespace, standardActionResult.Namespace))
	assert.Same(t, existingStandardAction, standardActionResult.ExistingStandard)
	assert.False(t, standardActionResult.NeedsCreate)
	assert.Nil(t, standardActionResult.AlreadyMigrated)
}

func TestEnsureRegisteredResourceActionResolutionWrapsResolverError(t *testing.T) {
	t.Parallel()

	namespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	sourceAction := &policy.Action{
		Id:   "action-1",
		Name: "read",
	}

	err := ensureRegisteredResourceActionResolution(
		&ResolvedTargets{},
		namespace,
		sourceAction,
		&resolver{
			existing: newExistingTargets(),
		},
	)
	require.ErrorContains(t, err, `action "action-1" in namespace "ns-1"`)
	require.ErrorContains(t, err, "matching standard action not found in target namespace")
}

func TestFilterRegisteredResourceToNamespaceRetainsUnboundValues(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}

	filtered, err := filterRegisteredResourceToNamespace(
		testRegisteredResource(
			"resource-1",
			"documents",
			testRegisteredResourceValue(
				"prod",
				testActionAttributeValue(
					"action-1",
					"decrypt",
					testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
				),
				testActionAttributeValue(
					"action-2",
					"encrypt",
					testAttributeValue("https://example.org/attr/classification/value/restricted", rightNamespace),
				),
			),
			&policy.RegisteredResourceValue{Value: "shared"},
		),
		leftNamespace,
	)
	require.NoError(t, err)

	require.Len(t, filtered.GetValues(), 2)
	require.Len(t, filtered.GetValues()[0].GetActionAttributeValues(), 1)
	assert.Equal(t, "action-1", filtered.GetValues()[0].GetActionAttributeValues()[0].GetAction().GetId())
	assert.Empty(t, filtered.GetValues()[1].GetActionAttributeValues())
}

func TestRegisteredResourceCandidateNamespacesDeduplicatesNamespaces(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}

	candidates, err := registeredResourceCandidateNamespaces(
		testRegisteredResource(
			"resource-1",
			"documents",
			testRegisteredResourceValue(
				"prod",
				testActionAttributeValue(
					"action-1",
					"decrypt",
					testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
				),
				testActionAttributeValue(
					"action-2",
					"decrypt-again",
					testAttributeValue("https://example.com/attr/classification/value/internal", leftNamespace),
				),
				testActionAttributeValue(
					"action-3",
					"encrypt",
					testAttributeValue("https://example.org/attr/classification/value/restricted", rightNamespace),
				),
			),
		),
		[]*policy.Namespace{leftNamespace, rightNamespace},
	)
	require.NoError(t, err)

	require.Len(t, candidates, 2)
	assert.True(t, sameNamespace(leftNamespace, candidates[0]))
	assert.True(t, sameNamespace(rightNamespace, candidates[1]))
}

func TestHuhInteractiveReviewerReturnsAbortWhenPromptAborts(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}
	reviewer := NewHuhInteractiveReviewer(
		&plannerTestHandler{},
		&testInteractivePrompter{selectErr: ErrInteractiveReviewAborted},
	)

	err := reviewer.Review(t.Context(), &ResolvedTargets{
		RegisteredResources: []*ResolvedRegisteredResource{
			{
				Source: testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
						),
						testActionAttributeValue(
							"action-2",
							"encrypt",
							testAttributeValue("https://example.org/attr/classification/value/restricted", rightNamespace),
						),
					),
				),
				Unresolved: &Unresolved{
					Reason: UnresolvedReasonRegisteredResourceConflictingNamespaces,
				},
			},
		},
	}, []*policy.Namespace{leftNamespace, rightNamespace})
	require.ErrorIs(t, err, ErrInteractiveReviewAborted)
}

func TestHuhInteractiveReviewerReturnsNilForNilResolvedTargets(t *testing.T) {
	t.Parallel()

	reviewer := NewHuhInteractiveReviewer(&plannerTestHandler{}, &testInteractivePrompter{})

	err := reviewer.Review(t.Context(), nil, nil)
	require.NoError(t, err)
}

func TestHuhInteractiveReviewerRequiresHandlerForConflictingReview(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}
	reviewer := NewHuhInteractiveReviewer(nil, &testInteractivePrompter{
		selectValue: namespaceSelectionValue(leftNamespace),
	})

	err := reviewer.Review(t.Context(), &ResolvedTargets{
		RegisteredResources: []*ResolvedRegisteredResource{
			{
				Source: testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
						),
						testActionAttributeValue(
							"action-2",
							"encrypt",
							testAttributeValue("https://example.org/attr/classification/value/restricted", rightNamespace),
						),
					),
				),
				Unresolved: &Unresolved{
					Reason: UnresolvedReasonRegisteredResourceConflictingNamespaces,
				},
			},
		},
	}, []*policy.Namespace{leftNamespace, rightNamespace})
	require.ErrorIs(t, err, ErrNilInteractiveReviewHandler)
}

func TestHuhInteractiveReviewerCachesNamespaceLookupsWithinReview(t *testing.T) {
	t.Parallel()

	leftNamespace := &policy.Namespace{
		Id:  "ns-1",
		Fqn: "https://example.com",
	}
	rightNamespace := &policy.Namespace{
		Id:  "ns-2",
		Fqn: "https://example.org",
	}

	handler := &plannerTestHandler{
		actionsByNamespace: map[string]*actions.ListActionsResponse{
			leftNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		registeredResourcesByNamespace: map[string]*registeredresources.ListRegisteredResourcesResponse{
			leftNamespace.GetId(): {
				Pagination: emptyPageResponse(),
			},
		},
		namespacesResponse: &namespaces.ListNamespacesResponse{
			Namespaces: []*policy.Namespace{leftNamespace, rightNamespace},
			Pagination: emptyPageResponse(),
		},
	}
	prompter := &testInteractivePrompter{
		selectValue: namespaceSelectionValue(leftNamespace),
	}
	reviewer := NewHuhInteractiveReviewer(handler, prompter)
	resolved := &ResolvedTargets{
		Scopes: []Scope{ScopeRegisteredResources},
		RegisteredResources: []*ResolvedRegisteredResource{
			{
				Source: testRegisteredResource(
					"resource-1",
					"documents",
					testRegisteredResourceValue(
						"prod",
						testActionAttributeValue(
							"action-1",
							"decrypt",
							testAttributeValue("https://example.com/attr/classification/value/secret", leftNamespace),
						),
						testActionAttributeValue(
							"action-2",
							"encrypt",
							testAttributeValue("https://example.org/attr/classification/value/restricted", rightNamespace),
						),
					),
				),
				Unresolved: &Unresolved{
					Reason: UnresolvedReasonRegisteredResourceConflictingNamespaces,
				},
			},
			{
				Source: testRegisteredResource(
					"resource-2",
					"records",
					testRegisteredResourceValue(
						"stage",
						testActionAttributeValue(
							"action-3",
							"review_records",
							testAttributeValue("https://example.com/attr/classification/value/internal", leftNamespace),
						),
						testActionAttributeValue(
							"action-4",
							"publish_records",
							testAttributeValue("https://example.org/attr/classification/value/restricted", rightNamespace),
						),
					),
				),
				Unresolved: &Unresolved{
					Reason: UnresolvedReasonRegisteredResourceConflictingNamespaces,
				},
			},
		},
	}

	err := reviewer.Review(t.Context(), resolved, []*policy.Namespace{leftNamespace, rightNamespace})
	require.NoError(t, err)
	assert.Equal(t, 2, prompter.selectCalls)
	assert.Equal(t, []string{leftNamespace.GetId()}, handler.actionCalls)
	assert.Equal(t, []string{leftNamespace.GetId()}, handler.registeredResourceCalls)
}

type testInteractivePrompter struct {
	confirmCalls      int
	lastConfirmPrompt *ConfirmPrompt
	confirmErr        error
	selectCalls       int
	lastSelectPrompt  *SelectPrompt
	selectValue       string
	selectErr         error
}

func (p *testInteractivePrompter) Confirm(_ context.Context, prompt ConfirmPrompt) error {
	p.confirmCalls++
	p.lastConfirmPrompt = &prompt
	return p.confirmErr
}

func (p *testInteractivePrompter) Select(_ context.Context, prompt SelectPrompt) (string, error) {
	p.selectCalls++
	p.lastSelectPrompt = &prompt
	return p.selectValue, p.selectErr
}
