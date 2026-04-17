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
	assert.Equal(t, "Registered resource https://reg_res/documents spans multiple target namespaces.", prompter.lastSelectPrompt.Title)
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
	require.Len(t, action.References, 1)
	assert.Equal(t, ActionReferenceKindRegisteredResource, action.References[0].Kind)
	assert.Equal(t, "resource-1", action.References[0].ID)
	assert.True(t, sameNamespace(leftNamespace, action.References[0].Namespace))
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
