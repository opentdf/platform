package namespacedpolicy

import (
	"context"
	"errors"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

const defaultPlannerPageSize int32 = 100

var ErrNilPlannerHandler = errors.New("planner handler is required")

type PolicyClient interface {
	ListActions(ctx context.Context, limit, offset int32, namespace string) (*actions.ListActionsResponse, error)
	ListSubjectConditionSets(ctx context.Context, limit, offset int32, namespace string) (*subjectmapping.ListSubjectConditionSetsResponse, error)
	ListSubjectMappings(ctx context.Context, limit, offset int32, namespace string) (*subjectmapping.ListSubjectMappingsResponse, error)
	ListRegisteredResources(ctx context.Context, limit, offset int32, namespace string) (*registeredresources.ListRegisteredResourcesResponse, error)
	ListObligationTriggers(ctx context.Context, namespace string, limit, offset int32) (*obligations.ListObligationTriggersResponse, error)
	ListNamespaces(ctx context.Context, state common.ActiveStateEnum, limit, offset int32) (*namespaces.ListNamespacesResponse, error)
}

type Planner struct {
	retriever       *Retriever
	requestedScopes scopeSet
	expandedScopes  scopeSet
	reviewer        InteractiveReviewer
}

type Option func(*Planner)

type Retrieved struct {
	Scopes     []Scope
	Candidates Candidates
}

type Candidates struct {
	Actions              []*policy.Action
	SubjectConditionSets []*policy.SubjectConditionSet
	SubjectMappings      []*policy.SubjectMapping
	RegisteredResources  []*policy.RegisteredResource
	ObligationTriggers   []*policy.ObligationTrigger
}

type ExistingTargets struct {
	CustomActions        map[string][]*policy.Action
	StandardActions      map[string][]*policy.Action
	SubjectConditionSets map[string][]*policy.SubjectConditionSet
	SubjectMappings      map[string][]*policy.SubjectMapping
	RegisteredResources  map[string][]*policy.RegisteredResource
	ObligationTriggers   map[string][]*policy.ObligationTrigger
}

func NewPlanner(handler PolicyClient, scopeCSV string, opts ...Option) (*Planner, error) {
	if handler == nil {
		return nil, ErrNilPlannerHandler
	}

	scopes, err := ParseScopes(scopeCSV)
	if err != nil {
		return nil, err
	}

	normalizedScopes, err := normalizeScopes(scopes)
	if err != nil {
		return nil, err
	}

	planner := &Planner{
		retriever:       newRetriever(handler, defaultPlannerPageSize),
		requestedScopes: normalizedScopes,
		expandedScopes:  expandScopes(normalizedScopes),
	}
	for _, opt := range opts {
		opt(planner)
	}
	if planner.retriever.pageSize <= 0 {
		planner.retriever.pageSize = defaultPlannerPageSize
	}

	return planner, nil
}

func WithPageSize(pageSize int32) Option {
	return func(planner *Planner) {
		planner.retriever.pageSize = pageSize
	}
}

func WithInteractiveReviewer(reviewer InteractiveReviewer) Option {
	return func(planner *Planner) {
		planner.reviewer = reviewer
	}
}

func (p *Planner) Plan(ctx context.Context) (*Plan, error) {
	retrieved, err := p.retrieve(ctx)
	if err != nil {
		return nil, err
	}

	namespaces, err := p.retriever.listNamespaces(ctx)
	if err != nil {
		return nil, err
	}

	derived, err := deriveTargets(retrieved, namespaces)
	if err != nil {
		return nil, err
	}

	existingTargets, err := p.retriever.listExistingTargets(ctx, p.requestedScopes, derived)
	if err != nil {
		return nil, err
	}

	resolved, err := resolveExisting(derived, existingTargets)
	if err != nil {
		return nil, err
	}

	if p.reviewer != nil {
		if err := p.reviewer.Review(ctx, resolved, namespaces); err != nil {
			return nil, err
		}
	}

	return finalizePlan(resolved, namespaces)
}

// Retrieve the candidate policy constructs for items within scope or dependent
// on that scope.
func (p *Planner) retrieve(ctx context.Context) (*Retrieved, error) {
	if p == nil || p.retriever == nil || p.retriever.handler == nil {
		return nil, ErrNilPlannerHandler
	}
	if len(p.requestedScopes) == 0 {
		return nil, ErrEmptyPlannerScope
	}

	retrieved, err := p.retriever.retrieve(ctx, p.requestedScopes)
	if err != nil {
		return nil, err
	}

	reduceDependencies(retrieved, p.requestedScopes)
	// Keep retrieval/reduction keyed off requestedScopes so "actions" does not
	// implicitly pull in reverse-lookup scopes like registered resources or
	// obligation triggers. The retrieved artifact still records expandedScopes to
	// reflect the full dependency closure used by later planner stages.
	retrieved.Scopes = p.expandedScopes.ordered()

	return retrieved, nil
}

func newRetrieved(scopes []Scope) *Retrieved {
	return &Retrieved{
		Scopes:     append([]Scope(nil), scopes...),
		Candidates: newCandidates(),
	}
}

func newCandidates() Candidates {
	return Candidates{}
}

func newExistingTargets() *ExistingTargets {
	return &ExistingTargets{
		CustomActions:        make(map[string][]*policy.Action),
		StandardActions:      make(map[string][]*policy.Action),
		SubjectConditionSets: make(map[string][]*policy.SubjectConditionSet),
		SubjectMappings:      make(map[string][]*policy.SubjectMapping),
		RegisteredResources:  make(map[string][]*policy.RegisteredResource),
		ObligationTriggers:   make(map[string][]*policy.ObligationTrigger),
	}
}
