package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/proto"
)

const (
	interactiveReviewAbortOption              = "__abort_interactive_review__"
	minimumRegisteredResourceReviewNamespaces = 2
)

var ErrNilInteractiveReviewHandler = errors.New("interactive review handler is required")

// InteractiveReviewer owns planner-time interactive review. It mutates
// resolved planner state before finalization when interactive review is enabled.
type InteractiveReviewer interface {
	Review(context.Context, *ResolvedTargets, []*policy.Namespace) error
}

// HuhInteractiveReviewer is the planner-owned interactive review entrypoint for
// `migrate namespaced-policy --interactive`.
//
// The only actionable planner-time review currently supported is resolving
// registered resources whose action-attribute-values span multiple namespaces.
type HuhInteractiveReviewer struct {
	handler  PolicyClient
	Prompter InteractivePrompter
	pageSize int32
}

func NewHuhInteractiveReviewer(handler PolicyClient, prompter InteractivePrompter) *HuhInteractiveReviewer {
	return &HuhInteractiveReviewer{
		handler:  handler,
		Prompter: prompter,
		pageSize: defaultPlannerPageSize,
	}
}

func (r *HuhInteractiveReviewer) Review(ctx context.Context, resolved *ResolvedTargets, namespaces []*policy.Namespace) error {
	if resolved == nil {
		return nil
	}

	for _, resource := range resolved.RegisteredResources {
		if !isConflictingRegisteredResource(resource) {
			continue
		}
		if err := r.reviewRegisteredResource(ctx, resolved, resource, namespaces); err != nil {
			return err
		}
	}

	return nil
}

func (r *HuhInteractiveReviewer) reviewRegisteredResource(ctx context.Context, resolved *ResolvedTargets, resource *ResolvedRegisteredResource, namespaces []*policy.Namespace) error {
	if resource == nil || resource.Source == nil {
		return nil
	}

	retriever, err := r.retriever()
	if err != nil {
		return err
	}

	candidates, err := registeredResourceCandidateNamespaces(resource.Source, namespaces)
	if err != nil {
		return fmt.Errorf("registered resource %q: %w", resource.Source.GetId(), err)
	}

	selected, err := r.prompter().Select(ctx, registeredResourceConflictPrompt(resource.Source, candidates))
	if err != nil {
		return err
	}
	if selected == interactiveReviewAbortOption {
		return ErrInteractiveReviewAborted
	}

	chosen := selectedNamespace(candidates, selected)
	if chosen == nil {
		return fmt.Errorf("registered resource %q: invalid namespace choice %q", resource.Source.GetId(), selected)
	}

	filtered, err := filterRegisteredResourceToNamespace(resource.Source, chosen)
	if err != nil {
		return fmt.Errorf("registered resource %q: %w", resource.Source.GetId(), err)
	}

	customActions, standardActions, err := retriever.listActionsForNamespaces(ctx, []*policy.Namespace{chosen})
	if err != nil {
		return fmt.Errorf("registered resource %q: %w", resource.Source.GetId(), err)
	}

	registeredResources, err := retriever.listRegisteredResourcesForNamespaces(ctx, []*policy.Namespace{chosen})
	if err != nil {
		return fmt.Errorf("registered resource %q: %w", resource.Source.GetId(), err)
	}

	actionResolver := &resolver{
		existing: &ExistingTargets{
			CustomActions:   customActions,
			StandardActions: standardActions,
		},
	}

	for _, value := range filtered.GetValues() {
		for _, aav := range value.GetActionAttributeValues() {
			if err := ensureRegisteredResourceActionResolution(resolved, resource.Source.GetId(), chosen, aav.GetAction(), actionResolver); err != nil {
				return fmt.Errorf("registered resource %q: %w", resource.Source.GetId(), err)
			}
		}
	}

	resource.Source = filtered
	resource.Namespace = chosen
	resource.Unresolved = nil
	resource.AlreadyMigrated = nil
	resource.NeedsCreate = false

	existing, found, err := resolveExistingRegisteredResource(filtered, registeredResources[chosen.GetId()])
	switch {
	case found:
		resource.AlreadyMigrated = existing
	case err != nil:
		return fmt.Errorf("registered resource %q in namespace %q: %w", filtered.GetId(), chosen.GetId(), err)
	default:
		resource.NeedsCreate = true
	}

	return nil
}

func (r *HuhInteractiveReviewer) prompter() InteractivePrompter {
	if r != nil && r.Prompter != nil {
		return r.Prompter
	}

	return &HuhPrompter{}
}

func (r *HuhInteractiveReviewer) retriever() (*Retriever, error) {
	if r == nil || r.handler == nil {
		return nil, ErrNilInteractiveReviewHandler
	}

	pageSize := r.pageSize
	if pageSize <= 0 {
		pageSize = defaultPlannerPageSize
	}

	return newRetriever(r.handler, pageSize), nil
}

func isConflictingRegisteredResource(resource *ResolvedRegisteredResource) bool {
	if resource == nil || resource.Unresolved == nil {
		return false
	}

	return resource.Unresolved.Reason == UnresolvedReasonRegisteredResourceConflictingNamespaces
}

func registeredResourceCandidateNamespaces(resource *policy.RegisteredResource, namespaces []*policy.Namespace) ([]*policy.Namespace, error) {
	if resource == nil {
		return nil, fmt.Errorf("%w: registered resource is empty", ErrUndeterminedTargetMapping)
	}

	deriver := newTargetDeriver(namespaces)
	ordered := newNamespaceAccumulator()

	for _, value := range resource.GetValues() {
		for _, aav := range value.GetActionAttributeValues() {
			namespace, err := deriver.resolveNamespace(namespaceFromAttributeValue(aav.GetAttributeValue()))
			if err != nil {
				return nil, err
			}
			ordered.add(namespace)
		}
	}

	candidates := ordered.slice()
	if len(candidates) < minimumRegisteredResourceReviewNamespaces {
		return nil, fmt.Errorf("%w: registered resource review requires multiple candidate namespaces", ErrUndeterminedTargetMapping)
	}

	return candidates, nil
}

func registeredResourceConflictPrompt(resource *policy.RegisteredResource, namespaces []*policy.Namespace) SelectPrompt {
	description := []string{
		fmt.Sprintf("Registered resource: %s (%s)", strings.TrimSpace(resource.GetName()), resource.GetId()),
		"Choose one target namespace for this registered resource.",
		"Bindings for other namespaces will be removed from the reviewed RR.",
	}
	description = append(description, registeredResourceConflictLines(resource)...)

	options := make([]PromptOption, 0, len(namespaces)+1)
	for _, namespace := range namespaces {
		options = append(options, PromptOption{
			Label:       namespaceLabel(namespace),
			Value:       namespaceSelectionValue(namespace),
			Description: "migrate to this namespace",
		})
	}
	options = append(options, PromptOption{
		Label:       "Abort run",
		Value:       interactiveReviewAbortOption,
		Description: "stop planning without changing this RR",
	})

	return SelectPrompt{
		Title:       fmt.Sprintf("Registered resource %s spans multiple target namespaces.", registeredResourceFQN(resource)),
		Description: description,
		Options:     options,
	}
}

func registeredResourceFQN(resource *policy.RegisteredResource) string {
	if resource == nil {
		return unknownLabel
	}

	name := strings.TrimSpace(resource.GetName())
	if name == "" {
		if id := strings.TrimSpace(resource.GetId()); id != "" {
			return id
		}
		return unknownLabel
	}

	if namespace := resource.GetNamespace(); namespace != nil {
		if fqn := strings.TrimSpace(namespace.GetFqn()); fqn != "" {
			return strings.TrimRight(fqn, "/") + "/reg_res/" + name
		}
		if namespaceName := strings.TrimSpace(namespace.GetName()); namespaceName != "" {
			return "https://" + namespaceName + "/reg_res/" + name
		}
	}

	return "https://reg_res/" + name
}

func registeredResourceConflictLines(resource *policy.RegisteredResource) []string {
	lines := make([]string, 0)
	for _, value := range resource.GetValues() {
		if value == nil {
			continue
		}
		if len(value.GetActionAttributeValues()) == 0 {
			lines = append(lines, fmt.Sprintf("Value %q has no action bindings.", value.GetValue()))
			continue
		}
		for _, aav := range value.GetActionAttributeValues() {
			if aav == nil {
				continue
			}
			lines = append(lines, fmt.Sprintf(
				"Value %q: action %q -> %s",
				value.GetValue(),
				actionLabel(aav.GetAction()),
				namespaceLabel(namespaceFromAttributeValue(aav.GetAttributeValue())),
			))
		}
	}

	return lines
}

func actionLabel(action *policy.Action) string {
	if action == nil {
		return unknownLabel
	}
	if name := strings.TrimSpace(action.GetName()); name != "" {
		return name
	}
	if id := strings.TrimSpace(action.GetId()); id != "" {
		return id
	}
	return unknownLabel
}

func namespaceSelectionValue(namespace *policy.Namespace) string {
	return namespaceRefKey(namespace)
}

func selectedNamespace(candidates []*policy.Namespace, value string) *policy.Namespace {
	for _, namespace := range candidates {
		if namespaceSelectionValue(namespace) == value {
			return namespace
		}
	}

	return nil
}

func filterRegisteredResourceToNamespace(resource *policy.RegisteredResource, namespace *policy.Namespace) (*policy.RegisteredResource, error) {
	if resource == nil {
		return nil, fmt.Errorf("%w: registered resource is empty", ErrUndeterminedTargetMapping)
	}
	if namespace == nil {
		return nil, fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping)
	}

	cloned, ok := proto.Clone(resource).(*policy.RegisteredResource)
	if !ok {
		return nil, errors.New("could not clone registered resource")
	}

	clonedValues := cloned.GetValues()
	cloned.Values = make([]*policy.RegisteredResourceValue, 0, len(clonedValues))
	for _, value := range clonedValues {
		if value == nil {
			continue
		}

		if len(value.GetActionAttributeValues()) == 0 {
			cloned.Values = append(cloned.Values, value)
			continue
		}

		filteredAAVs := make([]*policy.RegisteredResourceValue_ActionAttributeValue, 0, len(value.GetActionAttributeValues()))
		for _, aav := range value.GetActionAttributeValues() {
			if aav == nil || !sameNamespace(namespaceFromAttributeValue(aav.GetAttributeValue()), namespace) {
				continue
			}
			filteredAAVs = append(filteredAAVs, aav)
		}

		if len(filteredAAVs) == 0 {
			continue
		}

		value.ActionAttributeValues = filteredAAVs
		cloned.Values = append(cloned.Values, value)
	}

	return cloned, nil
}

// ensureRegisteredResourceActionResolution may append or update entries in
// resolved.Actions so the reviewed registered resource's action bindings remain
// executable after namespace-specific filtering.
func ensureRegisteredResourceActionResolution(resolved *ResolvedTargets, resourceID string, namespace *policy.Namespace, action *policy.Action, actionResolver *resolver) error {
	if resolved == nil {
		return ErrNilResolvedTargets
	}
	if namespace == nil {
		return fmt.Errorf("%w: empty namespace reference", ErrUndeterminedTargetMapping)
	}
	if action == nil || strings.TrimSpace(action.GetId()) == "" {
		return errors.New("registered resource binding action is missing")
	}
	if actionResolver == nil {
		return ErrNilInteractiveReviewHandler
	}

	item := resolvedActionByID(resolved.Actions, action.GetId())
	if item == nil {
		item = &ResolvedAction{
			Source:  cloneAction(action),
			Results: make([]*ResolvedActionResult, 0, 1),
		}
		resolved.Actions = append(resolved.Actions, item)
	} else if item.Source == nil {
		item.Source = cloneAction(action)
	}

	addActionReferenceIfMissing(item, &ActionReference{
		Kind:      ActionReferenceKindRegisteredResource,
		ID:        resourceID,
		Namespace: namespace,
	})

	if resolvedActionResultForNamespace(item, namespace) != nil {
		return nil
	}

	result, err := actionResolver.resolveActionTargetFromExisting(item.Source, namespace)
	if err != nil {
		return fmt.Errorf("action %q in namespace %q: %w", item.Source.GetId(), namespace.GetId(), err)
	}

	item.Results = append(item.Results, result)
	return nil
}

func resolvedActionByID(actions []*ResolvedAction, sourceID string) *ResolvedAction {
	for _, action := range actions {
		if action != nil && action.Source != nil && action.Source.GetId() == sourceID {
			return action
		}
	}

	return nil
}

func resolvedActionResultForNamespace(action *ResolvedAction, namespace *policy.Namespace) *ResolvedActionResult {
	if action == nil || namespace == nil {
		return nil
	}

	for _, result := range action.Results {
		if result != nil && sameNamespace(result.Namespace, namespace) {
			return result
		}
	}

	return nil
}

func addActionReferenceIfMissing(action *ResolvedAction, reference *ActionReference) {
	if action == nil || reference == nil {
		return
	}

	for _, existing := range action.References {
		if actionReferenceKey(existing) == actionReferenceKey(reference) {
			return
		}
	}

	action.References = append(action.References, reference)
}

func cloneAction(action *policy.Action) *policy.Action {
	if action == nil {
		return nil
	}

	cloned, ok := proto.Clone(action).(*policy.Action)
	if !ok {
		return &policy.Action{
			Id:        action.GetId(),
			Name:      action.GetName(),
			Metadata:  action.GetMetadata(),
			Namespace: action.GetNamespace(),
		}
	}

	return cloned
}
