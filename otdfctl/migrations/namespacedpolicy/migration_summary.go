package namespacedpolicy

import (
	"fmt"
	"strings"

	identifier "github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/otdfctl/migrations"
	"github.com/opentdf/platform/protocol/go/policy"
)

type summaryLines struct {
	applied    string
	pending    string
	failed     string
	skipped    string
	unresolved string
}

const unexpectedNilTargetReasonFormat = "received unexpected nil target for %s"

const (
	migrationAppliedCountLabel   = "created"
	migrationPendingCountLabel   = "to_create"
	migrationAppliedSectionLabel = "Created"
	migrationPendingSectionLabel = "Will Create"
)

func RenderNamespacedPolicySummary(plan *Plan, commit bool) string {
	return renderNamespacedPolicySummary(plan, commit, "success")
}

func RenderNamespacedPolicySummaryWithResult(plan *Plan, commit bool, result string) string {
	return renderNamespacedPolicySummary(plan, commit, result)
}

func planScopes(plan *Plan) []Scope {
	if plan == nil {
		return nil
	}
	return plan.Scopes
}

func renderNamespacedPolicySummary(plan *Plan, commit bool, result string) string {
	styles := migrations.NewDisplayStyles()
	return renderSummaryDocument(styles, summaryDocument{
		plannedTitle:   "Namespaced Policy Migration Plan",
		committedTitle: "Namespaced Policy Migration Committed",
		operation:      summaryOperationMigration,
		scopes:         planScopes(plan),
		commit:         commit,
		result:         result,
		summaries: []constructSummary{
			summarizeActions(plan, commit, styles),
			summarizeSubjectConditionSets(plan, commit, styles),
			summarizeSubjectMappings(plan, commit, styles),
			summarizeRegisteredResources(plan, commit, styles),
			summarizeObligationTriggers(plan, commit, styles),
		},
	})
}

func appendMigrationSummaryCountParts(parts []string, counts summaryCounts) []string {
	return append(parts,
		fmt.Sprintf("existing_standard=%d", counts.existingStandard),
		fmt.Sprintf("already_migrated=%d", counts.alreadyMigrated),
	)
}

func summarizeActions(plan *Plan, commit bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Actions",
		include: includesScope(planScopes(plan), ScopeActions),
	}
	if plan == nil {
		return summary
	}

	for _, action := range plan.Actions {
		if action == nil || action.Source == nil {
			continue
		}
		for _, target := range action.Targets {
			if target == nil {
				appendTargetlessUnresolved(&summary, styles, actionKind, action.Source.GetName(), unexpectedNilTargetReason(actionKind))
				continue
			}
			appendTargetStatusSummary(&summary, target.Status, classifyCreateExecution(commit, target.Execution), summaryLines{
				applied:    formatCreatedLine(styles, actionKind, action.Source.GetName(), target.Namespace, target.TargetID(), true),
				pending:    formatCreatedLine(styles, actionKind, action.Source.GetName(), target.Namespace, target.TargetID(), false),
				failed:     formatFailedLine(styles, actionKind, action.Source.GetName(), target.Namespace, executionFailure(target.Execution)),
				skipped:    formatSkippedLine(styles, actionKind, action.Source.GetName(), target.Namespace, target.Reason),
				unresolved: formatUnresolvedLine(styles, actionKind, action.Source.GetName(), target.Namespace, target.Reason),
			})
		}
	}

	return summary
}

func summarizeSubjectConditionSets(plan *Plan, commit bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Subject Condition Sets",
		include: includesScope(planScopes(plan), ScopeSubjectConditionSets),
	}
	if plan == nil {
		return summary
	}

	for _, scs := range plan.SubjectConditionSets {
		if scs == nil || scs.Source == nil {
			continue
		}
		for _, target := range scs.Targets {
			if target == nil {
				appendTargetlessUnresolved(&summary, styles, subjectConditionSetKind, scs.Source.GetId(), unexpectedNilTargetReason(subjectConditionSetKind))
				continue
			}
			appendTargetStatusSummary(&summary, target.Status, classifyCreateExecution(commit, target.Execution), summaryLines{
				applied:    formatSubjectConditionSetCreatedLine(styles, scs, target, true),
				pending:    formatSubjectConditionSetCreatedLine(styles, scs, target, false),
				failed:     formatFailedLine(styles, subjectConditionSetKind, scs.Source.GetId(), target.Namespace, executionFailure(target.Execution)),
				skipped:    formatSkippedLine(styles, subjectConditionSetKind, scs.Source.GetId(), target.Namespace, target.Reason),
				unresolved: formatUnresolvedLine(styles, subjectConditionSetKind, scs.Source.GetId(), target.Namespace, target.Reason),
			})
		}
	}

	return summary
}

func summarizeSubjectMappings(plan *Plan, commit bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Subject Mappings",
		include: includesScope(planScopes(plan), ScopeSubjectMappings),
	}
	if plan == nil {
		return summary
	}

	for _, mapping := range plan.SubjectMappings {
		if mapping == nil || mapping.Source == nil {
			continue
		}
		if mapping.Target == nil {
			appendTargetlessUnresolved(&summary, styles, subjectMappingKind, mapping.Source.GetId(), unexpectedNilTargetReason(subjectMappingKind))
			continue
		}

		appendTargetStatusSummary(&summary, mapping.Target.Status, classifyCreateExecution(commit, mapping.Target.Execution), summaryLines{
			applied:    formatSubjectMappingCreatedLine(styles, plan, mapping, true),
			pending:    formatSubjectMappingCreatedLine(styles, plan, mapping, false),
			failed:     formatFailedLine(styles, subjectMappingKind, mapping.Source.GetId(), mapping.Target.Namespace, executionFailure(mapping.Target.Execution)),
			skipped:    formatSkippedLine(styles, subjectMappingKind, mapping.Source.GetId(), mapping.Target.Namespace, mapping.Target.Reason),
			unresolved: formatUnresolvedLine(styles, subjectMappingKind, mapping.Source.GetId(), mapping.Target.Namespace, mapping.Target.Reason),
		})
	}

	return summary
}

func summarizeRegisteredResources(plan *Plan, commit bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Registered Resources",
		include: includesScope(planScopes(plan), ScopeRegisteredResources),
	}
	if plan == nil {
		return summary
	}

	for _, resource := range plan.RegisteredResources {
		if resource == nil || resource.Source == nil {
			continue
		}
		if resource.Target == nil {
			appendTargetlessUnresolved(&summary, styles, registeredResourceKind, resource.Source.GetName(), unresolvedRegisteredResourceReason(resource))
			continue
		}

		state := operationExecutionStatePending
		failure := ""
		if resource.Target.Status == TargetStatusCreate {
			state, failure = classifyRegisteredResourceExecution(commit, resource.Target)
		}
		appendTargetStatusSummary(&summary, resource.Target.Status, state, summaryLines{
			applied:    formatRegisteredResourceCreatedLine(styles, plan, resource, true),
			pending:    formatRegisteredResourceCreatedLine(styles, plan, resource, false),
			failed:     formatRegisteredResourceFailedLine(styles, resource, failure),
			skipped:    formatSkippedLine(styles, registeredResourceKind, resource.Source.GetName(), resource.Target.Namespace, resource.Target.Reason),
			unresolved: formatUnresolvedLine(styles, registeredResourceKind, resource.Source.GetName(), resource.Target.Namespace, registeredResourceUnresolvedReason(resource)),
		})
	}

	return summary
}

func summarizeObligationTriggers(plan *Plan, commit bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Obligation Triggers",
		include: includesScope(planScopes(plan), ScopeObligationTriggers),
	}
	if plan == nil {
		return summary
	}

	for _, trigger := range plan.ObligationTriggers {
		if trigger == nil || trigger.Source == nil {
			continue
		}
		if trigger.Target == nil {
			appendTargetlessUnresolved(&summary, styles, obligationTriggerKind, trigger.Source.GetId(), unexpectedNilTargetReason(obligationTriggerKind))
			continue
		}

		appendTargetStatusSummary(&summary, trigger.Target.Status, classifyCreateExecution(commit, trigger.Target.Execution), summaryLines{
			applied:    formatObligationTriggerCreatedLine(styles, plan, trigger, true),
			pending:    formatObligationTriggerCreatedLine(styles, plan, trigger, false),
			failed:     formatFailedLine(styles, obligationTriggerKind, trigger.Source.GetId(), trigger.Target.Namespace, executionFailure(trigger.Target.Execution)),
			skipped:    formatSkippedLine(styles, obligationTriggerKind, trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.Reason),
			unresolved: formatUnresolvedLine(styles, obligationTriggerKind, trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.Reason),
		})
	}

	return summary
}

func recordConstructTargetStatus(counts *summaryCounts, status TargetStatus) {
	if status == TargetStatusExistingStandard {
		counts.existingStandard++
		return
	}
	if status == TargetStatusAlreadyMigrated {
		counts.alreadyMigrated++
		return
	}
	if status == TargetStatusSkipped {
		counts.skipped++
		return
	}
	if status == TargetStatusUnresolved {
		counts.unresolved++
	}
}

func appendTargetStatusSummary(summary *constructSummary, status TargetStatus, createState operationExecutionState, lines summaryLines) {
	switch status {
	case TargetStatusCreate:
		switch createState {
		case operationExecutionStateApplied:
			summary.counts.applied++
			summary.applied = append(summary.applied, lines.applied)
		case operationExecutionStateFailed:
			summary.counts.failed++
			summary.failed = append(summary.failed, lines.failed)
		case operationExecutionStatePending:
			summary.counts.pending++
			summary.pending = append(summary.pending, lines.pending)
		}
	case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
		recordConstructTargetStatus(&summary.counts, status)
	case TargetStatusSkipped:
		recordConstructTargetStatus(&summary.counts, status)
		summary.skipped = append(summary.skipped, lines.skipped)
	case TargetStatusUnresolved:
		recordConstructTargetStatus(&summary.counts, status)
		summary.unresolved = append(summary.unresolved, lines.unresolved)
	}
}

func classifyCreateExecution(commit bool, execution *ExecutionResult) operationExecutionState {
	if !commit || execution == nil {
		return operationExecutionStatePending
	}
	if strings.TrimSpace(execution.Failure) != "" {
		return operationExecutionStateFailed
	}
	if execution.Applied || strings.TrimSpace(execution.CreatedTargetID) != "" {
		return operationExecutionStateApplied
	}
	return operationExecutionStatePending
}

func formatCreatedLine(styles *migrations.DisplayStyles, kind, label string, namespace *policy.Namespace, targetID string, commit bool) string {
	line := fmt.Sprintf(
		"%s %s -> %s",
		styles.Info().Render(kind),
		styles.Name().Render(strconvQuote(label)),
		styles.Namespace().Render(namespaceDisplay(namespace)),
	)
	if commit && targetID != "" {
		line = fmt.Sprintf("%s (id: %s)", line, styles.ID().Render(targetID))
	}
	return line
}

func formatFailedLine(styles *migrations.DisplayStyles, kind, label string, namespace *policy.Namespace, reason string) string {
	line := fmt.Sprintf(
		"%s %s -> %s",
		styles.Info().Render(kind),
		styles.Name().Render(strconvQuote(label)),
		styles.Namespace().Render(namespaceDisplay(namespace)),
	)
	if strings.TrimSpace(reason) == "" {
		return line
	}
	return fmt.Sprintf("%s: %s", line, styles.Warning().Render(reason))
}

func formatSubjectConditionSetCreatedLine(styles *migrations.DisplayStyles, scs *SubjectConditionSetPlan, target *SubjectConditionSetTargetPlan, commit bool) string {
	line := formatCreatedLine(styles, subjectConditionSetKind, scs.Source.GetId(), target.Namespace, target.TargetID(), commit)
	return appendDetails(line,
		fmt.Sprintf("subject_sets=%d", len(scs.Source.GetSubjectSets())),
	)
}

func formatSubjectMappingCreatedLine(styles *migrations.DisplayStyles, plan *Plan, mapping *SubjectMappingPlan, commit bool) string {
	line := formatCreatedLine(styles, subjectMappingKind, mapping.Source.GetId(), mapping.Target.Namespace, mapping.Target.TargetID(), commit)
	return appendDetails(line,
		"attribute_value="+styles.Namespace().Render(valueFQN(mapping.Source.GetAttributeValue())),
		"actions="+actionNamesSummary(styles, plan, mapping.Target.ActionSourceIDs),
		"scs_source="+styles.ID().Render(mapping.Target.SubjectConditionSetSourceID),
	)
}

func formatRegisteredResourceCreatedLine(styles *migrations.DisplayStyles, plan *Plan, resource *RegisteredResourcePlan, commit bool) string {
	line := formatCreatedLine(styles, registeredResourceKind, resource.Source.GetName(), resource.Target.Namespace, resource.Target.TargetID(), commit)

	return appendDetails(line,
		"values="+registeredResourceValueFQNsSummary(styles, resource),
		"action_bindings="+registeredResourceActionBindingsSummary(styles, plan, resource),
	)
}

func formatRegisteredResourceFailedLine(styles *migrations.DisplayStyles, resource *RegisteredResourcePlan, reason string) string {
	line := formatFailedLine(styles, registeredResourceKind, resource.Source.GetName(), resource.Target.Namespace, reason)
	if failedValue := registeredResourceFailedValue(resource); failedValue != "" {
		return appendDetails(line, "value="+styles.Namespace().Render(failedValue))
	}
	return line
}

func formatObligationTriggerCreatedLine(styles *migrations.DisplayStyles, plan *Plan, trigger *ObligationTriggerPlan, commit bool) string {
	line := formatCreatedLine(styles, obligationTriggerKind, trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.TargetID(), commit)
	return appendDetails(line,
		"action="+actionNamesSummary(styles, plan, []string{trigger.Target.ActionSourceID}),
		"attribute_value="+styles.Namespace().Render(valueFQN(trigger.Source.GetAttributeValue())),
		"obligation_value="+styles.ID().Render(obligationValueIDOrFQN(trigger.Source.GetObligationValue())),
	)
}

func formatUnresolvedLine(styles *migrations.DisplayStyles, kind, label string, namespace *policy.Namespace, reason string) string {
	line := fmt.Sprintf(
		"%s %s -> %s",
		styles.Info().Render(kind),
		styles.Name().Render(strconvQuote(label)),
		styles.Namespace().Render(namespaceDisplay(namespace)),
	)
	if strings.TrimSpace(reason) == "" {
		return line
	}
	return fmt.Sprintf("%s: %s", line, styles.Warning().Render(reason))
}

func formatUnresolvedLineWithoutNamespace(styles *migrations.DisplayStyles, kind, label string, reason string) string {
	line := fmt.Sprintf(
		"%s %s",
		styles.Info().Render(kind),
		styles.Name().Render(strconvQuote(label)),
	)
	if strings.TrimSpace(reason) == "" {
		return line
	}
	return fmt.Sprintf("%s: %s", line, styles.Warning().Render(reason))
}

func formatSkippedLine(styles *migrations.DisplayStyles, kind, label string, namespace *policy.Namespace, reason string) string {
	line := fmt.Sprintf(
		"%s %s -> %s",
		styles.Info().Render(kind),
		styles.Name().Render(strconvQuote(label)),
		styles.Namespace().Render(namespaceDisplay(namespace)),
	)
	if strings.TrimSpace(reason) == "" {
		return line
	}
	return fmt.Sprintf("%s: %s", line, styles.Warning().Render(reason))
}

func registeredResourceUnresolvedReason(resource *RegisteredResourcePlan) string {
	if resource == nil || resource.Target == nil {
		return ""
	}
	if resource.Target.Reason != "" {
		return resource.Target.Reason
	}
	return resource.Unresolved
}

func classifyRegisteredResourceExecution(commit bool, target *RegisteredResourceTargetPlan) (operationExecutionState, string) {
	if !commit {
		return operationExecutionStatePending, ""
	}
	if target.Execution != nil && strings.TrimSpace(target.Execution.Failure) != "" {
		return operationExecutionStateFailed, target.Execution.Failure
	}
	if target.Execution == nil || (!target.Execution.Applied && strings.TrimSpace(target.Execution.CreatedTargetID) == "") {
		return operationExecutionStatePending, ""
	}

	pendingValues := false
	for _, valuePlan := range target.Values {
		if valuePlan == nil {
			continue
		}
		if valuePlan.Execution != nil && strings.TrimSpace(valuePlan.Execution.Failure) != "" {
			return operationExecutionStateFailed, valuePlan.Execution.Failure
		}
		if valuePlan.Execution == nil || (!valuePlan.Execution.Applied && strings.TrimSpace(valuePlan.Execution.CreatedTargetID) == "") {
			pendingValues = true
		}
	}
	if pendingValues {
		return operationExecutionStatePending, ""
	}
	return operationExecutionStateApplied, ""
}

func appendTargetlessUnresolved(summary *constructSummary, styles *migrations.DisplayStyles, kind, label, reason string) {
	if summary == nil {
		return
	}
	summary.counts.unresolved++
	summary.unresolved = append(summary.unresolved, formatUnresolvedLineWithoutNamespace(styles, kind, label, reason))
}

func registeredResourceValueFQNsSummary(styles *migrations.DisplayStyles, resource *RegisteredResourcePlan) string {
	values := make([]string, 0, len(resource.Target.Values))
	seen := make(map[string]struct{}, len(resource.Target.Values))
	for _, valuePlan := range resource.Target.Values {
		fqn := registeredResourceValueFQN(valuePlan)
		if strings.TrimSpace(fqn) == "" {
			continue
		}
		if _, ok := seen[fqn]; ok {
			continue
		}
		seen[fqn] = struct{}{}
		values = append(values, styles.Namespace().Render(fqn))
	}
	return strings.Join(values, ", ")
}

func registeredResourceFailedValue(resource *RegisteredResourcePlan) string {
	if resource == nil || resource.Target == nil {
		return ""
	}
	for _, valuePlan := range resource.Target.Values {
		if valuePlan == nil || valuePlan.Execution == nil || strings.TrimSpace(valuePlan.Execution.Failure) == "" {
			continue
		}
		return registeredResourceValueFQN(valuePlan)
	}
	return ""
}

func registeredResourceActionBindingsSummary(styles *migrations.DisplayStyles, plan *Plan, resource *RegisteredResourcePlan) string {
	bindings := make([]string, 0)
	seen := make(map[string]struct{})
	for _, valuePlan := range resource.Target.Values {
		if valuePlan == nil {
			continue
		}
		for _, binding := range valuePlan.ActionBindings {
			if binding == nil {
				continue
			}
			actionName := actionNameBySourceID(plan, binding.SourceActionID)
			if actionName == "" {
				actionName = binding.SourceActionID
			}
			attrValue := valueFQN(binding.AttributeValue)
			label := fmt.Sprintf(
				"%s -> %s",
				styles.Name().Render(strconvQuote(actionName)),
				styles.Namespace().Render(attrValue),
			)
			if _, ok := seen[label]; ok {
				continue
			}
			seen[label] = struct{}{}
			bindings = append(bindings, label)
		}
	}
	return strings.Join(bindings, ", ")
}

func actionNamesSummary(styles *migrations.DisplayStyles, plan *Plan, sourceIDs []string) string {
	names := make([]string, 0, len(sourceIDs))
	seen := make(map[string]struct{}, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		if strings.TrimSpace(sourceID) == "" {
			continue
		}
		name := actionNameBySourceID(plan, sourceID)
		if name == "" {
			name = sourceID
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, styles.Name().Render(strconvQuote(name)))
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ", ")
}

func actionNameBySourceID(plan *Plan, sourceID string) string {
	if plan == nil {
		return ""
	}
	for _, action := range plan.Actions {
		if action == nil || action.Source == nil {
			continue
		}
		if action.Source.GetId() == sourceID {
			return action.Source.GetName()
		}
	}
	return ""
}

func unresolvedRegisteredResourceReason(resource *RegisteredResourcePlan) string {
	if resource == nil {
		return ""
	}
	return strings.TrimSpace(resource.Unresolved)
}

func unexpectedNilTargetReason(kind string) string {
	return fmt.Sprintf(unexpectedNilTargetReasonFormat, kind)
}

func registeredResourceValueFQN(valuePlan *RegisteredResourceValuePlan) string {
	if valuePlan == nil || valuePlan.Source == nil {
		return ""
	}
	resource := valuePlan.Source.GetResource()
	if resource == nil {
		return valuePlan.Source.GetValue()
	}

	namespace := ""
	if resource.GetNamespace() != nil {
		namespace = strings.TrimPrefix(strings.TrimSpace(resource.GetNamespace().GetFqn()), "https://")
	}

	return (&identifier.FullyQualifiedRegisteredResourceValue{
		Namespace: namespace,
		Name:      resource.GetName(),
		Value:     valuePlan.Source.GetValue(),
	}).FQN()
}

func namespaceDisplay(namespace *policy.Namespace) string {
	if namespace == nil {
		return "(global)"
	}
	if fqn := strings.TrimSpace(namespace.GetFqn()); fqn != "" {
		return fqn
	}
	if name := strings.TrimSpace(namespace.GetName()); name != "" {
		return name
	}
	if id := strings.TrimSpace(namespace.GetId()); id != "" {
		return id
	}
	return "(unknown namespace)"
}
