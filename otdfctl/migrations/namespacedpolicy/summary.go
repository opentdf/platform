package namespacedpolicy

import (
	"fmt"
	"strings"

	identifier "github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/otdfctl/migrations"
	"github.com/opentdf/platform/protocol/go/policy"
)

type migrationStatusCounts struct {
	created          int
	toCreate         int
	existingStandard int
	alreadyMigrated  int
	skipped          int
	failed           int
	unresolved       int
}

type migrationConstructSummary struct {
	label      string
	include    bool
	counts     migrationStatusCounts
	created    []string
	toCreate   []string
	failed     []string
	skipped    []string
	unresolved []string
}

const unexpectedNilTargetReasonFormat = "received unexpected nil target for %s"

type createExecutionState string

const (
	createExecutionStateCreated createExecutionState = "created"
	createExecutionStatePending createExecutionState = "pending"
	createExecutionStateFailed  createExecutionState = "failed"
)

func RenderNamespacedPolicySummary(plan *Plan, commit bool) string {
	return renderNamespacedPolicySummary(plan, commit, "success")
}

func RenderNamespacedPolicySummaryWithResult(plan *Plan, commit bool, result string) string {
	return renderNamespacedPolicySummary(plan, commit, result)
}

func renderNamespacedPolicySummary(plan *Plan, commit bool, result string) string {
	styles := migrations.NewDisplayStyles()
	summaries := []migrationConstructSummary{
		summarizeActions(plan, commit, styles),
		summarizeSubjectConditionSets(plan, commit, styles),
		summarizeSubjectMappings(plan, commit, styles),
		summarizeRegisteredResources(plan, commit, styles),
		summarizeObligationTriggers(plan, commit, styles),
	}

	var b strings.Builder
	if commit {
		b.WriteString(styles.Title().Render("Namespaced Policy Migration Committed"))
	} else {
		b.WriteString(styles.Title().Render("Namespaced Policy Migration Plan"))
	}
	b.WriteByte('\n')
	b.WriteString(styles.Separator().Render(styles.SeparatorText()))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%s %s\n", styles.Info().Render("Scopes:"), styles.Info().Render(joinScopeLabels(plan.Scopes)))
	fmt.Fprintf(&b, "%s %t\n", styles.Info().Render("Commit:"), commit)
	b.WriteString(styles.Info().Render("Result: " + strings.TrimSpace(result)))
	b.WriteByte('\n')

	for _, summary := range summaries {
		if !summary.include {
			continue
		}
		b.WriteByte('\n')
		b.WriteString(styles.Title().Render(summary.label))
		b.WriteByte('\n')
		b.WriteString(styles.Separator().Render(styles.SeparatorText()))
		b.WriteByte('\n')
		fmt.Fprintf(&b, "%s %s\n", styles.Info().Render("Counts:"), formatSummaryCounts(summary.counts, commit))

		if len(summary.created) > 0 {
			b.WriteByte('\n')
			b.WriteString(styles.Action().Render("Created"))
			b.WriteByte('\n')
			for _, line := range summary.created {
				b.WriteString("  - ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}

		if len(summary.toCreate) > 0 {
			b.WriteByte('\n')
			b.WriteString(styles.Action().Render("Will Create"))
			b.WriteByte('\n')
			for _, line := range summary.toCreate {
				b.WriteString("  - ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}

		if len(summary.failed) > 0 {
			b.WriteByte('\n')
			b.WriteString(styles.Warning().Render("Failed"))
			b.WriteByte('\n')
			for _, line := range summary.failed {
				b.WriteString("  - ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}

		if len(summary.skipped) > 0 {
			b.WriteByte('\n')
			b.WriteString(styles.Warning().Render("Skipped"))
			b.WriteByte('\n')
			for _, line := range summary.skipped {
				b.WriteString("  - ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}

		if len(summary.unresolved) > 0 {
			b.WriteByte('\n')
			b.WriteString(styles.Warning().Render("Unresolved"))
			b.WriteByte('\n')
			for _, line := range summary.unresolved {
				b.WriteString("  - ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

func summarizeActions(plan *Plan, commit bool, styles *migrations.DisplayStyles) migrationConstructSummary {
	summary := migrationConstructSummary{
		label:   "Actions",
		include: includesScope(plan, ScopeActions),
	}

	for _, action := range plan.Actions {
		if action == nil || action.Source == nil {
			continue
		}
		for _, target := range action.Targets {
			if target == nil {
				appendTargetlessUnresolved(&summary, styles, "action", action.Source.GetName(), unexpectedNilTargetReason("action"))
				continue
			}
			switch target.Status {
			case TargetStatusCreate:
				switch classifyCreateExecution(commit, target.Execution) {
				case createExecutionStateCreated:
					summary.counts.created++
					summary.created = append(summary.created, formatCreatedLine(styles, "action", action.Source.GetName(), target.Namespace, target.TargetID(), true))
				case createExecutionStateFailed:
					summary.counts.failed++
					summary.failed = append(summary.failed, formatFailedLine(styles, "action", action.Source.GetName(), target.Namespace, target.Execution.Failure))
				case createExecutionStatePending:
					summary.counts.toCreate++
					summary.toCreate = append(summary.toCreate, formatCreatedLine(styles, "action", action.Source.GetName(), target.Namespace, target.TargetID(), false))
				}
			case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
				recordTargetStatus(&summary.counts, target.Status)
			case TargetStatusSkipped:
				recordTargetStatus(&summary.counts, target.Status)
				summary.skipped = append(summary.skipped, formatSkippedLine(styles, "action", action.Source.GetName(), target.Namespace, target.Reason))
			case TargetStatusUnresolved:
				recordTargetStatus(&summary.counts, target.Status)
				summary.unresolved = append(summary.unresolved, formatUnresolvedLine(styles, "action", action.Source.GetName(), target.Namespace, target.Reason))
			}
		}
	}

	return summary
}

func summarizeSubjectConditionSets(plan *Plan, commit bool, styles *migrations.DisplayStyles) migrationConstructSummary {
	summary := migrationConstructSummary{
		label:   "Subject Condition Sets",
		include: includesScope(plan, ScopeSubjectConditionSets),
	}

	for _, scs := range plan.SubjectConditionSets {
		if scs == nil || scs.Source == nil {
			continue
		}
		for _, target := range scs.Targets {
			if target == nil {
				appendTargetlessUnresolved(&summary, styles, "subject condition set", scs.Source.GetId(), unexpectedNilTargetReason("subject condition set"))
				continue
			}
			switch target.Status {
			case TargetStatusCreate:
				switch classifyCreateExecution(commit, target.Execution) {
				case createExecutionStateCreated:
					summary.counts.created++
					summary.created = append(summary.created, formatSubjectConditionSetCreatedLine(styles, scs, target, true))
				case createExecutionStateFailed:
					summary.counts.failed++
					summary.failed = append(summary.failed, formatFailedLine(styles, "subject condition set", scs.Source.GetId(), target.Namespace, target.Execution.Failure))
				case createExecutionStatePending:
					summary.counts.toCreate++
					summary.toCreate = append(summary.toCreate, formatSubjectConditionSetCreatedLine(styles, scs, target, false))
				}
			case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
				recordTargetStatus(&summary.counts, target.Status)
			case TargetStatusSkipped:
				recordTargetStatus(&summary.counts, target.Status)
				summary.skipped = append(summary.skipped, formatSkippedLine(styles, "subject condition set", scs.Source.GetId(), target.Namespace, target.Reason))
			case TargetStatusUnresolved:
				recordTargetStatus(&summary.counts, target.Status)
				summary.unresolved = append(summary.unresolved, formatUnresolvedLine(styles, "subject condition set", scs.Source.GetId(), target.Namespace, target.Reason))
			}
		}
	}

	return summary
}

func summarizeSubjectMappings(plan *Plan, commit bool, styles *migrations.DisplayStyles) migrationConstructSummary {
	summary := migrationConstructSummary{
		label:   "Subject Mappings",
		include: includesScope(plan, ScopeSubjectMappings),
	}

	for _, mapping := range plan.SubjectMappings {
		if mapping == nil || mapping.Source == nil {
			continue
		}
		if mapping.Target == nil {
			appendTargetlessUnresolved(&summary, styles, "subject mapping", mapping.Source.GetId(), unexpectedNilTargetReason("subject mapping"))
			continue
		}

		switch mapping.Target.Status {
		case TargetStatusCreate:
			switch classifyCreateExecution(commit, mapping.Target.Execution) {
			case createExecutionStateCreated:
				summary.counts.created++
				summary.created = append(summary.created, formatSubjectMappingCreatedLine(styles, plan, mapping, true))
			case createExecutionStateFailed:
				summary.counts.failed++
				summary.failed = append(summary.failed, formatFailedLine(styles, "subject mapping", mapping.Source.GetId(), mapping.Target.Namespace, mapping.Target.Execution.Failure))
			case createExecutionStatePending:
				summary.counts.toCreate++
				summary.toCreate = append(summary.toCreate, formatSubjectMappingCreatedLine(styles, plan, mapping, false))
			}
		case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
			recordTargetStatus(&summary.counts, mapping.Target.Status)
		case TargetStatusSkipped:
			recordTargetStatus(&summary.counts, mapping.Target.Status)
			summary.skipped = append(summary.skipped, formatSkippedLine(styles, "subject mapping", mapping.Source.GetId(), mapping.Target.Namespace, mapping.Target.Reason))
		case TargetStatusUnresolved:
			recordTargetStatus(&summary.counts, mapping.Target.Status)
			summary.unresolved = append(summary.unresolved, formatUnresolvedLine(styles, "subject mapping", mapping.Source.GetId(), mapping.Target.Namespace, mapping.Target.Reason))
		}
	}

	return summary
}

func summarizeRegisteredResources(plan *Plan, commit bool, styles *migrations.DisplayStyles) migrationConstructSummary {
	summary := migrationConstructSummary{
		label:   "Registered Resources",
		include: includesScope(plan, ScopeRegisteredResources),
	}

	for _, resource := range plan.RegisteredResources {
		if resource == nil || resource.Source == nil {
			continue
		}
		if resource.Target == nil {
			appendTargetlessUnresolved(&summary, styles, "registered resource", resource.Source.GetName(), unresolvedRegisteredResourceReason(resource))
			continue
		}

		switch resource.Target.Status {
		case TargetStatusCreate:
			switch state, failure := classifyRegisteredResourceExecution(commit, resource.Target); state {
			case createExecutionStateCreated:
				summary.counts.created++
				summary.created = append(summary.created, formatRegisteredResourceCreatedLine(styles, plan, resource, true))
			case createExecutionStateFailed:
				summary.counts.failed++
				summary.failed = append(summary.failed, formatRegisteredResourceFailedLine(styles, resource, failure))
			case createExecutionStatePending:
				summary.counts.toCreate++
				summary.toCreate = append(summary.toCreate, formatRegisteredResourceCreatedLine(styles, plan, resource, false))
			}
		case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
			recordTargetStatus(&summary.counts, resource.Target.Status)
		case TargetStatusSkipped:
			recordTargetStatus(&summary.counts, resource.Target.Status)
			summary.skipped = append(summary.skipped, formatSkippedLine(styles, "registered resource", resource.Source.GetName(), resource.Target.Namespace, resource.Target.Reason))
		case TargetStatusUnresolved:
			recordTargetStatus(&summary.counts, resource.Target.Status)
			reason := resource.Target.Reason
			if reason == "" {
				reason = resource.Unresolved
			}
			summary.unresolved = append(summary.unresolved, formatUnresolvedLine(styles, "registered resource", resource.Source.GetName(), resource.Target.Namespace, reason))
		}
	}

	return summary
}

func summarizeObligationTriggers(plan *Plan, commit bool, styles *migrations.DisplayStyles) migrationConstructSummary {
	summary := migrationConstructSummary{
		label:   "Obligation Triggers",
		include: includesScope(plan, ScopeObligationTriggers),
	}

	for _, trigger := range plan.ObligationTriggers {
		if trigger == nil || trigger.Source == nil {
			continue
		}
		if trigger.Target == nil {
			appendTargetlessUnresolved(&summary, styles, "obligation trigger", trigger.Source.GetId(), unexpectedNilTargetReason("obligation trigger"))
			continue
		}

		switch trigger.Target.Status {
		case TargetStatusCreate:
			switch classifyCreateExecution(commit, trigger.Target.Execution) {
			case createExecutionStateCreated:
				summary.counts.created++
				summary.created = append(summary.created, formatObligationTriggerCreatedLine(styles, plan, trigger, true))
			case createExecutionStateFailed:
				summary.counts.failed++
				summary.failed = append(summary.failed, formatFailedLine(styles, "obligation trigger", trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.Execution.Failure))
			case createExecutionStatePending:
				summary.counts.toCreate++
				summary.toCreate = append(summary.toCreate, formatObligationTriggerCreatedLine(styles, plan, trigger, false))
			}
		case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
			recordTargetStatus(&summary.counts, trigger.Target.Status)
		case TargetStatusSkipped:
			recordTargetStatus(&summary.counts, trigger.Target.Status)
			summary.skipped = append(summary.skipped, formatSkippedLine(styles, "obligation trigger", trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.Reason))
		case TargetStatusUnresolved:
			recordTargetStatus(&summary.counts, trigger.Target.Status)
			summary.unresolved = append(summary.unresolved, formatUnresolvedLine(styles, "obligation trigger", trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.Reason))
		}
	}

	return summary
}

func recordTargetStatus(counts *migrationStatusCounts, status TargetStatus) {
	switch status {
	case TargetStatusCreate:
	case TargetStatusExistingStandard:
		counts.existingStandard++
	case TargetStatusAlreadyMigrated:
		counts.alreadyMigrated++
	case TargetStatusSkipped:
		counts.skipped++
	case TargetStatusUnresolved:
		counts.unresolved++
	}
}

func includesScope(plan *Plan, scope Scope) bool {
	if plan == nil {
		return false
	}
	for _, candidate := range plan.Scopes {
		if candidate == scope {
			return true
		}
	}
	return false
}

func joinScopeLabels(scopes []Scope) string {
	if len(scopes) == 0 {
		return "(none)"
	}

	labels := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		labels = append(labels, string(scope))
	}

	return strings.Join(labels, ", ")
}

func formatSummaryCounts(counts migrationStatusCounts, commit bool) string {
	var parts []string
	if commit {
		parts = append(parts, fmt.Sprintf("created=%d", counts.created))
	}
	if !commit || counts.toCreate > 0 {
		parts = append(parts, fmt.Sprintf("to_create=%d", counts.toCreate))
	}

	parts = append(parts,
		fmt.Sprintf("existing_standard=%d", counts.existingStandard),
		fmt.Sprintf("already_migrated=%d", counts.alreadyMigrated),
		fmt.Sprintf("skipped=%d", counts.skipped),
		fmt.Sprintf("failed=%d", counts.failed),
		fmt.Sprintf("unresolved=%d", counts.unresolved),
	)
	return strings.Join(parts, " ")
}

func classifyCreateExecution(commit bool, execution *ExecutionResult) createExecutionState {
	if !commit {
		return createExecutionStatePending
	}
	if execution == nil {
		return createExecutionStatePending
	}
	if strings.TrimSpace(execution.Failure) != "" {
		return createExecutionStateFailed
	}
	if execution.Applied || strings.TrimSpace(execution.CreatedTargetID) != "" {
		return createExecutionStateCreated
	}
	return createExecutionStatePending
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
	line := formatCreatedLine(styles, "subject condition set", scs.Source.GetId(), target.Namespace, target.TargetID(), commit)
	return appendDetails(line,
		fmt.Sprintf("subject_sets=%d", len(scs.Source.GetSubjectSets())),
	)
}

func formatSubjectMappingCreatedLine(styles *migrations.DisplayStyles, plan *Plan, mapping *SubjectMappingPlan, commit bool) string {
	line := formatCreatedLine(styles, "subject mapping", mapping.Source.GetId(), mapping.Target.Namespace, mapping.Target.TargetID(), commit)
	return appendDetails(line,
		"attribute_value="+styles.Namespace().Render(valueFQN(mapping.Source.GetAttributeValue())),
		"actions="+actionNamesSummary(styles, plan, mapping.Target.ActionSourceIDs),
		"scs_source="+styles.ID().Render(mapping.Target.SubjectConditionSetSourceID),
	)
}

func formatRegisteredResourceCreatedLine(styles *migrations.DisplayStyles, plan *Plan, resource *RegisteredResourcePlan, commit bool) string {
	line := formatCreatedLine(styles, "registered resource", resource.Source.GetName(), resource.Target.Namespace, resource.Target.TargetID(), commit)

	return appendDetails(line,
		"values="+registeredResourceValueFQNsSummary(styles, resource),
		"action_bindings="+registeredResourceActionBindingsSummary(styles, plan, resource),
	)
}

func formatRegisteredResourceFailedLine(styles *migrations.DisplayStyles, resource *RegisteredResourcePlan, reason string) string {
	line := formatFailedLine(styles, "registered resource", resource.Source.GetName(), resource.Target.Namespace, reason)
	if failedValue := registeredResourceFailedValue(resource); failedValue != "" {
		return appendDetails(line, "value="+styles.Namespace().Render(failedValue))
	}
	return line
}

func formatObligationTriggerCreatedLine(styles *migrations.DisplayStyles, plan *Plan, trigger *ObligationTriggerPlan, commit bool) string {
	line := formatCreatedLine(styles, "obligation trigger", trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.TargetID(), commit)
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

func classifyRegisteredResourceExecution(commit bool, target *RegisteredResourceTargetPlan) (createExecutionState, string) {
	if !commit {
		return createExecutionStatePending, ""
	}
	if target == nil {
		return createExecutionStatePending, ""
	}
	if target.Execution != nil && strings.TrimSpace(target.Execution.Failure) != "" {
		return createExecutionStateFailed, target.Execution.Failure
	}
	if target.Execution == nil || (!target.Execution.Applied && strings.TrimSpace(target.Execution.CreatedTargetID) == "") {
		return createExecutionStatePending, ""
	}

	pendingValues := false
	for _, valuePlan := range target.Values {
		if valuePlan == nil {
			continue
		}
		if valuePlan.Execution != nil && strings.TrimSpace(valuePlan.Execution.Failure) != "" {
			return createExecutionStateFailed, valuePlan.Execution.Failure
		}
		if valuePlan.Execution == nil || (!valuePlan.Execution.Applied && strings.TrimSpace(valuePlan.Execution.CreatedTargetID) == "") {
			pendingValues = true
		}
	}
	if pendingValues {
		return createExecutionStatePending, ""
	}
	return createExecutionStateCreated, ""
}

func appendTargetlessUnresolved(summary *migrationConstructSummary, styles *migrations.DisplayStyles, kind, label, reason string) {
	if summary == nil || strings.TrimSpace(reason) == "" {
		return
	}
	summary.counts.unresolved++
	summary.unresolved = append(summary.unresolved, formatUnresolvedLineWithoutNamespace(styles, kind, label, reason))
}

func appendDetails(line string, details ...string) string {
	filtered := make([]string, 0, len(details))
	for _, detail := range details {
		if strings.TrimSpace(detail) != "" {
			filtered = append(filtered, detail)
		}
	}
	if len(filtered) == 0 {
		return line
	}
	return fmt.Sprintf("%s (%s)", line, strings.Join(filtered, ", "))
}

func valueFQN(value *policy.Value) string {
	if value == nil {
		return ""
	}
	if value.GetFqn() != "" {
		return value.GetFqn()
	}
	return value.GetId()
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

func strconvQuote(value string) string {
	return fmt.Sprintf("%q", value)
}
