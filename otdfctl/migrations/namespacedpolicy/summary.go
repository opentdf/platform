package namespacedpolicy

import (
	"fmt"
	"strings"

	identifier "github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/otdfctl/migrations"
	"github.com/opentdf/platform/protocol/go/policy"
)

type migrationStatusCounts struct {
	create           int
	existingStandard int
	alreadyMigrated  int
	skipped          int
	unresolved       int
}

type migrationConstructSummary struct {
	label      string
	include    bool
	counts     migrationStatusCounts
	created    []string
	skipped    []string
	unresolved []string
}

const unexpectedNilTargetReasonFormat = "received unexpected nil target for %s"

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
		fmt.Fprintf(
			&b,
			"%s %s=%d existing_standard=%d already_migrated=%d skipped=%d unresolved=%d\n",
			styles.Info().Render("Counts:"),
			createCountLabel(commit),
			summary.counts.create,
			summary.counts.existingStandard,
			summary.counts.alreadyMigrated,
			summary.counts.skipped,
			summary.counts.unresolved,
		)

		if len(summary.created) > 0 {
			b.WriteByte('\n')
			if commit {
				b.WriteString(styles.Action().Render("Created"))
			} else {
				b.WriteString(styles.Action().Render("Will Create"))
			}
			b.WriteByte('\n')
			for _, line := range summary.created {
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
			recordTargetStatus(&summary.counts, target.Status)
			switch target.Status {
			case TargetStatusCreate:
				summary.created = append(summary.created, formatCreatedLine(styles, "action", action.Source.GetName(), target.Namespace, target.TargetID(), commit))
			case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
			case TargetStatusSkipped:
				summary.skipped = append(summary.skipped, formatSkippedLine(styles, "action", action.Source.GetName(), target.Namespace, target.Reason))
			case TargetStatusUnresolved:
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
			recordTargetStatus(&summary.counts, target.Status)
			switch target.Status {
			case TargetStatusCreate:
				summary.created = append(summary.created, formatSubjectConditionSetCreatedLine(styles, scs, target, commit))
			case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
			case TargetStatusSkipped:
				summary.skipped = append(summary.skipped, formatSkippedLine(styles, "subject condition set", scs.Source.GetId(), target.Namespace, target.Reason))
			case TargetStatusUnresolved:
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

		recordTargetStatus(&summary.counts, mapping.Target.Status)
		switch mapping.Target.Status {
		case TargetStatusCreate:
			summary.created = append(summary.created, formatSubjectMappingCreatedLine(styles, plan, mapping, commit))
		case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
		case TargetStatusSkipped:
			summary.skipped = append(summary.skipped, formatSkippedLine(styles, "subject mapping", mapping.Source.GetId(), mapping.Target.Namespace, mapping.Target.Reason))
		case TargetStatusUnresolved:
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

		recordTargetStatus(&summary.counts, resource.Target.Status)
		switch resource.Target.Status {
		case TargetStatusCreate:
			summary.created = append(summary.created, formatRegisteredResourceCreatedLine(styles, plan, resource, commit))
		case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
		case TargetStatusSkipped:
			summary.skipped = append(summary.skipped, formatSkippedLine(styles, "registered resource", resource.Source.GetName(), resource.Target.Namespace, resource.Target.Reason))
		case TargetStatusUnresolved:
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

		recordTargetStatus(&summary.counts, trigger.Target.Status)
		switch trigger.Target.Status {
		case TargetStatusCreate:
			summary.created = append(summary.created, formatObligationTriggerCreatedLine(styles, plan, trigger, commit))
		case TargetStatusExistingStandard, TargetStatusAlreadyMigrated:
		case TargetStatusSkipped:
			summary.skipped = append(summary.skipped, formatSkippedLine(styles, "obligation trigger", trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.Reason))
		case TargetStatusUnresolved:
			summary.unresolved = append(summary.unresolved, formatUnresolvedLine(styles, "obligation trigger", trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.Reason))
		}
	}

	return summary
}

func recordTargetStatus(counts *migrationStatusCounts, status TargetStatus) {
	switch status {
	case TargetStatusCreate:
		counts.create++
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

func createCountLabel(commit bool) string {
	if commit {
		return "created"
	}
	return "to_create"
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

func formatObligationTriggerCreatedLine(styles *migrations.DisplayStyles, plan *Plan, trigger *ObligationTriggerPlan, commit bool) string {
	line := formatCreatedLine(styles, "obligation trigger", trigger.Source.GetId(), trigger.Target.Namespace, trigger.Target.TargetID(), commit)
	return appendDetails(line,
		"action="+actionNamesSummary(styles, plan, []string{trigger.Target.ActionSourceID}),
		"attribute_value="+styles.Namespace().Render(valueFQN(trigger.Source.GetAttributeValue())),
		"obligation_value="+styles.ID().Render(obligationValueID(trigger.Source.GetObligationValue())),
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

func obligationValueID(value *policy.ObligationValue) string {
	if value == nil {
		return ""
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
