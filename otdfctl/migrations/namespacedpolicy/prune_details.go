package namespacedpolicy

import (
	"strconv"
	"strings"

	"github.com/opentdf/platform/otdfctl/migrations"
	"github.com/opentdf/platform/protocol/go/policy"
)

func renderPruneReviewDetails(details []string, result string) []string {
	lines := make([]string, 0, len(details)+1)
	for _, detail := range details {
		if strings.TrimSpace(detail) == "" {
			continue
		}
		lines = append(lines, detail)
	}
	if strings.TrimSpace(result) != "" {
		lines = append(lines, result)
	}
	return lines
}

func renderPruneReviewDescription(details []string, reason PruneStatusReason, execution *ExecutionResult) []string {
	return renderPruneReviewDetails(details, renderResultDetail(false, nil, reason, execution))
}

func renderPruneSummaryLine(base string, details []string, result string) string {
	line := appendDetails(base, details...)
	if strings.TrimSpace(result) == "" {
		return line
	}
	return line + ": " + result
}

func renderResultDetail(styled bool, styles *migrations.DisplayStyles, reason PruneStatusReason, execution *ExecutionResult) string {
	if !reason.IsZero() {
		return formatPruneDetail("reason", pruneWarningValue(styled, styles, reason.String()))
	}

	if failure := strings.TrimSpace(executionFailure(execution)); failure != "" {
		return formatPruneDetail("execution_failure", pruneWarningValue(styled, styles, failure))
	}

	return ""
}

func formatPruneDetail(label, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return label + "=" + value
}

func pruneIDValue(styled bool, styles *migrations.DisplayStyles, value string) string {
	if styled {
		return styles.ID().Render(value)
	}
	return value
}

func pruneNameValue(styled bool, styles *migrations.DisplayStyles, value string) string {
	if styled {
		return styles.Name().Render(value)
	}
	return value
}

func pruneNamespaceValue(styled bool, styles *migrations.DisplayStyles, value string) string {
	if styled {
		return styles.Namespace().Render(value)
	}
	return value
}

func pruneWarningValue(styled bool, styles *migrations.DisplayStyles, value string) string {
	if styled {
		return styles.Warning().Render(value)
	}
	return value
}

func targetRefsSummary(targets []TargetRef) string {
	labels := make([]string, 0, len(targets))
	for _, target := range targets {
		label := target.String()
		if label == noneLabel {
			continue
		}
		labels = append(labels, label)
	}
	if len(labels) == 0 {
		return noneLabel
	}
	return "[" + strings.Join(labels, ", ") + "]"
}

func styledTargetRefsSummary(styles *migrations.DisplayStyles, targets []TargetRef) string {
	labels := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.IsZero() {
			continue
		}
		labels = append(labels, styledTargetRefSummary(styles, target))
	}
	if len(labels) == 0 {
		return styles.ID().Render(noneLabel)
	}
	return "[" + strings.Join(labels, ", ") + "]"
}

func styledTargetRefSummary(styles *migrations.DisplayStyles, target TargetRef) string {
	if target.IsZero() {
		return styles.ID().Render(noneLabel)
	}

	parts := make([]string, 0, targetRefSummaryPartCapacity)
	if id := strings.TrimSpace(target.ID); id != "" {
		parts = append(parts, "id: "+styles.ID().Render(strconvQuote(id)))
	}

	namespace := strings.TrimSpace(target.NamespaceFQN)
	if namespace == "" {
		namespace = strings.TrimSpace(target.NamespaceID)
	}
	if namespace != "" {
		parts = append(parts, "namespace: "+styles.Namespace().Render(strconvQuote(namespace)))
	}

	if len(parts) == 0 {
		return styles.ID().Render(noneLabel)
	}
	return strings.Join(parts, " ")
}

func targetRefsPruneDetail(label string, targets []TargetRef, styled bool, styles *migrations.DisplayStyles) string {
	if styled {
		return formatPruneDetail(label, styledTargetRefsSummary(styles, targets))
	}
	return formatPruneDetail(label, targetRefsSummary(targets))
}

func targetRefPruneDetail(label string, target TargetRef, styled bool, styles *migrations.DisplayStyles) string {
	if styled {
		return formatPruneDetail(label, styledTargetRefSummary(styles, target))
	}
	return formatPruneDetail(label, target.String())
}

func policyActionsPruneDetail(label string, actions []*policy.Action, styled bool, styles *migrations.DisplayStyles) string {
	if styled {
		return formatPruneDetail(label, styledPolicyActionNamesSummary(styles, actions))
	}
	return formatPruneDetail(label, plainPolicyActionNamesSummary(actions))
}

func registeredResourceSourcePruneDetail(label string, resource *policy.RegisteredResource, styled bool, styles *migrations.DisplayStyles) string {
	if styled {
		return formatPruneDetail(label, styledRegisteredResourceSourceSummary(styles, resource))
	}
	return formatPruneDetail(label, plainRegisteredResourceSourceSummary(resource))
}

func (p *PruneActionPlan) pruneDetails(styled bool, styles *migrations.DisplayStyles) []string {
	return []string{
		formatPruneDetail("source_id", pruneIDValue(styled, styles, p.Source.GetId())),
		targetRefsPruneDetail("found_migrated_targets", p.MigratedTargets, styled, styles),
	}
}

func (p *PruneSubjectConditionSetPlan) pruneDetails(styled bool, styles *migrations.DisplayStyles) []string {
	return []string{
		formatPruneDetail("subject_sets", strconv.Itoa(len(p.Source.GetSubjectSets()))),
		targetRefsPruneDetail("found_migrated_targets", p.MigratedTargets, styled, styles),
	}
}

func (p *PruneSubjectMappingPlan) pruneDetails(styled bool, styles *migrations.DisplayStyles) []string {
	return []string{
		formatPruneDetail("attribute_value", pruneNamespaceValue(styled, styles, valueFQN(p.Source.GetAttributeValue()))),
		policyActionsPruneDetail("actions", p.Source.GetActions(), styled, styles),
		formatPruneDetail("scs_source", pruneIDValue(styled, styles, p.Source.GetSubjectConditionSet().GetId())),
		targetRefPruneDetail("found_migrated_target", p.MigratedTarget, styled, styles),
	}
}

func (p *PruneRegisteredResourcePlan) pruneDetails(styled bool, styles *migrations.DisplayStyles) []string {
	details := []string{
		formatPruneDetail("source_id", pruneIDValue(styled, styles, p.Source.GetId())),
		registeredResourceSourcePruneDetail("source", p.Source, styled, styles),
		targetRefPruneDetail("found_migrated_target", p.MigratedTarget, styled, styles),
	}
	if !styled && p.Reason.Type == PruneStatusReasonTypeRegisteredResourceSourceMismatch {
		details = append(details, formatPruneDetail("full_source", plainRegisteredResourceSourceSummary(p.FullSource)))
	}
	return details
}

func (p *PruneObligationTriggerPlan) pruneDetails(styled bool, styles *migrations.DisplayStyles) []string {
	return []string{
		formatPruneDetail("attribute_value", pruneNamespaceValue(styled, styles, valueFQN(p.Source.GetAttributeValue()))),
		formatPruneDetail("action", pruneNameValue(styled, styles, strconvQuote(actionLabel(p.Source.GetAction())))),
		formatPruneDetail("obligation_value", pruneIDValue(styled, styles, obligationValueIDOrFQN(p.Source.GetObligationValue()))),
		formatPruneDetail("context", pruneIDValue(styled, styles, plainRequestContextsSummary(p.Source.GetContext()))),
		targetRefPruneDetail("found_migrated_target", p.MigratedTarget, styled, styles),
	}
}
