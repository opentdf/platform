package namespacedpolicy

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/otdfctl/migrations"
)

type pruneSummaryItem interface {
	prunePlanItem
	summaryLine(*migrations.DisplayStyles) string
}

const (
	pruneAppliedCountLabel   = "deleted"
	prunePendingCountLabel   = "to_delete"
	pruneAppliedSectionLabel = "Deleted"
	prunePendingSectionLabel = "Will Delete"
)

// PruneSummaryResult identifies the overall prune command outcome shown in the
// rendered summary.
type PruneSummaryResult string

const (
	// PruneSummaryResultSuccess indicates the prune command completed without error.
	PruneSummaryResultSuccess PruneSummaryResult = "success"
	// PruneSummaryResultFailure indicates prune commit execution failed.
	PruneSummaryResultFailure PruneSummaryResult = "failure"
	// PruneSummaryResultAborted indicates the user aborted an interactive prune flow.
	PruneSummaryResultAborted PruneSummaryResult = "aborted"
)

func prunePlanScopes(plan *PrunePlan) []Scope {
	if plan == nil {
		return nil
	}
	return plan.Scopes
}

func RenderNamespacedPolicyPruneSummary(plan *PrunePlan, executed bool, result PruneSummaryResult) string {
	styles := migrations.NewDisplayStyles()
	return renderSummaryDocument(styles, summaryDocument{
		plannedTitle:   "Namespaced Policy Prune Plan",
		committedTitle: "Namespaced Policy Prune Committed",
		operation:      summaryOperationPrune,
		scopes:         prunePlanScopes(plan),
		commit:         executed,
		result:         string(result),
		summaries: []constructSummary{
			summarizePruneActions(plan, executed, styles),
			summarizePruneSubjectConditionSets(plan, executed, styles),
			summarizePruneSubjectMappings(plan, executed, styles),
			summarizePruneRegisteredResources(plan, executed, styles),
			summarizePruneObligationTriggers(plan, executed, styles),
		},
	})
}

func appendPruneSummaryCountParts(parts []string, counts summaryCounts) []string {
	return append(parts, fmt.Sprintf("blocked=%d", counts.blocked))
}

func summarizePruneActions(plan *PrunePlan, executed bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Actions",
		include: includesScope(prunePlanScopes(plan), ScopeActions),
	}
	if plan == nil {
		return summary
	}
	for _, action := range plan.Actions {
		if action == nil || action.Source == nil {
			continue
		}
		appendPruneStatusSummary(&summary, action, executed, styles)
	}
	return summary
}

func summarizePruneSubjectConditionSets(plan *PrunePlan, executed bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Subject Condition Sets",
		include: includesScope(prunePlanScopes(plan), ScopeSubjectConditionSets),
	}
	if plan == nil {
		return summary
	}
	for _, scs := range plan.SubjectConditionSets {
		if scs == nil || scs.Source == nil {
			continue
		}
		appendPruneStatusSummary(&summary, scs, executed, styles)
	}
	return summary
}

func summarizePruneSubjectMappings(plan *PrunePlan, executed bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Subject Mappings",
		include: includesScope(prunePlanScopes(plan), ScopeSubjectMappings),
	}
	if plan == nil {
		return summary
	}
	for _, mapping := range plan.SubjectMappings {
		if mapping == nil || mapping.Source == nil {
			continue
		}
		appendPruneStatusSummary(&summary, mapping, executed, styles)
	}
	return summary
}

func summarizePruneRegisteredResources(plan *PrunePlan, executed bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Registered Resources",
		include: includesScope(prunePlanScopes(plan), ScopeRegisteredResources),
	}
	if plan == nil {
		return summary
	}
	for _, resource := range plan.RegisteredResources {
		if resource == nil || resource.Source == nil {
			continue
		}
		appendPruneStatusSummary(&summary, resource, executed, styles)
	}
	return summary
}

func summarizePruneObligationTriggers(plan *PrunePlan, executed bool, styles *migrations.DisplayStyles) constructSummary {
	summary := constructSummary{
		label:   "Obligation Triggers",
		include: includesScope(prunePlanScopes(plan), ScopeObligationTriggers),
	}
	if plan == nil {
		return summary
	}
	for _, trigger := range plan.ObligationTriggers {
		if trigger == nil || trigger.Source == nil {
			continue
		}
		appendPruneStatusSummary(&summary, trigger, executed, styles)
	}
	return summary
}

func appendPruneStatusSummary[T pruneSummaryItem](summary *constructSummary, item T, executed bool, styles *migrations.DisplayStyles) {
	switch item.status() {
	case PruneStatusDelete:
		switch classifyPruneExecution(executed, item.execution()) {
		case operationExecutionStateApplied:
			summary.counts.applied++
			summary.applied = append(summary.applied, item.summaryLine(styles))
		case operationExecutionStateFailed:
			summary.counts.failed++
			summary.failed = append(summary.failed, item.summaryLine(styles))
		case operationExecutionStatePending:
			summary.counts.pending++
			summary.pending = append(summary.pending, item.summaryLine(styles))
		}
	case PruneStatusBlocked:
		summary.counts.blocked++
		summary.blocked = append(summary.blocked, item.summaryLine(styles))
	case PruneStatusUnresolved:
		summary.counts.unresolved++
		summary.unresolved = append(summary.unresolved, item.summaryLine(styles))
	case PruneStatusSkipped:
		summary.counts.skipped++
		summary.skipped = append(summary.skipped, item.summaryLine(styles))
	}
}

func classifyPruneExecution(executed bool, execution *ExecutionResult) operationExecutionState {
	if !executed || execution == nil {
		return operationExecutionStatePending
	}
	if len(strings.TrimSpace(execution.Failure)) != 0 {
		return operationExecutionStateFailed
	}
	if execution.Applied {
		return operationExecutionStateApplied
	}
	return operationExecutionStatePending
}

func (p *PruneActionPlan) summaryLine(styles *migrations.DisplayStyles) string {
	return renderPruneSummaryLine(
		formatPruneSourceLine(styles, actionKind, p.Source.GetName()),
		p.pruneDetails(true, styles),
		renderResultDetail(true, styles, p.Reason, p.Execution),
	)
}

func (p *PruneSubjectConditionSetPlan) summaryLine(styles *migrations.DisplayStyles) string {
	return renderPruneSummaryLine(
		formatPruneSourceLine(styles, subjectConditionSetKind, p.Source.GetId()),
		p.pruneDetails(true, styles),
		renderResultDetail(true, styles, p.Reason, p.Execution),
	)
}

func (p *PruneSubjectMappingPlan) summaryLine(styles *migrations.DisplayStyles) string {
	return renderPruneSummaryLine(
		formatPruneSourceLine(styles, subjectMappingKind, p.Source.GetId()),
		p.pruneDetails(true, styles),
		renderResultDetail(true, styles, p.Reason, p.Execution),
	)
}

func (p *PruneRegisteredResourcePlan) summaryLine(styles *migrations.DisplayStyles) string {
	return renderPruneSummaryLine(
		formatPruneSourceLine(styles, registeredResourceKind, p.Source.GetName()),
		p.pruneDetails(true, styles),
		renderResultDetail(true, styles, p.Reason, p.Execution),
	)
}

func (p *PruneObligationTriggerPlan) summaryLine(styles *migrations.DisplayStyles) string {
	return renderPruneSummaryLine(
		formatPruneSourceLine(styles, obligationTriggerKind, p.Source.GetId()),
		p.pruneDetails(true, styles),
		renderResultDetail(true, styles, p.Reason, p.Execution),
	)
}

func formatPruneSourceLine(styles *migrations.DisplayStyles, kind, label string) string {
	return fmt.Sprintf(
		"%s %s",
		styles.Info().Render(kind),
		styles.Name().Render(strconvQuote(label)),
	)
}
