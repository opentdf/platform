package namespacedpolicy

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/opentdf/platform/otdfctl/migrations"
)

type summaryCounts struct {
	applied          int
	pending          int
	existingStandard int
	alreadyMigrated  int
	skipped          int
	blocked          int
	failed           int
	unresolved       int
}

type summaryOperation string

const (
	summaryOperationMigration summaryOperation = "migration"
	summaryOperationPrune     summaryOperation = "prune"
)

type constructSummary struct {
	label      string
	include    bool
	counts     summaryCounts
	applied    []string
	pending    []string
	failed     []string
	skipped    []string
	blocked    []string
	unresolved []string
}

type operationExecutionState string

const (
	operationExecutionStateApplied operationExecutionState = "applied"
	operationExecutionStatePending operationExecutionState = "pending"
	operationExecutionStateFailed  operationExecutionState = "failed"
)

type summaryDocument struct {
	plannedTitle   string
	committedTitle string
	operation      summaryOperation
	scopes         []Scope
	commit         bool
	result         string
	summaries      []constructSummary
}

func renderSummaryDocument(styles *migrations.DisplayStyles, doc summaryDocument) string {
	var b strings.Builder
	if doc.commit {
		b.WriteString(styles.Title().Render(doc.committedTitle))
	} else {
		b.WriteString(styles.Title().Render(doc.plannedTitle))
	}
	b.WriteByte('\n')
	b.WriteString(styles.Separator().Render(styles.SeparatorText()))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%s %s\n", styles.Info().Render("Scopes:"), styles.Info().Render(joinScopeLabels(doc.scopes)))
	fmt.Fprintf(&b, "%s %t\n", styles.Info().Render("Commit:"), doc.commit)
	b.WriteString(styles.Info().Render("Result: " + strings.TrimSpace(doc.result)))
	b.WriteByte('\n')

	for _, summary := range doc.summaries {
		if !summary.include {
			continue
		}
		b.WriteByte('\n')
		b.WriteString(styles.Title().Render(summary.label))
		b.WriteByte('\n')
		b.WriteString(styles.Separator().Render(styles.SeparatorText()))
		b.WriteByte('\n')
		fmt.Fprintf(&b, "%s %s\n", styles.Info().Render("Counts:"), formatConstructSummaryCounts(summary.counts, doc.operation, doc.commit))

		appendSummarySection(&b, appliedSummarySection(doc.operation), styles.Action(), summary.applied)
		appendSummarySection(&b, pendingSummarySection(doc.operation), styles.Action(), summary.pending)
		appendSummarySection(&b, "Failed", styles.Warning(), summary.failed)
		appendSummarySection(&b, "Skipped", styles.Warning(), summary.skipped)
		appendSummarySection(&b, "Blocked", styles.Warning(), summary.blocked)
		appendSummarySection(&b, "Unresolved", styles.Warning(), summary.unresolved)
	}

	return strings.TrimRight(b.String(), "\n")
}

func appendSummarySection(b *strings.Builder, label string, style lipgloss.Style, lines []string) {
	if len(lines) == 0 {
		return
	}
	b.WriteByte('\n')
	b.WriteString(style.Render(label))
	b.WriteByte('\n')
	for _, line := range lines {
		b.WriteString("  - ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
}

func includesScope(scopes []Scope, scope Scope) bool {
	for _, candidate := range scopes {
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

func formatConstructSummaryCounts(counts summaryCounts, operation summaryOperation, commit bool) string {
	var parts []string
	if commit {
		parts = append(parts, fmt.Sprintf("%s=%d", appliedSummaryCount(operation), counts.applied))
	}
	if !commit || counts.pending > 0 {
		parts = append(parts, fmt.Sprintf("%s=%d", pendingSummaryCount(operation), counts.pending))
	}
	if operation == summaryOperationMigration {
		parts = appendMigrationSummaryCountParts(parts, counts)
	}
	parts = append(parts, fmt.Sprintf("skipped=%d", counts.skipped))
	if operation == summaryOperationPrune {
		parts = appendPruneSummaryCountParts(parts, counts)
	}
	parts = append(parts,
		fmt.Sprintf("failed=%d", counts.failed),
		fmt.Sprintf("unresolved=%d", counts.unresolved),
	)
	return strings.Join(parts, " ")
}

func appliedSummaryCount(operation summaryOperation) string {
	if operation == summaryOperationPrune {
		return pruneAppliedCountLabel
	}
	return migrationAppliedCountLabel
}

func pendingSummaryCount(operation summaryOperation) string {
	if operation == summaryOperationPrune {
		return prunePendingCountLabel
	}
	return migrationPendingCountLabel
}

func appliedSummarySection(operation summaryOperation) string {
	if operation == summaryOperationPrune {
		return pruneAppliedSectionLabel
	}
	return migrationAppliedSectionLabel
}

func pendingSummarySection(operation summaryOperation) string {
	if operation == summaryOperationPrune {
		return prunePendingSectionLabel
	}
	return migrationPendingSectionLabel
}

func executionFailure(execution *ExecutionResult) string {
	if execution == nil {
		return ""
	}
	return execution.Failure
}
