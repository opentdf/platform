package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	FlexColumnWidthOne   = 1
	FlexColumnWidthTwo   = 2
	FlexColumnWidthThree = 3
	FlexColumnWidthFour  = 4
	FlexColumnWidthFive  = 5
)

func NewTable(cols ...table.Column) table.Model {
	return table.New(cols).
		BorderRounded().
		WithBaseStyle(styleTable).
		WithNoPagination().
		WithTargetWidth(TermWidth())
}

func NewUUIDColumn() table.Column {
	return table.NewFlexColumn("id", "ID", FlexColumnWidthFive)
}

// Adds the page information to the table footer
func WithListPaginationFooter(t table.Model, p *policy.PageResponse) table.Model {
	info := []string{
		fmt.Sprintf("Total: %d", p.GetTotal()),
		fmt.Sprintf("Current Offset: %d", p.GetCurrentOffset()),
	}
	if p.GetNextOffset() > 0 {
		info = append(info, fmt.Sprintf("Next Offset: %d", p.GetNextOffset()))
	}

	content := strings.Join(info, "  |  ")

	leftAligned := lipgloss.NewStyle().Align(lipgloss.Left)
	return t.WithStaticFooter(content).WithBaseStyle(leftAligned)
}
