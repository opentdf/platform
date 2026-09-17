//nolint:forbidigo // should be able to print tables as needed
package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/evertras/bubble-table/table"
	"github.com/spf13/cobra"
)

func NewTabular(rows ...[]string) table.Model {
	columnKeyProperty := "Property"
	columnKeyValue := "Value"
	t := NewTable(
		table.NewFlexColumn(columnKeyProperty, columnKeyProperty, FlexColumnWidthOne),
		table.NewFlexColumn(columnKeyValue, columnKeyValue, FlexColumnWidthTwo),
	)

	tr := []table.Row{}
	if len(rows) == 0 {
		tr = append(tr, table.NewRow(table.RowData{
			columnKeyProperty: "No properties found",
			columnKeyValue:    "",
		}))
	}
	for _, r := range rows {
		p := r[0]
		v := ""
		if len(r) > 1 {
			v = r[1]
		}
		tr = append(tr, table.NewRow(table.RowData{
			columnKeyProperty: p,
			columnKeyValue:    v,
		}))
	}

	t = t.WithTargetWidth(TermWidth())

	t = t.WithRows(tr)
	return t
}

func getJSONHelper(command string) string {
	return fmt.Sprintf("Use '%s --json' to see all properties", command)
}

// unsafeCmdName is the group holding destructive variants; it owns no `list`.
const unsafeCmdName = "unsafe"

// hasSubcommand reports whether parent owns a subcommand under the given name
// or one of its aliases.
func hasSubcommand(parent *cobra.Command, name string) bool {
	for _, sub := range parent.Commands() {
		if sub.Name() == name || sub.HasAlias(name) {
			return true
		}
	}
	return false
}

// successMessages builds the success line and the footer hint for a completed
// command, in that order.
func successMessages(cmd *cobra.Command, id string, rows int) (string, string) {
	parent := cmd.Parent()
	if parent == nil {
		// A root command names no resource and has no sibling to point at.
		return cmd.Name(), ""
	}
	// Names, not Use: a command built from a man doc carries its operands there
	// ("get <id>"), which never matched the actions below and left the line blank.
	resourceShort := parent.Name()
	resource := parent.Name()
	for p := parent; p.Parent() != nil; p = p.Parent() {
		resource = p.Parent().Name() + " " + resource
	}

	// Offer a hint only where the command it names exists. Groups such as
	// `folders` and `users` have no `get`, and the hint sent readers to a
	// command that errors out.
	hint := func(owner *cobra.Command, path, action, suffix string) string {
		if !hasSubcommand(owner, action) {
			return ""
		}
		return getJSONHelper(path + " " + action + suffix)
	}
	getHint := func() string {
		target := id
		if target == "" {
			target = "<id>"
		}
		return hint(parent, resource, ActionGet, " --id="+target)
	}
	// `unsafe` holds no `list`; its parent does, and that is the path to name.
	listOwner, listPath := parent, resource
	if parent.Name() == unsafeCmdName && parent.Parent() != nil {
		listOwner, listPath = parent.Parent(), strings.ReplaceAll(resource, " "+unsafeCmdName, "")
	}
	listHint := func() string { return hint(listOwner, listPath, ActionList, "") }

	var msg struct {
		verb   string
		helper string
	}
	switch cmd.Name() {
	case ActionGet:
		msg.verb = fmt.Sprintf("Found %s: %s", resourceShort, id)
		msg.helper = getHint()
	case ActionCreate:
		msg.verb = fmt.Sprintf("Created %s: %s", resourceShort, id)
		msg.helper = getHint()
	case ActionUpdate:
		msg.verb = fmt.Sprintf("Updated %s: %s", resourceShort, id)
		msg.helper = getHint()
	case ActionDelete:
		msg.verb = fmt.Sprintf("Deleted %s: %s", resourceShort, id)
		msg.helper = listHint()
	case ActionDeactivate:
		msg.verb = fmt.Sprintf("Deactivated %s: %s", resourceShort, id)
		// TODO: pass the state filter so the deactivated row is still listed.
		msg.helper = listHint()
	case ActionList:
		if rows == 0 {
			// A header-only table reads like the command failed, so say so
			// plainly and skip the table below.
			msg.verb = fmt.Sprintf("No %s found", resourceShort)
		} else {
			msg.verb = fmt.Sprintf("Found %s list", resourceShort)
			msg.helper = getHint()
		}
	default:
		// Every command reports its outcome. Returning an empty message here
		// printed a bare SUCCESS bar with no text for any verb outside the list
		// above, such as `upload`, `download`, or `add`.
		msg.verb = fmt.Sprintf("%s %s", resourceShort, cmd.Name())
		if id != "" {
			msg.verb += ": " + id
		}
		msg.helper = getHint()
	}

	return msg.verb, msg.helper
}

func PrintSuccessTable(cmd *cobra.Command, id string, t table.Model) {
	rows := t.TotalRows()
	verb, helper := successMessages(cmd, id, rows)

	successMessage := SuccessMessage(verb)
	jsonDirections := FooterMessage(helper)

	ts := t.View()
	if rows == 0 {
		// Column headers over no rows read as a failure, but a static footer
		// carries the pagination counts, which are the only way to tell an empty
		// collection from an over-shot offset. Hiding the header renders the
		// footer alone, and renders nothing at all when there is no footer.
		ts = t.WithHeaderVisibility(false).View()
	}
	if strings.TrimSpace(ts) == "" {
		fmt.Println(lipgloss.JoinVertical(lipgloss.Top, successMessage, jsonDirections))
		return
	}

	fmt.Println(lipgloss.JoinVertical(lipgloss.Top, successMessage, ts, jsonDirections))
}
