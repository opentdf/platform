package cli

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTree builds a command tree shaped like the real one: a root, a
// resource group that owns a `get`, and a second group that does not.
func newTestTree(t *testing.T) *cobra.Command {
	t.Helper()

	root := &cobra.Command{Use: "otdfctl"}
	policy := &cobra.Command{Use: "policy"}

	// A group with a `get`, whose Use carries a positional argument the way a
	// man-doc command does.
	attributes := &cobra.Command{Use: "attributes"}
	attributes.AddCommand(
		&cobra.Command{Use: "get <id>"},
		&cobra.Command{Use: "create"},
		&cobra.Command{Use: "update"},
		&cobra.Command{Use: "delete"},
		&cobra.Command{Use: "deactivate"},
		&cobra.Command{Use: "list"},
	)

	// `unsafe` holds destructive variants and owns no `list` of its own, so its
	// hint has to name the parent's.
	unsafe := &cobra.Command{Use: "unsafe"}
	unsafe.AddCommand(&cobra.Command{Use: "delete"})
	attributes.AddCommand(unsafe)

	// A group with no `get`, which is what made the hint point at a command
	// that does not exist.
	folders := &cobra.Command{Use: "folders"}
	folders.AddCommand(
		&cobra.Command{Use: "create"},
		&cobra.Command{Use: "list"},
		&cobra.Command{Use: "upload"},
	)

	// A group with neither, to catch a hint naming a `list` that is not there.
	keys := &cobra.Command{Use: "keys"}
	keys.AddCommand(
		&cobra.Command{Use: "delete"},
		&cobra.Command{Use: "deactivate"},
	)

	policy.AddCommand(attributes, folders, keys)
	root.AddCommand(policy)
	return root
}

func find(t *testing.T, root *cobra.Command, path ...string) *cobra.Command {
	t.Helper()
	cmd, _, err := root.Find(path)
	require.NoError(t, err)
	require.Equal(t, path[len(path)-1], cmd.Name())
	return cmd
}

func TestSuccessMessagesVerbs(t *testing.T) {
	root := newTestTree(t)

	tests := []struct {
		name string
		path []string
		id   string
		rows int
		want string
	}{
		{"get", []string{"policy", "attributes", "get"}, "abc", 1, "Found attributes: abc"},
		{"create", []string{"policy", "attributes", "create"}, "abc", 1, "Created attributes: abc"},
		{"update", []string{"policy", "attributes", "update"}, "abc", 1, "Updated attributes: abc"},
		{"delete", []string{"policy", "attributes", "delete"}, "abc", 1, "Deleted attributes: abc"},
		{"deactivate", []string{"policy", "attributes", "deactivate"}, "abc", 1, "Deactivated attributes: abc"},
		{"list", []string{"policy", "attributes", "list"}, "", 3, "Found attributes list"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verb, _ := successMessages(find(t, root, tc.path...), tc.id, tc.rows)
			assert.Equal(t, tc.want, verb)
		})
	}
}

// TestSuccessMessagesMatchesCommandWithPositionalArgs pins the reason `get`
// reported nothing for man-doc commands: their Use is "get <id>", so matching
// on Use rather than the command name fell through to the empty default.
func TestSuccessMessagesMatchesCommandWithPositionalArgs(t *testing.T) {
	cmd := find(t, newTestTree(t), "policy", "attributes", "get")
	require.Equal(t, "get <id>", cmd.Use, "test premise: Use carries the argument")

	verb, helper := successMessages(cmd, "abc", 1)

	assert.Equal(t, "Found attributes: abc", verb)
	assert.Contains(t, helper, "otdfctl policy attributes get --id=abc")
}

// TestSuccessMessagesAlwaysReportsAnOutcome covers verbs outside the known set,
// which previously produced a SUCCESS bar with no text at all.
func TestSuccessMessagesAlwaysReportsAnOutcome(t *testing.T) {
	cmd := find(t, newTestTree(t), "policy", "folders", "upload")

	t.Run("with an id", func(t *testing.T) {
		verb, _ := successMessages(cmd, "abc", 1)
		assert.Equal(t, "folders upload: abc", verb)
		assert.NotEmpty(t, verb)
	})

	t.Run("without an id", func(t *testing.T) {
		verb, _ := successMessages(cmd, "", 1)
		assert.Equal(t, "folders upload", verb)
		assert.NotEmpty(t, verb)
	})
}

// TestSuccessMessagesHintOnlyWhenGetExists pins the hint defect: the footer
// suggested `<resource> get --id=…` for every group, including those with no
// `get` subcommand.
func TestSuccessMessagesHintOnlyWhenGetExists(t *testing.T) {
	root := newTestTree(t)

	t.Run("group with a get", func(t *testing.T) {
		_, helper := successMessages(find(t, root, "policy", "attributes", "create"), "abc", 1)
		assert.Equal(t, "Use 'otdfctl policy attributes get --id=abc --json' to see all properties", helper)
	})

	t.Run("group without a get", func(t *testing.T) {
		for _, leaf := range []string{"create", "list", "upload"} {
			_, helper := successMessages(find(t, root, "policy", "folders", leaf), "abc", 1)
			assert.Empty(t, helper, "leaf %q must not point at a get that does not exist", leaf)
		}
	})
}

// delete and deactivate point at a `list` rather than a `get`, and had the same
// defect: the hint was emitted whether or not that command existed.
func TestSuccessMessagesListHintOnlyWhenListExists(t *testing.T) {
	root := newTestTree(t)

	t.Run("group with a list", func(t *testing.T) {
		for _, leaf := range []string{"delete", "deactivate"} {
			_, helper := successMessages(find(t, root, "policy", "attributes", leaf), "abc", 1)
			assert.Equal(t, "Use 'otdfctl policy attributes list --json' to see all properties", helper, leaf)
		}
	})

	t.Run("group without a list", func(t *testing.T) {
		for _, leaf := range []string{"delete", "deactivate"} {
			_, helper := successMessages(find(t, root, "policy", "keys", leaf), "abc", 1)
			assert.Empty(t, helper, "leaf %q must not point at a list that does not exist", leaf)
		}
	})

	// `unsafe` owns no list, so the hint names the parent's and drops the
	// segment from the path.
	t.Run("under unsafe", func(t *testing.T) {
		_, helper := successMessages(find(t, root, "policy", "attributes", "unsafe", "delete"), "abc", 1)
		assert.Equal(t, "Use 'otdfctl policy attributes list --json' to see all properties", helper)
	})
}

// A root command has no parent to name the resource from.
func TestSuccessMessagesOnRootCommand(t *testing.T) {
	root := newTestTree(t)

	require.NotPanics(t, func() {
		verb, helper := successMessages(root, "", 0)
		assert.Equal(t, "otdfctl", verb)
		assert.Empty(t, helper)
	})
}

// TestSuccessMessagesKeepsIDPlaceholderLiteral guards the `<id>` placeholder in
// the list hint against being escaped or substituted.
func TestSuccessMessagesKeepsIDPlaceholderLiteral(t *testing.T) {
	_, helper := successMessages(find(t, newTestTree(t), "policy", "attributes", "list"), "", 2)

	assert.Contains(t, helper, "--id=<id>")
	assert.NotContains(t, helper, "&lt;")
}

// TestSuccessMessagesEmptyList replaces the header-only table, which read as a
// failure, with a statement that nothing was found.
func TestSuccessMessagesEmptyList(t *testing.T) {
	verb, helper := successMessages(find(t, newTestTree(t), "policy", "attributes", "list"), "", 0)

	assert.Equal(t, "No attributes found", verb)
	assert.Empty(t, helper, "there is nothing for the hint to point at")
}

// captureStdout collects what fn writes to os.Stdout. PrintSuccessTable prints
// there directly, so this is the only way to assert on what it renders.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	out := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		out <- buf.String()
	}()

	fn()

	require.NoError(t, w.Close())
	return <-out
}

// TestPrintSuccessTableOmitsEmptyTable is the output-level half of
// TestSuccessMessagesEmptyList: a zero-row result must report that nothing was
// found and print no table, because a header-only table reads as a failure.
func TestPrintSuccessTableOmitsEmptyTable(t *testing.T) {
	cmd := find(t, newTestTree(t), "policy", "attributes", "list")
	empty := NewTable(table.NewFlexColumn("id", "ID", FlexColumnWidthFive))

	t.Run("no rows", func(t *testing.T) {
		out := captureStdout(t, func() { PrintSuccessTable(cmd, "", empty) })

		assert.Contains(t, out, "No attributes found")
		assert.NotContains(t, out, "ID", "the header-only table must not be rendered")
		assert.NotContains(t, out, "│", "no table borders should reach stdout")
	})

	// A list command attaches its pagination counts as a static footer, which
	// only reaches stdout through the table's own View. Suppressing the whole
	// view for an empty result took the counts with it, so an over-shot --offset
	// reported "none found" and gave no hint that the collection was not empty.
	t.Run("no rows but a pagination footer", func(t *testing.T) {
		paged := WithListPaginationFooter(empty, &policy.PageResponse{Total: 10, CurrentOffset: 999})

		out := captureStdout(t, func() { PrintSuccessTable(cmd, "", paged) })

		assert.Contains(t, out, "No attributes found")
		assert.Contains(t, out, "Total: 10", "the pagination counts must survive an empty page")
		assert.Contains(t, out, "Current Offset: 999")
		assert.NotContains(t, out, "ID", "the column header is still suppressed")
	})

	t.Run("with rows", func(t *testing.T) {
		populated := empty.WithRows([]table.Row{
			table.NewRow(table.RowData{"id": "abc-123"}),
		})

		out := captureStdout(t, func() { PrintSuccessTable(cmd, "", populated) })

		assert.Contains(t, out, "Found attributes list")
		assert.Contains(t, out, "abc-123", "test premise: a populated table still renders")
	})
}

func TestHasSubcommand(t *testing.T) {
	root := newTestTree(t)

	attributes := find(t, root, "policy", "attributes")
	assert.True(t, hasSubcommand(attributes, ActionGet))
	assert.False(t, hasSubcommand(attributes, "upload"))

	folders := find(t, root, "policy", "folders")
	assert.False(t, hasSubcommand(folders, ActionGet))
	assert.True(t, hasSubcommand(folders, ActionList))
}
