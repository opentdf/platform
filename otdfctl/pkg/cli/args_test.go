package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforceSubcommandArgs(t *testing.T) {
	root := &cobra.Command{Use: "otdfctl"}
	group := &cobra.Command{Use: "policy"}
	nested := &cobra.Command{Use: "attributes"}
	leaf := &cobra.Command{Use: "list", Run: func(*cobra.Command, []string) {}}
	positional := &cobra.Command{
		Use:  "get <id>",
		Args: cobra.ExactArgs(1),
		Run:  func(*cobra.Command, []string) {},
	}
	nested.AddCommand(leaf, positional)
	group.AddCommand(nested)
	root.AddCommand(group)

	EnforceSubcommandArgs(root)

	t.Run("groups become runnable and reject stray args", func(t *testing.T) {
		for _, cmd := range []*cobra.Command{root, group, nested} {
			require.True(t, cmd.Runnable(), "%q should be runnable", cmd.Name())
			assert.True(t, IsHelpOnly(cmd), "%q should be marked help-only", cmd.Name())
			require.Error(t, cmd.Args(cmd, []string{"bogus"}), "%q should reject an unknown subcommand", cmd.Name())
			require.NoError(t, cmd.Args(cmd, nil), "%q with no args should still print help", cmd.Name())
		}
	})

	t.Run("commands with their own Run are untouched", func(t *testing.T) {
		assert.Nil(t, leaf.Args)
		assert.False(t, IsHelpOnly(leaf))
	})

	t.Run("declared positional args are preserved", func(t *testing.T) {
		require.NoError(t, positional.Args(positional, []string{"one"}))
		require.Error(t, positional.Args(positional, nil))
		assert.False(t, IsHelpOnly(positional))
	})
}

// TestEnforceSubcommandArgsIsIdempotent covers being called more than once, for
// example by a consumer that assembles its tree in stages.
func TestEnforceSubcommandArgsIsIdempotent(t *testing.T) {
	root := &cobra.Command{Use: "otdfctl"}
	group := &cobra.Command{Use: "policy"}
	group.AddCommand(&cobra.Command{Use: "list", Run: func(*cobra.Command, []string) {}})
	root.AddCommand(group)

	EnforceSubcommandArgs(root)
	EnforceSubcommandArgs(root)

	require.True(t, group.Runnable())
	assert.True(t, IsHelpOnly(group))
	assert.Error(t, group.Args(group, []string{"bogus"}))
}

// TestEnforceSubcommandArgsRejectsUnknownNestedCommand drives cobra end to end,
// which is where the defect actually showed: Execute returned nil and the
// process exited 0 on a typo.
func TestEnforceSubcommandArgsRejectsUnknownNestedCommand(t *testing.T) {
	newTree := func() *cobra.Command {
		root := &cobra.Command{Use: "otdfctl", SilenceErrors: true, SilenceUsage: true}
		group := &cobra.Command{Use: "policy"}
		group.AddCommand(&cobra.Command{Use: "list", Run: func(*cobra.Command, []string) {}})
		root.AddCommand(group)
		return root
	}

	t.Run("before", func(t *testing.T) {
		root := newTree()
		root.SetArgs([]string{"policy", "bogus"})
		root.SetOut(&nopWriter{})
		err := root.Execute()
		require.NoError(t, err, "test premise: cobra swallows flag.ErrHelp and reports success")
	})

	t.Run("after", func(t *testing.T) {
		root := newTree()
		EnforceSubcommandArgs(root)
		root.SetArgs([]string{"policy", "bogus"})
		root.SetOut(&nopWriter{})

		err := root.Execute()

		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown command "bogus" for "otdfctl policy"`)
	})
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
