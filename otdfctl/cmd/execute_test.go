package cmd

import (
	"io"
	"os"
	"testing"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MountRoot(t *testing.T) {
	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	rootCmd := cobra.Command{
		Use:   "new-root",
		Short: "new-root short",
		Long:  "new-root long",
	}

	err := MountRoot(&rootCmd, nil)
	require.NoError(t, err)

	assert.Equal(t, "new-root", rootCmd.Use)
	assert.Equal(t, "new-root short", rootCmd.Short)
	assert.Equal(t, "new-root long", rootCmd.Long)

	err = rootCmd.Execute()
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	require.NoError(t, err)

	// Ensure the old root is added with the existing name
	assert.Contains(t, string(buf[:n]), "otdfctl")

	os.Stdout = origStdout
}

func Test_MountRootWithRename(t *testing.T) {
	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	rootCmd := cobra.Command{
		Use:   "new-root",
		Short: "new-root short",
		Long:  "new-root long",
	}

	err := MountRoot(&rootCmd, &cobra.Command{
		Use:   "rename-otdfctl",
		Short: "rename-otdfctl short",
		Long:  "rename-otdfctl long",
	})
	require.NoError(t, err)

	assert.Equal(t, "new-root", rootCmd.Use)
	assert.Equal(t, "new-root short", rootCmd.Short)
	assert.Equal(t, "new-root long", rootCmd.Long)

	err = rootCmd.Execute()
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	require.NoError(t, err)

	// Ensure the old root is added as a subcommand and renamed
	assert.Contains(t, string(buf[:n]), "rename-otdfctl")

	os.Stdout = origStdout
}

func Test_MountRootError(t *testing.T) {
	require.Error(t, MountRoot(nil, nil))
	require.Error(t, MountRoot(nil, &cobra.Command{
		Use:   "rename-otdfctl",
		Short: "rename-otdfctl short",
		Long:  "rename-otdfctl long",
	}))
}

// mountForTest assembles and later removes a mounted consumer tree.
func mountForTest(t *testing.T) (*cobra.Command, string) {
	t.Helper()

	consumerRoot := &cobra.Command{Use: "consumer", SilenceErrors: true, SilenceUsage: true}
	consumerGroup := &cobra.Command{Use: "widgets"}
	consumerGroup.AddCommand(&cobra.Command{Use: "list", Run: func(*cobra.Command, []string) {}})
	consumerRoot.AddCommand(consumerGroup)

	require.NoError(t, MountRoot(consumerRoot, nil))
	enforceArgs(consumerRoot)

	t.Cleanup(func() { consumerRoot.RemoveCommand(RootCmd) })

	consumerRoot.SetOut(io.Discard)
	consumerRoot.SetErr(io.Discard)
	return consumerRoot, RootCmd.Name()
}

func TestMountedRootRejectsUnknownSubcommand(t *testing.T) {
	tests := []struct {
		name string
		args func(mounted string) []string
		want func(mounted string) string
	}{
		{
			name: "otdfctl root",
			args: func(m string) []string { return []string{m, "bogus"} },
			want: func(m string) string { return `unknown command "bogus" for "consumer ` + m + `"` },
		},
		{
			name: "otdfctl group",
			args: func(m string) []string { return []string{m, "policy", "bogus"} },
			want: func(m string) string { return `unknown command "bogus" for "consumer ` + m + ` policy"` },
		},
		{
			name: "consumer group",
			args: func(string) []string { return []string{"widgets", "bogus"} },
			want: func(string) string { return `unknown command "bogus" for "consumer widgets"` },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, mounted := mountForTest(t)
			root.SetArgs(tc.args(mounted))

			err := root.Execute()

			require.Error(t, err, "%v should be rejected", tc.args(mounted))
			assert.Equal(t, tc.want(mounted), err.Error())
		})
	}
}

func TestEveryRunnableCommandDeclaresItsArgs(t *testing.T) {
	cli.EnforceSubcommandArgs(RootCmd)

	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Runnable() {
			assert.NotNil(t, c.Args,
				"%q runs a handler, so it must declare the operands it takes (use cobra.NoArgs for none)",
				c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(RootCmd)
}

func TestMountedRootKeepsValidInvocations(t *testing.T) {
	root, mounted := mountForTest(t)

	for _, args := range [][]string{
		{mounted},
		{mounted, "policy"},
		{mounted, "profile"},
		{"widgets"},
	} {
		cmd, _, err := root.Find(args)
		if !assert.NoError(t, err, "%v should resolve", args) {
			continue
		}
		assert.NoError(t, cmd.ValidateArgs(nil), "%v is a valid bare invocation", args)
		require.Error(t, cmd.ValidateArgs([]string{"bogus"}), "%v takes no operand, so a stray one must fail", args)
	}

	del, _, err := root.Find([]string{mounted, "profile", "delete"})
	require.NoError(t, err)
	assert.NoError(t, del.ValidateArgs([]string{"my-profile"}))

	comp, _, err := root.Find([]string{"completion"})
	require.NoError(t, err)
	require.Equal(t, "completion", comp.Name(), "cobra's completion command must be in the tree")
	require.Error(t, comp.ValidateArgs([]string{"bogus"}))
	assert.True(t, comp.Runnable(), "NoArgs is only consulted once the group is runnable")
}

func TestPreserveJSONFlagOnError(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "after invalid flag", args: []string{"list", "--badarg", "--json"}, want: true},
		{name: "explicit true", args: []string{"list", "--badarg", "--json=true"}, want: true},
		{name: "last true", args: []string{"list", "--json=false", "--badarg", "--json"}, want: true},
		{name: "last false", args: []string{"list", "--json", "--badarg", "--json=false"}},
		{name: "long flag value", args: []string{"list", "--filename", "--json", "--badarg"}},
		{name: "short flag value", args: []string{"list", "-f", "--json", "--badarg"}},
		{name: "after separator", args: []string{"list", "--badarg", "--", "--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := &cobra.Command{Use: "root", SilenceErrors: true, SilenceUsage: true}
			root.PersistentFlags().Bool("json", false, "")
			list := &cobra.Command{Use: "list", Run: func(*cobra.Command, []string) {}}
			list.Flags().StringP("filename", "f", "", "")
			root.AddCommand(list)
			preserveJSONFlagOnError(root, tc.args)
			root.SetArgs(tc.args)

			cmd, err := root.ExecuteC()

			require.Error(t, err)
			jsonOut, flagErr := cmd.Flags().GetBool("json")
			require.NoError(t, flagErr)
			assert.Equal(t, tc.want, jsonOut)
		})
	}
}
