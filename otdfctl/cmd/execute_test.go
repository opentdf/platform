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

// mountForTest assembles a consumer root the way Execute does when WithMountTo
// is supplied: mount otdfctl under it, then validate the whole tree. The
// consumer owns a group of its own so both sides of the mount are covered.
// RootCmd is package state, so the mount is undone afterwards, and the mounted
// name is read back rather than assumed (Test_MountRootWithRename renames it).
func mountForTest(t *testing.T) (*cobra.Command, string) {
	t.Helper()

	consumerRoot := &cobra.Command{Use: "consumer", SilenceErrors: true, SilenceUsage: true}
	consumerGroup := &cobra.Command{Use: "widgets"}
	consumerGroup.AddCommand(&cobra.Command{Use: "list", Run: func(*cobra.Command, []string) {}})
	consumerRoot.AddCommand(consumerGroup)

	require.NoError(t, MountRoot(consumerRoot, nil))
	cli.EnforceSubcommandArgs(consumerRoot)

	t.Cleanup(func() { consumerRoot.RemoveCommand(RootCmd) })

	consumerRoot.SetOut(io.Discard)
	consumerRoot.SetErr(io.Discard)
	return consumerRoot, RootCmd.Name()
}

// TestMountedRootRejectsUnknownSubcommand covers the mounted form of the
// defect, where cobra's own safeguards do the least work. Cobra rejects an
// unknown subcommand only at the true root, and mounting makes otdfctl's root a
// subcommand, so every level here depends on this change: the otdfctl root on
// the NoArgs that ProcessDoc now assigns, and both groups on
// EnforceSubcommandArgs, which has to run against the assembled tree.
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

// TestMountedRootKeepsValidInvocations guards against the validation above
// rejecting the arguments a mounted otdfctl is supposed to accept.
func TestMountedRootKeepsValidInvocations(t *testing.T) {
	root, mounted := mountForTest(t)

	// Resolution only. Running these would reach real command handlers.
	for _, args := range [][]string{
		{mounted},
		{mounted, "policy"},
		{mounted, "profile", "list"},
		{"widgets", "list"},
	} {
		cmd, _, err := root.Find(args)
		if !assert.NoError(t, err, "%v should resolve", args) {
			continue
		}
		assert.NoError(t, cmd.ValidateArgs(nil), "%v should accept no positional arguments", args)
	}
}
