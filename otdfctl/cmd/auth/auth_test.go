package auth

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func Test_AuthCommands_InheritRootPreRun_Succeeds(t *testing.T) {
	InitCommands()
	require.Nil(t, Cmd.PersistentPreRun)
	require.Nil(t, Cmd.PersistentPreRunE)

	preRunErr := errors.New("root pre-run reached")
	root := &cobra.Command{
		Use:           "otdfctl",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return preRunErr
		},
	}
	root.AddCommand(Cmd)
	t.Cleanup(func() { root.RemoveCommand(Cmd) })

	for _, command := range Cmd.Commands() {
		if !command.Runnable() {
			continue
		}
		t.Run(command.Name(), func(t *testing.T) {
			root.SetArgs([]string{"auth", command.Name()})
			require.ErrorIs(t, root.Execute(), preRunErr)
		})
	}
}
