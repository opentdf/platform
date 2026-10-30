package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthCommandsDoNotBlockLinuxKeyring(t *testing.T) {
	InitCommands()
	// Linux availability is determined by the store/Secret Service operation,
	// never by a blanket auth-group pre-run that exits before login or logout.
	require.Nil(t, Cmd.PersistentPreRun)
	require.Nil(t, Cmd.PersistentPreRunE)
	for _, name := range []string{"login", "logout", "client-credentials"} {
		cmd, _, err := Cmd.Find([]string{name})
		require.NoError(t, err)
		require.NotSame(t, Cmd, cmd)
		require.NotNil(t, cmd.Run)
	}
}
