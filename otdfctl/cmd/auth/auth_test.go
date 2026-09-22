package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyringUnavailable(t *testing.T) {
	InitCommands()
	login, _, err := Cmd.Find([]string{"login"})
	require.NoError(t, err)

	assert.False(t, keyringUnavailable(Cmd, "linux"), "the group only prints help")
	assert.True(t, keyringUnavailable(login, "linux"), "a subcommand does touch the keyring")
	assert.False(t, keyringUnavailable(login, "darwin"), "other platforms have a keyring")
}
