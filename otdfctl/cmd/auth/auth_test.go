package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The keyring warning exits non-zero, so it must not fire for the bare group,
// which EnforceSubcommandArgs made runnable purely so that `auth bogus` fails.
func TestKeyringUnavailable(t *testing.T) {
	InitCommands()
	login, _, err := Cmd.Find([]string{"login"})
	assert.NoError(t, err)

	assert.False(t, keyringUnavailable(Cmd, "linux"), "the group only prints help")
	assert.True(t, keyringUnavailable(login, "linux"), "a subcommand does touch the keyring")
	assert.False(t, keyringUnavailable(login, "darwin"), "other platforms have a keyring")
}
