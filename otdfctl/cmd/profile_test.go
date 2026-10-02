package cmd

import (
	"testing"

	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfileStoreFlagRegisteredWhereItIsRead(t *testing.T) {
	for _, cmd := range storeFlagCommands() {
		t.Run(cmd.Name(), func(t *testing.T) {
			f := cmd.Flags().Lookup("store")
			require.NotNil(t, f, "%q resolves its driver from --store, so it must register the flag", cmd.Name())
			assert.Equal(t, string(profiles.ProfileDriverDefault), f.DefValue)
		})
	}
}

func TestProfileDeleteRequiresAProfile(t *testing.T) {
	require.NotNil(t, profileDeleteCmd.Args, "the command must declare its operands")

	require.Error(t, profileDeleteCmd.Args(profileDeleteCmd, nil),
		"no profile named: the handler would index args[0] on an empty slice")
	require.NoError(t, profileDeleteCmd.Args(profileDeleteCmd, []string{"my-profile"}))
	require.Error(t, profileDeleteCmd.Args(profileDeleteCmd, []string{"my-profile", "extra"}))
}

func TestProfileSetDefaultAcceptsStoreFlag(t *testing.T) {
	err := profileSetDefaultCmd.ParseFlags([]string{"--store", "keyring"})
	require.NoError(t, err)

	store, err := profileSetDefaultCmd.Flags().GetString("store")
	require.NoError(t, err)
	assert.Equal(t, "keyring", store)

	require.NoError(t, profileSetDefaultCmd.Flags().Set("store", "filesystem"))
}
