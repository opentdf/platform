package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProfileStoreFlagRegisteredWhereItIsRead pins the defect that set-default
// and set-endpoint resolved their profile driver from a --store flag neither
// command registered. GetOptionalString returns "" for an unregistered flag, so
// the selection silently fell back to the default driver, and passing --store
// failed as an unknown flag.
//
// InitProfileCommands runs from cmd's init, so the flags are already in place.
func TestProfileStoreFlagRegisteredWhereItIsRead(t *testing.T) {
	// Every command that resolves its driver from --store, whether through
	// newProfilerFromCLI or getDriverTypeFromUser directly.
	readsStoreFlag := []*cobra.Command{
		profileListCmd,
		profileGetCmd,
		profileDeleteCmd,
		profileDeleteAllCmd,
		profileSetDefaultCmd,
		profileSetEndpointCmd,
	}

	for _, cmd := range readsStoreFlag {
		t.Run(cmd.Name(), func(t *testing.T) {
			f := cmd.Flags().Lookup("store")
			require.NotNil(t, f, "%q resolves its driver from --store, so it must register the flag", cmd.Name())
			assert.Equal(t, "filesystem", f.DefValue)
		})
	}
}

// TestProfileSetDefaultAcceptsStoreFlag is the end-to-end form: parsing the
// flag used to fail outright on this command.
func TestProfileSetDefaultAcceptsStoreFlag(t *testing.T) {
	err := profileSetDefaultCmd.ParseFlags([]string{"--store", "keyring"})
	require.NoError(t, err)

	store, err := profileSetDefaultCmd.Flags().GetString("store")
	require.NoError(t, err)
	assert.Equal(t, "keyring", store)

	// Leave the shared command as InitProfileCommands built it.
	require.NoError(t, profileSetDefaultCmd.Flags().Set("store", "filesystem"))
}
