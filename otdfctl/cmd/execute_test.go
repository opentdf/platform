package cmd

import (
	"os"
	"testing"

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
