package migrate

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddCommandsPreservesExistingAndAddsExtension(t *testing.T) {
	parent := &cobra.Command{Use: "migrate"}
	useMigrateCommand(t, parent)

	baseRan := false
	base := &cobra.Command{
		Use:   "namespaced-policy",
		Short: "base migration",
		Run: func(cmd *cobra.Command, args []string) {
			baseRan = true
		},
	}

	extensionRan := false
	extension := &cobra.Command{
		Use:   "tenant-policy",
		Short: "tenant migration",
		Run: func(cmd *cobra.Command, args []string) {
			extensionRan = true
		},
	}

	require.NoError(t, AddCommands(base))
	require.NoError(t, AddCommands(extension))

	foundBase, _, err := parent.Find([]string{"namespaced-policy"})
	require.NoError(t, err)
	assert.Same(t, base, foundBase)

	parent.SetArgs([]string{"tenant-policy"})
	require.NoError(t, parent.Execute())
	assert.False(t, baseRan)
	assert.True(t, extensionRan)

	var help bytes.Buffer
	parent.SetOut(&help)
	parent.SetErr(&bytes.Buffer{})
	parent.SetArgs([]string{"--help"})
	require.NoError(t, parent.Execute())
	assert.Contains(t, help.String(), "namespaced-policy")
	assert.Contains(t, help.String(), "tenant-policy")
}

func TestAddCommandsRejectsDuplicateNamesAndAliases(t *testing.T) {
	tests := []struct {
		name     string
		existing []*cobra.Command
		add      []*cobra.Command
		wantErr  error
		wantMsg  string
	}{
		{
			name:     "duplicate name",
			existing: []*cobra.Command{{Use: "namespaced-policy"}},
			add:      []*cobra.Command{{Use: "namespaced-policy"}},
			wantErr:  ErrMigrateCommandAlreadyRegistered,
			wantMsg:  `"namespaced-policy"`,
		},
		{
			name:     "duplicate alias",
			existing: []*cobra.Command{{Use: "namespaced-policy", Aliases: []string{"np"}}},
			add:      []*cobra.Command{{Use: "tenant-policy", Aliases: []string{"np"}}},
			wantErr:  ErrMigrateCommandAlreadyRegistered,
			wantMsg:  `"np"`,
		},
		{
			name:     "incoming command name matches existing alias",
			existing: []*cobra.Command{{Use: "namespaced-policy", Aliases: []string{"np"}}},
			add:      []*cobra.Command{{Use: "np"}},
			wantErr:  ErrMigrateCommandAlreadyRegistered,
			wantMsg:  `"np"`,
		},
		{
			name:    "duplicate in same call",
			add:     []*cobra.Command{{Use: "tenant-policy"}, {Use: "tenant-policy"}},
			wantErr: ErrMigrateCommandAlreadyRegistered,
			wantMsg: `"tenant-policy"`,
		},
		{
			name:    "nil command",
			add:     []*cobra.Command{nil},
			wantErr: ErrNilMigrateCommand,
		},
		{
			name:    "empty command name",
			add:     []*cobra.Command{{}},
			wantErr: ErrEmptyMigrateCommandName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := &cobra.Command{Use: "migrate"}
			useMigrateCommand(t, parent)
			require.NoError(t, AddCommands(tt.existing...))

			err := AddCommands(tt.add...)
			require.Error(t, err)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected errors.Is(%v), got %v", tt.wantErr, err)
			}
			if tt.wantMsg != "" {
				assert.ErrorContains(t, err, tt.wantMsg)
			}
		})
	}
}

func TestAddCommandsRequiresInitialization(t *testing.T) {
	parent := &cobra.Command{Use: "migrate"}
	useMigrateCommand(t, parent, false)

	err := AddCommands(&cobra.Command{Use: "tenant-policy"})
	require.ErrorIs(t, err, ErrMigrateCommandsNotInitialized)
}

func useMigrateCommand(t *testing.T, command *cobra.Command, isInitialized ...bool) {
	t.Helper()

	originalCmd := Cmd
	originalInitialized := initialized
	Cmd = command
	initialized = true
	if len(isInitialized) > 0 {
		initialized = isInitialized[0]
	}
	t.Cleanup(func() {
		Cmd = originalCmd
		initialized = originalInitialized
	})
}
