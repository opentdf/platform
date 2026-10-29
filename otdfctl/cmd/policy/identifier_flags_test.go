package policy

import (
	"testing"

	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInjectIDFQNLookupFlags(t *testing.T) {
	tests := []struct {
		name      string
		flags     map[string]string
		wantError string
	}{
		{
			name:      "missing identifier",
			wantError: "at least one of the flags in the group [id fqn] is required",
		},
		{
			name:  "id only",
			flags: map[string]string{"id": "15d8d6c6-ef44-47a7-9e13-2367b90a64fe"},
		},
		{
			name:  "fqn only",
			flags: map[string]string{"fqn": "https://example.com/attr/classification"},
		},
		{
			name: "both identifiers",
			flags: map[string]string{
				"id":  "15d8d6c6-ef44-47a7-9e13-2367b90a64fe",
				"fqn": "https://example.com/attr/classification",
			},
			wantError: "if any flags in the group [id fqn] are set none of the others can be",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &man.Doc{
				Command: cobra.Command{Use: "get"},
				DocFlags: []man.DocFlag{
					{Name: "id", Shorthand: "i", Description: "ID"},
					{Name: "fqn", Shorthand: "f", Description: "FQN"},
				},
			}
			injectIDFQNLookupFlags(doc)

			for name, value := range tt.flags {
				require.NoError(t, doc.Flags().Set(name, value))
			}

			err := doc.ValidateFlagGroups()
			if tt.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}
