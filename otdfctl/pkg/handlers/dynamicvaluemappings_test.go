package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetAttributeDefinitionIDAndFQN(t *testing.T) {
	uuid := "891cfe85-b381-4f85-9699-5f7dbfe2a9ab"
	fqn := "https://hospital.co/attr/mrn"

	tests := []struct {
		name    string
		input   string
		wantID  string
		wantFQN string
	}{
		{
			name:   "uuid is treated as an id",
			input:  uuid,
			wantID: uuid,
		},
		{
			name:    "fqn is treated as an fqn",
			input:   fqn,
			wantFQN: fqn,
		},
		{
			name:    "non-uuid string is treated as an fqn",
			input:   "not-a-uuid",
			wantFQN: "not-a-uuid",
		},
		{
			name:  "empty string yields empty id and fqn",
			input: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotFQN := getAttributeDefinitionIDAndFQN(tt.input)
			require.Equal(t, tt.wantID, gotID)
			require.Equal(t, tt.wantFQN, gotFQN)
		})
	}
}
