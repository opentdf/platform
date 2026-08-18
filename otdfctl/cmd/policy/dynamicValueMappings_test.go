package policy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
)

func TestParseDynamicValueMappingActions(t *testing.T) {
	uuid1 := "891cfe85-b381-4f85-9699-5f7dbfe2a9ab"
	uuid2 := "3c51a593-cd4d-4b74-9f97-3b3b6b0a6f21"

	tests := []struct {
		name  string
		input []string
		want  []*policy.Action
	}{
		{
			name:  "empty slice",
			input: []string{},
			want:  []*policy.Action{},
		},
		{
			name:  "name reference",
			input: []string{"read"},
			want:  []*policy.Action{{Name: "read"}},
		},
		{
			name:  "uuid reference",
			input: []string{uuid1},
			want:  []*policy.Action{{Id: uuid1}},
		},
		{
			name:  "mixed ids and names",
			input: []string{uuid1, "read", uuid2, "create"},
			want: []*policy.Action{
				{Id: uuid1},
				{Name: "read"},
				{Id: uuid2},
				{Name: "create"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDynamicValueMappingActions(tt.input)
			require.Len(t, got, len(tt.want))
			for i, action := range got {
				require.Equal(t, tt.want[i].GetId(), action.GetId())
				require.Equal(t, tt.want[i].GetName(), action.GetName())
			}
		})
	}
}

func TestValidateDynamicValueMappingOperator(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    policy.SubjectMappingOperatorEnum
		wantErr bool
	}{
		{
			name:  "IN accepted",
			input: "IN",
			want:  policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		},
		{
			name:  "IN_CONTAINS accepted",
			input: "IN_CONTAINS",
			want:  policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS,
		},
		{
			name:    "NOT_IN rejected",
			input:   "NOT_IN",
			wantErr: true,
		},
		{
			name:    "UNSPECIFIED rejected",
			input:   "UNSPECIFIED",
			wantErr: true,
		},
		{
			name:    "unknown rejected",
			input:   "SOMETHING_ELSE",
			wantErr: true,
		},
		{
			name:    "empty rejected",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateDynamicValueMappingOperator(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
