package identifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse_AttributeFqn(t *testing.T) {
	// Test the generic Parse function with FullyQualifiedAttribute type
	testCases := []struct {
		name     string
		fqn      string
		wantErr  bool
		checkFqn func(*testing.T, *FullyQualifiedAttribute)
	}{
		{
			name:    "Valid namespace only FQN",
			fqn:     "https://example.org",
			wantErr: false,
			checkFqn: func(t *testing.T, fqa *FullyQualifiedAttribute) {
				require.Equal(t, "example.org", fqa.Namespace)
				require.Equal(t, "", fqa.Name)
				require.Equal(t, "", fqa.Value)
			},
		},
		{
			name:    "Valid attribute definition FQN",
			fqn:     "https://example.org/attr/classification",
			wantErr: false,
			checkFqn: func(t *testing.T, fqa *FullyQualifiedAttribute) {
				require.Equal(t, "example.org", fqa.Namespace)
				require.Equal(t, "classification", fqa.Name)
				require.Equal(t, "", fqa.Value)
			},
		},
		{
			name:    "Valid attribute value FQN",
			fqn:     "https://example.org/attr/classification/value/secret",
			wantErr: false,
			checkFqn: func(t *testing.T, fqa *FullyQualifiedAttribute) {
				require.Equal(t, "example.org", fqa.Namespace)
				require.Equal(t, "classification", fqa.Name)
				require.Equal(t, "secret", fqa.Value)
			},
		},
		{
			name:    "Invalid FQN format",
			fqn:     "invalid",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Parse[*FullyQualifiedAttribute](tc.fqn)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			tc.checkFqn(t, result)
		})
	}
}

func TestParse_ResourceMappingGroupFqn(t *testing.T) {
	// Test the generic Parse function with FullyQualifiedResourceMappingGroup type
	testCases := []struct {
		name     string
		fqn      string
		wantErr  bool
		checkFqn func(*testing.T, *FullyQualifiedResourceMappingGroup)
	}{
		{
			name:    "Valid resource mapping group FQN",
			fqn:     "https://example.org/resm/group1",
			wantErr: false,
			checkFqn: func(t *testing.T, fqrmg *FullyQualifiedResourceMappingGroup) {
				require.Equal(t, "example.org", fqrmg.Namespace)
				require.Equal(t, "group1", fqrmg.GroupName)
			},
		},
		{
			name:    "Invalid FQN format",
			fqn:     "invalid",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Parse[*FullyQualifiedResourceMappingGroup](tc.fqn)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			tc.checkFqn(t, result)
		})
	}
}

func TestParse_RegisteredResourceValueFqn(t *testing.T) {
	// Test the generic Parse function with FullyQualifiedRegisteredResourceValue type
	testCases := []struct {
		name     string
		fqn      string
		wantErr  bool
		checkFqn func(*testing.T, *FullyQualifiedRegisteredResourceValue)
	}{
		{
			name:    "Valid registered resource value FQN",
			fqn:     "https://reg_res/resource1/value/value1",
			wantErr: false,
			checkFqn: func(t *testing.T, fqrrv *FullyQualifiedRegisteredResourceValue) {
				require.Equal(t, "resource1", fqrrv.Name)
				require.Equal(t, "value1", fqrrv.Value)
			},
		},
		{
			name:    "Invalid FQN format",
			fqn:     "invalid",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Parse[*FullyQualifiedRegisteredResourceValue](tc.fqn)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			tc.checkFqn(t, result)
		})
	}
}

type mockType struct{}

func (m *mockType) FQN() string {
	return "https://example.org/mock"
}
func (m *mockType) Validate() error {
	return nil
}

func TestParse_UnsupportedType(t *testing.T) {
	// Test the generic Parse function with an unsupported type
	_, err := Parse[*mockType]("https://example.org")
	require.Error(t, err)
	// TODO: named error
	require.ErrorIs(t, err, ErrUnsupportedFQNType)
}
