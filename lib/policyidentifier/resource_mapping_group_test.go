package policyidentifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceMappingGroupFQN(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		groupName string
		want      string
	}{
		{
			name:      "basic example",
			namespace: "example.com",
			groupName: "test_group",
			want:      "https://example.com/resm/test_group",
		},
		{
			name:      "with subdomain",
			namespace: "sub.example.com",
			groupName: "test_group",
			want:      "https://sub.example.com/resm/test_group",
		},
		{
			name:      "with dashes",
			namespace: "example.com",
			groupName: "test-group",
			want:      "https://example.com/resm/test-group",
		},
		{
			name:      "with underscores",
			namespace: "example.com",
			groupName: "test_group",
			want:      "https://example.com/resm/test_group",
		},
		{
			name:      "with numbers",
			namespace: "example.com",
			groupName: "test123",
			want:      "https://example.com/resm/test123",
		},
		{
			name:      "lower case",
			namespace: "EXAMPle.com",
			groupName: "TEST123",
			want:      "https://example.com/resm/test123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rmg := &FullyQualifiedResourceMappingGroup{
				Namespace: tt.namespace,
				GroupName: tt.groupName,
			}
			got := rmg.FQN()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestResourceMappingGroupValidate(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		groupName string
		wantErr   bool
	}{
		// Valid cases
		{
			name:      "valid basic",
			namespace: "example.com",
			groupName: "test_group",
			wantErr:   false,
		},
		{
			name:      "valid with subdomain",
			namespace: "sub.example.com",
			groupName: "test_group",
			wantErr:   false,
		},
		{
			name:      "valid with dashes",
			namespace: "example.com",
			groupName: "test-group",
			wantErr:   false,
		},

		// Invalid cases
		{
			name:      "invalid namespace",
			namespace: "invalid",
			groupName: "test_group",
			wantErr:   true,
		},
		{
			name:      "invalid group name - starts with underscore",
			namespace: "example.com",
			groupName: "_test_group",
			wantErr:   true,
		},
		{
			name:      "invalid group name - ends with hyphen",
			namespace: "example.com",
			groupName: "test_group-",
			wantErr:   true,
		},
		{
			name:      "empty namespace",
			namespace: "",
			groupName: "test_group",
			wantErr:   true,
		},
		{
			name:      "empty group name",
			namespace: "example.com",
			groupName: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rmg := &FullyQualifiedResourceMappingGroup{
				Namespace: tt.namespace,
				GroupName: tt.groupName,
			}

			err := rmg.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseResourceMappingGroupFqn(t *testing.T) {
	tests := []struct {
		name          string
		fqn           string
		wantNamespace string
		wantGroupName string
		wantErr       bool
	}{
		{
			name:          "valid basic",
			fqn:           "https://namespace.com/resm/group_name",
			wantNamespace: "namespace.com",
			wantGroupName: "group_name",
			wantErr:       false,
		},
		{
			name:          "valid with subdomain",
			fqn:           "https://sub.example.com/resm/test_group",
			wantNamespace: "sub.example.com",
			wantGroupName: "test_group",
			wantErr:       false,
		},
		{
			name:          "valid with special characters",
			fqn:           "https://example.com/resm/test-group_123",
			wantNamespace: "example.com",
			wantGroupName: "test-group_123",
			wantErr:       false,
		},
		{
			name:          "lower cases",
			fqn:           "https://NAMEspace.com/resm/GROUP-xyz",
			wantNamespace: "namespace.com",
			wantGroupName: "group-xyz",
			wantErr:       false,
		},
		{
			name:    "empty string",
			fqn:     "",
			wantErr: true,
		},
		{
			name:    "invalid format",
			fqn:     "invalid",
			wantErr: true,
		},
		{
			name:    "wrong protocol",
			fqn:     "http://namespace.com/resm/group_name",
			wantErr: true,
		},
		{
			name:    "missing segments",
			fqn:     "https://namespace.com",
			wantErr: true,
		},
		{
			name:    "wrong path",
			fqn:     "https://namespace.com/resource/group_name",
			wantErr: true,
		},
		{
			name:    "extra prefix",
			fqn:     "somethinghttps://namespace.com/resm/group_name",
			wantErr: true,
		},
		{
			name:    "missing group name",
			fqn:     "https://namespace.com/resm/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseResourceMappingGroupFqn(tt.fqn)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResourceMappingGroupFqn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			require.Equal(t, tt.wantNamespace, got.Namespace)
			require.Equal(t, tt.wantGroupName, got.GroupName)
		})
	}
}

func TestResourceMappingGroupRoundTrip(t *testing.T) {
	// Test round trip from struct to FQN to parse and back
	tests := []struct {
		name      string
		namespace string
		groupName string
	}{
		{
			name:      "basic example",
			namespace: "example.com",
			groupName: "test_group",
		},
		{
			name:      "with subdomain",
			namespace: "sub.example.com",
			groupName: "test_group",
		},
		{
			name:      "with special characters",
			namespace: "example.com",
			groupName: "test-group_123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original resource mapping group
			original := &FullyQualifiedResourceMappingGroup{
				Namespace: tt.namespace,
				GroupName: tt.groupName,
			}

			// Get FQN
			fqn := original.FQN()

			// Parse the FQN
			parsed, err := parseResourceMappingGroupFqn(fqn)
			require.NoError(t, err)

			// Check the parsed values match original
			require.Equal(t, original.Namespace, parsed.Namespace)
			require.Equal(t, original.GroupName, parsed.GroupName)

			// Ensure the re-generated FQN matches the original
			require.Equal(t, fqn, parsed.FQN())
		})
	}
}
