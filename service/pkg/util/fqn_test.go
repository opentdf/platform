package util

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseResourceMappingGroupFqn_Valid_Succeeds(t *testing.T) {
	fqn := "https://namespace.com/resm/group_name"

	parsed, err := ParseResourceMappingGroupFqn(fqn)
	require.NoError(t, err)
	require.Equal(t, fqn, parsed.Fqn)
	require.Equal(t, "namespace.com", parsed.Namespace)
	require.Equal(t, "group_name", parsed.GroupName)
}

func TestParseResourceMappingGroupFqn_Invalid_Fails(t *testing.T) {
	invalidFQNs := []string{
		"",
		"invalid",
		"https://namespace.com",
		"http://namespace.com/resm/group_name",
		"somethinghttps://namespace.com/resm/group_name",
		"https://namespace.com/resm",
		"https://namespace.com/resm/",
	}

	for _, fqn := range invalidFQNs {
		parsed, err := ParseResourceMappingGroupFqn(fqn)
		require.EqualError(t, err, "error: valid FQN format of https://<namespace>/resm/<group name> must be provided")
		require.Nil(t, parsed)
	}
}

func TestParseRegisteredResourceValueFqn_Valid_Succeeds(t *testing.T) {
	fqn := "https://reg_res/valid/value/test"

	parsed, err := ParseRegisteredResourceValueFqn(fqn)
	require.NoError(t, err)
	require.Equal(t, fqn, parsed.Fqn)
	require.Equal(t, "valid", parsed.Name)
	require.Equal(t, "test", parsed.Value)
}

func TestParseRegisteredResourceValueFqn_Invalid_Fails(t *testing.T) {
	invalidFQNs := []string{
		"",
		"invalid",
		"https://reg_res",
		"https://reg_res/invalid",
		"http://reg_res/test/value/something",
		"somethinghttps://reg_res/test/value/something",
		"https://reg_res/invalid/value",
		"https://reg_res/invalid/value/",
	}

	for _, fqn := range invalidFQNs {
		parsed, err := ParseRegisteredResourceValueFqn(fqn)
		require.ErrorIs(t, err, ErrInvalidFQNFormat)
		require.Nil(t, parsed)
	}
}

func TestParseAttributeFqn(t *testing.T) {
	// Test cases for the ParseAttributeFqn function
	tests := []struct {
		name          string
		fqn           string
		wantNamespace string
		wantName      string
		wantValue     string
		wantErr       bool
	}{
		{
			name:          "Valid namespace only FQN",
			fqn:           "https://example.org",
			wantNamespace: "example.org",
			wantName:      "",
			wantValue:     "",
			wantErr:       false,
		},
		{
			name:          "Valid attribute definition FQN",
			fqn:           "https://example.org/attr/classification",
			wantNamespace: "example.org",
			wantName:      "classification",
			wantValue:     "",
			wantErr:       false,
		},
		{
			name:          "Valid attribute value FQN",
			fqn:           "https://example.org/attr/classification/value/secret",
			wantNamespace: "example.org",
			wantName:      "classification",
			wantValue:     "secret",
			wantErr:       false,
		},
		{
			name:          "Valid attribute value FQN with complex namespace",
			fqn:           "https://subdomain.example.org/attr/classification/value/secret",
			wantNamespace: "subdomain.example.org",
			wantName:      "classification",
			wantValue:     "secret",
			wantErr:       false,
		},
		{
			name:          "Valid attribute definition FQN with special characters in name",
			fqn:           "https://example.org/attr/special-chars_123",
			wantNamespace: "example.org",
			wantName:      "special-chars_123",
			wantValue:     "",
			wantErr:       false,
		},
		{
			name:          "Valid attribute value FQN with special characters in value",
			fqn:           "https://example.org/attr/classification/value/top-secret_123",
			wantNamespace: "example.org",
			wantName:      "classification",
			wantValue:     "top-secret_123",
			wantErr:       false,
		},
		{
			name:    "Invalid FQN - empty string",
			fqn:     "",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - missing https",
			fqn:     "example.org/attr/classification",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - wrong protocol",
			fqn:     "http://example.org/attr/classification",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - wrong path between namespace and name",
			fqn:     "https://example.org/attributes/classification",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - missing name",
			fqn:     "https://example.org/attr/",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - value path but no value",
			fqn:     "https://example.org/attr/classification/value/",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - extra segments",
			fqn:     "https://example.org/attr/classification/value/secret/extra",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAttributeFqn(tt.fqn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAttributeFqn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.Namespace != tt.wantNamespace {
				t.Errorf("ParseAttributeFqn() namespace = %v, want %v", got.Namespace, tt.wantNamespace)
			}
			if got.Name != tt.wantName {
				t.Errorf("ParseAttributeFqn() name = %v, want %v", got.Name, tt.wantName)
			}
			if got.Value != tt.wantValue {
				t.Errorf("ParseAttributeFqn() value = %v, want %v", got.Value, tt.wantValue)
				return
			}
		})
	}
}

func TestValidObjectNameRegex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid cases
		{"Simple alphanumeric", "abc123", true},
		{"Single letter", "a", true},
		{"Single number", "1", true},
		{"With underscore middle", "abc_123", true},
		{"With hyphen middle", "abc-123", true},
		{"Max length 253", "a" + strings.Repeat("b", 251) + "c", true},

		// Invalid cases
		{"With dot middle", "abc.123", false},
		{"Mixed special chars", "abc-123_def.456", false},
		{"Empty string", "", false},
		{"Underscore start", "_abc123", false},
		{"Underscore end", "abc123_", false},
		{"Hyphen start", "-abc123", false},
		{"Hyphen end", "abc123-", false},
		{"Dot start", ".abc123", false},
		{"Dot end", "abc123.", false},
		{"Special character", "abc@123", false},
		{"With spaces", "abc 123", false},
		{"Too long > 253", "a" + strings.Repeat("b", 252) + "c", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validObjectNameRegex.MatchString(tt.input)
			if got != tt.want {
				t.Errorf("validObjectNameRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidNamespaceRegex(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      bool
	}{
		// Valid namespaces
		{
			name:      "simple domain",
			namespace: "example.com",
			want:      true,
		},
		{
			name:      "subdomain",
			namespace: "sub.example.com",
			want:      true,
		},
		{
			name:      "multiple subdomains",
			namespace: "deep.sub.example.com",
			want:      true,
		},
		{
			name:      "with numbers",
			namespace: "example123.com",
			want:      true,
		},
		{
			name:      "domain with hyphen",
			namespace: "example-domain.com",
			want:      true,
		},
		{
			name:      "complex domain",
			namespace: "my-example123.sub.example-domain.com",
			want:      true,
		},
		{
			name:      "minimum valid domain",
			namespace: "a.co",
			want:      true,
		},
		{
			name:      "long segment at max 63 char limit",
			namespace: "abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz-abcdefghi.com",
			want:      true,
		},

		// Invalid namespaces
		{
			name:      "empty string",
			namespace: "",
			want:      false,
		},
		{
			name:      "no TLD",
			namespace: "example",
			want:      false,
		},
		{
			name:      "TLD too short",
			namespace: "example.c",
			want:      false,
		},
		{
			name:      "numeric TLD",
			namespace: "example.123",
			want:      false,
		},
		{
			name:      "hyphen at start of segment",
			namespace: "-example.com",
			want:      false,
		},
		{
			name:      "hyphen at end of segment",
			namespace: "example-.com",
			want:      false,
		},
		{
			name:      "segment too long (> 63 chars)",
			namespace: "abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz-abcdefghij.com",
			want:      false,
		},
		{
			name:      "invalid characters",
			namespace: "example_domain.com",
			want:      false,
		},
		{
			name:      "starts with dot",
			namespace: ".example.com",
			want:      false,
		},
		{
			name:      "ends with dot",
			namespace: "example.com.",
			want:      false,
		},
		{
			name:      "double dots",
			namespace: "example..com",
			want:      false,
		},
		{
			name:      "IP address format",
			namespace: "192.168.1.1",
			want:      false, // This is actually invalid because TLD must be letters
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validNamespaceRegex.MatchString(tt.namespace); got != tt.want {
				t.Errorf("validNamespaceRegex.MatchString(%q) = %v, want %v", tt.namespace, got, tt.want)
			}
		})
	}
}
