package identifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttributeFQN(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		attrName  string
		value     string
		want      string
	}{
		// Namespace-only FQNs
		{
			name:      "namespace only",
			namespace: "example.com",
			want:      "https://example.com",
		},
		{
			name:      "namespace with subdomain only",
			namespace: "sub.example.com",
			want:      "https://sub.example.com",
		},
		{
			name:      "namespace lower cased",
			namespace: "EXAMPLE.com",
			want:      "https://example.com",
		},

		// Definition FQNs
		{
			name:      "definition",
			namespace: "example.com",
			attrName:  "classification",
			want:      "https://example.com/attr/classification",
		},
		{
			name:      "definition with hyphen",
			namespace: "example.com",
			attrName:  "security-level",
			want:      "https://example.com/attr/security-level",
		},
		{
			name:      "definition with underscore",
			namespace: "example.com",
			attrName:  "security_level",
			want:      "https://example.com/attr/security_level",
		},
		{
			name:      "definition with numbers",
			namespace: "example.com",
			attrName:  "level123",
			want:      "https://example.com/attr/level123",
		},
		{
			name:      "definition lower cased",
			namespace: "EXAMPLE.com",
			attrName:  "TEst",
			want:      "https://example.com/attr/test",
		},

		// Value FQNs
		{
			name:      "value",
			namespace: "example.com",
			attrName:  "classification",
			value:     "secret",
			want:      "https://example.com/attr/classification/value/secret",
		},
		{
			name:      "complex value",
			namespace: "sub.example.com",
			attrName:  "security-level",
			value:     "top_secret123",
			want:      "https://sub.example.com/attr/security-level/value/top_secret123",
		},
		{
			name:      "value lower cased",
			namespace: "EXAMPLE.com",
			attrName:  "TEst",
			value:     "VALUE",
			want:      "https://example.com/attr/test/value/value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := &FullyQualifiedAttribute{
				Namespace: tt.namespace,
				Name:      tt.attrName,
				Value:     tt.value,
			}
			got := attr.FQN()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestAttributeValidate(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		attrName  string
		value     string
		wantErr   bool
	}{
		// Valid cases
		{
			name:      "valid namespace only",
			namespace: "example.com",
			attrName:  "",
			value:     "",
			wantErr:   false,
		},
		{
			name:      "valid definition",
			namespace: "example.com",
			attrName:  "classification",
			value:     "",
			wantErr:   false,
		},
		{
			name:      "valid value",
			namespace: "example.com",
			attrName:  "classification",
			value:     "secret",
			wantErr:   false,
		},

		// Invalid cases
		{
			name:      "invalid namespace - no TLD",
			namespace: "example",
			attrName:  "",
			value:     "",
			wantErr:   true,
		},
		{
			name:      "invalid namespace - starts with hyphen",
			namespace: "-example.com",
			attrName:  "",
			value:     "",
			wantErr:   true,
		},
		{
			name:      "invalid attribute name - starts with underscore",
			namespace: "example.com",
			attrName:  "_classification",
			value:     "",
			wantErr:   true,
		},
		{
			name:      "invalid attribute name - ends with hyphen",
			namespace: "example.com",
			attrName:  "classification-",
			value:     "",
			wantErr:   true,
		},
		{
			name:      "invalid value - starts with hyphen",
			namespace: "example.com",
			attrName:  "classification",
			value:     "-secret",
			wantErr:   true,
		},
		{
			name:      "invalid value - ends with underscore",
			namespace: "example.com",
			attrName:  "classification",
			value:     "secret_",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := &FullyQualifiedAttribute{
				Namespace: tt.namespace,
				Name:      tt.attrName,
				Value:     tt.value,
			}

			err := attr.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseAttributeFqn(t *testing.T) {
	// Test cases for the parseAttributeFqn function
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
			name:          "Valid attribute value FQN gets lower cased",
			fqn:           "https://example.org/attr/hello/value/WORLD",
			wantNamespace: "example.org",
			wantName:      "hello",
			wantValue:     "world",
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
			got, err := parseAttributeFqn(tt.fqn)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAttributeFqn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.Namespace != tt.wantNamespace {
				t.Errorf("parseAttributeFqn() namespace = %v, want %v", got.Namespace, tt.wantNamespace)
			}
			if got.Name != tt.wantName {
				t.Errorf("parseAttributeFqn() name = %v, want %v", got.Name, tt.wantName)
			}
			if got.Value != tt.wantValue {
				t.Errorf("parseAttributeFqn() value = %v, want %v", got.Value, tt.wantValue)
				return
			}
		})
	}
}

func TestAttributeRoundTrip(t *testing.T) {
	// Test round trip from struct to FQN to parse and back
	tests := []struct {
		name      string
		namespace string
		attrName  string
		value     string
	}{
		{
			name:      "namespace only",
			namespace: "example.com",
			attrName:  "",
			value:     "",
		},
		{
			name:      "definition",
			namespace: "example.com",
			attrName:  "classification",
			value:     "",
		},
		{
			name:      "value",
			namespace: "example.com",
			attrName:  "classification",
			value:     "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original attribute
			original := &FullyQualifiedAttribute{
				Namespace: tt.namespace,
				Name:      tt.attrName,
				Value:     tt.value,
			}

			// Get FQN
			fqn := original.FQN()

			// Parse the FQN
			parsed, err := parseAttributeFqn(fqn)
			require.NoError(t, err)

			// Check the parsed values match original
			require.Equal(t, original.Namespace, parsed.Namespace)
			require.Equal(t, original.Name, parsed.Name)
			require.Equal(t, original.Value, parsed.Value)

			// Ensure the re-generated FQN matches the original
			require.Equal(t, fqn, parsed.FQN())
		})
	}
}
