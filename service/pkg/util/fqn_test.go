package util

import (
	"testing"
)

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