package identifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegisteredResourceValueFQN(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		resName   string
		value     string
		want      string
	}{
		{
			name:      "namespaced basic example",
			namespace: "example.com",
			resName:   "resource",
			value:     "value",
			want:      "https://example.com/reg_res/resource/value/value",
		},
		{
			name:      "namespaced with hyphens",
			namespace: "example.com",
			resName:   "test-resource",
			value:     "test-value",
			want:      "https://example.com/reg_res/test-resource/value/test-value",
		},
		{
			name:      "namespaced with underscores",
			namespace: "example.com",
			resName:   "test_resource",
			value:     "test_value",
			want:      "https://example.com/reg_res/test_resource/value/test_value",
		},
		{
			name:      "namespaced with numbers",
			namespace: "example.com",
			resName:   "resource123",
			value:     "value456",
			want:      "https://example.com/reg_res/resource123/value/value456",
		},
		{
			name:      "namespaced lower case",
			namespace: "EXAMPLE.COM",
			resName:   "RESOURCE",
			value:     "VALUE",
			want:      "https://example.com/reg_res/resource/value/value",
		},
		{
			name:    "legacy no namespace",
			resName: "resource",
			value:   "value",
			want:    "https://reg_res/resource/value/value",
		},
		{
			name:    "legacy with hyphens",
			resName: "test-resource",
			value:   "test-value",
			want:    "https://reg_res/test-resource/value/test-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrv := &FullyQualifiedRegisteredResourceValue{
				Namespace: tt.namespace,
				Name:      tt.resName,
				Value:     tt.value,
			}
			got := rrv.FQN()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestRegisteredResourceValueValidate(t *testing.T) {
	tests := []struct {
		name    string
		resName string
		value   string
		wantErr bool
	}{
		// Valid cases
		{
			name:    "valid basic",
			resName: "resource",
			value:   "value",
			wantErr: false,
		},
		{
			name:    "valid with hyphens",
			resName: "test-resource",
			value:   "test-value",
			wantErr: false,
		},
		{
			name:    "valid with underscores",
			resName: "test_resource",
			value:   "test_value",
			wantErr: false,
		},
		{
			name:    "valid with numbers",
			resName: "resource123",
			value:   "value456",
			wantErr: false,
		},

		// Invalid cases
		{
			name:    "invalid resource name - starts with underscore",
			resName: "_resource",
			value:   "test_value",
			wantErr: true,
		},
		{
			name:    "invalid resource name - ends with hyphen",
			resName: "resource-",
			value:   "test_value",
			wantErr: true,
		},
		{
			name:    "invalid value - starts with hyphen",
			resName: "resource",
			value:   "-value",
			wantErr: true,
		},
		{
			name:    "invalid value - ends with underscore",
			resName: "resource",
			value:   "value_",
			wantErr: true,
		},
		{
			name:    "empty resource name",
			resName: "",
			value:   "test_value",
			wantErr: true,
		},
		{
			name:    "empty value",
			resName: "test_resource",
			value:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrv := &FullyQualifiedRegisteredResourceValue{
				Name:  tt.resName,
				Value: tt.value,
			}

			err := rrv.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseRegisteredResourceValueFqn(t *testing.T) {
	tests := []struct {
		name          string
		fqn           string
		wantNamespace string
		wantName      string
		wantValue     string
		wantErr       bool
	}{
		// New format tests
		{
			name:          "valid namespaced basic",
			fqn:           "https://example.com/reg_res/valid/value/test",
			wantNamespace: "example.com",
			wantName:      "valid",
			wantValue:     "test",
			wantErr:       false,
		},
		{
			name:          "valid namespaced with hyphens",
			fqn:           "https://example.com/reg_res/test-resource/value/test-value",
			wantNamespace: "example.com",
			wantName:      "test-resource",
			wantValue:     "test-value",
			wantErr:       false,
		},
		{
			name:          "valid namespaced with underscores",
			fqn:           "https://example.com/reg_res/test_resource/value/test_value",
			wantNamespace: "example.com",
			wantName:      "test_resource",
			wantValue:     "test_value",
			wantErr:       false,
		},
		{
			name:          "valid namespaced with numbers",
			fqn:           "https://example.com/reg_res/resource123/value/value456",
			wantNamespace: "example.com",
			wantName:      "resource123",
			wantValue:     "value456",
			wantErr:       false,
		},
		{
			name:          "valid namespaced lower case",
			fqn:           "https://EXAMPLE.COM/reg_res/RESOURce/value/valUE",
			wantNamespace: "example.com",
			wantName:      "resource",
			wantValue:     "value",
			wantErr:       false,
		},
		// Legacy format tests
		{
			name:      "valid legacy basic",
			fqn:       "https://reg_res/valid/value/test",
			wantName:  "valid",
			wantValue: "test",
			wantErr:   false,
		},
		{
			name:      "valid legacy with hyphens",
			fqn:       "https://reg_res/test-resource/value/test-value",
			wantName:  "test-resource",
			wantValue: "test-value",
			wantErr:   false,
		},
		{
			name:      "valid legacy with underscores",
			fqn:       "https://reg_res/test_resource/value/test_value",
			wantName:  "test_resource",
			wantValue: "test_value",
			wantErr:   false,
		},
		{
			name:      "valid legacy with numbers",
			fqn:       "https://reg_res/resource123/value/value456",
			wantName:  "resource123",
			wantValue: "value456",
			wantErr:   false,
		},
		{
			name:      "valid legacy lower case",
			fqn:       "https://reg_res/RESOURce/value/valUE",
			wantName:  "resource",
			wantValue: "value",
			wantErr:   false,
		},
		// Invalid format tests
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
			name:    "missing parts",
			fqn:     "https://example.com/reg_res/valid",
			wantErr: true,
		},
		{
			name:    "missing value segment",
			fqn:     "https://example.com/reg_res/valid/value",
			wantErr: true,
		},
		{
			name:    "wrong protocol",
			fqn:     "http://example.com/reg_res/test/value/something",
			wantErr: true,
		},
		{
			name:    "extra prefix",
			fqn:     "somethinghttps://example.com/reg_res/test/value/something",
			wantErr: true,
		},
		{
			name:    "invalid namespace format",
			fqn:     "https://not_a_valid_namespace/reg_res/test/value/something",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRegisteredResourceValueFqn(tt.fqn)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRegisteredResourceValueFqn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			require.Equal(t, tt.wantNamespace, got.Namespace)
			require.Equal(t, tt.wantName, got.Name)
			require.Equal(t, tt.wantValue, got.Value)
		})
	}
}

func TestRegisteredResourceValueRoundTrip(t *testing.T) {
	// Test round trip from struct to FQN to parse and back
	tests := []struct {
		name      string
		namespace string
		resName   string
		value     string
	}{
		{
			name:      "namespaced basic example",
			namespace: "example.com",
			resName:   "resource",
			value:     "value",
		},
		{
			name:      "namespaced with hyphens",
			namespace: "example.com",
			resName:   "test-resource",
			value:     "test-value",
		},
		{
			name:      "namespaced with underscores",
			namespace: "my.namespace.org",
			resName:   "test_resource",
			value:     "test_value",
		},
		{
			name:      "namespaced with numbers",
			namespace: "example.com",
			resName:   "resource123",
			value:     "value456",
		},
		{
			name:    "legacy basic example",
			resName: "resource",
			value:   "value",
		},
		{
			name:    "legacy with hyphens",
			resName: "test-resource",
			value:   "test-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original registered resource value
			original := &FullyQualifiedRegisteredResourceValue{
				Namespace: tt.namespace,
				Name:      tt.resName,
				Value:     tt.value,
			}

			// Get FQN
			fqn := original.FQN()

			// Parse the FQN
			parsed, err := parseRegisteredResourceValueFqn(fqn)
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
