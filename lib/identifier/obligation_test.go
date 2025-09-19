package identifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBreakOblFQN(t *testing.T) {
	validFQN := "https://namespace.com/obl/drm"
	nsFQN, oblName := BreakOblFQN(validFQN)
	require.Equal(t, "https://namespace.com", nsFQN)
	require.Equal(t, "drm", oblName)

	invalidFQN := ""
	nsFQN, oblName = BreakOblFQN(invalidFQN)
	require.Empty(t, nsFQN)
	require.Empty(t, oblName)
}

func TestBreakOblValFQN(t *testing.T) {
	validFQN := "https://namespace.com/obl/drm/value/watermark"
	nsFQN, oblName, valName := BreakOblValFQN(validFQN)
	require.Equal(t, "https://namespace.com", nsFQN)
	require.Equal(t, "drm", oblName)
	require.Equal(t, "watermark", valName)

	invalidFQN := ""
	nsFQN, oblName, valName = BreakOblValFQN(invalidFQN)
	require.Empty(t, nsFQN)
	require.Empty(t, oblName)
	require.Empty(t, valName)
}

func TestBuildOblFQN(t *testing.T) {
	nsFQN := "https://namespace.com"
	oblName := "drm"
	expectedFQN := nsFQN + "/obl/" + oblName
	fqn := BuildOblFQN(nsFQN, oblName)
	require.Equal(t, expectedFQN, fqn)
}

func TestBuildOblValFQN(t *testing.T) {
	nsFQN := "https://namespace.com"
	oblName := "drm"
	valName := "watermark"
	expectedFQN := nsFQN + "/obl/" + oblName + "/value/" + valName
	fqn := BuildOblValFQN(nsFQN, oblName, valName)
	require.Equal(t, expectedFQN, fqn)
}

func TestObligationFQN(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		oblName   string
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
			oblName:   "drm",
			want:      "https://example.com/obl/drm",
		},
		{
			name:      "definition with hyphen",
			namespace: "example.com",
			oblName:   "drm-",
			want:      "https://example.com/obl/drm-",
		},
		{
			name:      "definition with underscore",
			namespace: "example.com",
			oblName:   "drm_",
			want:      "https://example.com/obl/drm_",
		},
		{
			name:      "definition with numbers",
			namespace: "example.com",
			oblName:   "drm365",
			want:      "https://example.com/obl/drm365",
		},
		{
			name:      "definition lower cased",
			namespace: "EXAMPLE.com",
			oblName:   "DRM",
			want:      "https://example.com/obl/drm",
		},

		// Value FQNs
		{
			name:      "value",
			namespace: "example.com",
			oblName:   "drm",
			value:     "watermark",
			want:      "https://example.com/obl/drm/value/watermark",
		},
		{
			name:      "complex value",
			namespace: "sub.example.com",
			oblName:   "drm",
			value:     "expiration",
			want:      "https://sub.example.com/obl/drm/value/expiration",
		},
		{
			name:      "value lower cased",
			namespace: "EXAMPLE.com",
			oblName:   "DRM",
			value:     "WATERMARK",
			want:      "https://example.com/obl/drm/value/watermark",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obl := &FullyQualifiedObligation{
				Namespace: tt.namespace,
				Name:      tt.oblName,
				Value:     tt.value,
			}
			got := obl.FQN()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestObligationValidate(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		oblName   string
		value     string
		wantErr   bool
	}{
		// Valid cases
		{
			name:      "valid namespace only",
			namespace: "example.com",
			oblName:   "",
			value:     "",
			wantErr:   false,
		},
		{
			name:      "valid definition",
			namespace: "example.com",
			oblName:   "drm",
			value:     "",
			wantErr:   false,
		},
		{
			name:      "valid value",
			namespace: "example.com",
			oblName:   "drm",
			value:     "watermark",
			wantErr:   false,
		},

		// Invalid cases
		{
			name:      "invalid namespace - no TLD",
			namespace: "example",
			oblName:   "",
			value:     "",
			wantErr:   true,
		},
		{
			name:      "invalid namespace - starts with hyphen",
			namespace: "-example.com",
			oblName:   "",
			value:     "",
			wantErr:   true,
		},
		{
			name:      "invalid obligation name - starts with underscore",
			namespace: "example.com",
			oblName:   "_drm",
			value:     "",
			wantErr:   true,
		},
		{
			name:      "invalid obligation name - ends with hyphen",
			namespace: "example.com",
			oblName:   "drm-",
			value:     "",
			wantErr:   true,
		},
		{
			name:      "invalid value - starts with hyphen",
			namespace: "example.com",
			oblName:   "drm",
			value:     "-watermark",
			wantErr:   true,
		},
		{
			name:      "invalid value - ends with underscore",
			namespace: "example.com",
			oblName:   "drm",
			value:     "watermark_",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obl := &FullyQualifiedObligation{
				Namespace: tt.namespace,
				Name:      tt.oblName,
				Value:     tt.value,
			}

			err := obl.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseObligationFqn(t *testing.T) {
	// Test cases for the parseObligationFqn function
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
			name:          "Valid obligation definition FQN",
			fqn:           "https://example.org/obl/drm",
			wantNamespace: "example.org",
			wantName:      "drm",
			wantValue:     "",
			wantErr:       false,
		},
		{
			name:          "Valid obligation value FQN",
			fqn:           "https://example.org/obl/drm/value/watermark",
			wantNamespace: "example.org",
			wantName:      "drm",
			wantValue:     "watermark",
			wantErr:       false,
		},
		{
			name:          "Valid obligation value FQN with complex namespace",
			fqn:           "https://subdomain.example.org/obl/drm/value/watermark",
			wantNamespace: "subdomain.example.org",
			wantName:      "drm",
			wantValue:     "watermark",
			wantErr:       false,
		},
		{
			name:          "Valid obligation definition FQN with special characters in name",
			fqn:           "https://example.org/obl/drm_365",
			wantNamespace: "example.org",
			wantName:      "drm_365",
			wantValue:     "",
			wantErr:       false,
		},
		{
			name:          "Valid obligation value FQN with special characters in value",
			fqn:           "https://example.org/obl/drm/value/expiration_365",
			wantNamespace: "example.org",
			wantName:      "drm",
			wantValue:     "expiration_365",
			wantErr:       false,
		},
		{
			name:          "Valid obligation value FQN gets lower cased",
			fqn:           "https://example.org/obl/DRM/value/WATERMARK",
			wantNamespace: "example.org",
			wantName:      "drm",
			wantValue:     "watermark",
			wantErr:       false,
		},
		{
			name:    "Invalid FQN - empty string",
			fqn:     "",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - missing https",
			fqn:     "example.org/obl/drm",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - wrong protocol",
			fqn:     "http://example.org/obl/drm",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - wrong path between namespace and name",
			fqn:     "https://example.org/obligation/drm",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - missing name",
			fqn:     "https://example.org/obl/",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - value path but no value",
			fqn:     "https://example.org/obl/drm/value/",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - extra segments",
			fqn:     "https://example.org/obl/drm/value/watermark/extra",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseObligationFqn(tt.fqn)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseObligationFqn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.Namespace != tt.wantNamespace {
				t.Errorf("parseObligationFqn() namespace = %v, want %v", got.Namespace, tt.wantNamespace)
			}
			if got.Name != tt.wantName {
				t.Errorf("parseObligationFqn() name = %v, want %v", got.Name, tt.wantName)
			}
			if got.Value != tt.wantValue {
				t.Errorf("parseObligationFqn() value = %v, want %v", got.Value, tt.wantValue)
				return
			}
		})
	}
}

func TestObligationRoundTrip(t *testing.T) {
	// Test round trip from struct to FQN to parse and back
	tests := []struct {
		name      string
		namespace string
		oblName   string
		value     string
	}{
		{
			name:      "namespace only",
			namespace: "example.com",
			oblName:   "",
			value:     "",
		},
		{
			name:      "definition",
			namespace: "example.com",
			oblName:   "drm",
			value:     "",
		},
		{
			name:      "value",
			namespace: "example.com",
			oblName:   "drm",
			value:     "watermark",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original obligation
			original := &FullyQualifiedObligation{
				Namespace: tt.namespace,
				Name:      tt.oblName,
				Value:     tt.value,
			}

			// Get FQN
			fqn := original.FQN()

			// Parse the FQN
			parsed, err := parseObligationFqn(fqn)
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
