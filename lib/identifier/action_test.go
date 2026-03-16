package identifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBreakActFQN(t *testing.T) {
	validFQN := "https://namespace.com/act/read"
	nsFQN, actName := BreakActFQN(validFQN)
	require.Equal(t, "https://namespace.com", nsFQN)
	require.Equal(t, "read", actName)

	invalidFQN := ""
	nsFQN, actName = BreakActFQN(invalidFQN)
	require.Empty(t, nsFQN)
	require.Empty(t, actName)
}

func TestBuildActFQN(t *testing.T) {
	nsFQN := "https://namespace.com"
	actName := "read"
	expectedFQN := nsFQN + "/act/" + actName
	fqn := BuildActFQN(nsFQN, actName)
	require.Equal(t, expectedFQN, fqn)
}

func TestActionFQN(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		actName   string
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
			actName:   "read",
			want:      "https://example.com/act/read",
		},
		{
			name:      "definition with hyphen",
			namespace: "example.com",
			actName:   "read-",
			want:      "https://example.com/act/read-",
		},
		{
			name:      "definition with underscore",
			namespace: "example.com",
			actName:   "read_",
			want:      "https://example.com/act/read_",
		},
		{
			name:      "definition with numbers",
			namespace: "example.com",
			actName:   "read365",
			want:      "https://example.com/act/read365",
		},
		{
			name:      "definition lower cased",
			namespace: "EXAMPLE.com",
			actName:   "READ",
			want:      "https://example.com/act/read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			act := &FullyQualifiedAction{
				Namespace: tt.namespace,
				Name:      tt.actName,
			}
			got := act.FQN()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestActionValidate(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		actName   string
		wantErr   bool
	}{
		// Valid cases
		{
			name:      "valid namespace only",
			namespace: "example.com",
			actName:   "",
			wantErr:   false,
		},
		{
			name:      "valid definition",
			namespace: "example.com",
			actName:   "read",
			wantErr:   false,
		},

		// Invalid cases
		{
			name:      "invalid namespace - no TLD",
			namespace: "example",
			actName:   "",
			wantErr:   true,
		},
		{
			name:      "invalid namespace - starts with hyphen",
			namespace: "-example.com",
			actName:   "",
			wantErr:   true,
		},
		{
			name:      "invalid action name - starts with underscore",
			namespace: "example.com",
			actName:   "_read",
			wantErr:   true,
		},
		{
			name:      "invalid action name - ends with hyphen",
			namespace: "example.com",
			actName:   "read-",
			wantErr:   true,
		},
		{
			name:      "invalid action name - starts with hyphen",
			namespace: "example.com",
			actName:   "-read",
			wantErr:   true,
		},
		{
			name:      "invalid action name - ends with underscore",
			namespace: "example.com",
			actName:   "read_",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			act := &FullyQualifiedAction{
				Namespace: tt.namespace,
				Name:      tt.actName,
			}

			err := act.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseActionFqn(t *testing.T) {
	// Test cases for the parseActionFqn function
	tests := []struct {
		name          string
		fqn           string
		wantNamespace string
		wantName      string
		wantErr       bool
	}{
		{
			name:          "Valid namespace only FQN",
			fqn:           "https://example.org",
			wantNamespace: "example.org",
			wantName:      "",
			wantErr:       false,
		},
		{
			name:          "Valid action definition FQN",
			fqn:           "https://example.org/act/read",
			wantNamespace: "example.org",
			wantName:      "read",
			wantErr:       false,
		},
		{
			name:          "Valid action FQN with special characters in name",
			fqn:           "https://example.org/act/read_365",
			wantNamespace: "example.org",
			wantName:      "read_365",
			wantErr:       false,
		},
		{
			name:          "Valid action FQN gets lower cased",
			fqn:           "https://example.org/act/READ",
			wantNamespace: "example.org",
			wantName:      "read",
			wantErr:       false,
		},
		{
			name:    "Invalid FQN - empty string",
			fqn:     "",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - missing https",
			fqn:     "example.org/act/read",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - wrong protocol",
			fqn:     "http://example.org/act/read",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - wrong path between namespace and name",
			fqn:     "https://example.org/action/read",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - missing name",
			fqn:     "https://example.org/act/",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - adds value",
			fqn:     "https://example.org/act/read/value",
			wantErr: true,
		},
		{
			name:    "Invalid FQN - extra segments",
			fqn:     "https://example.org/act/read/value/something/extra",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseActionFqn(tt.fqn)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseActionFqn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.Namespace != tt.wantNamespace {
				t.Errorf("parseActionFqn() namespace = %v, want %v", got.Namespace, tt.wantNamespace)
			}
			if got.Name != tt.wantName {
				t.Errorf("parseActionFqn() name = %v, want %v", got.Name, tt.wantName)
			}
		})
	}
}

func TestActionRoundTrip(t *testing.T) {
	// Test round trip from struct to FQN to parse and back
	tests := []struct {
		name      string
		namespace string
		actName   string
	}{
		{
			name:      "namespace only",
			namespace: "example.com",
			actName:   "",
		},
		{
			name:      "definition",
			namespace: "example.com",
			actName:   "read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original action
			original := &FullyQualifiedAction{
				Namespace: tt.namespace,
				Name:      tt.actName,
			}

			// Get FQN
			fqn := original.FQN()

			// Parse the FQN
			parsed, err := parseActionFqn(fqn)
			require.NoError(t, err)

			// Check the parsed values match original
			require.Equal(t, original.Namespace, parsed.Namespace)
			require.Equal(t, original.Name, parsed.Name)

			// Ensure the re-generated FQN matches the original
			require.Equal(t, fqn, parsed.FQN())
		})
	}
}
