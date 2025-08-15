package transformation

import (
	"reflect"
	"testing"
)

func TestTransformationRegistry_ApplyTransformation(t *testing.T) {
	registry := NewTransformationRegistry()

	tests := []struct {
		name         string
		value        interface{}
		transformation string
		providerType string
		expected     interface{}
		hasError     bool
	}{
		// Common transformations should work for all provider types
		{
			name:           "CSV to Array - SQL",
			value:          "a,b,c",
			transformation: CommonCSVToArray,
			providerType:   "sql",
			expected:       []string{"a", "b", "c"},
			hasError:       false,
		},
		{
			name:           "CSV to Array - LDAP",
			value:          "a,b,c",
			transformation: CommonCSVToArray,
			providerType:   "ldap",
			expected:       []string{"a", "b", "c"},
			hasError:       false,
		},
		{
			name:           "CSV to Array - Claims",
			value:          "a,b,c",
			transformation: CommonCSVToArray,
			providerType:   "claims",
			expected:       []string{"a", "b", "c"},
			hasError:       false,
		},

		// SQL-specific transformations
		{
			name:           "Postgres Array - SQL",
			value:          "{apple,banana,cherry}",
			transformation: SQLPostgresArray,
			providerType:   "sql",
			expected:       []string{"apple", "banana", "cherry"},
			hasError:       false,
		},
		{
			name:           "Postgres Array - LDAP (should fail)",
			value:          "{apple,banana,cherry}",
			transformation: SQLPostgresArray,
			providerType:   "ldap",
			expected:       nil,
			hasError:       true,
		},

		// LDAP-specific transformations
		{
			name:           "LDAP DN to CN - LDAP",
			value:          "CN=Users,OU=Groups,DC=example,DC=com",
			transformation: LDAPDNToCN,
			providerType:   "ldap",
			expected:       "Users",
			hasError:       false,
		},
		{
			name:           "LDAP DN to CN - SQL (should fail)",
			value:          "CN=Users,OU=Groups,DC=example,DC=com",
			transformation: LDAPDNToCN,
			providerType:   "sql",
			expected:       nil,
			hasError:       true,
		},

		// Claims-specific transformations
		{
			name:           "JWT Extract Scope - Claims",
			value:          "read write admin",
			transformation: ClaimsExtractScope,
			providerType:   "claims",
			expected:       []string{"read", "write", "admin"},
			hasError:       false,
		},
		{
			name:           "JWT Extract Scope - SQL (should fail)",
			value:          "read write admin",
			transformation: ClaimsExtractScope,
			providerType:   "sql",
			expected:       nil,
			hasError:       true,
		},

		// Empty transformation should return original value
		{
			name:           "Empty transformation",
			value:          "test",
			transformation: "",
			providerType:   "sql",
			expected:       "test",
			hasError:       false,
		},

		// Unknown transformation
		{
			name:           "Unknown transformation",
			value:          "test",
			transformation: "unknown",
			providerType:   "sql",
			expected:       nil,
			hasError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := registry.ApplyTransformation(tt.value, tt.transformation, tt.providerType)

			if tt.hasError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ApplyTransformation(%v, %s, %s) = %v, expected %v",
					tt.value, tt.transformation, tt.providerType, result, tt.expected)
			}
		})
	}
}

func TestTransformationRegistry_GetSupportedTransformations(t *testing.T) {
	registry := NewTransformationRegistry()

	tests := []struct {
		name         string
		providerType string
		expectedMin  int // Minimum number of expected transformations
		shouldContain []string
	}{
		{
			name:         "SQL provider",
			providerType: "sql",
			expectedMin:  6, // 5 common + 1 SQL-specific
			shouldContain: []string{
				CommonCSVToArray, CommonArray, CommonString,
				SQLPostgresArray,
			},
		},
		{
			name:         "LDAP provider",
			providerType: "ldap",
			expectedMin:  9, // 5 common + 4 LDAP-specific
			shouldContain: []string{
				CommonCSVToArray, CommonArray, CommonString,
				LDAPDNToCNArray, LDAPDNToCN, LDAPAttrValues, LDAPADGroupName,
			},
		},
		{
			name:         "Claims provider",
			providerType: "claims",
			expectedMin:  7, // 5 common + 2 Claims-specific
			shouldContain: []string{
				CommonCSVToArray, CommonArray, CommonString,
				ClaimsExtractScope, ClaimsNormalizeGroups,
			},
		},
		{
			name:         "Unknown provider",
			providerType: "unknown",
			expectedMin:  5, // Only common transformations
			shouldContain: []string{
				CommonCSVToArray, CommonArray, CommonString, CommonLowercase, CommonUppercase,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.GetSupportedTransformations(tt.providerType)

			if len(result) < tt.expectedMin {
				t.Errorf("GetSupportedTransformations(%s) returned %d transformations, expected at least %d",
					tt.providerType, len(result), tt.expectedMin)
			}

			for _, expected := range tt.shouldContain {
				found := false
				for _, actual := range result {
					if actual == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("GetSupportedTransformations(%s) missing expected transformation: %s",
						tt.providerType, expected)
				}
			}
		})
	}
}

func TestTransformationRegistry_ValidateTransformation(t *testing.T) {
	registry := NewTransformationRegistry()

	tests := []struct {
		name           string
		transformation string
		providerType   string
		expectError    bool
	}{
		// Valid combinations
		{"CSV to Array - SQL", CommonCSVToArray, "sql", false},
		{"CSV to Array - LDAP", CommonCSVToArray, "ldap", false},
		{"CSV to Array - Claims", CommonCSVToArray, "claims", false},
		{"Postgres Array - SQL", SQLPostgresArray, "sql", false},
		{"LDAP DN to CN - LDAP", LDAPDNToCN, "ldap", false},
		{"JWT Extract Scope - Claims", ClaimsExtractScope, "claims", false},

		// Invalid combinations
		{"Postgres Array - LDAP", SQLPostgresArray, "ldap", true},
		{"Postgres Array - Claims", SQLPostgresArray, "claims", true},
		{"LDAP DN to CN - SQL", LDAPDNToCN, "sql", true},
		{"LDAP DN to CN - Claims", LDAPDNToCN, "claims", true},
		{"JWT Extract Scope - SQL", ClaimsExtractScope, "sql", true},
		{"JWT Extract Scope - LDAP", ClaimsExtractScope, "ldap", true},

		// Unknown transformations
		{"Unknown - SQL", "unknown", "sql", true},
		{"Unknown - LDAP", "unknown", "ldap", true},
		{"Unknown - Claims", "unknown", "claims", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.ValidateTransformation(tt.transformation, tt.providerType)

			if tt.expectError {
				if err == nil {
					t.Errorf("ValidateTransformation(%s, %s) expected error but got none",
						tt.transformation, tt.providerType)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateTransformation(%s, %s) unexpected error: %v",
						tt.transformation, tt.providerType, err)
				}
			}
		})
	}
}

func TestDefaultRegistry(t *testing.T) {
	// Test that the default registry is initialized and works
	result, err := DefaultRegistry.ApplyTransformation("a,b,c", CommonCSVToArray, "sql")
	if err != nil {
		t.Errorf("DefaultRegistry failed: %v", err)
	}

	expected := []string{"a", "b", "c"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("DefaultRegistry.ApplyTransformation() = %v, expected %v", result, expected)
	}
}