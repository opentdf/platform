package ldap

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/transformation"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

func TestLDAPMapper_ExtractParameters(t *testing.T) {
	mapper := NewLDAPMapper()

	tests := []struct {
		name           string
		jwtClaims      types.JWTClaims
		inputMapping   []types.InputMapping
		expectedParams map[string]interface{}
		expectError    bool
	}{
		{
			name: "Basic parameter extraction",
			jwtClaims: types.JWTClaims{
				"preferred_username": "testuser",
				"contractor_id":      "C12345",
			},
			inputMapping: []types.InputMapping{
				{JWTClaim: "preferred_username", Parameter: "username", Required: true},
				{JWTClaim: "contractor_id", Parameter: "contractor_id", Required: false},
			},
			expectedParams: map[string]interface{}{
				"username":      "testuser",
				"contractor_id": "C12345",
			},
			expectError: false,
		},
		{
			name: "LDAP filter escaping",
			jwtClaims: types.JWTClaims{
				"username": "test(user)*",
			},
			inputMapping: []types.InputMapping{
				{JWTClaim: "username", Parameter: "username", Required: true},
			},
			expectedParams: map[string]interface{}{
				"username": "test\\28user\\29\\2a", // Should be escaped
			},
			expectError: false,
		},
		{
			name: "Required claim missing",
			jwtClaims: types.JWTClaims{
				"username": "testuser",
			},
			inputMapping: []types.InputMapping{
				{JWTClaim: "username", Parameter: "username", Required: true},
				{JWTClaim: "contractor_id", Parameter: "contractor_id", Required: true},
			},
			expectedParams: nil,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := mapper.ExtractParameters(tt.jwtClaims, tt.inputMapping)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(params) != len(tt.expectedParams) {
				t.Errorf("Expected %d parameters, got %d", len(tt.expectedParams), len(params))
			}

			for key, expectedValue := range tt.expectedParams {
				if actualValue, exists := params[key]; !exists {
					t.Errorf("Expected parameter %s not found", key)
				} else if actualValue != expectedValue {
					t.Errorf("Parameter %s: expected %v, got %v", key, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestLDAPMapper_TransformResults(t *testing.T) {
	mapper := NewLDAPMapper()

	tests := []struct {
		name           string
		rawData        map[string]interface{}
		outputMapping  []types.OutputMapping
		expectedClaims map[string]interface{}
		expectError    bool
	}{
		{
			name: "Basic attribute transformation",
			rawData: map[string]interface{}{
				"uid":         "testuser",
				"cn":          "Test User",
				"department":  "Engineering",
			},
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "uid", ClaimName: "username"},
				{SourceAttribute: "cn", ClaimName: "display_name"},
				{SourceAttribute: "department", ClaimName: "organizational_unit"},
			},
			expectedClaims: map[string]interface{}{
				"username":           "testuser",
				"display_name":       "Test User",
				"organizational_unit": "Engineering",
			},
			expectError: false,
		},
		{
			name: "LDAP DN to CN array transformation",
			rawData: map[string]interface{}{
				"memberOf": []interface{}{
					"CN=Admins,OU=Groups,DC=company,DC=com",
					"CN=Users,OU=Groups,DC=company,DC=com",
					"CN=Finance,OU=Groups,DC=company,DC=com",
				},
			},
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "memberOf", ClaimName: "group_memberships", Transformation: "ldap_dn_to_cn_array"},
			},
			expectedClaims: map[string]interface{}{
				"group_memberships": []string{"Admins", "Users", "Finance"},
			},
			expectError: false,
		},
		{
			name: "LDAP DN to CN single transformation",
			rawData: map[string]interface{}{
				"manager": "CN=John Doe,OU=Management,DC=company,DC=com",
			},
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "manager", ClaimName: "manager_name", Transformation: "ldap_dn_to_cn"},
			},
			expectedClaims: map[string]interface{}{
				"manager_name": "John Doe",
			},
			expectError: false,
		},
		{
			name: "LDAP attribute values transformation",
			rawData: map[string]interface{}{
				"mail": []interface{}{"user@company.com", "user.alt@company.com"},
			},
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "mail", ClaimName: "email_addresses", Transformation: "ldap_attribute_values"},
			},
			expectedClaims: map[string]interface{}{
				"email_addresses": []string{"user@company.com", "user.alt@company.com"},
			},
			expectError: false,
		},
		{
			name: "AD group name transformation",
			rawData: map[string]interface{}{
				"primaryGroup": "CN=Domain Users,CN=Users,DC=company,DC=com",
			},
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "primaryGroup", ClaimName: "primary_group", Transformation: "ad_group_name"},
			},
			expectedClaims: map[string]interface{}{
				"primary_group": "Domain Users",
			},
			expectError: false,
		},
		{
			name: "Missing source attribute (ignored)",
			rawData: map[string]interface{}{
				"uid": "testuser",
			},
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "uid", ClaimName: "username"},
				{SourceAttribute: "missing_attr", ClaimName: "missing"},
			},
			expectedClaims: map[string]interface{}{
				"username": "testuser",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := mapper.TransformResults(tt.rawData, tt.outputMapping)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(claims) != len(tt.expectedClaims) {
				t.Errorf("Expected %d claims, got %d", len(tt.expectedClaims), len(claims))
			}

			for key, expectedValue := range tt.expectedClaims {
				if actualValue, exists := claims[key]; !exists {
					t.Errorf("Expected claim %s not found", key)
				} else {
					// Handle slice comparison
					if expectedSlice, ok := expectedValue.([]string); ok {
						if actualSlice, ok := actualValue.([]string); ok {
							if len(expectedSlice) != len(actualSlice) {
								t.Errorf("Claim %s: expected slice length %d, got %d", key, len(expectedSlice), len(actualSlice))
							} else {
								for i, expectedItem := range expectedSlice {
									if actualSlice[i] != expectedItem {
										t.Errorf("Claim %s[%d]: expected %v, got %v", key, i, expectedItem, actualSlice[i])
									}
								}
							}
						} else {
							t.Errorf("Claim %s: expected slice, got %T", key, actualValue)
						}
					} else if actualValue != expectedValue {
						t.Errorf("Claim %s: expected %v, got %v", key, expectedValue, actualValue)
					}
				}
			}
		})
	}
}

func TestLDAPMapper_ValidateInputMapping(t *testing.T) {
	mapper := NewLDAPMapper()

	tests := []struct {
		name         string
		inputMapping []types.InputMapping
		expectError  bool
	}{
		{
			name: "Valid input mapping",
			inputMapping: []types.InputMapping{
				{JWTClaim: "username", Parameter: "username", Required: true},
				{JWTClaim: "contractor_id", Parameter: "contractor_id", Required: false},
			},
			expectError: false,
		},
		{
			name: "Invalid template variable in parameter",
			inputMapping: []types.InputMapping{
				{JWTClaim: "username", Parameter: "user-name", Required: true}, // Hyphen not allowed
			},
			expectError: true,
		},
		{
			name: "Parameter starting with number",
			inputMapping: []types.InputMapping{
				{JWTClaim: "id", Parameter: "1user_id", Required: true},
			},
			expectError: true,
		},
		{
			name: "Empty JWT claim",
			inputMapping: []types.InputMapping{
				{JWTClaim: "", Parameter: "username", Required: true},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapper.ValidateInputMapping(tt.inputMapping)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLDAPMapper_ValidateOutputMapping(t *testing.T) {
	mapper := NewLDAPMapper()

	tests := []struct {
		name          string
		outputMapping []types.OutputMapping
		expectError   bool
	}{
		{
			name: "Valid output mapping",
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "uid", ClaimName: "username"},
				{SourceAttribute: "cn", ClaimName: "display_name"},
			},
			expectError: false,
		},
		{
			name: "Empty source attribute",
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "", ClaimName: "username"},
			},
			expectError: true,
		},
		{
			name: "Invalid LDAP attribute name",
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "user@name", ClaimName: "username"}, // @ not allowed
			},
			expectError: true,
		},
		{
			name: "Unsupported transformation",
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "memberOf", ClaimName: "groups", Transformation: "unsupported_transform"},
			},
			expectError: true,
		},
		{
			name: "Supported LDAP transformation",
			outputMapping: []types.OutputMapping{
				{SourceAttribute: "memberOf", ClaimName: "groups", Transformation: "ldap_dn_to_cn_array"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapper.ValidateOutputMapping(tt.outputMapping)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLDAPMapper_GetSupportedTransformations(t *testing.T) {
	mapper := NewLDAPMapper()
	transformations := mapper.GetSupportedTransformations()

	expectedTransformations := []string{
		// Common transformations
		"csv_to_array",
		"array",
		"string",
		"lowercase",
		"uppercase",
		// LDAP-specific transformations
		"ldap_dn_to_cn_array",
		"ldap_dn_to_cn",
		"ldap_attribute_values",
		"ad_group_name",
	}

	if len(transformations) != len(expectedTransformations) {
		t.Errorf("Expected %d transformations, got %d", len(expectedTransformations), len(transformations))
	}

	transformationMap := make(map[string]bool)
	for _, transform := range transformations {
		transformationMap[transform] = true
	}

	for _, expected := range expectedTransformations {
		if !transformationMap[expected] {
			t.Errorf("Expected transformation %s not found", expected)
		}
	}
}

func TestLDAPMapper_extractCNFromDN(t *testing.T) {
	// This function has been moved to the transformation package
	// Test it there directly using the transformation.ExtractCNFromDN function
	tests := []struct {
		name     string
		dn       string
		expected string
	}{
		{
			name:     "Standard DN",
			dn:       "CN=John Doe,OU=Users,DC=company,DC=com",
			expected: "John Doe",
		},
		{
			name:     "DN with spaces",
			dn:       "CN=Test User, OU=Groups, DC=example, DC=org",
			expected: "Test User",
		},
		{
			name:     "DN without CN",
			dn:       "OU=Users,DC=company,DC=com",
			expected: "",
		},
		{
			name:     "Empty DN",
			dn:       "",
			expected: "",
		},
		{
			name:     "CN only",
			dn:       "CN=Admin",
			expected: "Admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Import and use the transformation package function directly
			result := transformation.ExtractCNFromDN(tt.dn)
			if result != tt.expected {
				t.Errorf("ExtractCNFromDN(%s): expected %s, got %s", tt.dn, tt.expected, result)
			}
		})
	}
}

func TestLDAPMapper_escapeLDAPFilter(t *testing.T) {
	mapper := NewLDAPMapper()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No special characters",
			input:    "normaluser",
			expected: "normaluser",
		},
		{
			name:     "Parentheses",
			input:    "user(test)",
			expected: "user\\28test\\29",
		},
		{
			name:     "Asterisk",
			input:    "user*",
			expected: "user\\2a",
		},
		{
			name:     "Backslash",
			input:    "domain\\user",
			expected: "domain\\5cuser",
		},
		{
			name:     "All special characters",
			input:    "user\\*()",
			expected: "user\\5c\\2a\\28\\29",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.escapeLDAPFilter(tt.input)
			if result != tt.expected {
				t.Errorf("escapeLDAPFilter(%s): expected %s, got %s", tt.input, tt.expected, result)
			}
		})
	}
}

func TestLDAPMapper_isValidLDAPAttribute(t *testing.T) {
	tests := []struct {
		name      string
		attribute string
		expected  bool
	}{
		{"Valid attribute", "uid", true},
		{"Valid attribute with numbers", "attr123", true},
		{"Valid attribute with hyphen", "user-name", true},
		{"Invalid empty string", "", false},
		{"Invalid starting with number", "123attr", false},
		{"Invalid with space", "user name", false},
		{"Invalid with special chars", "user@attr", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidLDAPAttribute(tt.attribute)
			if result != tt.expected {
				t.Errorf("isValidLDAPAttribute(%s): expected %v, got %v", tt.attribute, tt.expected, result)
			}
		})
	}
}