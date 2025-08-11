package transformation

import (
	"reflect"
	"testing"
)

func TestExtractCNFromDN(t *testing.T) {
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
		{
			name:     "Multiple CN components (first wins)",
			dn:       "CN=First,CN=Second,OU=Users,DC=company,DC=com",
			expected: "First",
		},
		{
			name:     "Case insensitive CN",
			dn:       "cn=lowercase,OU=Users,DC=company,DC=com",
			expected: "lowercase",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractCNFromDN(tt.dn)
			if result != tt.expected {
				t.Errorf("ExtractCNFromDN(%s) = %s, expected %s", tt.dn, result, tt.expected)
			}
		})
	}
}

func TestEscapeLDAPFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No special characters",
			input:    "normaltext",
			expected: "normaltext",
		},
		{
			name:     "Parentheses",
			input:    "(test)",
			expected: "\\28test\\29",
		},
		{
			name:     "Asterisk",
			input:    "test*search",
			expected: "test\\2asearch",
		},
		{
			name:     "Backslash",
			input:    "test\\escape",
			expected: "test\\5cescape",
		},
		{
			name:     "All special characters",
			input:    "test\\*()value",
			expected: "test\\5c\\2a\\28\\29value",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeLDAPFilter(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeLDAPFilter(%s) = %s, expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyLDAPDNToCNArray(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		hasError bool
	}{
		{
			name: "Array of DNs as []interface{}",
			input: []interface{}{
				"CN=User1,OU=Users,DC=company,DC=com",
				"CN=User2,OU=Users,DC=company,DC=com",
			},
			expected: []string{"User1", "User2"},
			hasError: false,
		},
		{
			name: "Array of DNs as []string",
			input: []string{
				"CN=Admin,OU=Admins,DC=company,DC=com",
				"CN=Manager,OU=Management,DC=company,DC=com",
			},
			expected: []string{"Admin", "Manager"},
			hasError: false,
		},
		{
			name: "Mixed valid and invalid DNs",
			input: []string{
				"CN=Valid,OU=Users,DC=company,DC=com",
				"OU=NoCommonName,DC=company,DC=com",
				"CN=AnotherValid,DC=company,DC=com",
			},
			expected: []string{"Valid", "AnotherValid"},
			hasError: false,
		},
		{
			name:     "Non-array input",
			input:    "CN=Single,OU=Users,DC=company,DC=com",
			expected: nil,
			hasError: true,
		},
		{
			name:     "Empty array",
			input:    []string{},
			expected: []string{},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyLDAPDNToCNArray(tt.input)

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
				t.Errorf("ApplyLDAPDNToCNArray(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyLDAPDNToCN(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		hasError bool
	}{
		{
			name:     "Valid DN",
			input:    "CN=John Doe,OU=Users,DC=company,DC=com",
			expected: "John Doe",
			hasError: false,
		},
		{
			name:     "DN without CN",
			input:    "OU=Users,DC=company,DC=com",
			expected: "",
			hasError: false,
		},
		{
			name:     "Non-string input",
			input:    123,
			expected: nil,
			hasError: true,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyLDAPDNToCN(tt.input)

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

			if result != tt.expected {
				t.Errorf("ApplyLDAPDNToCN(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyLDAPAttributeValues(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		hasError bool
	}{
		{
			name:     "Array of interfaces",
			input:    []interface{}{"value1", "value2", 123},
			expected: []string{"value1", "value2", "123"},
			hasError: false,
		},
		{
			name:     "Array of strings",
			input:    []string{"attr1", "attr2", "attr3"},
			expected: []string{"attr1", "attr2", "attr3"},
			hasError: false,
		},
		{
			name:     "Single value",
			input:    "single_value",
			expected: []string{"single_value"},
			hasError: false,
		},
		{
			name:     "Single integer",
			input:    42,
			expected: []string{"42"},
			hasError: false,
		},
		{
			name:     "Empty array",
			input:    []string{},
			expected: []string{},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyLDAPAttributeValues(tt.input)

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
				t.Errorf("ApplyLDAPAttributeValues(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyADGroupName(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		hasError bool
	}{
		{
			name:     "DN format group",
			input:    "CN=Admins,OU=Groups,DC=company,DC=com",
			expected: "Admins",
			hasError: false,
		},
		{
			name:     "Simple group name",
			input:    "SimpleGroup",
			expected: "SimpleGroup",
			hasError: false,
		},
		{
			name:     "Non-string input",
			input:    123,
			expected: nil,
			hasError: true,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyADGroupName(tt.input)

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

			if result != tt.expected {
				t.Errorf("ApplyADGroupName(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyLDAPTransformation(t *testing.T) {
	tests := []struct {
		name           string
		transformation string
		input          interface{}
		expected       interface{}
		hasError       bool
	}{
		{
			name:           "LDAP DN to CN Array",
			transformation: LDAPDNToCNArray,
			input:          []string{"CN=User1,OU=Users", "CN=User2,OU=Users"},
			expected:       []string{"User1", "User2"},
			hasError:       false,
		},
		{
			name:           "LDAP DN to CN",
			transformation: LDAPDNToCN,
			input:          "CN=Admin,OU=Admins,DC=company,DC=com",
			expected:       "Admin",
			hasError:       false,
		},
		{
			name:           "LDAP Attribute Values",
			transformation: LDAPAttrValues,
			input:          []interface{}{"val1", "val2"},
			expected:       []string{"val1", "val2"},
			hasError:       false,
		},
		{
			name:           "AD Group Name",
			transformation: LDAPADGroupName,
			input:          "CN=Managers,OU=Groups,DC=company,DC=com",
			expected:       "Managers",
			hasError:       false,
		},
		{
			name:           "Unknown transformation",
			transformation: "unknown_ldap_transform",
			input:          "test",
			expected:       nil,
			hasError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyLDAPTransformation(tt.input, tt.transformation)

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
				t.Errorf("ApplyLDAPTransformation(%v, %s) = %v, expected %v",
					tt.input, tt.transformation, result, tt.expected)
			}
		})
	}
}