package transformation

import (
	"testing"
)

func TestGetCommonTransformations(t *testing.T) {
	transformations := GetCommonTransformations()
	
	expected := []string{
		CommonCSVToArray,
		CommonArray,
		CommonString,
		CommonLowercase,
		CommonUppercase,
	}
	
	if len(transformations) != len(expected) {
		t.Errorf("Expected %d transformations, got %d", len(expected), len(transformations))
	}
	
	for _, exp := range expected {
		found := false
		for _, actual := range transformations {
			if actual == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected transformation %s not found", exp)
		}
	}
}

func TestGetAllSQLTransformations(t *testing.T) {
	transformations := GetAllSQLTransformations()
	
	// Should include both common and SQL-specific transformations
	expectedCommon := GetCommonTransformations()
	expectedSQL := GetSQLTransformations()
	expectedTotal := len(expectedCommon) + len(expectedSQL)
	
	if len(transformations) != expectedTotal {
		t.Errorf("Expected %d transformations, got %d", expectedTotal, len(transformations))
	}
	
	// Check that all common transformations are included
	for _, common := range expectedCommon {
		found := false
		for _, actual := range transformations {
			if actual == common {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected common transformation %s not found", common)
		}
	}
	
	// Check that all SQL-specific transformations are included
	for _, sql := range expectedSQL {
		found := false
		for _, actual := range transformations {
			if actual == sql {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected SQL transformation %s not found", sql)
		}
	}
}

func TestIsCommonTransformation(t *testing.T) {
	tests := []struct {
		name           string
		transformation string
		expected       bool
	}{
		{"CSV to Array", CommonCSVToArray, true},
		{"Array", CommonArray, true},
		{"String", CommonString, true},
		{"Lowercase", CommonLowercase, true},
		{"Uppercase", CommonUppercase, true},
		{"SQL Postgres Array", SQLPostgresArray, false},
		{"LDAP DN to CN", LDAPDNToCN, false},
		{"Unknown", "unknown_transformation", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCommonTransformation(tt.transformation)
			if result != tt.expected {
				t.Errorf("IsCommonTransformation(%s) = %v, expected %v", tt.transformation, result, tt.expected)
			}
		})
	}
}

func TestIsSupportedByProvider(t *testing.T) {
	tests := []struct {
		name           string
		transformation string
		providerType   string
		expected       bool
	}{
		// Common transformations should work for all providers
		{"CSV to Array - SQL", CommonCSVToArray, "sql", true},
		{"CSV to Array - LDAP", CommonCSVToArray, "ldap", true},
		{"CSV to Array - Claims", CommonCSVToArray, "claims", true},
		
		// Provider-specific transformations
		{"Postgres Array - SQL", SQLPostgresArray, "sql", true},
		{"Postgres Array - LDAP", SQLPostgresArray, "ldap", false},
		{"Postgres Array - Claims", SQLPostgresArray, "claims", false},
		
		{"LDAP DN to CN - LDAP", LDAPDNToCN, "ldap", true},
		{"LDAP DN to CN - SQL", LDAPDNToCN, "sql", false},
		{"LDAP DN to CN - Claims", LDAPDNToCN, "claims", false},
		
		
		// Unknown transformations
		{"Unknown - SQL", "unknown", "sql", false},
		{"Unknown - LDAP", "unknown", "ldap", false},
		{"Unknown - Claims", "unknown", "claims", false},
		
		// Unknown provider types
		{"CSV to Array - Unknown Provider", CommonCSVToArray, "unknown", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSupportedByProvider(tt.transformation, tt.providerType)
			if result != tt.expected {
				t.Errorf("IsSupportedByProvider(%s, %s) = %v, expected %v", 
					tt.transformation, tt.providerType, result, tt.expected)
			}
		})
	}
}

func TestTransformationConstants(t *testing.T) {
	// Test that constants have expected values to prevent accidental changes
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Common CSV to Array", CommonCSVToArray, "csv_to_array"},
		{"Common Array", CommonArray, "array"},
		{"Common String", CommonString, "string"},
		{"Common Lowercase", CommonLowercase, "lowercase"},
		{"Common Uppercase", CommonUppercase, "uppercase"},
		
		{"SQL Postgres Array", SQLPostgresArray, "postgres_array"},
		{"LDAP DN to CN Array", LDAPDNToCNArray, "ldap_dn_to_cn_array"},
		{"LDAP DN to CN", LDAPDNToCN, "ldap_dn_to_cn"},
		{"LDAP Attribute Values", LDAPAttrValues, "ldap_attribute_values"},
		{"LDAP AD Group Name", LDAPADGroupName, "ad_group_name"},
		
		{"Claims Extract Scope", ClaimsExtractScope, "jwt_extract_scope"},
		{"Claims Normalize Groups", ClaimsNormalizeGroups, "jwt_normalize_groups"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Constant %s = %s, expected %s", tt.name, tt.constant, tt.expected)
			}
		})
	}
}