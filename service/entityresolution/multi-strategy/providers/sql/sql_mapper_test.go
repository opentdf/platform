package sql

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

func TestSQLMapper_ExtractParameters(t *testing.T) {
	mapper := NewSQLMapper()

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
				"email": "user@example.com",
				"sub":   "user123",
			},
			inputMapping: []types.InputMapping{
				{JWTClaim: "email", Parameter: "user_email", Required: true},
				{JWTClaim: "sub", Parameter: "user_id", Required: false},
			},
			expectedParams: map[string]interface{}{
				"user_email": "user@example.com",
				"user_id":    "user123",
			},
			expectError: false,
		},
		{
			name: "Parameter sanitization",
			jwtClaims: types.JWTClaims{
				"username": "  admin  ",
			},
			inputMapping: []types.InputMapping{
				{JWTClaim: "username", Parameter: "username", Required: true},
			},
			expectedParams: map[string]interface{}{
				"username": "admin", // Should be trimmed
			},
			expectError: false,
		},
		{
			name: "SQL injection attempt in parameter name",
			jwtClaims: types.JWTClaims{
				"email": "user@example.com",
			},
			inputMapping: []types.InputMapping{
				{JWTClaim: "email", Parameter: "user'; DROP TABLE users; --", Required: true},
			},
			expectedParams: nil,
			expectError:    true,
		},
		{
			name: "Required claim missing",
			jwtClaims: types.JWTClaims{
				"email": "user@example.com",
			},
			inputMapping: []types.InputMapping{
				{JWTClaim: "email", Parameter: "user_email", Required: true},
				{JWTClaim: "sub", Parameter: "user_id", Required: true},
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

func TestSQLMapper_TransformResults(t *testing.T) {
	mapper := NewSQLMapper()

	tests := []struct {
		name           string
		rawData        map[string]interface{}
		outputMapping  []types.OutputMapping
		expectedClaims map[string]interface{}
		expectError    bool
	}{
		{
			name: "Basic column transformation",
			rawData: map[string]interface{}{
				"user_id":    123,
				"email":      "user@example.com",
				"department": "Engineering",
			},
			outputMapping: []types.OutputMapping{
				{SourceColumn: "user_id", ClaimName: "subject_id"},
				{SourceColumn: "email", ClaimName: "email_address"},
				{SourceColumn: "department", ClaimName: "organizational_unit"},
			},
			expectedClaims: map[string]interface{}{
				"subject_id":          123,
				"email_address":       "user@example.com",
				"organizational_unit": "Engineering",
			},
			expectError: false,
		},
		{
			name: "PostgreSQL array transformation",
			rawData: map[string]interface{}{
				"groups": "{admin,user,finance}",
			},
			outputMapping: []types.OutputMapping{
				{SourceColumn: "groups", ClaimName: "group_memberships", Transformation: "postgres_array"},
			},
			expectedClaims: map[string]interface{}{
				"group_memberships": []string{"admin", "user", "finance"},
			},
			expectError: false,
		},
		{
			name: "CSV to array transformation",
			rawData: map[string]interface{}{
				"roles": "manager,analyst,reviewer",
			},
			outputMapping: []types.OutputMapping{
				{SourceColumn: "roles", ClaimName: "role_assignments", Transformation: "csv_to_array"},
			},
			expectedClaims: map[string]interface{}{
				"role_assignments": []string{"manager", "analyst", "reviewer"},
			},
			expectError: false,
		},
		{
			name: "String transformation",
			rawData: map[string]interface{}{
				"user_id": 12345,
			},
			outputMapping: []types.OutputMapping{
				{SourceColumn: "user_id", ClaimName: "subject_id", Transformation: "string"},
			},
			expectedClaims: map[string]interface{}{
				"subject_id": "12345",
			},
			expectError: false,
		},
		{
			name: "Missing source column (ignored)",
			rawData: map[string]interface{}{
				"email": "user@example.com",
			},
			outputMapping: []types.OutputMapping{
				{SourceColumn: "email", ClaimName: "email_address"},
				{SourceColumn: "missing_column", ClaimName: "missing"},
			},
			expectedClaims: map[string]interface{}{
				"email_address": "user@example.com",
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

func TestSQLMapper_ValidateInputMapping(t *testing.T) {
	mapper := NewSQLMapper()

	tests := []struct {
		name         string
		inputMapping []types.InputMapping
		expectError  bool
	}{
		{
			name: "Valid input mapping",
			inputMapping: []types.InputMapping{
				{JWTClaim: "email", Parameter: "user_email", Required: true},
				{JWTClaim: "sub", Parameter: "user_id", Required: false},
			},
			expectError: false,
		},
		{
			name: "Invalid SQL identifier in parameter",
			inputMapping: []types.InputMapping{
				{JWTClaim: "email", Parameter: "user-email", Required: true}, // Hyphen not allowed
			},
			expectError: true,
		},
		{
			name: "Parameter starting with number",
			inputMapping: []types.InputMapping{
				{JWTClaim: "email", Parameter: "1user_email", Required: true},
			},
			expectError: true,
		},
		{
			name: "Empty JWT claim",
			inputMapping: []types.InputMapping{
				{JWTClaim: "", Parameter: "user_email", Required: true},
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

func TestSQLMapper_ValidateOutputMapping(t *testing.T) {
	mapper := NewSQLMapper()

	tests := []struct {
		name          string
		outputMapping []types.OutputMapping
		expectError   bool
	}{
		{
			name: "Valid output mapping",
			outputMapping: []types.OutputMapping{
				{SourceColumn: "user_id", ClaimName: "subject"},
				{SourceColumn: "email", ClaimName: "email_address"},
			},
			expectError: false,
		},
		{
			name: "Empty source column",
			outputMapping: []types.OutputMapping{
				{SourceColumn: "", ClaimName: "subject"},
			},
			expectError: true,
		},
		{
			name: "Invalid SQL column name",
			outputMapping: []types.OutputMapping{
				{SourceColumn: "user-id", ClaimName: "subject"}, // Hyphen not allowed
			},
			expectError: true,
		},
		{
			name: "Unsupported transformation",
			outputMapping: []types.OutputMapping{
				{SourceColumn: "groups", ClaimName: "group_memberships", Transformation: "unsupported_transform"},
			},
			expectError: true,
		},
		{
			name: "Supported SQL transformation",
			outputMapping: []types.OutputMapping{
				{SourceColumn: "groups", ClaimName: "group_memberships", Transformation: "postgres_array"},
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

func TestSQLMapper_GetSupportedTransformations(t *testing.T) {
	mapper := NewSQLMapper()
	transformations := mapper.GetSupportedTransformations()

	expectedTransformations := []string{
		// Common transformations
		"csv_to_array",
		"array",
		"string",
		"lowercase",
		"uppercase",
		// SQL-specific transformations
		"postgres_array",
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

func TestSQLMapper_isValidSQLIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   bool
	}{
		{"Valid identifier", "user_id", true},
		{"Valid identifier with numbers", "user123", true},
		{"Valid identifier starting with underscore", "_private", true},
		{"Invalid empty string", "", false},
		{"Invalid starting with number", "123user", false},
		{"Invalid with hyphen", "user-id", false},
		{"Invalid with space", "user id", false},
		{"Invalid with special chars", "user@id", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSQLIdentifier(tt.identifier)
			if result != tt.expected {
				t.Errorf("isValidSQLIdentifier(%s): expected %v, got %v", tt.identifier, tt.expected, result)
			}
		})
	}
}
