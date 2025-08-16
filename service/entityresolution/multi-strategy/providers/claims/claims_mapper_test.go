package claims

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

func TestClaimsMapper_ExtractParameters(t *testing.T) {
	mapper := NewMapper()

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
		{
			name: "Optional claim missing",
			jwtClaims: types.JWTClaims{
				"email": "user@example.com",
			},
			inputMapping: []types.InputMapping{
				{JWTClaim: "email", Parameter: "user_email", Required: true},
				{JWTClaim: "sub", Parameter: "user_id", Required: false},
			},
			expectedParams: map[string]interface{}{
				"user_email": "user@example.com",
			},
			expectError: false,
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

func TestClaimsMapper_TransformResults(t *testing.T) {
	mapper := NewMapper()

	tests := []struct {
		name           string
		rawData        map[string]interface{}
		outputMapping  []types.OutputMapping
		expectedClaims map[string]interface{}
		expectError    bool
	}{
		{
			name: "Basic claim transformation",
			rawData: map[string]interface{}{
				"sub":   "user123",
				"email": "user@example.com",
				"name":  "Test User",
			},
			outputMapping: []types.OutputMapping{
				{SourceClaim: "sub", ClaimName: "subject"},
				{SourceClaim: "email", ClaimName: "email_address"},
				{SourceClaim: "name", ClaimName: "display_name"},
			},
			expectedClaims: map[string]interface{}{
				"subject":       "user123",
				"email_address": "user@example.com",
				"display_name":  "Test User",
			},
			expectError: false,
		},
		{
			name: "CSV to array transformation",
			rawData: map[string]interface{}{
				"groups": "admin,user,finance",
			},
			outputMapping: []types.OutputMapping{
				{SourceClaim: "groups", ClaimName: "group_memberships", Transformation: "csv_to_array"},
			},
			expectedClaims: map[string]interface{}{
				"group_memberships": []string{"admin", "user", "finance"},
			},
			expectError: false,
		},
		{
			name: "JWT extract scope transformation",
			rawData: map[string]interface{}{
				"scope": "read write admin",
			},
			outputMapping: []types.OutputMapping{
				{SourceClaim: "scope", ClaimName: "scopes", Transformation: "jwt_extract_scope"},
			},
			expectedClaims: map[string]interface{}{
				"scopes": []string{"read", "write", "admin"},
			},
			expectError: false,
		},
		{
			name: "JWT normalize groups transformation - comma separated",
			rawData: map[string]interface{}{
				"groups": "admin, user, finance",
			},
			outputMapping: []types.OutputMapping{
				{SourceClaim: "groups", ClaimName: "normalized_groups", Transformation: "jwt_normalize_groups"},
			},
			expectedClaims: map[string]interface{}{
				"normalized_groups": []string{"admin", "user", "finance"},
			},
			expectError: false,
		},
		{
			name: "Missing source claim (ignored)",
			rawData: map[string]interface{}{
				"sub": "user123",
			},
			outputMapping: []types.OutputMapping{
				{SourceClaim: "sub", ClaimName: "subject"},
				{SourceClaim: "missing_claim", ClaimName: "missing"},
			},
			expectedClaims: map[string]interface{}{
				"subject": "user123",
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
				verifyClaimValue(t, claims, key, expectedValue)
			}
		})
	}
}

func verifyClaimValue(t *testing.T, claims map[string]interface{}, key string, expectedValue interface{}) {
	actualValue, exists := claims[key]
	if !exists {
		t.Errorf("Expected claim %s not found", key)
		return
	}

	// Handle slice comparison
	expectedSlice, isSlice := expectedValue.([]string)
	if !isSlice {
		if actualValue != expectedValue {
			t.Errorf("Claim %s: expected %v, got %v", key, expectedValue, actualValue)
		}
		return
	}

	actualSlice, sliceOK := actualValue.([]string)
	if !sliceOK {
		t.Errorf("Claim %s: expected slice, got %T", key, actualValue)
		return
	}

	if len(expectedSlice) != len(actualSlice) {
		t.Errorf("Claim %s: expected slice length %d, got %d", key, len(expectedSlice), len(actualSlice))
		return
	}

	for i, expectedItem := range expectedSlice {
		if actualSlice[i] != expectedItem {
			t.Errorf("Claim %s[%d]: expected %v, got %v", key, i, expectedItem, actualSlice[i])
		}
	}
}

func TestClaimsMapper_ValidateInputMapping(t *testing.T) {
	mapper := NewMapper()

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
			name: "Empty JWT claim",
			inputMapping: []types.InputMapping{
				{JWTClaim: "", Parameter: "user_email", Required: true},
			},
			expectError: true,
		},
		{
			name: "Empty parameter",
			inputMapping: []types.InputMapping{
				{JWTClaim: "email", Parameter: "", Required: true},
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

func TestClaimsMapper_ValidateOutputMapping(t *testing.T) {
	mapper := NewMapper()

	tests := []struct {
		name          string
		outputMapping []types.OutputMapping
		expectError   bool
	}{
		{
			name: "Valid output mapping",
			outputMapping: []types.OutputMapping{
				{SourceClaim: "sub", ClaimName: "subject"},
				{SourceClaim: "email", ClaimName: "email_address"},
			},
			expectError: false,
		},
		{
			name: "Empty source claim",
			outputMapping: []types.OutputMapping{
				{SourceClaim: "", ClaimName: "subject"},
			},
			expectError: true,
		},
		{
			name: "Empty claim name",
			outputMapping: []types.OutputMapping{
				{SourceClaim: "sub", ClaimName: ""},
			},
			expectError: true,
		},
		{
			name: "Unsupported transformation",
			outputMapping: []types.OutputMapping{
				{SourceClaim: "sub", ClaimName: "subject", Transformation: "unsupported_transform"},
			},
			expectError: true,
		},
		{
			name: "Supported transformation",
			outputMapping: []types.OutputMapping{
				{SourceClaim: "groups", ClaimName: "group_memberships", Transformation: "csv_to_array"},
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

func TestClaimsMapper_GetSupportedTransformations(t *testing.T) {
	mapper := NewMapper()
	transformations := mapper.GetSupportedTransformations()

	expectedTransformations := []string{
		"csv_to_array",
		"array",
		"string",
		"lowercase",
		"uppercase",
		"jwt_extract_scope",
		"jwt_normalize_groups",
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
