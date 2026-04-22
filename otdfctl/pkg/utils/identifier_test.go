package utils

import (
	"testing"
)

func TestClassifyString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected IdentifierStringType
	}{
		{
			name:     "Valid UUID",
			input:    "123e4567-e89b-12d3-a456-426614174000",
			expected: StringTypeUUID,
		},
		{
			name:     "Valid UUID with spaces",
			input:    "  123e4567-e89b-12d3-a456-426614174000  ",
			expected: StringTypeUUID,
		},
		{
			name:     "Valid URI - https",
			input:    "https://example.com/path?query=value",
			expected: StringTypeURI,
		},
		{
			name:     "Valid URI - http",
			input:    "http://localhost:8080",
			expected: StringTypeURI,
		},
		{
			name:     "Valid URI with spaces",
			input:    "  https://example.com/path  ",
			expected: StringTypeURI,
		},
		{
			name:     "Generic string - name",
			input:    "my-kas-server",
			expected: StringTypeGeneric,
		},
		{
			name:     "Generic string - simple word",
			input:    "kas1",
			expected: StringTypeGeneric,
		},
		{
			name:     "Generic string with spaces",
			input:    "  My KAS Name  ",
			expected: StringTypeGeneric,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: StringTypeUnknown,
		},
		{
			name:     "String with only spaces",
			input:    "   ",
			expected: StringTypeUnknown,
		},
		{
			name:     "Invalid UUID - too short",
			input:    "123e4567-e89b-12d3-a456-42661417400",
			expected: StringTypeGeneric, // Falls back to generic
		},
		{
			name:     "Invalid URI - no scheme",
			input:    "example.com/path",
			expected: StringTypeGeneric, // Falls back to generic
		},
		{
			name:     "Invalid URI - no host",
			input:    "https:///path",
			expected: StringTypeGeneric, // Falls back to generic
		},
		{
			name:     "String that looks like URI but isn't absolute",
			input:    "/just/a/path",
			expected: StringTypeGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyString(tt.input); got != tt.expected {
				t.Errorf("ClassifyString() = %v, want %v", got, tt.expected)
			}
		})
	}
}
