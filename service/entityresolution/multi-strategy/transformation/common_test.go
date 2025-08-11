package transformation

import (
	"reflect"
	"testing"
)

func TestApplyCSVToArray(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		hasError bool
	}{
		{
			name:     "Valid CSV string",
			input:    "apple,banana,cherry",
			expected: []string{"apple", "banana", "cherry"},
			hasError: false,
		},
		{
			name:     "CSV with spaces",
			input:    "apple, banana , cherry ",
			expected: []string{"apple", "banana", "cherry"},
			hasError: false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: []string{},
			hasError: false,
		},
		{
			name:     "Single item",
			input:    "apple",
			expected: []string{"apple"},
			hasError: false,
		},
		{
			name:     "Non-string input",
			input:    123,
			expected: nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyCSVToArray(tt.input)
			
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
				t.Errorf("ApplyCSVToArray(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyArray(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		hasError bool
	}{
		{
			name:     "Already []interface{}",
			input:    []interface{}{"a", "b", "c"},
			expected: []interface{}{"a", "b", "c"},
			hasError: false,
		},
		{
			name:     "Convert []string to []interface{}",
			input:    []string{"a", "b", "c"},
			expected: []interface{}{"a", "b", "c"},
			hasError: false,
		},
		{
			name:     "Wrap single value",
			input:    "single",
			expected: []interface{}{"single"},
			hasError: false,
		},
		{
			name:     "Wrap integer",
			input:    123,
			expected: []interface{}{123},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyArray(tt.input)
			
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
				t.Errorf("ApplyArray(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyString(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		hasError bool
	}{
		{
			name:     "String input",
			input:    "hello",
			expected: "hello",
			hasError: false,
		},
		{
			name:     "Integer input",
			input:    123,
			expected: "123",
			hasError: false,
		},
		{
			name:     "Boolean input",
			input:    true,
			expected: "true",
			hasError: false,
		},
		{
			name:     "Nil input",
			input:    nil,
			expected: "<nil>",
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyString(tt.input)
			
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
				t.Errorf("ApplyString(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyLowercase(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		hasError bool
	}{
		{
			name:     "String input",
			input:    "HELLO",
			expected: "hello",
			hasError: false,
		},
		{
			name:     "Mixed case",
			input:    "HeLLo WoRLd",
			expected: "hello world",
			hasError: false,
		},
		{
			name:     "Already lowercase",
			input:    "hello",
			expected: "hello",
			hasError: false,
		},
		{
			name:     "Integer input",
			input:    123,
			expected: "123",
			hasError: false,
		},
		{
			name:     "Boolean input",
			input:    true,
			expected: "true",
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyLowercase(tt.input)
			
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
				t.Errorf("ApplyLowercase(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyUppercase(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		hasError bool
	}{
		{
			name:     "String input",
			input:    "hello",
			expected: "HELLO",
			hasError: false,
		},
		{
			name:     "Mixed case",
			input:    "HeLLo WoRLd",
			expected: "HELLO WORLD",
			hasError: false,
		},
		{
			name:     "Already uppercase",
			input:    "HELLO",
			expected: "HELLO",
			hasError: false,
		},
		{
			name:     "Integer input",
			input:    123,
			expected: "123",
			hasError: false,
		},
		{
			name:     "Boolean input",
			input:    false,
			expected: "FALSE",
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyUppercase(tt.input)
			
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
				t.Errorf("ApplyUppercase(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyCommonTransformation(t *testing.T) {
	tests := []struct {
		name           string
		transformation string
		input          interface{}
		expected       interface{}
		hasError       bool
	}{
		{
			name:           "CSV to Array",
			transformation: CommonCSVToArray,
			input:          "a,b,c",
			expected:       []string{"a", "b", "c"},
			hasError:       false,
		},
		{
			name:           "Array transformation",
			transformation: CommonArray,
			input:          "single",
			expected:       []interface{}{"single"},
			hasError:       false,
		},
		{
			name:           "String transformation",
			transformation: CommonString,
			input:          123,
			expected:       "123",
			hasError:       false,
		},
		{
			name:           "Lowercase transformation",
			transformation: CommonLowercase,
			input:          "HELLO",
			expected:       "hello",
			hasError:       false,
		},
		{
			name:           "Uppercase transformation",
			transformation: CommonUppercase,
			input:          "hello",
			expected:       "HELLO",
			hasError:       false,
		},
		{
			name:           "Unknown transformation",
			transformation: "unknown",
			input:          "test",
			expected:       nil,
			hasError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyCommonTransformation(tt.input, tt.transformation)
			
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
				t.Errorf("ApplyCommonTransformation(%v, %s) = %v, expected %v", 
					tt.input, tt.transformation, result, tt.expected)
			}
		})
	}
}