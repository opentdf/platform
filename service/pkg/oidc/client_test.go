package oidc

import (
	"testing"
)

func TestSetSkipValidationForTest(t *testing.T) {
	// Save the original value to restore later
	originalValue := skipValidation
	defer func() {
		skipValidation = originalValue
	}()

	// Test setting to true
	SetSkipValidationForTest(true)
	if !skipValidation {
		t.Error("Expected skipValidation to be true")
	}

	// Test setting to false
	SetSkipValidationForTest(false)
	if skipValidation {
		t.Error("Expected skipValidation to be false")
	}
}
