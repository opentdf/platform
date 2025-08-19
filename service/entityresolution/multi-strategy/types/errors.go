package types

import (
	"fmt"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeConfiguration ErrorType = "configuration"
	ErrorTypeProvider      ErrorType = "provider"
	ErrorTypeStrategy      ErrorType = "strategy"
	ErrorTypeMapping       ErrorType = "mapping"
	ErrorTypeJWT           ErrorType = "jwt"
	ErrorTypeHealth        ErrorType = "health"
)

// MultiStrategyError represents an error in the multi-strategy ERS
type MultiStrategyError struct {
	Type     ErrorType              `json:"type"`
	Message  string                 `json:"message"`
	Context  map[string]interface{} `json:"context,omitempty"`
	Original error                  `json:"original,omitempty"`
}

// NewMultiStrategyError creates a new multi-strategy error
func NewMultiStrategyError(errorType ErrorType, message string, context map[string]interface{}) *MultiStrategyError {
	return &MultiStrategyError{
		Type:    errorType,
		Message: message,
		Context: context,
	}
}

// Error implements the error interface
func (e *MultiStrategyError) Error() string {
	if e.Original != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Type, e.Message, e.Original)
	}
	return fmt.Sprintf("[%s] %s", e.Type, e.Message)
}

// Unwrap returns the original error for error wrapping
func (e *MultiStrategyError) Unwrap() error {
	return e.Original
}

// WrapMultiStrategyError wraps an existing error with multi-strategy context
func WrapMultiStrategyError(errorType ErrorType, message string, original error, context map[string]interface{}) *MultiStrategyError {
	return &MultiStrategyError{
		Type:     errorType,
		Message:  message,
		Context:  context,
		Original: original,
	}
}

// Common error constructors
func NewConfigurationError(message string, context map[string]interface{}) error {
	return NewMultiStrategyError(ErrorTypeConfiguration, message, context)
}

func NewProviderError(message string, context map[string]interface{}) error {
	return NewMultiStrategyError(ErrorTypeProvider, message, context)
}

func NewStrategyError(message string, context map[string]interface{}) error {
	return NewMultiStrategyError(ErrorTypeStrategy, message, context)
}

func NewMappingError(message string, context map[string]interface{}) error {
	return NewMultiStrategyError(ErrorTypeMapping, message, context)
}

func NewJWTError(message string, context map[string]interface{}) error {
	return NewMultiStrategyError(ErrorTypeJWT, message, context)
}

func NewHealthError(message string, context map[string]interface{}) error {
	return NewMultiStrategyError(ErrorTypeHealth, message, context)
}
