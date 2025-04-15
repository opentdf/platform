// Package cryptoproviders implements interfaces and errors for crypto operations
package cryptoproviders

import "fmt"

// ErrProviderNotFound is returned when a requested crypto provider is not registered
type ErrProviderNotFound struct {
	ProviderID string
}

func (e ErrProviderNotFound) Error() string {
	return fmt.Sprintf("crypto provider not found: %s", e.ProviderID)
}

// ErrInvalidKeyFormat is returned when a key is not in the expected format
type ErrInvalidKeyFormat struct {
	Details string
}

func (e ErrInvalidKeyFormat) Error() string {
	return fmt.Sprintf("invalid key format: %s", e.Details)
}

// ErrOperationFailed is returned when a crypto operation fails
type ErrOperationFailed struct {
	Op  string
	Err error
}

func (e ErrOperationFailed) Error() string {
	return fmt.Sprintf("crypto operation failed: %s: %v", e.Op, e.Err)
}

func (e ErrOperationFailed) Unwrap() error {
	return e.Err
}
