// Package errors holds the error types used throughout the application.
package errors

type Error string

func (e Error) Error() string {
	return string(e)
}

const (
	// Config Errors
	ErrLoadingConfig = Error("failed to load config")

	// GRPC Errors.
	ErrCreatingResource = Error("failed to create resource")
	ErrDeletingResource = Error("failed to delete resource")
	ErrGettingResource  = Error("failed to get resource")
	ErrListingResource  = Error("failed to list resources")
	ErrUpdatingResource = Error("failed to update resource")
	ErrNotFound         = Error("resource not found")
)

// DB Errors.

// ACRE Errors.

// ACSE Errors

// Attributes Errors
