package store

import (
	"errors"
	"fmt"
	"regexp"
)

// DriverOpt is a variadic function to apply any driver-specific options, which
// apply any side effects/hooks necessary for the driver.
type DriverOpt func() error

// StoreInterface is an interface for a store of a single key and value under a namespace.
// The key is unique within the namespace, and the stored value is a JSON-serialized struct.
//
// In a CLI 'example_cli' consuming this store to save user profiles, the namespace would be 'example_cli',
// and the key would be the specific CLI user's profile name.
type NewStoreInterface func(serviceNamespace, key string, driverOpt ...DriverOpt) (StoreInterface, error)

// TODO: should we reconfigure this abstraction so we have a more traditional key-value store?
// Would need to be a v2 concern as would definitely be breaking.

// StoreInterface is a reusable interface that varied drivers can share to implement a store.
type StoreInterface interface {
	// Exists returns true if the value exists in the store.
	Exists() bool
	// Get retrieves the entry bytes from the store.
	Get() ([]byte, error)
	// Set marshals the provided value into JSON and stores it.
	Set(value interface{}) error
	// Delete removes the entry from the store.
	Delete() error
}

// NewCustomStore is a package global to init a custom store implementation.
var NewCustomStore NewStoreInterface

const maxFileNameLength = 255

// ValidateNamespaceKey ensures the namespace and key are valid and within length bounds.
func ValidateNamespaceKey(serviceNamespace, key string) error {
	// Regular expression for allowed characters (alphanumerics, underscore, hyphen)
	validName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	if len(serviceNamespace) == 0 {
		return errors.Join(ErrNamespaceInvalid, ErrValueEmpty)
	}

	if len(key) == 0 {
		return errors.Join(ErrKeyInvalid, ErrValueEmpty)
	}

	if !validName.MatchString(serviceNamespace) {
		return fmt.Errorf("%w, %w, namespace: %s", ErrNamespaceInvalid, ErrValueBadCharacters, serviceNamespace)
	}
	if !validName.MatchString(key) {
		return fmt.Errorf("%w, %w, key: %s", ErrKeyInvalid, ErrValueBadCharacters, key)
	}

	// Ensure the filename is within length bounds when including a file extension
	filename := fmt.Sprintf("%s_%s.ext", serviceNamespace, key)
	if len(filename) > maxFileNameLength {
		return fmt.Errorf("%w, <namespace_key>.ext exceeds maximum length (%d): %s", ErrLengthExceeded, maxFileNameLength, filename)
	}

	return nil
}
