package security

import (
	"errors"
)

var (
	ErrCertNotFound = errors.New("certificate not found")
)

// KeyType represents the format in which a key can be exported
type KeyType int

const (
	// KeyTypeJWK represents a key in JWK format
	KeyTypeJWK KeyType = iota
	// KeyTypePKCS8 represents a key in PKCS8 format
	KeyTypePKCS8
)

// KeyIdentifier uniquely identifies a key
type KeyIdentifier string

// KeyDetails provides information about a specific key
type KeyDetails interface {
	// ID returns the unique identifier for the key
	ID() KeyIdentifier

	// Algorithm returns the algorithm used by the key
	Algorithm() string

	// IsLegacy returns true if this is a legacy key that should only be used for decryption
	IsLegacy() bool

	// ExportPublicKey exports the public key in the specified format
	ExportPublicKey(format KeyType) (string, error)

	// ExportCertificate exports the certificate associated with the key, if available
	ExportCertificate() (string, error)
}

// KeyLookup provides methods to locate keys by various criteria
type KeyLookup interface {
	// FindKeyByAlgorithm returns a key for the specified algorithm
	// If includeLegacy is true, legacy keys will be included in the search
	FindKeyByAlgorithm(algorithm string, includeLegacy bool) (KeyDetails, error)

	// FindKeyByID returns a key with the specified ID
	FindKeyByID(id KeyIdentifier) (KeyDetails, error)

	// ListKeys returns all available keys
	ListKeys() ([]KeyDetails, error)
}
