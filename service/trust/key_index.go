package trust

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
)

// KeyType represents the format in which a key can be exported
type KeyType int

// Key Options to pass into ListKeysWith
// when filtering keys
type ListKeyOptions struct {
	LegacyOnly bool
}

const (
	// KeyTypeJWK represents a key in JWK format
	KeyTypeJWK KeyType = iota
	// KeyTypePKCS8 represents a key in PKCS8 format
	KeyTypePKCS8
)

// KeyIdentifier uniquely identifies a key
type KeyIdentifier string

type PrivateKey struct {
	// Key ID of the Key used to wrap the private key
	WrappingKeyID KeyIdentifier
	// Wrapped Key is the encrypted private key
	WrappedKey string
}

// KeyDetails provides information about a specific key
type KeyDetails interface {
	// ID returns the unique identifier for the key
	ID() KeyIdentifier

	// Algorithm returns the algorithm used by the key
	Algorithm() ocrypto.KeyType

	// IsLegacy returns true if this is a legacy key that should only be used for decryption
	IsLegacy() bool

	// ExportPrivateKey exports the private key in the specified format
	// Returns error if key is not exportable
	ExportPrivateKey(ctx context.Context) (*PrivateKey, error)

	// ExportPublicKey exports the public key in the specified format
	ExportPublicKey(ctx context.Context, format KeyType) (string, error)

	// ExportCertificate exports the certificate associated with the key, if available
	ExportCertificate(ctx context.Context) (string, error)

	// Gets the mode indicator for the key; this is used to lookup the appropriate KeyManager.
	System() string

	// Get the provider configutaiton for the key
	ProviderConfig() *policy.KeyProviderConfig
}

// KeyIndex provides methods to locate keys by various criteria
type KeyIndex interface {
	fmt.Stringer
	slog.LogValuer
	// FindKeyByAlgorithm returns a key for the specified algorithm
	// If includeLegacy is true, legacy keys will be included in the search
	FindKeyByAlgorithm(ctx context.Context, algorithm string, includeLegacy bool) (KeyDetails, error)

	// FindKeyByID returns a key with the specified ID
	FindKeyByID(ctx context.Context, id KeyIdentifier) (KeyDetails, error)

	// ListKeys returns all available keys
	ListKeys(ctx context.Context) ([]KeyDetails, error)

	// List keys with options
	ListKeysWith(ctx context.Context, opts ListKeyOptions) ([]KeyDetails, error)
}

// RegisteredKasURIResolver resolves the registered KAS URI for KAS when running with key management.
type RegisteredKasURIResolver interface {
	ResolveURI() (string, error)
	String() string
	LogValue() slog.Value
}
