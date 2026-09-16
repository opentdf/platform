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

// KeyOptions configures behavior common to key lookup and listing operations.
type KeyOptions struct {
	// ID identifies the key to find.
	ID     KeyIdentifier
	KASURI string
}

// FindKeyOptions configures a key lookup.
type FindKeyOptions struct {
	KeyOptions
}

// ListKeyOptions configures key listing and filtering.
type ListKeyOptions struct {
	KeyOptions
	LegacyOnly bool
}

const (
	// KeyTypeJWK represents a key in JWK format
	KeyTypeJWK KeyType = iota
	// KeyTypePKCS8 represents a key in PKCS8 format
	KeyTypePKCS8
)

// KeyIdentifier identifies a key within its source's scope, not necessarily globally.
type KeyIdentifier string

type PrivateKey struct {
	// Key ID of the Key used to wrap the private key
	WrappingKeyID KeyIdentifier
	// Wrapped Key is the encrypted private key
	WrappedKey string
}

// KeyDetails provides information about a specific key
type KeyDetails interface {
	// ID returns the key's identifier within its source's scope.
	// For a KasKey, uniqueness requires both this ID and its KAS registry.
	// Prefer using the CacheKey() method which should always return a unique
	// string for backing keys
	ID() KeyIdentifier

	// CacheKey returns an opaque, stable identifier that distinguishes this key
	// from keys in other registries or providers sharing a cache.
	// Use ID for key lookups amonst key providers and CacheKey for caching key material.
	CacheKey() string

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

	// FindKeyWith returns a key using the specified options.
	FindKeyWith(ctx context.Context, opts FindKeyOptions) (KeyDetails, error)

	// ListKeys returns all available keys
	ListKeys(ctx context.Context) ([]KeyDetails, error)

	// List keys with options
	ListKeysWith(ctx context.Context, opts ListKeyOptions) ([]KeyDetails, error)
}
