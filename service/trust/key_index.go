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

// KeyIdentifier identifies a key within the backing key adapter's scope, not necessarily globally.
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
	// Managers must use this ID when requesting keys from their providers.
	// For a KasKey, uniqueness requires both this ID and its KAS URI.
	// For identity across key sources, use ScopedKeyIdentifier when implemented.
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

// ScopedKeyIdentifier optionally provides an identity that distinguishes keys
// across key sources, where KeyDetails.ID() alone may not be unique.
// Use it for caching or comparing keys across sources. Provider requests and
// provider-scoped lookups must continue to use KeyDetails.ID().
type ScopedKeyIdentifier interface {
	// ScopedKeyID returns an opaque, stable identifier that includes the key's source
	// scope. For KAS keys, this scope is the KAS URI, so registrations sharing a
	// key ID remain distinct.
	ScopedKeyID() string
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
