package recrypt

import "github.com/opentdf/platform/lib/ocrypto"

// A package with an interface for cryptography operations,
// such that they can be implemented either
// through an HSM
// or with go crypto primitives.

// KeyIdentifier uniquely identifies a key within this crypto provider.
type KeyIdentifier string

// Algorithm identifies a cryptographic algorithm.
type Algorithm string

// KeyFormat identifies a key format.
type KeyFormat string

// CryptoProviders implement KAS key unwrap functionality.
// These include:
//   - Presenting stable public keys for wrapping client encryption keys.
//   - Backward compatibility
//   - Key agreement for nanoTDF and other EC based solutions
//
// This may be Closeable
type Provider interface {
	// Return current preferred key identifier(s) for wrapping with the given algorithm.
	CurrentKID(alg Algorithm) ([]KeyIdentifier, error)

	// Return one or more 'legacy' key identifiers that can be used when no KID is presented
	// [optional]
	LegacyKIDs(a Algorithm) ([]KeyIdentifier, error)

	// Returns a public key or cert for the given key ID and algorithm in the given format.
	// Currently, only the JWK format supports multiple keys at once.
	PublicKey(a Algorithm, k []KeyIdentifier, f KeyFormat) (string, error)

	// Perform an unwrap using the given alg/keyid pair on the given wrapped key bytes
	Unwrap(k KeyIdentifier, ciphertext []byte) (UnwrappedKey, error)

	// Derive a shared key. Note: alg includes curve if present?
	Derive(k KeyIdentifier, ephemeralPublicKeyBytes []byte) (UnwrappedKey, error)

	ParseAlgorithm(s string) (Algorithm, error)
	ParseKeyFormat(s string) (KeyFormat, error)
	ParseKeyIdentifier(s string) (KeyIdentifier, error)
}

// Optional type to implement closeable crypto providers
// Probably not needed? But maybe we should do this anyway?
type Closeable interface {
	Close()
}

// Optional type for a crypto provider that can generate keys
type KeyGenerator interface {
	// Generate a new key of the given algorithm, with an optional identifier
	GenerateKey(a Algorithm, id KeyIdentifier) (KeyIdentifier, error)
}

type NanoWrapResponse struct {
	EntityWrappedKey []byte
	SessionPublicKey string
}

type UnwrappedKey interface {
	Digest(msg []byte) ([]byte, error)
	Wrap(within ocrypto.AsymEncryption) ([]byte, error)
	NanoWrap(within []byte) (*NanoWrapResponse, error)
	DecryptNanoPolicy(cipherText []byte, tagSize int) ([]byte, error)
}

type KeyDetails struct {
	// The key identifier
	ID KeyIdentifier
	// The algorithm of the key
	Algorithm Algorithm
	// If the key is 'current' for the given algorithm
	Current bool
	// Label value, if present on the key.
	Label string
	// Public PEM value, if available
	Public string
}

// Optional type for a crypto provider that can list its keys
type Lister interface {
	// List all keys in the provider
	List() ([]KeyDetails, error)
}

const (
	// No algorithm specified in a request
	AlgorithmUndefined Algorithm = ""
	// Key agreement along P-256
	AlgorithmECP256R1 Algorithm = "ec:secp256r1"
	// Key agreement along P-256
	AlgorithmECP384R1 Algorithm = "ec:secp384r1"
	// Key agreement along P-256
	AlgorithmECP521R1 Algorithm = "ec:secp521r1"
	// Used for encryption with RSA of the KAO
	AlgorithmRSA2048 Algorithm = "rsa:2048"

	// Unspecified key format
	KeyFormatUndefined KeyFormat = ""
	// JavaScript Object Notation Web Key (JWK)
	KeyFormatJWK KeyFormat = "jwk"
	// Privacy Enhanced Mail (PEM) format
	KeyFormatPEM KeyFormat = "pkcs8"
)
