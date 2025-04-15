// Package cryptoProviders provides a flexible cryptographic service that supports
// multiple providers and different modes of key management.
//
// The package implements three modes of operation for key management:
//
// 1. LOCAL with KEK from configuration:
//   - Private keys are wrapped with a Key Encryption Key (KEK) provided via configuration
//   - The default provider handles key unwrapping and crypto operations
//   - Suitable for development or when keys are managed locally
//
// 2. LOCAL with KEK from Provider:
//   - Private keys are wrapped with a KEK stored in a provider (e.g., AWS KMS)
//   - The specified provider handles key unwrapping
//   - The default provider handles crypto operations
//   - Provides better security by using a managed key service
//
// 3. REMOTE operations:
//   - All crypto operations happen within a KMS or HSM
//   - No key unwrapping is needed as keys never leave the secure environment
//   - Highest level of security as private keys remain in the secure module
//
// The mode is determined by the KeyMode and ProviderConfig of the key reference:
// - KeyMode_KEY_MODE_LOCAL with no ProviderConfig uses mode 1
// - KeyMode_KEY_MODE_LOCAL with ProviderConfig uses mode 2
// - KeyMode_KEY_MODE_REMOTE uses mode 3
//
// For encryption operations (which only use public keys), the provider selection
// is simpler but still respects the configured provider:
// - If ProviderConfig is specified, use that provider
// - Otherwise, use the default provider
package cryptoproviders

import (
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"

	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	DefaultProvider                = "default"
	DefaultRSAOAEPHash crypto.Hash = crypto.SHA256
)

// KeyFormat represents the format and encoding of a cryptographic key
type KeyFormat struct {
	// Raw key bytes
	Raw []byte
	// Format specifies how the key bytes are encoded (e.g. "pem", "der", "compressed", "uncompressed")
	Format string
}

// NewKeyFormat creates a new KeyFormat from raw bytes with default PEM format
func NewKeyFormat(raw []byte) KeyFormat {
	return KeyFormat{
		Raw:    raw,
		Format: "pem", // Default format
	}
}

type PrivateKeyCtx struct {
	WrappedKey []byte `json:"wrappedKey"`
}

type KeyRef struct {
	Key       KeyFormat
	Algorithm policy.Algorithm
}

// FromBytes creates a KeyRef from raw bytes and algorithm
func NewKeyRef(raw []byte, algorithm policy.Algorithm) KeyRef {
	return KeyRef{
		Key:       NewKeyFormat(raw),
		Algorithm: algorithm,
	}
}

// GetRawBytes returns the raw key bytes
func (k *KeyRef) GetRawBytes() []byte {
	return k.Key.Raw
}

// IsRSA returns true if the algorithm is an RSA variant
func (k *KeyRef) IsRSA() bool {
	return k.Algorithm == policy.Algorithm_ALGORITHM_RSA_2048 ||
		k.Algorithm == policy.Algorithm_ALGORITHM_RSA_4096
}

// IsEC returns true if the algorithm is an EC variant
func (k *KeyRef) IsEC() bool {
	return k.Algorithm == policy.Algorithm_ALGORITHM_EC_P256 ||
		k.Algorithm == policy.Algorithm_ALGORITHM_EC_P384 ||
		k.Algorithm == policy.Algorithm_ALGORITHM_EC_P521
}

// GetExpectedRSAKeySize returns the expected key size in bytes for RSA keys
func (k *KeyRef) GetExpectedRSAKeySize() int {
	switch k.Algorithm {
	case policy.Algorithm_ALGORITHM_RSA_2048:
		return 256 // 2048 bits = 256 bytes
	case policy.Algorithm_ALGORITHM_RSA_4096:
		return 512 // 4096 bits = 512 bytes
	default:
		return 0
	}
}

// Validate checks if the key format matches the algorithm
func (k *KeyRef) Validate() error {
	if k.Key.Raw == nil {
		return ErrInvalidKeyFormat{Details: "key bytes cannot be nil"}
	}

	if k.IsRSA() {
		expectedSize := k.GetExpectedRSAKeySize()
		if expectedSize == 0 {
			return ErrInvalidKeyFormat{Details: "unsupported RSA key size"}
		}
		if len(k.Key.Raw) != expectedSize {
			return ErrInvalidKeyFormat{Details: fmt.Sprintf("invalid RSA key length: expected %d bytes", expectedSize)}
		}
	}

	if k.IsEC() {
		// EC public keys should be 65 bytes uncompressed or 33 bytes compressed
		keyLen := len(k.Key.Raw)
		if keyLen != 33 && keyLen != 65 {
			return ErrInvalidKeyFormat{Details: "invalid EC key length: must be 33 (compressed) or 65 (uncompressed) bytes"}
		}
	}

	return nil
}

// CryptoService manages multiple CryptoProviders and handles provider selection
type CryptoService struct {
	defaultProvider CryptoProvider
	providers       map[string]CryptoProvider
	mu              sync.RWMutex
}

// NewCryptoService creates a new CryptoService with the specified default provider
func NewCryptoService(defaultProvider CryptoProvider) *CryptoService {
	if defaultProvider == nil {
		panic("default crypto provider cannot be nil")
	}
	cs := &CryptoService{
		defaultProvider: defaultProvider,
		providers:       make(map[string]CryptoProvider),
	}
	cs.providers[DefaultProvider] = defaultProvider
	return cs
}

// RegisterProvider adds a new crypto provider to the service
func (c *CryptoService) RegisterProvider(provider CryptoProvider) {
	if provider == nil {
		panic("cannot register nil provider")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.providers[provider.Identifier()] = provider
}

// GetProvider returns a provider by its identifier
func (c *CryptoService) GetProvider(id string) (CryptoProvider, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if provider, exists := c.providers[id]; exists {
		return provider, nil
	}
	return nil, ErrProviderNotFound{ProviderID: id}
}

// EncryptOpts contains options for asymmetric encryption
type EncryptOpts struct {
	KeyRef       KeyRef
	Data         []byte
	Hash         crypto.Hash // For RSA-OAEP
	EphemeralKey []byte      // For EC
}

// DecryptOpts contains options for asymmetric decryption
type DecryptOpts struct {
	KeyRef       KeyRef
	CipherText   []byte
	EphemeralKey []byte // For EC
	KEK          []byte // For local mode
}

// CryptoProvider defines the interface for cryptographic operations
type CryptoProvider interface {
	// Identifier returns the provider's unique identifier
	Identifier() string

	// Symmetric methods
	EncryptSymmetric(ctx context.Context, key []byte, data []byte) ([]byte, error)
	DecryptSymmetric(ctx context.Context, key []byte, cipherText []byte) ([]byte, error)

	// Unified methods for asymmetric cryptography
	EncryptAsymmetric(ctx context.Context, opts EncryptOpts) (cipherText []byte, ephemeralKey []byte, err error)
	DecryptAsymmetric(ctx context.Context, opts DecryptOpts) ([]byte, error)
}

// DecryptAsymmetric provides a unified interface for asymmetric decryption
func (c *CryptoService) DecryptAsymmetric(ctx context.Context, keyRef *policy.AsymmetricKey, cipherText []byte, opts ...interface{}) ([]byte, error) {
	if keyRef == nil {
		return nil, ErrInvalidKeyFormat{Details: "key reference is nil"}
	}

	if len(cipherText) == 0 {
		return nil, ErrOperationFailed{Op: "asymmetric decryption", Err: fmt.Errorf("empty ciphertext")}
	}

	// Parse private key context
	pkCtx := &PrivateKeyCtx{}
	if err := json.Unmarshal(keyRef.GetPrivateKeyCtx(), pkCtx); err != nil {
		return nil, ErrInvalidKeyFormat{Details: fmt.Sprintf("failed to unmarshal private key context: %v", err)}
	}

	// Initialize decrypt options
	decOpts := DecryptOpts{
		CipherText: cipherText,
	}

	// Handle algorithm-specific options with flattening to support functional options signature
	for _, opt := range opts {
		switch v := opt.(type) {
		case []RSAOptions:
			cfg := &rsaConfig{}
			for _, o := range v {
				if err := o(cfg); err != nil {
					return nil, ErrOperationFailed{Op: "applying RSA options", Err: err}
				}
			}
			decOpts.KEK = cfg.kek
		case RSAOptions:
			cfg := &rsaConfig{}
			if err := v(cfg); err != nil {
				return nil, ErrOperationFailed{Op: "applying RSA options", Err: err}
			}
			decOpts.KEK = cfg.kek
		case []ECOptions:
			cfg := &ecConfig{}
			for _, o := range v {
				fmt.Println("Applying EC option from slice")
				if err := o(cfg); err != nil {
					return nil, ErrOperationFailed{Op: "applying EC options", Err: err}
				}
			}
			decOpts.KEK = cfg.kek
			decOpts.EphemeralKey = cfg.ephemeralKey
			fmt.Println(hex.EncodeToString(decOpts.KEK))
		case ECOptions:
			fmt.Println("Applying EC option")
			cfg := &ecConfig{}
			if err := v(cfg); err != nil {
				return nil, ErrOperationFailed{Op: "applying EC options", Err: err}
			}
			decOpts.KEK = cfg.kek
			decOpts.EphemeralKey = cfg.ephemeralKey
		default:
			fmt.Println("Unrecognized option type:", reflect.TypeOf(opt))
		}
	}

	switch keyRef.GetKeyMode() {
	case policy.KeyMode_KEY_MODE_REMOTE:
		// Mode 3: All crypto operations happen in KMS/HSM
		provider, err := c.GetProvider(keyRef.GetProviderConfig().GetName())
		if err != nil {
			return nil, err
		}

		decOpts.KeyRef = NewKeyRef(keyRef.GetPrivateKeyCtx(), keyRef.GetKeyAlgorithm())
		return provider.DecryptAsymmetric(ctx, decOpts)

	case policy.KeyMode_KEY_MODE_LOCAL:
		var unwrappedKey []byte
		var err error

		if providerConfig := keyRef.GetProviderConfig(); providerConfig != nil {
			// Mode 2: LOCAL with KEK stored in Provider
			provider, err := c.GetProvider(providerConfig.GetName())
			if err != nil {
				return nil, err
			}
			unwrappedKey, err = provider.DecryptSymmetric(ctx, keyRef.GetPrivateKeyCtx(), pkCtx.WrappedKey)
			if err != nil {
				return nil, ErrOperationFailed{Op: "provider key unwrapping", Err: err}
			}
		} else {
			// Mode 1: LOCAL with KEK from configuration
			if decOpts.KEK == nil {
				return nil, ErrOperationFailed{Op: "local decryption", Err: fmt.Errorf("KEK not set")}
			}
			c.mu.RLock()
			provider := c.providers[DefaultProvider]
			c.mu.RUnlock()

			if provider == nil {
				return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
			}

			unwrappedKey, err = provider.DecryptSymmetric(ctx, decOpts.KEK, pkCtx.WrappedKey)
			if err != nil {
				return nil, ErrOperationFailed{Op: "local key unwrapping", Err: err}
			}
		}

		// Now decrypt data with the unwrapped private key using default provider
		c.mu.RLock()
		provider := c.providers[DefaultProvider]
		c.mu.RUnlock()

		if provider == nil {
			return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
		}

		decOpts.KeyRef = NewKeyRef(unwrappedKey, keyRef.GetKeyAlgorithm())
		return provider.DecryptAsymmetric(ctx, decOpts)

	default:
		return nil, ErrOperationFailed{Op: "asymmetric decryption", Err: fmt.Errorf("unsupported key mode: %v", keyRef.GetKeyMode())}
	}
}

// EncryptAsymmetric provides a unified interface for asymmetric encryption
func (c *CryptoService) EncryptAsymmetric(ctx context.Context, data []byte, keyRef *policy.AsymmetricKey, opts ...interface{}) ([]byte, []byte, error) {
	if keyRef == nil {
		return nil, nil, ErrInvalidKeyFormat{Details: "key reference is nil"}
	}

	if len(data) == 0 {
		return nil, nil, ErrOperationFailed{Op: "asymmetric encryption", Err: fmt.Errorf("empty data")}
	}

	var provider CryptoProvider
	if providerConfig := keyRef.GetProviderConfig(); providerConfig != nil {
		// Use specified provider for REMOTE mode or provider-specific operations
		var err error
		provider, err = c.GetProvider(providerConfig.GetName())
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Use default provider for LOCAL mode without provider config
		c.mu.RLock()
		provider = c.providers[DefaultProvider]
		c.mu.RUnlock()
	}

	if provider == nil {
		return nil, nil, ErrProviderNotFound{ProviderID: DefaultProvider}
	}

	// Initialize encrypt options
	encOpts := EncryptOpts{
		KeyRef: NewKeyRef(keyRef.GetPublicKeyCtx(), keyRef.GetKeyAlgorithm()),
		Data:   data,
	}

	// Handle algorithm-specific options
	for _, opt := range opts {
		switch o := opt.(type) {
		case RSAOptions:
			cfg := &rsaConfig{}
			if err := o(cfg); err != nil {
				return nil, nil, ErrOperationFailed{Op: "applying RSA options", Err: err}
			}
			encOpts.Hash = cfg.hash
		case ECOptions:
			cfg := &ecConfig{}
			if err := o(cfg); err != nil {
				return nil, nil, ErrOperationFailed{Op: "applying EC options", Err: err}
			}
			encOpts.EphemeralKey = cfg.ephemeralKey
		}
	}

	return provider.EncryptAsymmetric(ctx, encOpts)
}

// EncryptSymmetric encrypts data using a symmetric key, selecting the provider based on key mode.
func (c *CryptoService) EncryptSymmetric(ctx context.Context, keyRef *policy.SymmetricKey, data []byte) ([]byte, error) {
	if keyRef == nil {
		return nil, ErrInvalidKeyFormat{Details: "symmetric key reference is nil"}
	}
	keyCtx := keyRef.GetKeyCtx()
	if len(keyCtx) == 0 {
		return nil, ErrInvalidKeyFormat{Details: "symmetric key context is nil/empty"}
	}
	if len(data) == 0 {
		return nil, ErrOperationFailed{Op: "symmetric encryption", Err: fmt.Errorf("empty data")}
	}

	var provider CryptoProvider
	var err error

	switch keyRef.GetKeyMode() {
	case policy.KeyMode_KEY_MODE_REMOTE:
		// Mode 3: Remote operation, use the specified provider with the key context (likely an identifier)
		providerConfig := keyRef.GetProviderConfig()
		if providerConfig == nil {
			return nil, ErrOperationFailed{Op: "symmetric encryption", Err: fmt.Errorf("provider config missing for remote key mode")}
		}
		provider, err = c.GetProvider(providerConfig.GetName())
		if err != nil {
			return nil, err
		}
		// Provider handles the key context directly
		return provider.EncryptSymmetric(ctx, keyCtx, data)

	case policy.KeyMode_KEY_MODE_LOCAL:
		providerConfig := keyRef.GetProviderConfig()
		if providerConfig != nil {
			// Mode 2: Key context is wrapped. Encryption with a wrapped key is not supported directly.
			// If the intent was to use a provider-managed key, it should be Mode 3.
			return nil, ErrOperationFailed{Op: "symmetric encryption", Err: fmt.Errorf("symmetric encryption in local mode with provider config (Mode 2) is not supported; use remote mode (Mode 3) for provider-managed keys")}
		} else {
			// Mode 1: Use default provider with the raw key context
			c.mu.RLock()
			provider = c.providers[DefaultProvider]
			c.mu.RUnlock()
			if provider == nil {
				return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
			}
			// Default provider uses the raw key context
			return provider.EncryptSymmetric(ctx, keyCtx, data)
		}
	default:
		return nil, ErrOperationFailed{Op: "symmetric encryption", Err: fmt.Errorf("unsupported key mode: %v", keyRef.GetKeyMode())}
	}
}

// DecryptSymmetric decrypts data using a symmetric key, selecting the provider based on key mode.
func (c *CryptoService) DecryptSymmetric(ctx context.Context, keyRef *policy.SymmetricKey, cipherText []byte) ([]byte, error) {
	if keyRef == nil {
		return nil, ErrInvalidKeyFormat{Details: "symmetric key reference is nil"}
	}
	keyCtx := keyRef.GetKeyCtx()
	if len(keyCtx) == 0 {
		return nil, ErrInvalidKeyFormat{Details: "symmetric key context is nil/empty"}
	}
	if len(cipherText) == 0 {
		return nil, ErrOperationFailed{Op: "symmetric decryption", Err: fmt.Errorf("empty ciphertext")}
	}

	var provider CryptoProvider
	var err error

	switch keyRef.GetKeyMode() {
	case policy.KeyMode_KEY_MODE_REMOTE:
		// Mode 3: Remote operation, use the specified provider with the key context (likely an identifier)
		providerConfig := keyRef.GetProviderConfig()
		if providerConfig == nil {
			return nil, ErrOperationFailed{Op: "symmetric decryption", Err: fmt.Errorf("provider config missing for remote key mode")}
		}
		provider, err = c.GetProvider(providerConfig.GetName())
		if err != nil {
			return nil, err
		}
		// Provider handles the key context directly
		return provider.DecryptSymmetric(ctx, keyCtx, cipherText)

	case policy.KeyMode_KEY_MODE_LOCAL:
		providerConfig := keyRef.GetProviderConfig()
		if providerConfig != nil {
			// Mode 2: Key context is wrapped. Unwrap using the specified provider, then decrypt using default.
			unwrappingProvider, err := c.GetProvider(providerConfig.GetName())
			if err != nil {
				return nil, fmt.Errorf("failed to get unwrapping provider '%s': %w", providerConfig.GetName(), err)
			}

			// Use the provider's DecryptSymmetric to *unwrap* the key context (which holds the wrapped key)
			// The KEK is managed implicitly by the provider (e.g., KMS)
			unwrappedKey, err := unwrappingProvider.DecryptSymmetric(ctx, keyCtx, keyCtx) // Pass keyCtx as both 'key' and 'ciphertext' for unwrapping
			if err != nil {
				return nil, ErrOperationFailed{Op: "provider key unwrapping (symmetric)", Err: err}
			}

			// Now use the default provider with the unwrapped key to decrypt the actual ciphertext
			c.mu.RLock()
			decryptionProvider := c.providers[DefaultProvider]
			c.mu.RUnlock()
			if decryptionProvider == nil {
				return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
			}
			return decryptionProvider.DecryptSymmetric(ctx, unwrappedKey, cipherText)

		} else {
			// Mode 1: Use default provider with the raw key context
			c.mu.RLock()
			provider = c.providers[DefaultProvider]
			c.mu.RUnlock()
			if provider == nil {
				return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
			}
			// Default provider uses the raw key context
			return provider.DecryptSymmetric(ctx, keyCtx, cipherText)
		}
	default:
		return nil, ErrOperationFailed{Op: "symmetric decryption", Err: fmt.Errorf("unsupported key mode: %v", keyRef.GetKeyMode())}
	}
}
