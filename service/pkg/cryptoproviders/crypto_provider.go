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
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
)

const (
	DefaultProvider                = "default"
	DefaultRSAOAEPHash crypto.Hash = crypto.SHA256
)

type KeyRef struct {
	Key       []byte
	Algorithm policy.Algorithm
}

// GetRawBytes returns the raw key bytes
func (k *KeyRef) GetRawBytes() []byte {
	return k.Key
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
func (k *KeyRef) GetExpectedKeySize() int {
	switch k.Algorithm {
	case policy.Algorithm_ALGORITHM_RSA_2048:
		return 256 // 2048 bits = 256 bytes
	case policy.Algorithm_ALGORITHM_RSA_4096:
		return 512 // 4096 bits = 512 bytes
	case policy.Algorithm_ALGORITHM_EC_P256:
		return 32 // 256 bits = 32 bytes
	case policy.Algorithm_ALGORITHM_EC_P384:
		return 48 // 384 bits = 48 bytes
	case policy.Algorithm_ALGORITHM_EC_P521:
		return 66 // 521 bits = 66 bytes (rounded up)
	default:
		return 0
	}
}

// Validate checks if the key format matches the algorithm
func (k *KeyRef) Validate() error {
	if k.Key == nil {
		return ErrInvalidKeyFormat{Details: "key bytes cannot be nil"}
	}

	if k.IsRSA() {
		expectedSize := k.GetExpectedKeySize()
		if expectedSize == 0 {
			return ErrInvalidKeyFormat{Details: "unsupported RSA key size"}
		}
		if len(k.Key) != expectedSize {
			return ErrInvalidKeyFormat{Details: fmt.Sprintf("invalid RSA key length: expected %d bytes", expectedSize)}
		}
	}

	if k.IsEC() {
		// EC public keys should be 65 bytes uncompressed or 33 bytes compressed
		keyLen := len(k.Key)
		if keyLen != 33 && keyLen != 65 {
			return ErrInvalidKeyFormat{Details: "invalid EC key length: must be 33 (compressed) or 65 (uncompressed) bytes"}
		}
	}

	return nil
}

// CryptoService manages multiple CryptoProviders and handles provider selection
type CryptoService struct {
	l               *logger.Logger
	defaultProvider CryptoProvider
	providers       map[string]CryptoProvider
	mu              sync.RWMutex
}

// NewCryptoService creates a new CryptoService with the specified default provider
func NewCryptoService(defaultProvider CryptoProvider, l *logger.Logger) *CryptoService {
	if defaultProvider == nil {
		panic("default crypto provider cannot be nil")
	}
	cs := &CryptoService{
		l:               l,
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
	KeyRef KeyRef
	Data   []byte
	config
}

// DecryptOpts contains options for asymmetric decryption
type DecryptOpts struct {
	KeyRef     KeyRef
	CipherText []byte
	config
}

// CryptoProvider defines the interface for cryptographic operations
type PrivateKeyContext struct {
	WrappedKey []byte `json:"wrappedKey,omitempty"`
	File       File   `json:"file,omitempty"`
}

type File struct {
	Path      string `json:"path,omitempty"`
	Encrypted bool   `json:"encrypted,omitempty"`
}

type CryptoProvider interface {
	// Identifier returns the provider's unique identifier
	Identifier() string

	// Symmetric methods
	EncryptSymmetric(ctx context.Context, key []byte, data []byte) ([]byte, error)
	DecryptSymmetric(ctx context.Context, key []byte, cipherText []byte) ([]byte, error)

	// Unified methods for asymmetric cryptography
	EncryptAsymmetric(ctx context.Context, opts EncryptOpts) (cipherText []byte, ephemeralKey []byte, err error)
	DecryptAsymmetric(ctx context.Context, opts DecryptOpts) ([]byte, error)

	// UnwrapKey unwraps the private key bytes from the given PrivateKeyContext and KEK
	UnwrapKey(ctx context.Context, privateKeyCtx *PrivateKeyContext, kek []byte) ([]byte, error)
}

// DecryptAsymmetric provides a unified interface for asymmetric decryption
func (c *CryptoService) DecryptAsymmetric(ctx context.Context, keyRef *policy.AsymmetricKey, cipherText []byte, opts ...Options) ([]byte, error) {
	log := c.l.With("operation", "DecryptAsymmetric")

	if keyRef == nil {
		log.ErrorContext(ctx, "key reference is nil")
		return nil, ErrInvalidKeyFormat{Details: "key reference is nil"}
	}

	log = log.With("provider", keyRef.GetProviderConfig().GetName())
	log = log.With("key_id", keyRef.GetKeyId())
	log = log.With("algorithm", keyRef.GetKeyAlgorithm().String())

	if len(cipherText) == 0 {
		log.ErrorContext(ctx, "ciphertext is empty")
		return nil, ErrOperationFailed{Op: "asymmetric decryption", Err: fmt.Errorf("empty ciphertext")}
	}

	// Parse private key context
	privateKeyCtx := &PrivateKeyContext{}
	if err := json.Unmarshal(keyRef.GetPrivateKeyCtx(), privateKeyCtx); err != nil {
		log.ErrorContext(ctx, "failed to unmarshal private key context", slog.String("error", err.Error()))
		return nil, ErrInvalidKeyFormat{Details: fmt.Sprintf("failed to unmarshal private key context: %v", err)}
	}

	// Initialize decrypt options
	decOpts := DecryptOpts{
		CipherText: cipherText,
	}
	cfg := &config{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			log.ErrorContext(ctx, "filed to apply options", slog.String("error", err.Error()))
			return nil, ErrOperationFailed{Op: "applying options", Err: err}
		}
	}

	decOpts.config = *cfg

	switch keyRef.GetKeyMode() {
	case policy.KeyMode_KEY_MODE_REMOTE:
		// Mode 3: All crypto operations happen in KMS/HSM
		provider, err := c.GetProvider(keyRef.GetProviderConfig().GetName())
		if err != nil {
			log.ErrorContext(ctx, "provider not found for remote mode", slog.String("error", err.Error()))
			return nil, err
		}

		decOpts.KeyRef = KeyRef{Key: keyRef.GetPrivateKeyCtx(), Algorithm: keyRef.GetKeyAlgorithm()}
		log.DebugContext(ctx, "delegating remote asymmetric decryption to provider")
		return provider.DecryptAsymmetric(ctx, decOpts)

	case policy.KeyMode_KEY_MODE_LOCAL:
		var unwrappedKey []byte
		var err error

		if providerConfig := keyRef.GetProviderConfig(); providerConfig != nil {
			// Mode 2: LOCAL with KEK stored in Provider
			provider, err := c.GetProvider(providerConfig.GetName())
			if err != nil {
				log.ErrorContext(ctx, "provider not found for local mode (provider KEK)", slog.String("error", err.Error()))
				return nil, err
			}
			log.DebugContext(ctx, "unwrapping key using provider")
			unwrappedKey, err = provider.UnwrapKey(ctx, privateKeyCtx, decOpts.KEK)
			if err != nil {
				log.ErrorContext(ctx, "provider key unwrapping failed", slog.String("error", err.Error()))
				return nil, ErrOperationFailed{Op: "provider key unwrapping", Err: err}
			}
		} else {
			// Mode 1: LOCAL with KEK from configuration
			if decOpts.KEK == nil {
				log.ErrorContext(ctx, "kek not set for local decryption")
				return nil, ErrOperationFailed{Op: "local decryption", Err: fmt.Errorf("KEK not set")}
			}
			c.mu.RLock()
			provider := c.providers[DefaultProvider]
			c.mu.RUnlock()

			if provider == nil {
				log.ErrorContext(ctx, "default provider not found")
				return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
			}

			log.DebugContext(ctx, "unwrapping key using default provider")
			unwrappedKey, err = provider.UnwrapKey(ctx, privateKeyCtx, decOpts.KEK)
			if err != nil {
				log.ErrorContext(ctx, "Local key unwrapping failed", slog.String("error", err.Error()))
				return nil, ErrOperationFailed{Op: "local key unwrapping", Err: err}
			}
		}

		// Now decrypt data with the unwrapped private key using default provider
		c.mu.RLock()
		provider := c.providers[DefaultProvider]
		c.mu.RUnlock()

		if provider == nil {
			log.ErrorContext(ctx, "default provider not found for decryption")
			return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
		}

		decOpts.KeyRef = KeyRef{Key: unwrappedKey, Algorithm: keyRef.GetKeyAlgorithm()}
		log.DebugContext(ctx, "decrypting with unwrapped key using default provider")
		return provider.DecryptAsymmetric(ctx, decOpts)

	default:
		log.ErrorContext(ctx, "unsupported key mode", slog.String("key_mode", keyRef.GetKeyMode().String()))
		return nil, ErrOperationFailed{Op: "asymmetric decryption", Err: fmt.Errorf("unsupported key mode: %v", keyRef.GetKeyMode())}
	}
}

// EncryptAsymmetric provides a unified interface for asymmetric encryption
func (c *CryptoService) EncryptAsymmetric(ctx context.Context, data []byte, keyRef *policy.AsymmetricKey, opts ...Options) ([]byte, []byte, error) {
	log := c.l.With("operation", "EncryptAsymmetric")

	if keyRef == nil {
		log.ErrorContext(ctx, "key reference is nil")
		return nil, nil, ErrInvalidKeyFormat{Details: "key reference is nil"}
	}

	log = log.With("provider", keyRef.GetProviderConfig().GetName())
	log = log.With("key_id", keyRef.GetKeyId())
	log = log.With("algorithm", keyRef.GetKeyAlgorithm().String())

	if len(data) == 0 {
		log.ErrorContext(ctx, "data is empty")
		return nil, nil, ErrOperationFailed{Op: "asymmetric encryption", Err: fmt.Errorf("empty data")}
	}

	cfg := &config{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			log.ErrorContext(ctx, "filed to apply options", slog.String("error", err.Error()))
			return nil, nil, fmt.Errorf("error applying options: %w", err)
		}
	}

	encOpts := EncryptOpts{
		KeyRef: KeyRef{Key: keyRef.GetPublicKeyCtx(), Algorithm: keyRef.GetKeyAlgorithm()},
		Data:   data,
	}

	encOpts.config = *cfg

	var provider CryptoProvider
	if providerConfig := keyRef.GetProviderConfig(); providerConfig != nil {
		// Use specified provider for REMOTE mode or provider-specific operations
		var err error
		provider, err = c.GetProvider(providerConfig.GetName())
		if err != nil {
			log.ErrorContext(ctx, "provider not found for remote mode", slog.String("error", err.Error()))
			return nil, nil, err
		}
		log.DebugContext(ctx, "delegating remote asymmetric encryption to provider")
	} else {
		// Use default provider for LOCAL mode without provider config
		c.mu.RLock()
		provider = c.providers[DefaultProvider]
		c.mu.RUnlock()
	}

	if provider == nil {
		log.ErrorContext(ctx, "provider not found")
		return nil, nil, ErrProviderNotFound{ProviderID: DefaultProvider}
	}

	log.DebugContext(ctx, "encrypting data using asymmetric encryption")
	return provider.EncryptAsymmetric(ctx, encOpts)
}

// EncryptSymmetric encrypts data using a symmetric key, selecting the provider based on key mode.
func (c *CryptoService) EncryptSymmetric(ctx context.Context, keyRef *policy.SymmetricKey, data []byte) ([]byte, error) {
	log := c.l.With("operation", "EncryptSymmetric")

	if keyRef == nil {
		log.ErrorContext(ctx, "key reference is nil")
		return nil, ErrInvalidKeyFormat{Details: "symmetric key reference is nil"}
	}

	log = log.With("provider", keyRef.GetProviderConfig().GetName())
	log = log.With("key_id", keyRef.GetKeyId())

	keyCtx := keyRef.GetKeyCtx()
	if len(keyCtx) == 0 {
		log.ErrorContext(ctx, "symmetric key context is nil or empty")
		return nil, ErrInvalidKeyFormat{Details: "symmetric key context is nil/empty"}
	}
	if len(data) == 0 {
		log.ErrorContext(ctx, "data to encrypt is empty")
		return nil, ErrOperationFailed{Op: "symmetric encryption", Err: fmt.Errorf("empty data")}
	}

	var provider CryptoProvider
	var err error

	switch keyRef.GetKeyMode() {
	case policy.KeyMode_KEY_MODE_REMOTE:
		// Mode 3: Remote operation, use the specified provider with the key context (likely an identifier)
		providerConfig := keyRef.GetProviderConfig()
		if providerConfig == nil {
			log.ErrorContext(ctx, "provider config is nil for remote key mode")
			return nil, ErrOperationFailed{Op: "symmetric encryption", Err: fmt.Errorf("provider config missing for remote key mode")}
		}
		provider, err = c.GetProvider(providerConfig.GetName())
		if err != nil {
			log.ErrorContext(ctx, "failed to get provider for remote key mode", "error", err.Error())
			return nil, err
		}
		// Provider handles the key context directly
		return provider.EncryptSymmetric(ctx, keyCtx, data)

	case policy.KeyMode_KEY_MODE_LOCAL:
		providerConfig := keyRef.GetProviderConfig()
		if providerConfig != nil {
			// Mode 2: Key context is wrapped. Encryption with a wrapped key is not supported directly.
			// If the intent was to use a provider-managed key, it should be Mode 3.
			log.ErrorContext(ctx, "symmetric encryption in local mode with provider config (Mode 2) is not supported")
			return nil, ErrOperationFailed{Op: "symmetric encryption", Err: fmt.Errorf("symmetric encryption in local mode with provider config (Mode 2) is not supported; use remote mode (Mode 3) for provider-managed keys")}
		} else {
			// Mode 1: Use default provider with the raw key context
			c.mu.RLock()
			provider = c.providers[DefaultProvider]
			c.mu.RUnlock()
			if provider == nil {
				log.ErrorContext(ctx, "default provider not found for local key mode")
				return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
			}
			// Default provider uses the raw key context
			log.DebugContext(ctx, "using default provider for encryption", slog.String("provider", DefaultProvider))
			return provider.EncryptSymmetric(ctx, keyCtx, data)
		}
	default:
		log.ErrorContext(ctx, "unsupported key mode in symmetric encryption", slog.String("key_mode", keyRef.GetKeyMode().String()))
		return nil, ErrOperationFailed{Op: "symmetric encryption", Err: fmt.Errorf("unsupported key mode: %v", keyRef.GetKeyMode())}
	}
}

// DecryptSymmetric decrypts data using a symmetric key, selecting the provider based on key mode.
func (c *CryptoService) DecryptSymmetric(ctx context.Context, keyRef *policy.SymmetricKey, cipherText []byte) ([]byte, error) {
	log := c.l.With("operation", "DecryptSymmetric")

	if keyRef == nil {
		log.ErrorContext(ctx, "symmetric key reference is nil")
		return nil, ErrInvalidKeyFormat{Details: "symmetric key reference is nil"}
	}

	log = log.With("provider", keyRef.GetProviderConfig().GetName())
	log = log.With("key_id", keyRef.GetKeyId())

	keyCtx := keyRef.GetKeyCtx()
	if len(keyCtx) == 0 {
		log.ErrorContext(ctx, "symmetric key context is nil or empty")
		return nil, ErrInvalidKeyFormat{Details: "symmetric key context is nil/empty"}
	}

	if len(cipherText) == 0 {
		log.ErrorContext(ctx, "ciphertext is empty")
		return nil, ErrOperationFailed{Op: "symmetric decryption", Err: fmt.Errorf("empty ciphertext")}
	}

	var provider CryptoProvider
	var err error

	switch keyRef.GetKeyMode() {
	case policy.KeyMode_KEY_MODE_REMOTE:
		// Mode 3: Remote operation, use the specified provider with the key context (likely an identifier)
		providerConfig := keyRef.GetProviderConfig()
		if providerConfig == nil {
			log.ErrorContext(ctx, "provider config missing for remote key mode")
			return nil, ErrOperationFailed{Op: "symmetric decryption", Err: fmt.Errorf("provider config missing for remote key mode")}
		}
		provider, err = c.GetProvider(providerConfig.GetName())
		if err != nil {
			log.ErrorContext(ctx, "failed to get provider for remote key mode", slog.String("error", err.Error()))
			return nil, err
		}
		// Provider handles the key context directly
		log.DebugContext(ctx, "using remote provider for symmetric decryption")
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
				log.ErrorContext(ctx, "failed to unwrap key context", slog.String("error", err.Error()))
				return nil, ErrOperationFailed{Op: "provider key unwrapping (symmetric)", Err: err}
			}

			// Now use the default provider with the unwrapped key to decrypt the actual ciphertext
			c.mu.RLock()
			provider := c.providers[DefaultProvider]
			c.mu.RUnlock()
			if provider == nil {
				log.ErrorContext(ctx, "default provider not found")
				return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
			}
			log.DebugContext(ctx, "using default provider to perform symmetric decryption")
			return provider.DecryptSymmetric(ctx, unwrappedKey, cipherText)

		} else {
			// Mode 1: Use default provider with the raw key context
			c.mu.RLock()
			provider = c.providers[DefaultProvider]
			c.mu.RUnlock()
			if provider == nil {
				log.ErrorContext(ctx, "default provider not found")
				return nil, ErrProviderNotFound{ProviderID: DefaultProvider}
			}
			// Default provider uses the raw key context
			log.DebugContext(ctx, "using default provider to perform decryption")
			return provider.DecryptSymmetric(ctx, keyCtx, cipherText)
		}
	default:
		log.ErrorContext(ctx, "unsupported key mode", "key_mode", keyRef.GetKeyMode())
		return nil, ErrOperationFailed{Op: "symmetric decryption", Err: fmt.Errorf("unsupported key mode: %v", keyRef.GetKeyMode())}
	}
}
