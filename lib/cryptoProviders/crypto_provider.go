package cryptoProviders

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/opentdf/platform/protocol/go/policy"
	"golang.org/x/crypto/hkdf"
)

const (
	DefaultProvider                = "default"
	DefaultRSAOAEPHash crypto.Hash = crypto.SHA256
)

type PrivateKeyCtx struct {
	WrappedKey []byte `json:"wrappedKey"`
}

type KeyRef struct {
	Key       []byte
	Algorithm policy.Algorithm
}

type CryptoService struct {
	defaultProvider CryptoProvider
	providers       map[string]CryptoProvider
}

func NewCryptoService(defaultProvider CryptoProvider) *CryptoService {
	cs := &CryptoService{
		providers: make(map[string]CryptoProvider),
	}
	cs.providers[DefaultProvider] = defaultProvider

	return cs
}

func (c *CryptoService) RegisterProvider(provider CryptoProvider) {
	c.providers[provider.Identifier()] = provider
}

type CryptoProvider interface {
	Identifier() string
	EncryptRSAOAEP(ctx context.Context, hash crypto.Hash, keyRef KeyRef, data []byte) ([]byte, error)
	DecryptRSAOAEP(ctx context.Context, keyRef KeyRef, cipherText []byte) ([]byte, error)
	EncryptEC(ctx context.Context, keyRef KeyRef, ephemeralPublicKey []byte, data []byte) ([]byte, []byte, error)
	DecryptEC(ctx context.Context, keyRef KeyRef, ephemeralPublicKey []byte, cipherText []byte) ([]byte, error)
	// DecryptAsymmetric(ctx context.Context, keyRef KeyRef, cipherText []byte) ([]byte, error)
	// DeriveSharedKey(ctx context.Context, privateKeyRef KeyRef, publicKeyRef KeyRef) ([]byte, error)
	// Sign(ctx context.Context, data []byte, keyRef KeyRef) ([]byte, error)
	// // VerifySignature(ctx context.Context, signature []byte, data []byte, keyRef policy.AsymmetricKey) (bool, error)
	// EncryptSymmetric(ctx context.Context, key []byte, data []byte) ([]byte, error)
	DecryptSymmetric(ctx context.Context, key []byte, cipherText []byte) ([]byte, error)
}

func (c *CryptoService) EncryptRSAOAEP(ctx context.Context, data []byte, keyRef *policy.AsymmetricKey, opts ...RSAOptions) ([]byte, error) {
	var (
		cipherText []byte
		err        error
	)

	cfg := &rsaConfig{
		hash: DefaultRSAOAEPHash,
	}
	// Apply options (you'll need to add the loop here)
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err // Handle option errors
		}
	}

	// Encrypt using RSA-OAEP
	if provider := keyRef.GetProviderConfig(); provider != nil {
		// Use provider
		//c.providers[provider.GetName()]
	} else {
		// Use default provider
		cipherText, err = c.providers[DefaultProvider].EncryptRSAOAEP(ctx, cfg.hash, KeyRef{Key: keyRef.GetPublicKeyCtx(), Algorithm: keyRef.GetKeyAlgorithm()}, data)
		if err != nil {
			return nil, err
		}
	}

	return cipherText, nil

}

func (c *CryptoService) DecryptRSAOAEP(ctx context.Context, data []byte, keyRef *policy.AsymmetricKey, opts ...RSAOptions) ([]byte, error) {
	var (
		plainText  []byte
		rsaPrivKey []byte
	)

	cfg := &rsaConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	pkCtx := &PrivateKeyCtx{}
	err := json.Unmarshal(keyRef.GetPrivateKeyCtx(), pkCtx)
	if err != nil {
		return nil, err
	}
	switch keyRef.GetKeyMode() {
	case policy.KeyMode_KEY_MODE_REMOTE:
		plainText, err = c.providers[keyRef.GetProviderConfig().GetName()].DecryptRSAOAEP(ctx, KeyRef{Key: keyRef.GetPrivateKeyCtx(), Algorithm: keyRef.GetKeyAlgorithm()}, data)
		if err != nil {
			return nil, err
		}
		break
	case policy.KeyMode_KEY_MODE_LOCAL:
		// Decrypt Private Key with KEK
		if provider := keyRef.GetProviderConfig(); provider != nil {
			// Use provider
			rsaPrivKey, err = c.providers[provider.GetName()].DecryptSymmetric(ctx, keyRef.GetPrivateKeyCtx(), pkCtx.WrappedKey)
		} else {
			// Use default provider
			// Decrypt with KEK
			if cfg.kek == nil {
				return nil, errors.New("KEK not set")
			}
			rsaPrivKey, err = c.providers[DefaultProvider].DecryptSymmetric(ctx, cfg.kek, pkCtx.WrappedKey)
			if err != nil {
				return nil, err
			}
		}

		// Now Decrypt data with Private Key
		plainText, err = c.providers[DefaultProvider].DecryptRSAOAEP(ctx, KeyRef{Key: rsaPrivKey, Algorithm: keyRef.GetKeyAlgorithm()}, data)
		if err != nil {
			return nil, err
		}
	}

	return plainText, nil
}

// func (c *CryptoService) DecryptAsymmetric(ctx context.Context, keyRef *policy.AsymmetricKey, cipherText []byte, opts ...AsymOption) ([]byte, error) {
// 	cfg := &asymConfig{}
// 	for _, opt := range opts {
// 		if err := opt(cfg); err != nil {
// 			return nil, err
// 		}
// 	}

// 	if keyRef.GetProviderConfig() != nil {
// 		// Use provider to decrypt with private key
// 		provider, exists := c.providers[keyRef.GetProviderConfig().GetProvider()]
// 		if !exists {
// 			return nil, errors.New("provider not found")
// 		}
// 		return provider.DecryptAsymmetric(ctx, KeyRef{
// 			Key:       keyRef.GetKey(),
// 			Algorithm: keyRef.GetKeyAlgorithm(),
// 		}, cipherText)
// 	} else {
// 		if len(cfg.kek) == 0 {
// 			return nil, errors.New("kek is required for asymmetric decryption if no provider config is provided")
// 		}
// 		switch keyRef.GetKeyAlgorithm() {
// 		case policy.Algorithm_ALGORITHM_RSA_2048, policy.Algorithm_ALGORITHM_EC_P256:
// 			return c.providers[DefaultProvider].DecryptAsymmetric(ctx, KeyRef{
// 				Key:       keyRef.GetKey(),
// 				Algorithm: keyRef.GetKeyAlgorithm(),
// 			}, cipherText)
// 		default:
// 			return nil, errors.New("unsupported algorithm")
// 		}
// 	}
// }

func (c *CryptoService) EncryptEC(ctx context.Context, data []byte, keyRef *policy.AsymmetricKey, ephemeralPublicKey []byte, opts ...ECOptions) ([]byte, []byte, error) {
	var (
		cipherText []byte
		epk        []byte
		err        error
	)

	cfg := &ecConfig{}
	// Apply options (you'll need to add the loop here)
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, nil, err // Handle option errors
		}
	}

	// Encrypt using EC
	if provider := keyRef.GetProviderConfig(); provider != nil {
		// Use provider
		//c.providers[provider.GetName()]
	} else {
		// Use default provider
		cipherText, epk, err = c.providers[DefaultProvider].EncryptEC(ctx, KeyRef{Key: keyRef.GetPublicKeyCtx(), Algorithm: keyRef.GetKeyAlgorithm()}, ephemeralPublicKey, data)
		if err != nil {
			return nil, nil, err
		}
	}

	return cipherText, epk, nil
}

func (c *CryptoService) DecryptEC(ctx context.Context, keyRef *policy.AsymmetricKey, ephemeralPublicKey []byte, cipherText []byte, opts ...ECOptions) ([]byte, error) {
	var (
		plainText    []byte
		ecPrivateKey []byte
	)

	cfg := &ecConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	pkCtx := &PrivateKeyCtx{}
	err := json.Unmarshal(keyRef.GetPrivateKeyCtx(), pkCtx)
	if err != nil {
		return nil, err
	}
	switch keyRef.GetKeyMode() {
	case policy.KeyMode_KEY_MODE_REMOTE:
		sharedKey, err := c.providers[keyRef.GetProviderConfig().GetName()].DecryptEC(ctx, KeyRef{Key: keyRef.GetPrivateKeyCtx(), Algorithm: keyRef.GetKeyAlgorithm()}, ephemeralPublicKey, cipherText)
		if err != nil {
			return nil, err
		}
		fmt.Println(hex.EncodeToString(sharedKey))
		digest := sha256.New()
		digest.Write([]byte("TDF"))
		salt := digest.Sum(nil)

		hkdfObj := hkdf.New(sha256.New, sharedKey, salt, nil)
		derivedKey := make([]byte, len(sharedKey))
		if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
			return nil, fmt.Errorf("hkdf failure: %w", err)
		}

		fmt.Println("Derived Key", hex.EncodeToString(derivedKey))

		plainText, err = c.providers[DefaultProvider].DecryptSymmetric(ctx, derivedKey, cipherText)
		if err != nil {
			return nil, fmt.Errorf("symmetric decryption failure: %w", err)
		}
		break
	case policy.KeyMode_KEY_MODE_LOCAL:
		if provider := keyRef.GetProviderConfig(); provider != nil {
			// Use provider
			ecPrivateKey, err = c.providers[provider.GetName()].DecryptSymmetric(ctx, keyRef.GetPrivateKeyCtx(), pkCtx.WrappedKey)
		} else {
			// Use default provider
			// Decrypt with KEK
			if cfg.kek == nil {
				return nil, errors.New("KEK not set")
			}
			ecPrivateKey, err = c.providers[DefaultProvider].DecryptSymmetric(ctx, cfg.kek, pkCtx.WrappedKey)
			if err != nil {
				return nil, err
			}
		}

		// Now Decrypt data with Private Key
		plainText, err = c.providers[DefaultProvider].DecryptEC(ctx, KeyRef{Key: ecPrivateKey, Algorithm: keyRef.GetKeyAlgorithm()}, ephemeralPublicKey, cipherText)
		if err != nil {
			return nil, err
		}
	}

	return plainText, nil
}

func (c *CryptoService) DeriveSharedKey(privateKey *policy.AsymmetricKey, publicKey *policy.AsymmetricKey) ([]byte, error) {
	// Implementation of DeriveSharedKey
	return nil, nil
}

func (c *CryptoService) Sign(data []byte, keyRef *policy.AsymmetricKey) ([]byte, error) {
	// Implementation of Sign
	return nil, nil
}

func (c *CryptoService) VerifySignature(signature []byte, data []byte, keyRef *policy.AsymmetricKey) (bool, error) {
	// Implementation of VerifySignature
	return false, nil
}

func (c *CryptoService) EncryptSymmetric(keyRef *policy.SymmetricKey, data []byte) ([]byte, error) {
	// Implementation of EncryptSymmetric
	return nil, nil
}

func (c *CryptoService) DecryptSymmetric(keyRef *policy.SymmetricKey, cipherText []byte) ([]byte, error) {
	// Implementation of DecryptSymmetric
	return nil, nil
}
