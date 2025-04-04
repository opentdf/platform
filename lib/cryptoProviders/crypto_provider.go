package cryptoProviders

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	DefaultProvider = "default"
)

type KeyRef struct {
	Key       []byte
	Algorithm policy.Algorithm
}

type CryptoService struct {
	providers map[string]CryptoProvider
}

type CryptoProvider interface {
	Identifier() string
	EncryptAsymmetric(ctx context.Context, keyRef KeyRef, data []byte) ([]byte, error)
	DecryptAsymmetric(ctx context.Context, keyRef KeyRef, cipherText []byte) ([]byte, error)
	DeriveSharedKey(ctx context.Context, privateKeyRef KeyRef, publicKeyRef KeyRef) ([]byte, error)
	Sign(ctx context.Context, data []byte, keyRef KeyRef) ([]byte, error)
	VerifySignature(ctx context.Context, signature []byte, data []byte, keyRef policy.AsymmetricKey) (bool, error)
	EncryptSymmetric(ctx context.Context, keyRef KeyRef, data []byte) ([]byte, error)
	DecryptSymmetric(ctx context.Context, keyRef KeyRef, cipherText []byte) ([]byte, error)
}

func (c *CryptoService) EncryptAsymmetric(ctx context.Context, keyRef *policy.AsymmetricKey, data []byte) ([]byte, error) {
	key := KeyRef{
		Key: keyRef.GetPublicKeyCtx(),
		//Algorithm: keyRef.Get,
	}
	// Implementation of EncryptAsymmetric
	switch keyRef.GetKeyMode() {
	case policy.KeyMode_KEY_MODE_LOCAL:
		// If provider is not nil in local mode the kek is remote
		if keyRef.GetProviderConfig() != nil {
			//provider := c.providers[keyRef.GetProviderConfig().GetName()]
		} else { // If provider is nil in local mode the kek is local
			provider := c.providers[DefaultProvider]
			return provider.EncryptAsymmetric(ctx, key, data)
		}
	case policy.KeyMode_KEY_MODE_REMOTE:
		//provider := c.providers[keyRef.GetProviderConfig().GetName()]
	}
	return nil, nil
}

func (c *CryptoService) DecryptAsymmetric(keyRef *policy.AsymmetricKey, cipherText []byte) ([]byte, error) {
	// Implementation of DecryptAsymmetric
	return nil, nil
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
