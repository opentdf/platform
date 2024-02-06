package sdk

import (
	"fmt"
	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
)

type AuthConfig struct {
	signingPublicKey  string
	signingPrivateKey string
	authToken         string
}

// NewAuthConfig Create a new instance of authConfig
func NewAuthConfig() (*AuthConfig, error) {
	rsaKeyPair, err := crypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewRSAKeyPair failed: %w", err)
	}

	publicKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PublicKeyInPemFormat failed: %w", err)
	}

	privateKey, err := rsaKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PrivateKeyInPemFormat failed: %w", err)
	}

	return &AuthConfig{signingPublicKey: publicKey, signingPrivateKey: privateKey}, nil
}
