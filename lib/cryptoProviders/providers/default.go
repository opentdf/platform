package providers

import (
	"context"
	"fmt"

	cryptoProviders "github.com/opentdf/platform/lib/cryptoProvider"
	"github.com/opentdf/platform/protocol/go/policy"
)

type Default struct{}

func (d *Default) Identifier() string {
	return "default"
}

func (d *Default) EncryptAsymmetric(ctx context.Context, keyRef cryptoProviders.KeyRef, data []byte) ([]byte, error) {
	// Implementation of EncryptAsymmetric
	switch keyRef.Algorithm {
	case policy.Algorithm_ALGORITHM_EC_P256, policy.Algorithm_ALGORITHM_EC_P384, policy.Algorithm_ALGORITHM_EC_P521:
		// ECDSA
	case policy.Algorithm_ALGORITHM_RSA_2048, policy.Algorithm_ALGORITHM_RSA_4096:
		// RSA
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", keyRef.Algorithm)
	}
	return nil, nil
}

func (d *Default) DecryptAsymmetric(ctx context.Context, keyRef cryptoProviders.KeyRef, cipherText []byte) ([]byte, error) {
	// Implementation of DecryptAsymmetric
	return nil, nil
}

func (d *Default) Sign(ctx context.Context, data []byte, keyRef cryptoProviders.KeyRef) ([]byte, error) {
	// Implementation of Sign
	return nil, nil
}

func (d *Default) VerifySignature(ctx context.Context, signature []byte, data []byte, keyRef cryptoProviders.KeyRef) (bool, error) {
	// Implementation of VerifySignature
	return false, nil
}

func (d *Default) EncryptSymmetric(ctx context.Context, keyRef cryptoProviders.KeyRef, data []byte) ([]byte, error) {
	// Implementation of EncryptSymmetric
	return nil, nil
}
