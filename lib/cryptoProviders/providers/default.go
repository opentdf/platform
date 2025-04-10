package providers

import (
	"context"
	"crypto"
	"fmt"

	"github.com/opentdf/platform/lib/cryptoProviders"
	"github.com/opentdf/platform/lib/ocrypto"
)

type Default struct{}

func NewDefault() *Default {
	return &Default{}
}

func (d *Default) Identifier() string {
	return "default"
}

func (d *Default) EncryptRSAOAEP(ctx context.Context, hash crypto.Hash, keyRef cryptoProviders.KeyRef, data []byte) ([]byte, error) {
	fmt.Println("Default RSA Encrypt!!!!!!!!!!")

	asym, err := ocrypto.NewAsymEncryption(string(keyRef.Key))
	if err != nil {
		return nil, err
	}
	cipherText, err := asym.Encrypt(data)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func (d *Default) DecryptRSAOAEP(ctx context.Context, keyRef cryptoProviders.KeyRef, cipherText []byte) ([]byte, error) {
	fmt.Println("Default RSA Decrypt!!!!!!!!!!")

	asym, err := ocrypto.FromPrivatePEM(string(keyRef.Key))
	if err != nil {
		return nil, err
	}
	plainText, err := asym.Decrypt(cipherText)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func (d *Default) EncryptEC(ctx context.Context, keyRef cryptoProviders.KeyRef, ephemeralPublicKey []byte, data []byte) ([]byte, []byte, error) {
	fmt.Println("Default EC Encrypt!!!!!!!!!!")
	asym, err := ocrypto.FromPublicPEM(string(ephemeralPublicKey))
	if err != nil {
		return nil, nil, err
	}

	cipherText, err := asym.Encrypt(data)
	if err != nil {
		return nil, nil, err
	}

	return cipherText, asym.EphemeralKey(), nil
}

func (d *Default) DecryptEC(ctx context.Context, keyRef cryptoProviders.KeyRef, ephemeralPublicKey []byte, cipherText []byte) ([]byte, error) {
	fmt.Println("Default EC Decrypt!!!!!!!!!!")

	// Parse the private key
	key, err := ocrypto.ECPrivateKeyFromPem(keyRef.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}

	ed, err := ocrypto.NewECDecryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create EC decryptor: %w", err)
	}

	return ed.DecryptWithEphemeralKey(cipherText, ephemeralPublicKey)
}

func (d *Default) DecryptSymmetric(ctx context.Context, key []byte, cipherText []byte) ([]byte, error) {
	fmt.Println("Default Symmetric Decrypt!!!!!!!!!!")
	// Implementation of DecryptSymmetric
	gcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		return nil, err
	}

	plainText, err := gcm.Decrypt(cipherText)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
