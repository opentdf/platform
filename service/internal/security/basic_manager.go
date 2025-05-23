package security

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/trust"
	"google.golang.org/protobuf/encoding/protojson"
)

const basicManagerName = "opentdf.io/basic"

type BasicManager struct {
	l       *logger.Logger
	rootKey []byte
}

func NewBasicManager(logger *logger.Logger, rootKey []byte) *BasicManager {
	return &BasicManager{
		l:       logger,
		rootKey: rootKey,
	}
}

func (b *BasicManager) Name() string {
	return basicManagerName
}

func (b *BasicManager) Decrypt(_ context.Context, keyDetails trust.KeyDetails, ciphertext []byte, ephemeralPublicKey []byte) (trust.ProtectedKey, error) {
	// Implementation of Decrypt method

	// Get Private Key
	privateKeyCtx, err := keyDetails.ExportPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	// Unmarshal the private key to policy.KasPrivateKeyCtx
	wrappedKey := &policy.KasPrivateKeyCtx{}
	if err := protojson.Unmarshal(privateKeyCtx, wrappedKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	// Decrypt the wrapped key with the root key
	gcm, err := ocrypto.NewAESGcm(b.rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM instance: %w", err)
	}

	privKey, err := gcm.Decrypt([]byte(wrappedKey.GetWrappedKey()))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt wrapped key: %w", err)
	}

	decrypter, err := ocrypto.FromPrivatePEM(string(privKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create decryptor from private PEM: %w", err)
	}

	switch keyDetails.Algorithm() {
	case policy.Algorithm_ALGORITHM_RSA_2048.String(), policy.Algorithm_ALGORITHM_RSA_4096.String():
		plaintext, err := decrypter.Decrypt(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt with RSA: %w", err)
		}
		return NewInProcessAESKey(plaintext), nil
	case policy.Algorithm_ALGORITHM_EC_P256.String(), policy.Algorithm_ALGORITHM_EC_P384.String(), policy.Algorithm_ALGORITHM_EC_P521.String():
		ecDecryptor, ok := decrypter.(*ocrypto.ECDecryptor)
		if !ok {
			return nil, errors.New("failed to cast to ECDecryptor")
		}
		plaintext, err := ecDecryptor.DecryptWithEphemeralKey(ciphertext, ephemeralPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt with ephemeral key: %w", err)
		}
		return NewInProcessAESKey(plaintext), nil
	}

	return nil, fmt.Errorf("unsupported algorithm: %s", keyDetails.Algorithm())
}

func (b *BasicManager) DeriveKey(_ context.Context, keyDetails trust.KeyDetails, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (trust.ProtectedKey, error) {
	// Implementation of DeriveKey method
	privateKeyCtx, err := keyDetails.ExportPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wrappedKey := &policy.KasPrivateKeyCtx{}
	if err := protojson.Unmarshal(privateKeyCtx, wrappedKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}
	gcm, err := ocrypto.NewAESGcm(b.rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM instance: %w", err)
	}
	privKey, err := gcm.Decrypt([]byte(wrappedKey.GetWrappedKey()))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt wrapped key: %w", err)
	}
	ephemeralECDSAPublicKey, err := ocrypto.UncompressECPubKey(curve, ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to uncompress ephemeral public key: %w", err)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(ephemeralECDSAPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA public key: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	ephemeralECDSAPublicKeyPEM := pem.EncodeToMemory(pemBlock)

	symmetricKey, err := ocrypto.ComputeECDHKey(privKey, ephemeralECDSAPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ECDH key: %w", err)
	}

	key, err := ocrypto.CalculateHKDF(NanoVersionSalt(), symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate HKDF: %w", err)
	}
	return NewInProcessAESKey(key), nil
}

func (b *BasicManager) GenerateECSessionKey(_ context.Context, ephemeralPublicKey string) (trust.Encapsulator, error) {
	// Implementation of GenerateECSessionKey method
	return ocrypto.FromPublicPEMWithSalt(ephemeralPublicKey, NanoVersionSalt(), nil)
}

func (b *BasicManager) Close() {
	// Zero out the root key to minimize its time in memory.
	for i := range b.rootKey {
		b.rootKey[i] = 0
	}
	b.rootKey = nil
	return
}
