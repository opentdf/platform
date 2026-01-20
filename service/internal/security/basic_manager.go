package security

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/trust"
)

const (
	// BasicManagerName is the unique identifier for the BasicManager.
	BasicManagerName     = "opentdf.io/basic"
	ristrettoBufferItems = 64
	ristrettoMaxCost     = 3400000
	ristrettoNumCounters = ristrettoMaxCost * 10
	ristrettoCacheTTL    = 30
)

type BasicManager struct {
	l       *logger.Logger
	rootKey []byte
	cache   *cache.Cache
}

func NewBasicManager(logger *logger.Logger, c *cache.Cache, rootKey string) (*BasicManager, error) {
	rk, err := hex.DecodeString(rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to hex decode root key: %w", err)
	}

	return &BasicManager{
		l:       logger,
		rootKey: rk,
		cache:   c,
	}, nil
}

func (b *BasicManager) Name() string {
	return BasicManagerName
}

func (b *BasicManager) Decrypt(ctx context.Context, keyDetails trust.KeyDetails, ciphertext []byte, ephemeralPublicKey []byte) (ocrypto.ProtectedKey, error) {
	// Implementation of Decrypt method

	// Get Private Key
	privateKeyCtx, err := keyDetails.ExportPrivateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	privKey, err := b.unwrap(ctx, string(keyDetails.ID()), privateKeyCtx.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap private key: %w", err)
	}

	decrypter, err := ocrypto.FromPrivatePEM(string(privKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create decryptor from private PEM: %w", err)
	}

	switch keyDetails.Algorithm() {
	case ocrypto.RSA2048Key, ocrypto.RSA4096Key:
		plaintext, err := decrypter.Decrypt(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt with RSA: %w", err)
		}
		protectedKey, err := ocrypto.NewAESProtectedKey(plaintext)
		if err != nil {
			return nil, fmt.Errorf("failed to create protected key: %w", err)
		}
		return protectedKey, nil
	case ocrypto.EC256Key, ocrypto.EC384Key, ocrypto.EC521Key:
		ecPrivKey, err := ocrypto.ECPrivateKeyFromPem(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create EC private key from PEM: %w", err)
		}
		ecDecryptor, err := ocrypto.NewECDecryptor(ecPrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDecryptor: %w", err)
		}
		plaintext, err := ecDecryptor.DecryptWithEphemeralKey(ciphertext, ephemeralPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt with ephemeral key: %w", err)
		}
		protectedKey, err := ocrypto.NewAESProtectedKey(plaintext)
		if err != nil {
			return nil, fmt.Errorf("failed to create protected key: %w", err)
		}
		return protectedKey, nil
	}

	return nil, fmt.Errorf("unsupported algorithm: %s", keyDetails.Algorithm())
}

func (b *BasicManager) DeriveKey(ctx context.Context, keyDetails trust.KeyDetails, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ocrypto.ProtectedKey, error) {
	// Implementation of DeriveKey method
	privateKeyCtx, err := keyDetails.ExportPrivateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	privKey, err := b.unwrap(ctx, string(keyDetails.ID()), privateKeyCtx.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap private key: %w", err)
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

	key, err := ocrypto.CalculateHKDF(TDFSalt(), symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate HKDF: %w", err)
	}
	protectedKey, err := ocrypto.NewAESProtectedKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create protected key: %w", err)
	}
	return protectedKey, nil
}

type OCEncapsulator struct {
	ocrypto.PublicKeyEncryptor
}

func (e *OCEncapsulator) Encapsulate(dek ocrypto.ProtectedKey) ([]byte, error) {
	// Delegate to the ProtectedKey to avoid exposing raw key material
	return dek.Export(e)
}

func (e *OCEncapsulator) PublicKeyAsPEM() (string, error) {
	return e.PublicKeyInPemFormat()
}

func (b *BasicManager) GenerateECSessionKey(_ context.Context, ephemeralPublicKey string) (ocrypto.Encapsulator, error) {
	pke, err := ocrypto.FromPublicPEMWithSalt(ephemeralPublicKey, TDFSalt(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key encryptor: %w", err)
	}
	return &OCEncapsulator{PublicKeyEncryptor: pke}, nil
}

func (b *BasicManager) Close() {
	// Zero out the root key to minimize its time in memory.
	for i := range b.rootKey {
		b.rootKey[i] = 0
	}
	b.rootKey = nil
}

func (b *BasicManager) unwrap(ctx context.Context, kid string, wrappedKey string) ([]byte, error) {
	cacheEnabled := b.cache != nil
	if cacheEnabled {
		if privKey, err := b.cache.Get(ctx, kid); err == nil {
			b.l.DebugContext(ctx, "found private key in cache", slog.String("kid", kid))
			if privKeyBytes, ok := privKey.([]byte); ok {
				return privKeyBytes, nil
			}
			b.l.ErrorContext(ctx,
				"private key in cache is not of type []byte",
				slog.String("kid", kid),
				slog.Any("type", fmt.Sprintf("%T", privKey)),
			)
			return nil, errors.New("private key in cache is not of type []byte")
		}
		b.l.DebugContext(ctx, "private key not found in cache", slog.String("kid", kid))
	} else {
		b.l.DebugContext(ctx, "cache not configured, skipping cache lookup", slog.String("kid", kid))
	}

	// base64 decode
	wk, err := base64.StdEncoding.DecodeString(wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode wrapped key: %w", err)
	}

	gcm, err := ocrypto.NewAESGcm(b.rootKey)
	if err != nil {
		if errors.Is(err, ocrypto.ErrInvalidKeyData) {
			return nil, fmt.Errorf("basic key manager is not configured: %w", err)
		}
		return nil, fmt.Errorf("failed to create AES-GCM instance: %w", err)
	}

	privKey, err := gcm.Decrypt(wk)
	if err != nil {
		if errors.Is(err, ocrypto.ErrInvalidCiphertext) {
			return nil, fmt.Errorf("wrapped key data is corrupted or invalid format: %w", err)
		}
		return nil, fmt.Errorf("failed to decrypt wrapped key: %w", err)
	}

	if cacheEnabled {
		if err := b.cache.Set(ctx, kid, privKey, nil); err != nil {
			b.l.ErrorContext(ctx,
				"failed to cache private key",
				slog.String("kid", kid),
				slog.Any("error", err),
			)
		}
	}

	return privKey, nil
}
