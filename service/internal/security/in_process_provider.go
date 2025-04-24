package security

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/trust"
)

const modeInProcess = "opentdf.io/in-process"

// StandardUnwrappedKey implements the UnwrappedKeyData interface
type StandardUnwrappedKey struct {
	rawKey []byte
	logger *slog.Logger
}

// NewStandardUnwrappedKey creates a new instance of StandardUnwrappedKey
func NewStandardUnwrappedKey(rawKey []byte) *StandardUnwrappedKey {
	return &StandardUnwrappedKey{
		rawKey: rawKey,
		logger: slog.Default(),
	}
}

func (k *StandardUnwrappedKey) DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error) {
	aesGcm, err := ocrypto.NewAESGcm(k.rawKey)
	if err != nil {
		return nil, err
	}

	decryptedData, err := aesGcm.DecryptWithIVAndTagSize(iv, body, tagSize)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// Export returns the raw key data, optionally encrypting it with the provided encryptor
func (k *StandardUnwrappedKey) Export(encryptor trust.Encapsulator) ([]byte, error) {
	if encryptor == nil {
		return k.rawKey, nil
	}

	// If an encryptor is provided, encrypt the key data before returning
	encryptedKey, err := encryptor.Encrypt(k.rawKey)
	if err != nil {
		if k.logger != nil {
			k.logger.Warn("failed to encrypt key data for export", "err", err)
		}
		return nil, err
	}

	return encryptedKey, nil
}

// VerifyBinding checks if the policy binding matches the given policy data
func (k *StandardUnwrappedKey) VerifyBinding(ctx context.Context, policy, policyBinding []byte) error {
	if len(k.rawKey) == 0 {
		return errors.New("key data is empty")
	}

	actualHMAC, err := k.generateHMACDigest(ctx, policy)
	if err != nil {
		return fmt.Errorf("unable to generate policy hmac: %w", err)
	}

	if !hmac.Equal(actualHMAC, policyBinding) {
		return errors.New("policy hmac mismatch")
	}

	return nil
}

// generateHMACDigest is a helper to generate an HMAC digest from a message using the key
func (k *StandardUnwrappedKey) generateHMACDigest(ctx context.Context, msg []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k.rawKey)
	_, err := mac.Write(msg)
	if err != nil {
		if k.logger != nil {
			k.logger.WarnContext(ctx, "failed to compute hmac")
		}
		return nil, errors.New("policy hmac")
	}
	return mac.Sum(nil), nil
}

func convertPEMToJWK(_ string) (string, error) {
	// Implement the conversion logic here or use an external library if available.
	// For now, return a placeholder error to indicate the function is not implemented.
	return "", errors.New("convertPEMToJWK function is not implemented")
}

// InProcessProvider adapts a CryptoProvider to the SecurityProvider interface
type InProcessProvider struct {
	cryptoProvider CryptoProvider
	logger         *slog.Logger
}

// KeyDetailsAdapter adapts CryptoProvider to KeyDetails
type KeyDetailsAdapter struct {
	id             trust.KeyIdentifier
	algorithm      string
	legacy         bool
	cryptoProvider CryptoProvider
}

// Mode returns the mode of the key details
func (k *KeyDetailsAdapter) Mode() string {
	return modeInProcess
}

func (k *KeyDetailsAdapter) ID() trust.KeyIdentifier {
	return k.id
}

func (k *KeyDetailsAdapter) Algorithm() string {
	return k.algorithm
}

func (k *KeyDetailsAdapter) IsLegacy() bool {
	return k.legacy
}

func (k *KeyDetailsAdapter) ExportPublicKey(_ context.Context, format trust.KeyType) (string, error) {
	kid := string(k.id)
	switch format {
	case trust.KeyTypeJWK:
		// For JWK format (currently only supported for RSA)
		if k.algorithm == AlgorithmRSA2048 {
			return k.cryptoProvider.RSAPublicKeyAsJSON(kid)
		}
		// For EC keys, we return the public key in PEM format
		pemKey, err := k.cryptoProvider.ECPublicKey(kid)
		if err != nil {
			return "", err
		}
		jwkKey, err := convertPEMToJWK(pemKey)
		if err != nil {
			return "", err
		}

		return jwkKey, nil
	case trust.KeyTypePKCS8:
		// Try to get the key as an RSA key first
		if rsaKey, err := k.cryptoProvider.RSAPublicKey(kid); err == nil {
			return rsaKey, nil
		}
		return k.cryptoProvider.ECPublicKey(kid)
	default:
		return "", ErrCertNotFound
	}
}

func (k *KeyDetailsAdapter) ExportCertificate(_ context.Context) (string, error) {
	kid := string(k.id)
	if k.algorithm == AlgorithmECP256R1 {
		return k.cryptoProvider.ECCertificate(kid)
	}
	return "", fmt.Errorf("certificates only available for EC keys")
}

// NewSecurityProviderAdapter creates a new adapter that implements SecurityProvider using a CryptoProvider
func NewSecurityProviderAdapter(cryptoProvider CryptoProvider) trust.KeyService {
	return &InProcessProvider{
		cryptoProvider: cryptoProvider,
		logger:         slog.Default(),
	}
}

// Name returns the name of the provider
func (a *InProcessProvider) Name() string {
	return modeInProcess
}

// WithLogger sets the logger for the adapter
func (a *InProcessProvider) WithLogger(logger *slog.Logger) *InProcessProvider {
	a.logger = logger
	return a
}

// FindKeyByAlgorithm finds a key by algorithm using the underlying CryptoProvider
func (a *InProcessProvider) FindKeyByAlgorithm(_ context.Context, algorithm string, _ bool) (trust.KeyDetails, error) {
	// Get the key ID for this algorithm
	kid := a.cryptoProvider.FindKID(algorithm)
	if kid == "" {
		return nil, ErrCertNotFound
	}
	return &KeyDetailsAdapter{
		id:             trust.KeyIdentifier(kid),
		algorithm:      algorithm,
		cryptoProvider: a.cryptoProvider,
	}, nil
}

// FindKeyByID finds a key by ID
func (a *InProcessProvider) FindKeyByID(_ context.Context, id trust.KeyIdentifier) (trust.KeyDetails, error) {
	// Try to determine the algorithm by checking if the key works with known algorithms
	for _, alg := range []string{AlgorithmECP256R1, AlgorithmRSA2048} {
		// This is a hack since the original provider doesn't have a way to check if a key exists
		if alg == AlgorithmECP256R1 {
			if _, err := a.cryptoProvider.ECPublicKey(string(id)); err == nil {
				return &KeyDetailsAdapter{
					id:             id,
					algorithm:      alg,
					legacy:         false,
					cryptoProvider: a.cryptoProvider,
				}, nil
			}
		} else if alg == AlgorithmRSA2048 {
			if _, err := a.cryptoProvider.RSAPublicKey(string(id)); err == nil {
				return &KeyDetailsAdapter{
					id:             id,
					algorithm:      alg,
					legacy:         false,
					cryptoProvider: a.cryptoProvider,
				}, nil
			}
		}
	}
	return nil, ErrCertNotFound
}

// ListKeys lists all available keys
func (a *InProcessProvider) ListKeys(_ context.Context) ([]trust.KeyDetails, error) {
	// This is a limited implementation as CryptoProvider doesn't expose a list of all keys
	var keys []trust.KeyDetails

	// Try to find keys for known algorithms
	for _, alg := range []string{AlgorithmRSA2048, AlgorithmECP256R1} {
		if kid := a.cryptoProvider.FindKID(alg); kid != "" {
			keys = append(keys, &KeyDetailsAdapter{
				id:             trust.KeyIdentifier(kid),
				algorithm:      alg,
				cryptoProvider: a.cryptoProvider,
			})
		}
	}

	return keys, nil
}

// Decrypt implements the unified decryption method for both RSA and EC
func (a *InProcessProvider) Decrypt(ctx context.Context, keyID trust.KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) (trust.ProtectedKey, error) {
	kid := string(keyID)

	// Try to determine the key type
	keyType, err := a.determineKeyType(ctx, kid)
	if err != nil {
		return nil, err
	}

	var rawKey []byte
	switch keyType {
	case AlgorithmRSA2048:
		if len(ephemeralPublicKey) > 0 {
			return nil, errors.New("ephemeral public key should not be provided for RSA decryption")
		}
		rawKey, err = a.cryptoProvider.RSADecrypt(crypto.SHA1, kid, "", ciphertext)

	case AlgorithmECP256R1:
		if len(ephemeralPublicKey) == 0 {
			return nil, errors.New("ephemeral public key is required for EC decryption")
		}
		rawKey, err = a.cryptoProvider.ECDecrypt(kid, ephemeralPublicKey, ciphertext)

	default:
		return nil, errors.New("unsupported key algorithm")
	}

	if err != nil {
		return nil, err
	}

	return &StandardUnwrappedKey{
		rawKey: rawKey,
		logger: a.logger,
	}, nil
}

// determineKeyType tries to determine the algorithm of a key based on its ID
// This is a helper method for the Decrypt method
func (a *InProcessProvider) determineKeyType(_ context.Context, kid string) (string, error) {
	// First try RSA
	if _, err := a.cryptoProvider.RSAPublicKey(kid); err == nil {
		return AlgorithmRSA2048, nil
	}

	// Then try EC
	if _, err := a.cryptoProvider.ECPublicKey(kid); err == nil {
		return AlgorithmECP256R1, nil
	}

	return "", errors.New("could not determine key type")
}

// DeriveKey generates a symmetric key for NanoTDF
func (a *InProcessProvider) DeriveKey(_ context.Context, kasKID trust.KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (trust.ProtectedKey, error) {
	k, err := a.cryptoProvider.GenerateNanoTDFSymmetricKey(string(kasKID), ephemeralPublicKeyBytes, curve)
	return NewStandardUnwrappedKey(k), err
}

// GenerateECSessionKey generates a session key for NanoTDF
func (a *InProcessProvider) GenerateECSessionKey(_ context.Context, ephemeralPublicKey string) (trust.Encapsulator, error) {
	return ocrypto.FromPublicPEMWithSalt(ephemeralPublicKey, versionSalt(), nil)
}

// Close releases any resources held by the provider
func (a *InProcessProvider) Close() {
	a.cryptoProvider.Close()
}
