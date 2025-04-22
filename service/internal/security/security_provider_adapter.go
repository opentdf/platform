package security

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"errors"
)

// SecurityProviderAdapter adapts a CryptoProvider to the SecurityProvider interface
type SecurityProviderAdapter struct {
	cryptoProvider CryptoProvider
}

// NewSecurityProviderAdapter creates a new adapter that implements SecurityProvider using a CryptoProvider
func NewSecurityProviderAdapter(cryptoProvider CryptoProvider) SecurityProvider {
	return &SecurityProviderAdapter{
		cryptoProvider: cryptoProvider,
	}
}

// FindKeyByAlgorithm finds a key by algorithm using the underlying CryptoProvider
func (a *SecurityProviderAdapter) FindKeyByAlgorithm(ctx context.Context, algorithm string, includeLegacy bool) (KeyDetails, error) {
	// Get the key ID for this algorithm
	kid := a.cryptoProvider.FindKID(algorithm)
	if kid == "" {
		return nil, ErrCertNotFound
	}
	return &KeyDetailsAdapter{
		id:             KeyIdentifier(kid),
		algorithm:      algorithm,
		cryptoProvider: a.cryptoProvider,
	}, nil
}

// FindKeyByID finds a key by ID
func (a *SecurityProviderAdapter) FindKeyByID(ctx context.Context, id KeyIdentifier) (KeyDetails, error) {
	// Legacy CryptoProvider doesn't have a direct method for this, so we create
	// a KeyDetails with the given ID and let individual operations validate
	return &KeyDetailsAdapter{
		id:             id,
		cryptoProvider: a.cryptoProvider,
	}, nil
}

// ListKeys lists all available keys
func (a *SecurityProviderAdapter) ListKeys(ctx context.Context) ([]KeyDetails, error) {
	// This is a limited implementation as CryptoProvider doesn't expose a list of all keys
	var keys []KeyDetails

	// Try to find keys for known algorithms
	for _, alg := range []string{AlgorithmRSA2048, AlgorithmECP256R1} {
		if kid := a.cryptoProvider.FindKID(alg); kid != "" {
			keys = append(keys, &KeyDetailsAdapter{
				id:             KeyIdentifier(kid),
				algorithm:      alg,
				cryptoProvider: a.cryptoProvider,
			})
		}
	}

	return keys, nil
}

// Decrypt implements the unified decryption method for both RSA and EC
func (a *SecurityProviderAdapter) Decrypt(ctx context.Context, keyID KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) ([]byte, error) {
	kid := string(keyID)

	// Try to determine the key type
	keyType, err := a.determineKeyType(ctx, kid)
	if err != nil {
		return nil, err
	}

	switch keyType {
	case AlgorithmRSA2048:
		if len(ephemeralPublicKey) > 0 {
			return nil, errors.New("ephemeral public key should not be provided for RSA decryption")
		}
		return a.cryptoProvider.RSADecrypt(crypto.SHA1, kid, "", ciphertext)

	case AlgorithmECP256R1:
		if len(ephemeralPublicKey) == 0 {
			return nil, errors.New("ephemeral public key is required for EC decryption")
		}
		return a.cryptoProvider.ECDecrypt(kid, ephemeralPublicKey, ciphertext)

	default:
		return nil, errors.New("unsupported key algorithm")
	}
}

// determineKeyType tries to determine the algorithm of a key based on its ID
// This is a helper method for the Decrypt method
func (a *SecurityProviderAdapter) determineKeyType(ctx context.Context, kid string) (string, error) {
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

// GenerateNanoTDFSymmetricKey generates a symmetric key for NanoTDF
func (a *SecurityProviderAdapter) GenerateNanoTDFSymmetricKey(ctx context.Context, kasKID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error) {
	return a.cryptoProvider.GenerateNanoTDFSymmetricKey(string(kasKID), ephemeralPublicKeyBytes, curve)
}

// GenerateEphemeralKasKeys generates ephemeral keys for KAS operations
func (a *SecurityProviderAdapter) GenerateEphemeralKasKeys(ctx context.Context) (any, []byte, error) {
	return a.cryptoProvider.GenerateEphemeralKasKeys()
}

// GenerateNanoTDFSessionKey generates a session key for NanoTDF
func (a *SecurityProviderAdapter) GenerateNanoTDFSessionKey(ctx context.Context, privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error) {
	return a.cryptoProvider.GenerateNanoTDFSessionKey(privateKeyHandle, ephemeralPublicKey)
}

// Close releases any resources held by the provider
func (a *SecurityProviderAdapter) Close() {
	a.cryptoProvider.Close()
}

// KeyDetailsAdapter adapts CryptoProvider to KeyDetails
type KeyDetailsAdapter struct {
	id             KeyIdentifier
	algorithm      string
	legacy         bool
	cryptoProvider CryptoProvider
}

func (k *KeyDetailsAdapter) ID() KeyIdentifier {
	return k.id
}

func (k *KeyDetailsAdapter) Algorithm() string {
	return k.algorithm
}

func (k *KeyDetailsAdapter) IsLegacy() bool {
	return k.legacy
}

func (k *KeyDetailsAdapter) ExportPublicKey(ctx context.Context, format KeyType) (string, error) {
	kid := string(k.id)
	switch format {
	case KeyTypeJWK:
		// For JWK format (currently only supported for RSA)
		return k.cryptoProvider.RSAPublicKeyAsJSON(kid)
	case KeyTypePKCS8:
		// Try to get the key as an RSA key first
		if rsaKey, err := k.cryptoProvider.RSAPublicKey(kid); err == nil {
			return rsaKey, nil
		}
		// If that fails, try as an EC key
		return k.cryptoProvider.ECPublicKey(kid)
	default:
		return "", ErrCertNotFound
	}
}

func (k *KeyDetailsAdapter) ExportCertificate(ctx context.Context) (string, error) {
	kid := string(k.id)
	// Only EC keys have certificates in the current implementation
	return k.cryptoProvider.ECCertificate(kid)
}
