package security

import (
	"crypto"
	"crypto/elliptic"
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
func (a *SecurityProviderAdapter) FindKeyByAlgorithm(algorithm string, includeLegacy bool) (KeyDetails, error) {
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
func (a *SecurityProviderAdapter) FindKeyByID(id KeyIdentifier) (KeyDetails, error) {
	// Legacy CryptoProvider doesn't have a direct method for this, so we create
	// a KeyDetails with the given ID and let individual operations validate
	return &KeyDetailsAdapter{
		id:             id,
		cryptoProvider: a.cryptoProvider,
	}, nil
}

// ListKeys lists all available keys
func (a *SecurityProviderAdapter) ListKeys() ([]KeyDetails, error) {
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

// RSADecrypt decrypts data with an RSA key
func (a *SecurityProviderAdapter) RSADecrypt(keyID KeyIdentifier, ciphertext []byte) ([]byte, error) {
	return a.cryptoProvider.RSADecrypt(crypto.SHA1, string(keyID), "", ciphertext)
}

// ECDecrypt decrypts data with an EC key
func (a *SecurityProviderAdapter) ECDecrypt(keyID KeyIdentifier, ephemeralPublicKey, ciphertext []byte) ([]byte, error) {
	return a.cryptoProvider.ECDecrypt(string(keyID), ephemeralPublicKey, ciphertext)
}

// GenerateNanoTDFSymmetricKey generates a symmetric key for NanoTDF
func (a *SecurityProviderAdapter) GenerateNanoTDFSymmetricKey(kasKID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error) {
	return a.cryptoProvider.GenerateNanoTDFSymmetricKey(string(kasKID), ephemeralPublicKeyBytes, curve)
}

// GenerateEphemeralKasKeys generates ephemeral keys for KAS operations
func (a *SecurityProviderAdapter) GenerateEphemeralKasKeys() (any, []byte, error) {
	return a.cryptoProvider.GenerateEphemeralKasKeys()
}

// GenerateNanoTDFSessionKey generates a session key for NanoTDF
func (a *SecurityProviderAdapter) GenerateNanoTDFSessionKey(privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error) {
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

func (k *KeyDetailsAdapter) ExportPublicKey(format KeyType) (string, error) {
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

func (k *KeyDetailsAdapter) ExportCertificate() (string, error) {
	kid := string(k.id)
	// Only EC keys have certificates in the current implementation
	return k.cryptoProvider.ECCertificate(kid)
}
