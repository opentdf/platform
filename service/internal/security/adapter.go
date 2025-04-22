package security

import (
	"crypto"
	"crypto/elliptic"
	"fmt"
)

// CryptoProviderAdapter adapts the existing CryptoProvider to the new SecurityProvider interface
type CryptoProviderAdapter struct {
	provider CryptoProvider
}

// NewSecurityProviderAdapter creates a new SecurityProvider from an existing CryptoProvider
func NewSecurityProviderAdapter(provider CryptoProvider) SecurityProvider {
	return &CryptoProviderAdapter{provider: provider}
}

// key implementation of the KeyDetails interface for the adapter
type key struct {
	id        KeyIdentifier
	algorithm string
	legacy    bool
	provider  CryptoProvider
}

func (k *key) ID() KeyIdentifier {
	return k.id
}

func (k *key) Algorithm() string {
	return k.algorithm
}

func (k *key) IsLegacy() bool {
	return k.legacy
}

func (k *key) ExportPublicKey(format KeyType) (string, error) {
	keyID := string(k.id)
	if k.algorithm == AlgorithmECP256R1 {
		return k.provider.ECPublicKey(keyID)
	} else if k.algorithm == AlgorithmRSA2048 {
		if format == KeyTypeJWK {
			return k.provider.RSAPublicKeyAsJSON(keyID)
		}
		return k.provider.RSAPublicKey(keyID)
	}
	return "", fmt.Errorf("unsupported algorithm for export: %s", k.algorithm)
}

func (k *key) ExportCertificate() (string, error) {
	keyID := string(k.id)
	if k.algorithm == AlgorithmECP256R1 {
		return k.provider.ECCertificate(keyID)
	}
	return "", fmt.Errorf("certificates only available for EC keys")
}

// FindKeyByAlgorithm implements KeyLookup.FindKeyByAlgorithm
func (a *CryptoProviderAdapter) FindKeyByAlgorithm(algorithm string, includeLegacy bool) (KeyDetails, error) {
	// The legacy CryptoProvider doesn't have a concept of legacy keys directly
	// so we ignore the includeLegacy parameter here
	kid := a.provider.FindKID(algorithm)
	if kid == "" {
		return nil, ErrCertNotFound
	}
	return &key{
		id:        KeyIdentifier(kid),
		algorithm: algorithm,
		legacy:    false,
		provider:  a.provider,
	}, nil
}

// FindKeyByID implements KeyLookup.FindKeyByID
func (a *CryptoProviderAdapter) FindKeyByID(id KeyIdentifier) (KeyDetails, error) {
	// Try to determine the algorithm by checking if the key works with known algorithms
	for _, alg := range []string{AlgorithmECP256R1, AlgorithmRSA2048} {
		// This is a hack since the original provider doesn't have a way to check if a key exists
		if alg == AlgorithmECP256R1 {
			if _, err := a.provider.ECPublicKey(string(id)); err == nil {
				return &key{
					id:        id,
					algorithm: alg,
					legacy:    false,
					provider:  a.provider,
				}, nil
			}
		} else if alg == AlgorithmRSA2048 {
			if _, err := a.provider.RSAPublicKey(string(id)); err == nil {
				return &key{
					id:        id,
					algorithm: alg,
					legacy:    false,
					provider:  a.provider,
				}, nil
			}
		}
	}
	return nil, ErrCertNotFound
}

// ListKeys implements KeyLookup.ListKeys
func (a *CryptoProviderAdapter) ListKeys() ([]KeyDetails, error) {
	// The original CryptoProvider doesn't have a way to list all keys,
	// so we can only include the default keys for each algorithm
	var keys []KeyDetails
	for _, alg := range []string{AlgorithmECP256R1, AlgorithmRSA2048} {
		kid := a.provider.FindKID(alg)
		if kid != "" {
			keys = append(keys, &key{
				id:        KeyIdentifier(kid),
				algorithm: alg,
				legacy:    false,
				provider:  a.provider,
			})
		}
	}
	return keys, nil
}

// RSADecrypt implements SecurityProvider.RSADecrypt
func (a *CryptoProviderAdapter) RSADecrypt(keyID KeyIdentifier, ciphertext []byte) ([]byte, error) {
	// We use SHA1 as the hash and empty key label as in the original code
	return a.provider.RSADecrypt(crypto.SHA1, string(keyID), "", ciphertext)
}

// ECDecrypt implements SecurityProvider.ECDecrypt
func (a *CryptoProviderAdapter) ECDecrypt(keyID KeyIdentifier, ephemeralPublicKey, ciphertext []byte) ([]byte, error) {
	return a.provider.ECDecrypt(string(keyID), ephemeralPublicKey, ciphertext)
}

// GenerateNanoTDFSymmetricKey implements SecurityProvider.GenerateNanoTDFSymmetricKey
func (a *CryptoProviderAdapter) GenerateNanoTDFSymmetricKey(kasKID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error) {
	return a.provider.GenerateNanoTDFSymmetricKey(string(kasKID), ephemeralPublicKeyBytes, curve)
}

// GenerateEphemeralKasKeys implements SecurityProvider.GenerateEphemeralKasKeys
func (a *CryptoProviderAdapter) GenerateEphemeralKasKeys() (any, []byte, error) {
	return a.provider.GenerateEphemeralKasKeys()
}

// GenerateNanoTDFSessionKey implements SecurityProvider.GenerateNanoTDFSessionKey
func (a *CryptoProviderAdapter) GenerateNanoTDFSessionKey(privateKeyHandle any, ephemeralPublicKey []byte) ([]byte, error) {
	return a.provider.GenerateNanoTDFSessionKey(privateKeyHandle, ephemeralPublicKey)
}

// Close implements SecurityProvider.Close
func (a *CryptoProviderAdapter) Close() {
	a.provider.Close()
}
