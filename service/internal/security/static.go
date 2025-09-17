package security

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/trust"
)

const staticKeyProviderName = "opentdf.io/static"

func convertPEMToJWK(_ string) (string, error) {
	// Implement the conversion logic here or use an external library if available.
	// For now, return a placeholder error to indicate the function is not implemented.
	return "", errors.New("convertPEMToJWK function is not implemented")
}

// StaticKeyService adapts a CryptoProvider to the trust.KeyService interface
type StaticKeyService struct {
	cryptoProvider *StandardCrypto
	logger         *slog.Logger
	defaultKeys    map[string]bool
	legacyKeys     map[string]bool
}

// staticKeyDetails adapts CryptoProvider to KeyDetails
type staticKeyDetails struct {
	id             trust.KeyIdentifier
	algorithm      ocrypto.KeyType
	legacy         bool
	cryptoProvider *StandardCrypto
}

// Mode returns the mode of the key details
func (k *staticKeyDetails) System() string {
	return staticKeyProviderName
}

func (k *staticKeyDetails) ID() trust.KeyIdentifier {
	return k.id
}

func (k *staticKeyDetails) Algorithm() ocrypto.KeyType {
	return k.algorithm
}

func (k *staticKeyDetails) IsLegacy() bool {
	return k.legacy
}

func (k *staticKeyDetails) ExportPrivateKey(_ context.Context) (*trust.PrivateKey, error) {
	return nil, errors.New("private key export not supported")
}

func (k *staticKeyDetails) ExportPublicKey(_ context.Context, format trust.KeyType) (string, error) {
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

func (k *staticKeyDetails) ExportCertificate(_ context.Context) (string, error) {
	kid := string(k.id)
	if k.algorithm == AlgorithmECP256R1 {
		return k.cryptoProvider.ECCertificate(kid)
	}
	return "", errors.New("certificates only available for EC keys")
}

func (k *staticKeyDetails) ProviderConfig() *policy.KeyProviderConfig {
	// Provider config is not supported for this adapter.
	return nil
}

// NewStaticKeyService creates a new adapter that implements SecurityProvider using a CryptoProvider
func NewStaticKeyService(cryptoProvider *StandardCrypto, defaultKeys, legacyKeys []string) trust.KeyService {
	legacyKeysMap := make(map[string]bool, len(legacyKeys))
	for _, key := range legacyKeys {
		legacyKeysMap[key] = true
	}

	defaultKeysMap := make(map[string]bool, len(defaultKeys))
	for _, key := range defaultKeys {
		defaultKeysMap[key] = true
	}

	return &StaticKeyService{
		cryptoProvider: cryptoProvider,
		logger:         slog.Default(),
		defaultKeys:    defaultKeysMap,
		legacyKeys:     legacyKeysMap,
	}
}

// Name returns the name of the provider
func (a *StaticKeyService) Name() string {
	return staticKeyProviderName
}

// WithLogger sets the logger for the adapter
func (a *StaticKeyService) WithLogger(logger *slog.Logger) *StaticKeyService {
	a.logger = logger
	return a
}

// FindKeyByAlgorithm finds a key by algorithm using the underlying CryptoProvider.
// This will only return default keys if legacy is false.
// If legacy is true, it will return the first legacy key found that matches the algorithm.
func (a *StaticKeyService) FindKeyByAlgorithm(_ context.Context, algorithm string, legacy bool) (trust.KeyDetails, error) {
	// Get the key ID for this algorithm
	kids, err := a.cryptoProvider.ListKIDsByAlgorithm(algorithm)
	if err != nil || len(kids) == 0 {
		return nil, ErrCertNotFound
	}
	for _, kid := range kids {
		if legacy && a.legacyKeys[kid] || !legacy && a.defaultKeys[kid] {
			return &staticKeyDetails{
				id:             trust.KeyIdentifier(kid),
				algorithm:      ocrypto.KeyType(algorithm),
				cryptoProvider: a.cryptoProvider,
				legacy:         legacy,
			}, nil
		}
	}
	return nil, ErrCertNotFound
}

// FindKeyByID finds a key by ID
func (a *StaticKeyService) FindKeyByID(_ context.Context, id trust.KeyIdentifier) (trust.KeyDetails, error) {
	if k, err := a.cryptoProvider.RSAPublicKey(string(id)); err == nil {
		e, err := ocrypto.FromPublicPEM(k)
		if err != nil {
			return nil, fmt.Errorf("failed to parse rsa public key while scanning for [%s]: %w", id, err)
		}
		return &staticKeyDetails{
			id:             id,
			algorithm:      e.KeyType(),
			legacy:         a.legacyKeys[string(id)],
			cryptoProvider: a.cryptoProvider,
		}, nil
	}
	if k, err := a.cryptoProvider.ECPublicKey(string(id)); err == nil {
		e, err := ocrypto.FromPublicPEM(k)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ec public key while scanning for [%s]: %w", id, err)
		}
		return &staticKeyDetails{
			id:             id,
			algorithm:      e.KeyType(),
			legacy:         a.legacyKeys[string(id)],
			cryptoProvider: a.cryptoProvider,
		}, nil
	}
	return nil, ErrCertNotFound
}

// ListKeys lists all available keys
func (a *StaticKeyService) ListKeys(ctx context.Context) ([]trust.KeyDetails, error) {
	return a.ListKeysWith(ctx, trust.ListKeyOptions{LegacyOnly: false})
}

func (a *StaticKeyService) ListKeysWith(ctx context.Context, opts trust.ListKeyOptions) ([]trust.KeyDetails, error) {
	// This is a limited implementation as CryptoProvider doesn't expose a list of all keys
	var keys []trust.KeyDetails

	// Try to find keys for known algorithms
	for _, alg := range []string{AlgorithmRSA2048, AlgorithmECP256R1} {
		if kids, err := a.cryptoProvider.ListKIDsByAlgorithm(alg); err == nil && len(kids) > 0 {
			for _, kid := range kids {
				if opts.LegacyOnly && !a.legacyKeys[kid] {
					continue // Skip non-legacy keys if LegacyOnly is true
				}
				keys = append(keys, &staticKeyDetails{
					id:             trust.KeyIdentifier(kid),
					algorithm:      ocrypto.KeyType(alg),
					cryptoProvider: a.cryptoProvider,
					legacy:         a.legacyKeys[kid],
				})
			}
		} else if err != nil {
			if a.logger != nil {
				a.logger.WarnContext(ctx,
					"failed to list keys by algorithm",
					slog.String("algorithm", alg),
					slog.Any("error", err),
				)
			}
		}
	}

	return keys, nil
}

// Decrypt implements the unified decryption method for both RSA and EC
func (a *StaticKeyService) Decrypt(ctx context.Context, keyDetails trust.KeyDetails, ciphertext []byte, ephemeralPublicKey []byte) (ocrypto.ProtectedKey, error) {
	kid := string(keyDetails.ID())

	var protectedKey ocrypto.ProtectedKey
	var err error

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
		protectedKey, err = a.cryptoProvider.ECDecrypt(ctx, kid, ephemeralPublicKey, ciphertext)

	default:
		return nil, errors.New("unsupported key algorithm")
	}

	if err != nil {
		return nil, err
	}

	if protectedKey == nil {
		protectedKey, err = ocrypto.NewAESProtectedKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create protected key: %w", err)
		}
	}

	return protectedKey, nil
}

// DeriveKey generates a symmetric key for NanoTDF
func (a *StaticKeyService) DeriveKey(_ context.Context, keyDetails trust.KeyDetails, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ocrypto.ProtectedKey, error) {
	k, err := a.cryptoProvider.GenerateNanoTDFSymmetricKey(string(keyDetails.ID()), ephemeralPublicKeyBytes, curve)
	if err != nil {
		return nil, err
	}
	protectedKey, err := ocrypto.NewAESProtectedKey(k)
	if err != nil {
		return nil, fmt.Errorf("failed to create protected key: %w", err)
	}
	return protectedKey, nil
}

// GenerateECSessionKey generates a session key for NanoTDF
func (a *StaticKeyService) GenerateECSessionKey(_ context.Context, ephemeralPublicKey string) (trust.Encapsulator, error) {
	pke, err := ocrypto.FromPublicPEMWithSalt(ephemeralPublicKey, NanoVersionSalt(), nil)
	if err != nil {
		return nil, fmt.Errorf("session key generation failed to create public key encryptor: %w", err)
	}
	return &OCEncapsulator{PublicKeyEncryptor: pke}, nil
}

// Close releases any resources held by the provider
func (a *StaticKeyService) Close() {
	a.cryptoProvider.Close()
}

// determineKeyType tries to determine the algorithm of a key based on its ID
// This is a helper method for the Decrypt method
func (a *StaticKeyService) determineKeyType(_ context.Context, kid string) (string, error) {
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
