package security

import (
	"context"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/trust"
)

const inProcessSystemName = "opentdf.io/in-process"

// InProcessAESKey implements the trust.ProtectedKey interface with an in-memory secret key
type InProcessAESKey struct {
	rawKey []byte
	logger *slog.Logger
}

var _ trust.ProtectedKey = (*InProcessAESKey)(nil)

// NewInProcessAESKey creates a new instance of StandardUnwrappedKey
func NewInProcessAESKey(rawKey []byte) *InProcessAESKey {
	return &InProcessAESKey{
		rawKey: rawKey,
		logger: slog.Default(),
	}
}

func (k *InProcessAESKey) DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error) {
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

// Export returns the raw key data, optionally encrypting it with the provided trust.Encapsulator
func (k *InProcessAESKey) Export(encapsulator trust.Encapsulator) ([]byte, error) {
	if encapsulator == nil {
		if k.logger != nil {
			k.logger.Warn("exporting raw key data without encryption")
		}
		return k.rawKey, nil
	}

	// If an encryptor is provided, encrypt the key data before returning
	encryptedKey, err := encapsulator.Encrypt(k.rawKey)
	if err != nil {
		if k.logger != nil {
			k.logger.Warn("failed to encrypt key data for export", slog.Any("err", err))
		}
		return nil, err
	}

	return encryptedKey, nil
}

// VerifyBinding checks if the policy binding matches the given policy data
func (k *InProcessAESKey) VerifyBinding(ctx context.Context, policy, policyBinding []byte) error {
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
func (k *InProcessAESKey) generateHMACDigest(ctx context.Context, msg []byte) ([]byte, error) {
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
	cryptoProvider *StandardCrypto
	logger         *slog.Logger
	defaultKeys    map[string]bool
	legacyKeys     map[string]bool
}

// KeyDetailsAdapter adapts CryptoProvider to KeyDetails
type KeyDetailsAdapter struct {
	id             trust.KeyIdentifier
	algorithm      ocrypto.KeyType
	legacy         bool
	cryptoProvider *StandardCrypto
}

// Mode returns the mode of the key details
func (k *KeyDetailsAdapter) System() string {
	return inProcessSystemName
}

func (k *KeyDetailsAdapter) ID() trust.KeyIdentifier {
	return k.id
}

func (k *KeyDetailsAdapter) Algorithm() ocrypto.KeyType {
	return k.algorithm
}

func (k *KeyDetailsAdapter) IsLegacy() bool {
	return k.legacy
}

func (k *KeyDetailsAdapter) ExportPrivateKey(_ context.Context) (*trust.PrivateKey, error) {
	return nil, errors.New("private key export not supported")
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
		return k.cryptoProvider.PublicKey(kid)
	default:
		return "", ErrCertNotFound
	}
}

func (k *KeyDetailsAdapter) ExportCertificate(_ context.Context) (string, error) {
	kid := string(k.id)
	switch k.algorithm {
	case AlgorithmECP256R1, AlgorithmECP384R1, AlgorithmECP521R1:
		return k.cryptoProvider.ECCertificate(kid)
	}
	return "", errors.New("certificates only available for EC keys")
}

func (k *KeyDetailsAdapter) ProviderConfig() *policy.KeyProviderConfig {
	// Provider config is not supported for this adapter.
	return nil
}

// NewSecurityProviderAdapter creates a new adapter that implements SecurityProvider using a CryptoProvider
func NewSecurityProviderAdapter(cryptoProvider *StandardCrypto, defaultKeys, legacyKeys []string) trust.KeyService {
	legacyKeysMap := make(map[string]bool, len(legacyKeys))
	for _, key := range legacyKeys {
		legacyKeysMap[key] = true
	}

	defaultKeysMap := make(map[string]bool, len(defaultKeys))
	for _, key := range defaultKeys {
		defaultKeysMap[key] = true
	}

	return &InProcessProvider{
		cryptoProvider: cryptoProvider,
		logger:         slog.Default(),
		defaultKeys:    defaultKeysMap,
		legacyKeys:     legacyKeysMap,
	}
}

// Name returns the name of the provider
func (a *InProcessProvider) Name() string {
	return inProcessSystemName
}

// WithLogger sets the logger for the adapter
func (a *InProcessProvider) WithLogger(logger *slog.Logger) *InProcessProvider {
	a.logger = logger
	return a
}

// FindKeyByAlgorithm finds a key by algorithm using the underlying CryptoProvider.
// This will only return default keys if legacy is false.
// If legacy is true, it will return the first legacy key found that matches the algorithm.
func (a *InProcessProvider) FindKeyByAlgorithm(_ context.Context, algorithm string, legacy bool) (trust.KeyDetails, error) {
	// Get the key ID for this algorithm
	kids, err := a.cryptoProvider.ListKIDsByAlgorithm(algorithm)
	if err != nil || len(kids) == 0 {
		return nil, ErrCertNotFound
	}
	for _, kid := range kids {
		if legacy && a.legacyKeys[kid] || !legacy && a.defaultKeys[kid] {
			return &KeyDetailsAdapter{
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
func (a *InProcessProvider) FindKeyByID(_ context.Context, id trust.KeyIdentifier) (trust.KeyDetails, error) {
	k, ok := a.cryptoProvider.keysByID[string(id)]
	if !ok {
		return nil, ErrCertNotFound
	}
	switch t := k.(type) {
	case t:
		return &KeyDetailsAdapter{
			id:             id,
			algorithm:      t.Algorithm,
			legacy:         a.legacyKeys[string(id)],
			cryptoProvider: a.cryptoProvider,
		}, nil
	case PrivateKeyCrypto:
		return &KeyDetailsAdapter{
			id:             id,
			algorithm:      ocrypto.KeyType(t.Algorithm),
			legacy:         a.legacyKeys[string(id)],
			cryptoProvider: a.cryptoProvider,
		}, nil
	default:
		if a.logger != nil {
			a.logger.Warn("unknown key type for ID", slog.String("id", string(id)))
		}
		return nil, ErrCertNotFound
	}
}

// ListKeys lists all available keys
func (a *InProcessProvider) ListKeys(ctx context.Context) ([]trust.KeyDetails, error) {
	return a.ListKeysWith(ctx, trust.ListKeyOptions{LegacyOnly: false})
}

func (a *InProcessProvider) ListKeysWith(ctx context.Context, opts trust.ListKeyOptions) ([]trust.KeyDetails, error) {
	// This is a limited implementation as CryptoProvider doesn't expose a list of all keys
	var keys []trust.KeyDetails

	// Try to find keys for known algorithms
	for _, alg := range []string{AlgorithmRSA2048, AlgorithmECP256R1} {
		if kids, err := a.cryptoProvider.ListKIDsByAlgorithm(alg); err == nil && len(kids) > 0 {
			for _, kid := range kids {
				if opts.LegacyOnly && !a.legacyKeys[kid] {
					continue // Skip non-legacy keys if LegacyOnly is true
				}
				keys = append(keys, &KeyDetailsAdapter{
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
func (a *InProcessProvider) Decrypt(ctx context.Context, keyDetails trust.KeyDetails, ciphertext []byte, ephemeralPublicKey []byte) (trust.ProtectedKey, error) {
	kid := string(keyDetails.ID())
	k, ok := a.cryptoProvider.keysByID[kid]
	if !ok {
		return nil, ErrCertNotFound
	}

	var rawKey []byte
	var err error
	switch t := k.(type) {
	case StandardECCrypto:
		if len(ephemeralPublicKey) == 0 {
			return nil, errors.New("ephemeral public key is required for EC decryption")
		}
		rawKey, err = a.cryptoProvider.ECDecrypt(ctx, kid, ephemeralPublicKey, ciphertext)

	case PrivateKeyCrypto:
		rawKey, err = t.dec.DecryptWithEphemeralKey(ciphertext, ephemeralPublicKey)

	default:
		if a.logger != nil {
			a.logger.Warn("unknown key ID in rewrap", slog.Any("kid", keyDetails.ID()))
		}
		err = ErrCertNotFound
	}

	if err != nil {
		return nil, err
	}

	return &InProcessAESKey{
		rawKey: rawKey,
		logger: a.logger,
	}, nil
}

// DeriveKey generates a symmetric key for NanoTDF
func (a *InProcessProvider) DeriveKey(_ context.Context, keyDetails trust.KeyDetails, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (trust.ProtectedKey, error) {
	k, err := a.cryptoProvider.GenerateNanoTDFSymmetricKey(string(keyDetails.ID()), ephemeralPublicKeyBytes, curve)
	return NewInProcessAESKey(k), err
}

// GenerateECSessionKey generates a session key for NanoTDF
func (a *InProcessProvider) GenerateECSessionKey(_ context.Context, ephemeralPublicKey string) (trust.Encapsulator, error) {
	return ocrypto.FromPublicPEMWithSalt(ephemeralPublicKey, NanoVersionSalt(), "")
}

// Close releases any resources held by the provider
func (a *InProcessProvider) Close() {
	a.cryptoProvider.Close()
}
