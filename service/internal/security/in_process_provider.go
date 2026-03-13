package security

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/trust"
)

const inProcessSystemName = "opentdf.io/in-process"

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
	case ocrypto.RSA2048Key, ocrypto.RSA4096Key, ocrypto.MLKEM768Key:
		return "", errors.New("certificates only available for EC keys")
	}
	return "", errors.New("certificates only available for EC keys")
}

func (k *KeyDetailsAdapter) ProviderConfig() *policy.KeyProviderConfig {
	return &policy.KeyProviderConfig{
		Manager: inProcessSystemName,
		Name:    "static",
	}
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

// Implement fmt.Stringer so Index's default to our String() method
func (a *InProcessProvider) String() string {
	return inProcessSystemName
}

// Implement slog.LogValuer for slog logging.
func (a *InProcessProvider) LogValue() slog.Value {
	return slog.StringValue(a.String())
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
	key, ok := a.cryptoProvider.keysByID[string(id)]
	if !ok {
		return nil, ErrCertNotFound
	}

	switch key := key.(type) {
	case StandardECCrypto:
		return &KeyDetailsAdapter{
			id:             id,
			algorithm:      ocrypto.KeyType(key.Algorithm),
			legacy:         a.legacyKeys[string(id)],
			cryptoProvider: a.cryptoProvider,
		}, nil
	case PrivateKeyCrypto:
		return &KeyDetailsAdapter{
			id:             id,
			algorithm:      ocrypto.KeyType(key.Algorithm),
			legacy:         a.legacyKeys[string(id)],
			cryptoProvider: a.cryptoProvider,
		}, nil
	default:
		return nil, ErrCertNotFound
	}
}

// ListKeys lists all available keys
func (a *InProcessProvider) ListKeys(ctx context.Context) ([]trust.KeyDetails, error) {
	return a.ListKeysWith(ctx, trust.ListKeyOptions{LegacyOnly: false})
}

func (a *InProcessProvider) ListKeysWith(ctx context.Context, opts trust.ListKeyOptions) ([]trust.KeyDetails, error) {
	var keys []trust.KeyDetails

	for kid, key := range a.cryptoProvider.keysByID {
		if opts.LegacyOnly && !a.legacyKeys[kid] {
			continue
		}

		var algorithm ocrypto.KeyType
		switch key := key.(type) {
		case StandardECCrypto:
			algorithm = ocrypto.KeyType(key.Algorithm)
		case PrivateKeyCrypto:
			algorithm = ocrypto.KeyType(key.Algorithm)
		default:
			if a.logger != nil {
				a.logger.WarnContext(ctx,
					"failed to list key with unsupported type",
					slog.String("kid", kid),
					slog.Any("type", fmt.Sprintf("%T", key)),
				)
			}
			continue
		}

		keys = append(keys, &KeyDetailsAdapter{
			id:             trust.KeyIdentifier(kid),
			algorithm:      algorithm,
			cryptoProvider: a.cryptoProvider,
			legacy:         a.legacyKeys[kid],
		})
	}

	return keys, nil
}

// Decrypt implements the unified decryption method for both RSA and EC
func (a *InProcessProvider) Decrypt(ctx context.Context, keyDetails trust.KeyDetails, ciphertext []byte, ephemeralPublicKey []byte) (ocrypto.ProtectedKey, error) {
	kid := string(keyDetails.ID())
	key, ok := a.cryptoProvider.keysByID[kid]
	if !ok {
		return nil, ErrCertNotFound
	}

	var rawKey []byte
	var err error
	switch key := key.(type) {
	case StandardECCrypto:
		if len(ephemeralPublicKey) == 0 {
			return nil, errors.New("ephemeral public key is required for EC decryption")
		}
		protectedKey, err := a.cryptoProvider.ECDecrypt(ctx, kid, ephemeralPublicKey, ciphertext)
		if err != nil {
			return nil, err
		}
		return protectedKey, nil
	case PrivateKeyCrypto:
		rawKey, err = key.dec.DecryptWithEphemeralKey(ciphertext, ephemeralPublicKey)
	default:
		return nil, errors.New("unsupported key algorithm")
	}

	if err != nil {
		return nil, err
	}
	return ocrypto.NewAESProtectedKey(rawKey)
}

// DeriveKey computes an ECDH shared secret and derives an AES key via HKDF.
func (a *InProcessProvider) DeriveKey(_ context.Context, keyDetails trust.KeyDetails, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ocrypto.ProtectedKey, error) {
	kid := string(keyDetails.ID())
	k, ok := a.cryptoProvider.keysByID[kid]
	if !ok {
		return nil, ErrKeyPairInfoNotFound
	}
	ec, ok := k.(StandardECCrypto)
	if !ok {
		return nil, ErrKeyPairInfoMalformed
	}

	ephemeralECDSAPublicKey, err := ocrypto.UncompressECPubKey(curve, ephemeralPublicKeyBytes)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.MarshalPKIXPublicKey(ephemeralECDSAPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA public key: %w", err)
	}
	ephemeralECDSAPublicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	symmetricKey, err := ocrypto.ComputeECDHKey([]byte(ec.ecPrivateKeyPem), ephemeralECDSAPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ComputeECDHKey failed: %w", err)
	}

	key, err := ocrypto.CalculateHKDF(TDFSalt(), symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}
	protectedKey, err := ocrypto.NewAESProtectedKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create protected key: %w", err)
	}
	return protectedKey, nil
}

// GenerateECSessionKey generates a session key for ECDH-based response encryption.
func (a *InProcessProvider) GenerateECSessionKey(_ context.Context, ephemeralPublicKey string) (ocrypto.Encapsulator, error) {
	pke, err := ocrypto.FromPublicPEMWithSalt(ephemeralPublicKey, TDFSalt(), nil)
	if err != nil {
		return nil, fmt.Errorf("session key generation failed to create public key encryptor: %w", err)
	}
	return &OCEncapsulator{PublicKeyEncryptor: pke}, nil
}

// Close releases any resources held by the provider
func (a *InProcessProvider) Close() {
	a.cryptoProvider.Close()
}
