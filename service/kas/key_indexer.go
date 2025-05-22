package kas

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/trust"
)

var ErrNoActiveKeyForAlgorithm = errors.New("no active key found for specified algorithm")

// Used for reaching out to platform to get keys
type KeyIndexer struct {
	// SDK is the SDK instance used to interact with the platform
	sdk *sdk.SDK
	// KasURI
	kasURI string
	// Logger is the logger instance used for logging
	log *logger.Logger
}

// platformKeyAdapter is an adapter for KeyDetails, where keys come from the platform
type KeyAdapter struct {
	key *policy.KasKey
	log *logger.Logger
}

func NewPlatformKeyIndexer(sdk *sdk.SDK, kasURI string, l *logger.Logger) *KeyIndexer {
	return &KeyIndexer{
		sdk:    sdk,
		kasURI: kasURI,
		log:    l,
	}
}

func convertAlgToEnum(alg string) (policy.Algorithm, error) {
	switch alg {
	case "rsa:2048":
		return policy.Algorithm_ALGORITHM_RSA_2048, nil
	case "rsa:4096":
		return policy.Algorithm_ALGORITHM_RSA_4096, nil
	case "ec:secp256r1":
		return policy.Algorithm_ALGORITHM_EC_P256, nil
	case "ec:secp384r1":
		return policy.Algorithm_ALGORITHM_EC_P384, nil
	case "ec:secp521r1":
		return policy.Algorithm_ALGORITHM_EC_P521, nil
	default:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func (p *KeyIndexer) FindKeyByAlgorithm(ctx context.Context, algorithm string, _ bool) (trust.KeyDetails, error) {
	alg, err := convertAlgToEnum(algorithm)
	if err != nil {
		return nil, err
	}

	req := &kasregistry.ListKeysRequest{
		KeyAlgorithm: alg,
		KasFilter: &kasregistry.ListKeysRequest_KasUri{
			KasUri: p.kasURI,
		},
	}
	resp, err := p.sdk.KeyAccessServerRegistry.ListKeys(ctx, req)
	if err != nil {
		return nil, err
	}

	// Find active key.
	var activeKey *policy.KasKey
	for _, key := range resp.GetKasKeys() {
		if key.GetKey().GetKeyStatus() == policy.KeyStatus_KEY_STATUS_ACTIVE {
			activeKey = key
			break
		}
	}
	if activeKey == nil {
		return nil, ErrNoActiveKeyForAlgorithm
	}

	return &KeyAdapter{
		key: activeKey,
		log: p.log,
	}, nil
}

func (p *KeyIndexer) FindKeyByID(ctx context.Context, id trust.KeyIdentifier) (trust.KeyDetails, error) {
	req := &kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_Uri{
					Uri: p.kasURI,
				},
				Kid: string(id),
			},
		},
	}

	resp, err := p.sdk.KeyAccessServerRegistry.GetKey(ctx, req)
	if err != nil {
		return nil, err
	}

	return &KeyAdapter{
		key: resp.GetKasKey(),
		log: p.log,
	}, nil
}

func (p *KeyIndexer) ListKeys(ctx context.Context) ([]trust.KeyDetails, error) {
	req := &kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{
			KasUri: p.kasURI,
		},
	}
	resp, err := p.sdk.KeyAccessServerRegistry.ListKeys(ctx, req)
	if err != nil {
		return nil, err
	}

	keys := make([]trust.KeyDetails, len(resp.GetKasKeys()))
	for i, key := range resp.GetKasKeys() {
		keys[i] = &KeyAdapter{
			key: key,
			log: p.log,
		}
	}

	return keys, nil
}

func (p *KeyAdapter) ID() trust.KeyIdentifier {
	return trust.KeyIdentifier(p.key.GetKey().GetKeyId())
}

// Might need to convert this to a standard format
func (p *KeyAdapter) Algorithm() string {
	return p.key.GetKey().GetKeyAlgorithm().String()
}

func (p *KeyAdapter) IsLegacy() bool {
	return false
}

// This will point to the correct "manager"
func (p *KeyAdapter) System() string {
	var mode string
	if p.key.GetKey().GetProviderConfig() != nil {
		mode = p.key.GetKey().GetProviderConfig().GetName()
	}
	return mode
}

func pemToPublicKey(publicPEM string) (*rsa.PublicKey, error) {
	// Decode the PEM data
	block, _ := pem.Decode([]byte(publicPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block or incorrect PEM type")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Assert type and return
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

// Repurpose of the StandardCrypto function
func rsaPublicKeyAsJSON(_ context.Context, publicPEM string) (string, error) {
	pubKey, err := pemToPublicKey(publicPEM)
	if err != nil {
		return "", err
	}

	rsaPublicKeyJwk, err := jwk.FromRaw(pubKey)
	if err != nil {
		return "", fmt.Errorf("jwk.FromRaw: %w", err)
	}

	// Convert the public key to JSON format
	pubKeyJSON, err := json.Marshal(rsaPublicKeyJwk)
	if err != nil {
		return "", err
	}

	return string(pubKeyJSON), nil
}

// Repurpose of the StandardCrypto function
func convertPEMToJWK(_ string) (string, error) {
	return "", errors.New("convertPEMToJWK function is not implemented")
}

func (p *KeyAdapter) ExportPublicKey(ctx context.Context, format trust.KeyType) (string, error) {
	publicKeyCtx := p.key.GetKey().GetPublicKeyCtx()

	// Decode the base64-encoded public key
	decodedPubKey, err := base64.StdEncoding.DecodeString(publicKeyCtx.GetPem())
	if err != nil {
		return "", err
	}

	switch format {
	case trust.KeyTypeJWK:
		// For JWK format (currently only supported for RSA)
		if p.key.GetKey().GetKeyAlgorithm() == policy.Algorithm_ALGORITHM_RSA_2048 ||
			p.key.GetKey().GetKeyAlgorithm() == policy.Algorithm_ALGORITHM_RSA_4096 {
			return rsaPublicKeyAsJSON(ctx, string(decodedPubKey))
		}
		// For EC keys, we return the public key in PEM format
		jwkKey, err := convertPEMToJWK(string(decodedPubKey))
		if err != nil {
			return "", err
		}

		return jwkKey, nil
	case trust.KeyTypePKCS8:
		return string(decodedPubKey), nil
	default:
		return "", errors.New("unsupported key type")
	}
}

func (p *KeyAdapter) ExportCertificate(_ context.Context) (string, error) {
	return "", errors.New("not implemented")
}
