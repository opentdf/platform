package security

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	kNanoTDFMagicStringAndVersion = "L1L"
)

type StandardConfig struct {
	Keys []KeyPairInfo `mapstructure:"keys" json:"keys"`
	// Deprecated
	RSAKeys map[string]StandardKeyInfo `mapstructure:"rsa,omitempty" json:"rsa,omitempty"`
	// Deprecated
	ECKeys map[string]StandardKeyInfo `mapstructure:"ec,omitempty" json:"ec,omitempty"`
}

type KeyPairInfo struct {
	// Valid algorithm. May be able to be derived from Private but it is better to just say it.
	Algorithm string `mapstructure:"alg" json:"alg"`
	// Key identifier. Should be short
	KID string `mapstructure:"kid" json:"kid"`
	// Implementation specific locator for private key;
	// for 'standard' crypto service this is the path to a PEM file
	Private string `mapstructure:"private" json:"private"`
	// Optional locator for the corresponding certificate.
	// If not found, only public key (derivable from Private) is available.
	Certificate string `mapstructure:"cert" json:"cert"`
	// Optional enumeration of intended usages of keypair
	Usage string `mapstructure:"usage" json:"usage"`
	// Optional long form description of key pair including purpose and life cycle information
	Purpose string `mapstructure:"purpose" json:"purpose"`
}

type StandardKeyInfo struct {
	PrivateKeyPath string `mapstructure:"private_key_path" json:"private_key_path"`
	PublicKeyPath  string `mapstructure:"public_key_path" json:"public_key_path"`
}

type StandardRSACrypto struct {
	KeyPairInfo
	asymDecryption ocrypto.AsymDecryption
	asymEncryption ocrypto.AsymEncryption
}

type StandardECCrypto struct {
	KeyPairInfo
	ecPrivateKeyPem  string
	ecCertificatePEM string

	// Lazily filled in
	sk *ecdh.PrivateKey
}

// List of keys by identifier
type keylist map[string]any

type StandardCrypto struct {
	// Lists of keysByAlg first sorted by algorithm
	keysByAlg map[string]keylist

	// Lists all keys by identifier.
	keysByID keylist
}

// NewStandardCrypto Create a new instance of standard crypto
func NewStandardCrypto(cfg StandardConfig) (*StandardCrypto, error) {
	switch {
	case len(cfg.Keys) > 0 && len(cfg.RSAKeys)+len(cfg.ECKeys) > 0:
		return nil, errors.New("please specify `keys` only; remove deprecated `rsa` and `ec` fields from cfg")
	case len(cfg.Keys) > 0:
		return loadKeys(cfg.Keys)
	default:
		return loadDeprecatedKeys(cfg.RSAKeys, cfg.ECKeys)
	}
}

func loadKeys(ks []KeyPairInfo) (*StandardCrypto, error) {
	keysByAlg := make(map[string]keylist)
	keysByID := make(keylist)
	for _, k := range ks {
		slog.Info("crypto cfg loading", "id", k.KID, "alg", k.Algorithm)
		if _, ok := keysByID[k.KID]; ok {
			return nil, fmt.Errorf("duplicate key identifier [%s]", k.KID)
		}
		if _, ok := keysByAlg[k.Algorithm]; !ok {
			keysByAlg[k.Algorithm] = make(map[string]any)
		}
		loadedKey, err := loadKey(k)
		if err != nil {
			return nil, err
		}
		keysByAlg[k.Algorithm][k.KID] = loadedKey
		keysByID[k.KID] = loadedKey
	}
	return &StandardCrypto{
		keysByAlg: keysByAlg,
		keysByID:  keysByID,
	}, nil
}

func loadKey(k KeyPairInfo) (any, error) {
	privatePEM, err := os.ReadFile(k.Private)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file [%s]: %w", k.Private, err)
	}
	var certPEM []byte
	if k.Certificate != "" {
		certPEM, err = os.ReadFile(k.Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file [%s]: %w", k.Certificate, err)
		}
	}
	switch k.Algorithm {
	case AlgorithmECP256R1:
		return StandardECCrypto{
			KeyPairInfo:      k,
			ecPrivateKeyPem:  string(privatePEM),
			ecCertificatePEM: string(certPEM),
		}, nil
	case AlgorithmRSA2048:
		asymDecryption, err := ocrypto.NewAsymDecryption(string(privatePEM))
		if err != nil {
			return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
		}
		asymEncryption, err := ocrypto.NewAsymEncryption(string(certPEM))
		if err != nil {
			return nil, fmt.Errorf("ocrypto.NewAsymEncryption failed: %w", err)
		}
		return StandardRSACrypto{
			KeyPairInfo:    k,
			asymDecryption: asymDecryption,
			asymEncryption: asymEncryption,
		}, nil
	default:
		return nil, errors.New("unsupported algorithm [" + k.Algorithm + "]")
	}
}

func loadDeprecatedKeys(rsaKeys map[string]StandardKeyInfo, ecKeys map[string]StandardKeyInfo) (*StandardCrypto, error) {
	keysByAlg := make(map[string]keylist)
	keysByID := make(keylist)

	if len(ecKeys) > 0 {
		keysByAlg[AlgorithmECP256R1] = make(map[string]any)
	}
	if len(rsaKeys) > 0 {
		keysByAlg[AlgorithmRSA2048] = make(map[string]any)
	}

	for id, kasInfo := range rsaKeys {
		privatePemData, err := os.ReadFile(kasInfo.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to rsa private key file: %w", err)
		}

		asymDecryption, err := ocrypto.NewAsymDecryption(string(privatePemData))
		if err != nil {
			return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
		}

		publicPemData, err := os.ReadFile(kasInfo.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to rsa public key file: %w", err)
		}

		asymEncryption, err := ocrypto.NewAsymEncryption(string(publicPemData))
		if err != nil {
			return nil, fmt.Errorf("ocrypto.NewAsymEncryption failed: %w", err)
		}

		k := StandardRSACrypto{
			KeyPairInfo: KeyPairInfo{
				Algorithm:   AlgorithmRSA2048,
				KID:         id,
				Private:     kasInfo.PrivateKeyPath,
				Certificate: kasInfo.PublicKeyPath,
			},
			asymDecryption: asymDecryption,
			asymEncryption: asymEncryption,
		}
		keysByAlg[AlgorithmRSA2048][id] = k
		keysByID[id] = k
	}
	for id, kasInfo := range ecKeys {
		slog.Info("cfg.ECKeys", "id", id, "kasInfo", kasInfo)
		// private and public EC KAS key
		privatePemData, err := os.ReadFile(kasInfo.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to EC private key file: %w", err)
		}
		// certificate EC KAS key
		ecCertificatePEM, err := os.ReadFile(kasInfo.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to EC certificate file: %w", err)
		}
		k := StandardECCrypto{
			KeyPairInfo: KeyPairInfo{
				Algorithm:   AlgorithmRSA2048,
				KID:         id,
				Private:     kasInfo.PrivateKeyPath,
				Certificate: kasInfo.PublicKeyPath,
			},
			ecPrivateKeyPem:  string(privatePemData),
			ecCertificatePEM: string(ecCertificatePEM),
		}
		keysByAlg[AlgorithmECP256R1][id] = k
		keysByID[id] = k
	}

	return &StandardCrypto{
		keysByAlg: keysByAlg,
		keysByID:  keysByID,
	}, nil
}

func (s StandardCrypto) FindKID(alg string) string {
	if ks, ok := s.keysByAlg[alg]; ok && len(ks) > 0 {
		for kid := range ks {
			return kid
		}
	}
	return ""
}

func (s StandardCrypto) RSAPublicKey(kid string) (string, error) {
	k, ok := s.keysByID[kid]
	if !ok {
		return "", fmt.Errorf("no rsa key with id [%s]: %w", kid, ErrCertNotFound)
	}
	rsa, ok := k.(StandardRSACrypto)
	if !ok {
		return "", fmt.Errorf("key with id [%s] is not an RSA key: %w", kid, ErrCertNotFound)
	}

	pem, err := rsa.asymEncryption.PublicKeyInPemFormat()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve rsa public key file: %w", err)
	}

	return pem, nil
}

func (s StandardCrypto) ECCertificate(kid string) (string, error) {
	k, ok := s.keysByID[kid]
	if !ok {
		return "", fmt.Errorf("no ec key with id [%s]: %w", kid, ErrCertNotFound)
	}
	ec, ok := k.(StandardECCrypto)
	if !ok {
		return "", fmt.Errorf("key with id [%s] is not an EC key: %w", kid, ErrCertNotFound)
	}
	return ec.ecCertificatePEM, nil
}

// Exports the EC public key with kid as a pem encode pkix
func (s StandardCrypto) ECPublicKey(kid string) (string, error) {
	k, ok := s.keysByID[kid]
	if !ok {
		return "", ErrCertNotFound
	}
	ec, ok := k.(StandardECCrypto)
	if !ok {
		return "", ErrCertNotFound
	}

	ecPrivateKey, err := ocrypto.ECPrivateKeyFromPem([]byte(ec.ecPrivateKeyPem))
	if err != nil {
		return "", fmt.Errorf("ECPrivateKeyFromPem failed: %s %w", kid, err)
	}

	ecPublicKey := ecPrivateKey.PublicKey()
	derBytes, err := x509.MarshalPKIXPublicKey(ecPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %s %w", kid, err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if pemBytes == nil {
		return "", fmt.Errorf("failed to encode public key to PEM: %s", kid)
	}
	return string(pemBytes), nil
}

func (s StandardCrypto) RSADecrypt(_ crypto.Hash, kid string, _ string, ciphertext []byte) ([]byte, error) {
	k, ok := s.keysByID[kid]
	if !ok {
		return nil, ErrCertNotFound
	}
	rsa, ok := k.(StandardRSACrypto)
	if !ok {
		return nil, ErrCertNotFound
	}

	data, err := rsa.asymDecryption.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return data, nil
}

func (s StandardCrypto) RSAPublicKeyAsJSON(kid string) (string, error) {
	k, ok := s.keysByID[kid]
	if !ok {
		return "", ErrCertNotFound
	}
	if !ok {
		return "", ErrCertNotFound
	}
	rsa, ok := k.(StandardRSACrypto)
	if !ok {
		return "", ErrCertNotFound
	}

	rsaPublicKeyJwk, err := jwk.FromRaw(rsa.asymEncryption.PublicKey)
	if err != nil {
		return "", fmt.Errorf("jwk.FromRaw: %w", err)
	}

	jsonPublicKey, err := json.Marshal(rsaPublicKeyJwk)
	if err != nil {
		return "", fmt.Errorf("jwk.FromRaw: %w", err)
	}

	return string(jsonPublicKey), nil
}

func (s StandardCrypto) GenerateNanoTDFSymmetricKey(kasKID string, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) ([]byte, error) {
	ephemeralECDSAPublicKey, err := ocrypto.UncompressECPubKey(curve, ephemeralPublicKeyBytes)
	if err != nil {
		return nil, err
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

	k, ok := s.keysByID[kasKID]
	if !ok {
		return nil, ErrKeyPairInfoNotFound
	}
	ec, ok := k.(StandardECCrypto)
	if !ok {
		return nil, ErrKeyPairInfoMalformed
	}

	symmetricKey, err := ocrypto.ComputeECDHKey([]byte(ec.ecPrivateKeyPem), ephemeralECDSAPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ComputeECDHKey failed: %w", err)
	}

	key, err := ocrypto.CalculateHKDF(versionSalt(), symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}

	return key, nil
}

func (s StandardCrypto) GenerateEphemeralKasKeys() (any, []byte, error) {
	ephemeralKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		return nil, nil, fmt.Errorf("ocrypto.NewECKeyPair failed: %w", err)
	}

	pubKeyInPem, err := ephemeralKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key in PEM format: %w", err)
	}
	pubKeyBytes := []byte(pubKeyInPem)

	privKey, err := ocrypto.ConvertToECDHPrivateKey(ephemeralKeyPair.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert provate key to ECDH: %w", err)
	}
	return privKey, pubKeyBytes, nil
}

func (s StandardCrypto) GenerateNanoTDFSessionKey(privateKey any, ephemeralPublicKeyPEM []byte) ([]byte, error) {
	ecdhKey, err := ocrypto.ConvertToECDHPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("GenerateNanoTDFSessionKey failed to ConvertToECDHPrivateKey: %w", err)
	}
	ephemeralECDHPublicKey, err := ocrypto.ECPubKeyFromPem(ephemeralPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("GenerateNanoTDFSessionKey failed to ocrypto.ECPubKeyFromPem: %w", err)
	}
	// shared secret
	sessionKey, err := ecdhKey.ECDH(ephemeralECDHPublicKey)
	if err != nil {
		return nil, fmt.Errorf("GenerateNanoTDFSessionKey failed to ecdhKey.ECDH: %w", err)
	}

	salt := versionSalt()
	derivedKey, err := ocrypto.CalculateHKDF(salt, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}
	return derivedKey, nil
}

func (s StandardCrypto) Close() {
}

func TDFSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)
	return salt
}

func versionSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte(kNanoTDFMagicStringAndVersion))
	return digest.Sum(nil)
}

// ECDecrypt uses hybrid ECIES to decrypt the data.
func (s *StandardCrypto) ECDecrypt(keyID string, ephemeralPublicKey, ciphertext []byte) ([]byte, error) {
	unwrappedKey, err := s.Decrypt(context.Background(), KeyIdentifier(keyID), ciphertext, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}
	return unwrappedKey.Export(nil)
}

// Decrypt implements the SecurityProvider Decrypt method
func (s *StandardCrypto) Decrypt(ctx context.Context, keyID KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) (ProtectedKey, error) {
	kid := string(keyID)
	ska, ok := s.keysByID[kid]
	if !ok {
		return nil, fmt.Errorf("key [%s] not found", kid)
	}

	var rawKey []byte
	var err error

	switch key := ska.(type) {
	case StandardECCrypto:
		if len(ephemeralPublicKey) == 0 {
			return nil, fmt.Errorf("ephemeral public key is required for EC decryption")
		}

		if key.sk == nil {
			// Parse the private key
			loaded, err := ocrypto.ECPrivateKeyFromPem([]byte(key.ecPrivateKeyPem))
			if err != nil {
				return nil, fmt.Errorf("failed to parse EC private key: %w", err)
			}
			key.sk = loaded
		}

		ed, err := ocrypto.NewSaltedECDecryptor(key.sk, TDFSalt(), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create EC decryptor: %w", err)
		}

		rawKey, err = ed.DecryptWithEphemeralKey(ciphertext, ephemeralPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt with ephemeral key: %w", err)
		}

	case StandardRSACrypto:
		if len(ephemeralPublicKey) > 0 {
			return nil, fmt.Errorf("ephemeral public key should not be provided for RSA decryption")
		}

		rawKey, err = key.asymDecryption.Decrypt(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported key type for key ID [%s]", kid)
	}

	return &StandardUnwrappedKey{
		rawKey: rawKey,
		logger: slog.Default(),
	}, nil
}
