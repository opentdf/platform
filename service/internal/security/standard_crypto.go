package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	kNanoTDFMagicStringAndVersion = "L1L"
)

type StandardConfig struct {
	// A jwk set of private keys
	Set string `mapstructure:"set"`

	// Deprecated
	Keys []KeyPairInfo `mapstructure:"keys"`
	// Deprecated
	RSAKeys map[string]StandardKeyInfo `yaml:"rsa,omitempty" mapstructure:"rsa"`
	// Deprecated
	ECKeys map[string]StandardKeyInfo `yaml:"ec,omitempty" mapstructure:"ec"`
}

type KeyPairInfo struct {
	// Valid algorithm. May be able to be derived from Private but it is better to just say it.
	Algorithm string `mapstructure:"alg"`
	// Key identifier. Should be short
	KID string `mapstructure:"kid"`
	// Implementation specific locator for private key;
	// for 'standard' crypto service this is the path to a PEM file
	Private string `mapstructure:"private"`
	// Optional locator for the corresponding certificate.
	// If not found, only public key (derivable from Private) is available.
	Certificate string `mapstructure:"cert"`
	// Optional enumeration of intended usages of keypair
	Usage string `mapstructure:"usage"`
	// Optional long form description of key pair including purpose and life cycle information
	Purpose string `mapstructure:"purpose"`
}

type StandardKeyInfo struct {
	PrivateKeyPath string `yaml:"private_key_path" mapstructure:"private_key_path"`
	PublicKeyPath  string `yaml:"public_key_path" mapstructure:"public_key_path"`
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
}

// List of keys by identifier
type keylist map[string]any

type StandardCrypto struct {
	// Lists of keys first sorted by algorithm
	keys map[string]keylist
}

// NewStandardCrypto Create a new instance of standard crypto
func NewStandardCrypto(cfg StandardConfig) (*StandardCrypto, error) {
	switch {
	case cfg.Set != "":
		return loadKeySet(cfg.Set)
	case len(cfg.Keys) > 0 && len(cfg.RSAKeys)+len(cfg.ECKeys) > 0:
		return nil, errors.New("please specify `keys` only; remove deprecated `rsa` and `ec` fields from cfg")
	case len(cfg.Keys) > 0:
		return loadKeys(cfg.Keys)
	default:
		return loadDeprecatedKeys(cfg.RSAKeys, cfg.ECKeys)
	}
}

func unmarshalKeySet(f string) (jwk.Set, error) {
	jwksBytes, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read jwk set [%s]: %w", f, err)
	}
	jwks := jwk.NewSet()
	if err := json.Unmarshal(jwksBytes, jwks); err != nil {
		return nil, fmt.Errorf("failed to parse jwk set [%s]: %w", f, err)
	}
	return jwks, nil
}

func certTemplate() (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) //nolint:mnd // random 16 byte serial number
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number [%w]", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "kas"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30 * 365), //nolint:mnd // About a year to expire
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

func loadKeySet(privPath string) (*StandardCrypto, error) {
	keys := make(map[string]keylist)
	privSet, err := unmarshalKeySet(privPath)
	if err != nil {
		return nil, err
	}
	for i := 0; i < privSet.Len(); i++ {
		k, ok := privSet.Key(i)
		if !ok {
			return nil, fmt.Errorf("invalid jwk set [%s]", privPath)
		}
		var alg string
		var keyInfo any
		switch k.KeyType() {
		case "EC":
			var ecK ecdsa.PrivateKey
			err := k.Raw(&ecK)
			if err != nil {
				return nil, fmt.Errorf("invalid ec jwk item kid=[%s] found in [%s]: [%w]", k.KeyID(), privPath, err)
			}
			privateBytes, err := x509.MarshalPKCS8PrivateKey(&ecK)
			if err != nil {
				return nil, fmt.Errorf("unable to marshal ec private key kid=[%s] found in [%s]: [%w]", k.KeyID(), privPath, err)
			}
			privatePEM := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: privateBytes,
				},
			)

			certTemplate, err := certTemplate()
			if err != nil {
				return nil, fmt.Errorf("unable to create cert template [%w]", err)
			}
			pubBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &ecK.PublicKey, &ecK)
			if err != nil {
				return nil, fmt.Errorf("unable to create cert [%w]", err)
			}
			_, err = x509.ParseCertificate(pubBytes)
			if err != nil {
				return nil, fmt.Errorf("unable to parse cert [%w]", err)
			}
			// Encode public key to PKCS#1 ASN.1 PEM.
			pubPEM := pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: pubBytes,
				},
			)

			keyInfo = StandardECCrypto{
				KeyPairInfo: KeyPairInfo{
					KID: k.KeyID(),
				},
				ecPrivateKeyPem:  string(privatePEM),
				ecCertificatePEM: string(pubPEM),
			}
			if v, ok := k.Get("crv"); !ok || v.(jwa.EllipticCurveAlgorithm) != "P-256" {
				return nil, fmt.Errorf("unsupported curve for kid=[%s], crv=[%s]", k.KeyID(), v)
			}
			alg = "ec:secp256r1"
		case "RSA":
			var rsaK rsa.PrivateKey
			err := k.Raw(&rsaK)
			if err != nil {
				return nil, fmt.Errorf("invalid rsa jwk item kid=[%s] found in [%s]: [%w]", k.KeyID(), privPath, err)
			}
			keyInfo = StandardRSACrypto{
				KeyPairInfo: KeyPairInfo{
					KID: k.KeyID(),
				},
				asymDecryption: ocrypto.AsymDecryption{PrivateKey: &rsaK},
				asymEncryption: ocrypto.AsymEncryption{PublicKey: &rsaK.PublicKey},
			}
			alg = fmt.Sprintf("rsa:%d", rsaK.N.BitLen())
		default:
			return nil, fmt.Errorf("invalid key: type [%s], kid [%s]", k.KeyType(), k.KeyID())
		}
		if _, ok := keys[alg]; !ok {
			keys[alg] = make(map[string]any)
		}
		slog.Debug("cryptoprovider: registered", "alg", alg, "kid", k.KeyID())
		keys[alg][k.KeyID()] = keyInfo
	}
	return &StandardCrypto{
		keys: keys,
	}, nil
}

func loadKeys(ks []KeyPairInfo) (*StandardCrypto, error) {
	keys := make(map[string]keylist)
	for _, k := range ks {
		slog.Info("crypto cfg loading", "id", k.KID, "alg", k.Algorithm)
		if _, ok := keys[k.Algorithm]; !ok {
			keys[k.Algorithm] = make(map[string]any)
		}
		loadedKey, err := loadKey(k)
		if err != nil {
			return nil, err
		}
		keys[k.Algorithm][k.KID] = loadedKey
	}
	return &StandardCrypto{
		keys: keys,
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
	keys := make(map[string]keylist)

	if len(ecKeys) > 0 {
		keys[AlgorithmECP256R1] = make(map[string]any)
	}
	if len(rsaKeys) > 0 {
		keys[AlgorithmRSA2048] = make(map[string]any)
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

		keys[AlgorithmRSA2048][id] = StandardRSACrypto{
			KeyPairInfo: KeyPairInfo{
				Algorithm:   AlgorithmRSA2048,
				KID:         id,
				Private:     kasInfo.PrivateKeyPath,
				Certificate: kasInfo.PublicKeyPath,
			},
			asymDecryption: asymDecryption,
			asymEncryption: asymEncryption,
		}
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
		keys[AlgorithmECP256R1][id] = StandardECCrypto{
			KeyPairInfo: KeyPairInfo{
				Algorithm:   AlgorithmECP256R1,
				KID:         id,
				Private:     kasInfo.PrivateKeyPath,
				Certificate: kasInfo.PublicKeyPath,
			},
			ecPrivateKeyPem:  string(privatePemData),
			ecCertificatePEM: string(ecCertificatePEM),
		}
	}

	return &StandardCrypto{
		keys: keys,
	}, nil
}

func (s StandardCrypto) FindKID(alg string) string {
	if ks, ok := s.keys[alg]; ok && len(ks) > 0 {
		for kid := range ks {
			return kid
		}
	}
	return ""
}

func (s StandardCrypto) RSAPublicKey(kid string) (string, error) {
	rsaKeys, ok := s.keys[AlgorithmRSA2048]
	if !ok || len(rsaKeys) == 0 {
		return "", ErrCertNotFound
	}
	k, ok := rsaKeys[kid]
	if !ok {
		return "", ErrCertNotFound
	}
	rsa, ok := k.(StandardRSACrypto)
	if !ok {
		return "", ErrCertNotFound
	}

	pem, err := rsa.asymEncryption.PublicKeyInPemFormat()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve rsa public key file: %w", err)
	}

	return pem, nil
}

func (s StandardCrypto) ECCertificate(kid string) (string, error) {
	ecKeys, ok := s.keys[AlgorithmECP256R1]
	if !ok || len(ecKeys) == 0 {
		return "", ErrCertNotFound
	}
	k, ok := ecKeys[kid]
	if !ok {
		return "", ErrCertNotFound
	}
	ec, ok := k.(StandardECCrypto)
	if !ok {
		return "", ErrCertNotFound
	}
	return ec.ecCertificatePEM, nil
}

func (s StandardCrypto) ECPublicKey(kid string) (string, error) {
	ecKeys, ok := s.keys[AlgorithmECP256R1]
	if !ok || len(ecKeys) == 0 {
		return "", ErrCertNotFound
	}
	k, ok := ecKeys[kid]
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
	rsaKeys, ok := s.keys[AlgorithmRSA2048]
	if !ok || len(rsaKeys) == 0 {
		return nil, ErrCertNotFound
	}
	k, ok := rsaKeys[kid]
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
	rsaKeys, ok := s.keys[AlgorithmRSA2048]
	if !ok || len(rsaKeys) == 0 {
		return "", ErrCertNotFound
	}
	k, ok := rsaKeys[kid]
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

	ecKeys, ok := s.keys[AlgorithmECP256R1]
	if !ok || len(ecKeys) == 0 {
		return nil, ErrCertNotFound
	}
	k, ok := ecKeys[kasKID]
	if !ok {
		return nil, ErrCertNotFound
	}
	ec, ok := k.(StandardECCrypto)
	if !ok {
		return nil, ErrCertNotFound
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

func versionSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte(kNanoTDFMagicStringAndVersion))
	return digest.Sum(nil)
}
