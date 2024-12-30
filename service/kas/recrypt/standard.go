package recrypt

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk"
)

type keyHolder struct {
	Algorithm
	KeyIdentifier
	crypto.PrivateKey
	certPEM   []byte
	publicPEM []byte
}

// Implementation of the recrypt CryptoProvider interface using standard go crypto primitives.
type Standard struct {
	keys             map[KeyIdentifier]keyHolder
	currentKIDsByAlg map[Algorithm][]KeyIdentifier
	legacyKIDs       map[Algorithm][]KeyIdentifier
}

func NewStandard() *Standard {
	return &Standard{
		keys:             map[KeyIdentifier]keyHolder{},
		currentKIDsByAlg: map[Algorithm][]KeyIdentifier{},
		legacyKIDs:       map[Algorithm][]KeyIdentifier{},
	}
}

// StandardOption is a functional option type for configuring the Standard struct.
type StandardOption func(*Standard) error

// WithKey adds the given key by type and id.
func WithKey(id KeyIdentifier, alg Algorithm, privateKey crypto.PrivateKey, certPEM []byte, isCurrent, checkForLegacy bool) StandardOption {
	return func(s *Standard) error {
		s.keys[id] = keyHolder{
			Algorithm:     alg,
			KeyIdentifier: id,
			PrivateKey:    privateKey,
			certPEM:       certPEM,
		}
		if isCurrent {
			s.currentKIDsByAlg[alg] = append(s.currentKIDsByAlg[alg], id)
			return nil
		}
		if checkForLegacy {
			s.legacyKIDs[alg] = append(s.legacyKIDs[alg], id)
		}
		return nil
	}
}

func (s *Standard) ParseKeyIdentifier(k string) (KeyIdentifier, error) {
	return KeyIdentifier(k), nil
}

func (s *Standard) ParseAlgorithm(a string) (Algorithm, error) {
	switch a {
	case string(AlgorithmRSA2048):
		return AlgorithmRSA2048, nil
	case string(AlgorithmECP256R1):
		return AlgorithmECP256R1, nil
	case string(AlgorithmECP384R1):
		return AlgorithmECP384R1, nil
	case string(AlgorithmECP521R1):
		return AlgorithmECP521R1, nil
	case "":
		return AlgorithmUndefined, nil
	}
	return AlgorithmUndefined, fmt.Errorf("invalid algorithm [%s]", a)
}

func curveFor(a Algorithm) (elliptic.Curve, error) {
	switch a { //nolint:exhaustive // We only support EC algorithms
	case AlgorithmECP256R1:
		return elliptic.P256(), nil
	case AlgorithmECP384R1:
		return elliptic.P384(), nil
	case AlgorithmECP521R1:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve or algorithm [%s]", a)
	}
}

func (s *Standard) ParseKeyFormat(f string) (KeyFormat, error) {
	switch f {
	case string(KeyFormatJWK):
		return KeyFormatJWK, nil
	case string(KeyFormatPEM):
		return KeyFormatPEM, nil
	case "":
		return KeyFormatUndefined, nil
	}
	return KeyFormatUndefined, fmt.Errorf("invalid key format [%s]", f)
}

// NewStandardWithOptions creates a new Standard instance with the provided options.
func NewStandardWithOptions(opts ...StandardOption) (*Standard, error) {
	s := &Standard{
		keys:             map[KeyIdentifier]keyHolder{},
		currentKIDsByAlg: map[Algorithm][]KeyIdentifier{},
		legacyKIDs:       map[Algorithm][]KeyIdentifier{},
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Standard) CurrentKID(alg Algorithm) ([]KeyIdentifier, error) {
	kids, ok := s.currentKIDsByAlg[alg]
	if !ok {
		return nil, fmt.Errorf("no current KIDs for algorithm %s", alg)
	}
	return kids, nil
}

func (s *Standard) LegacyKIDs(a Algorithm) ([]KeyIdentifier, error) {
	kid, ok := s.legacyKIDs[a]
	if !ok {
		return nil, fmt.Errorf("no legacy KIDs for algorithm %s", a)
	}
	return kid, nil
}

func (s *Standard) PublicKey(a Algorithm, k []KeyIdentifier, f KeyFormat) (string, error) {
	if len(k) == 0 {
		k = s.currentKIDsByAlg[a]
	}
	if len(k) > 1 && f != KeyFormatJWK {
		return "", fmt.Errorf("only JWK format supports multiple keys at once")
	}

	switch f {
	case KeyFormatJWK:
		jwks := jwk.NewSet()
		for _, kid := range k {
			holder, ok := s.keys[kid]
			if !ok {
				return "", fmt.Errorf("key not found [%s]", kid)
			}
			var j jwk.Key
			var err error
			switch secret := holder.PrivateKey.(type) {
			case *ecdsa.PrivateKey:
				j, err = jwk.FromRaw(secret.Public())
			case *rsa.PrivateKey:
				j, err = jwk.FromRaw(secret.Public())
			default:
				return "", fmt.Errorf("invalid algorithm [%s] or format [%s]", a, f)
			}
			if err != nil {
				return "", fmt.Errorf("jwk.FromRaw failed for key [%s]: %w", kid, err)
			}
			if err := jwks.AddKey(j); err != nil {
				return "", fmt.Errorf("jwk.AddKey failed for key [%s]: %w", kid, err)
			}
		}
		asjson, err := json.Marshal(jwks)
		if err != nil {
			return "", fmt.Errorf("jwk.FromRaw: %w", err)
		}

		return string(asjson), nil
	case KeyFormatPEM:
		fallthrough
	case KeyFormatUndefined:
		holder, ok := s.keys[k[0]]
		if !ok {
			return "", fmt.Errorf("key not found [%s]", k[0])
		}
		if len(holder.publicPEM) > 0 {
			return string(holder.publicPEM), nil
		}
		switch secret := holder.PrivateKey.(type) {
		case *ecdh.PrivateKey:
			publicKeyBytes, err := x509.MarshalPKIXPublicKey(secret.PublicKey())
			if err != nil {
				return "", fmt.Errorf("x509.MarshalPKIXPublicKey failed: %w", err)
			}

			holder.publicPEM = pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: publicKeyBytes,
				},
			)
			return string(holder.publicPEM), nil

		case *ecdsa.PrivateKey:
			publicPEM, err := ocrypto.ECPublicKeyInPemFormat(secret.PublicKey)
			if err != nil {
				return "", fmt.Errorf("failed to get public key in PEM format: %w", err)
			}
			holder.publicPEM = []byte(publicPEM)
			return publicPEM, nil
		case *rsa.PrivateKey:
			publicKeyBytes, err := x509.MarshalPKIXPublicKey(&secret.PublicKey)
			if err != nil {
				return "", fmt.Errorf("x509.MarshalPKIXPublicKey failed: %w", err)
			}

			publicPEM := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: publicKeyBytes,
				},
			)
			holder.publicPEM = publicPEM
			return string(publicPEM), nil
		}
		return "", fmt.Errorf("invalid algorithm [%T] or format [%s]", holder.PrivateKey, f)
	}
	return "", fmt.Errorf("invalid format [%s]", f)
}

func (s *Standard) Unwrap(k KeyIdentifier, ciphertext []byte) (UnwrappedKey, error) {
	holder, ok := s.keys[k]
	if !ok || holder.PrivateKey == nil {
		return nil, fmt.Errorf("key not found [%s]", k)
	}
	secret, ok := holder.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA key [%s]", k)
	}

	data, err := secret.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return aesUnwrappedKey{
		h:     *s,
		value: data,
	}, nil
}

func (s *Standard) Derive(k KeyIdentifier, compressedDataPublicKey []byte) (UnwrappedKey, error) {
	privateKeyHolder, ok := s.keys[k]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}

	crv, err := curveFor(privateKeyHolder.Algorithm)
	if err != nil {
		return nil, err
	}

	// server private bits
	ecdhKey, err := ocrypto.ConvertToECDHPrivateKey(privateKeyHolder.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("derive: ConvertToECDHPrivateKey failed: %w", err)
	}

	// client public bits
	ephemeralECDSAPublicKey, err := ocrypto.UncompressECPubKey(crv, compressedDataPublicKey)
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

	ecdhPublicKey, err := ocrypto.ECPubKeyFromPem(ephemeralECDSAPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ECPubKeyFromPem failed: %w", err)
	}

	symmetricKey, err := ecdhKey.ECDH(ecdhPublicKey)
	if err != nil {
		return nil, fmt.Errorf("there was a problem deriving a shared ECDH key: %w", err)
	}

	derivedKey, err := ocrypto.CalculateHKDF(versionSalt(), symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}

	return aesUnwrappedKey{
		h:     *s,
		value: derivedKey,
	}, nil
}

func (s *Standard) Close() {
	// Nothing to do
}

func (s *Standard) GenerateKey(a Algorithm, id KeyIdentifier) (KeyIdentifier, error) {
	switch a {
	case AlgorithmRSA2048:
		return s.generateRSAKeyPair(id)
	case AlgorithmUndefined:
		return "", fmt.Errorf("not implemented")
	case AlgorithmECP256R1:
		return s.generateECKeyPair(id, a, ocrypto.ECCModeSecp256r1)
	case AlgorithmECP384R1:
		return s.generateECKeyPair(id, a, ocrypto.ECCModeSecp384r1)
	case AlgorithmECP521R1:
		return s.generateECKeyPair(id, a, ocrypto.ECCModeSecp521r1)
	default:
		return "", fmt.Errorf("unsupported algorithm [%s]", a)
	}
}

func certTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) //nolint:mnd // 128 bit uid is sufficiently unique
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

func (s *Standard) generateRSAKeyPair(id KeyIdentifier) (KeyIdentifier, error) {
	keyRSA, err := rsa.GenerateKey(rand.Reader, 2048) //nolint:mnd // 256 byte key
	if err != nil {
		return "", fmt.Errorf("unable to generate rsa key [%w]", err)
	}

	certTemplate, err := certTemplate()
	if err != nil {
		return "", fmt.Errorf("unable to create cert template [%w]", err)
	}

	// self signed cert
	pubBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, keyRSA.Public(), keyRSA)
	if err != nil {
		return "", fmt.Errorf("unable to create cert [%w]", err)
	}
	_, err = x509.ParseCertificate(pubBytes)
	if err != nil {
		return "", fmt.Errorf("unable to parse cert [%w]", err)
	}
	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: pubBytes,
		},
	)

	s.keys[id] = keyHolder{
		Algorithm:     AlgorithmRSA2048,
		KeyIdentifier: id,
		PrivateKey:    keyRSA,
		publicPEM:     pubPEM,
	}
	return id, nil
}

func (s *Standard) generateECKeyPair(id KeyIdentifier, a Algorithm, m ocrypto.ECCMode) (KeyIdentifier, error) {
	ephemeralKeyPair, err := ocrypto.NewECKeyPair(m)
	if err != nil {
		return "", fmt.Errorf("ocrypto.NewECKeyPair failed: %w", err)
	}

	pubKeyInPem, err := ephemeralKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return "", fmt.Errorf("failed to get public key in PEM format: %w", err)
	}
	pubKeyBytes := []byte(pubKeyInPem)

	privKey, err := ocrypto.ConvertToECDHPrivateKey(ephemeralKeyPair.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to convert private key to ECDH: %w", err)
	}
	s.keys[id] = keyHolder{
		Algorithm:     a,
		KeyIdentifier: id,
		PrivateKey:    privKey,
		publicPEM:     pubKeyBytes,
	}
	return id, nil
}

func (s *Standard) DestroyKey(id KeyIdentifier) error {
	// removes id key from s.keys, and other fields
	holder, ok := s.keys[id]
	if !ok {
		// already deleted
		return nil
	}
	delete(s.keys, id)
	// remove from currentKIDsByAlg
	alg := holder.Algorithm
	for i, kid := range s.currentKIDsByAlg[alg] {
		if kid == id {
			s.currentKIDsByAlg[alg] = append(s.currentKIDsByAlg[alg][:i], s.currentKIDsByAlg[alg][i+1:]...)
			break
		}
	}
	for i, kid := range s.legacyKIDs[alg] {
		if kid == id {
			s.legacyKIDs[alg] = append(s.legacyKIDs[alg][:i], s.legacyKIDs[alg][i+1:]...)
			break
		}
	}
	return nil
}

func (s Standard) List() ([]KeyDetails, error) {
	currentKeyIDs := make(map[KeyIdentifier]bool)
	for _, kids := range s.currentKIDsByAlg {
		for _, kid := range kids {
			currentKeyIDs[kid] = true
		}
	}

	var keys []KeyDetails
	for _, holder := range s.keys {
		keys = append(keys, KeyDetails{
			ID:        holder.KeyIdentifier,
			Algorithm: holder.Algorithm,
			Public:    string(holder.publicPEM),
			Current:   currentKeyIDs[holder.KeyIdentifier],
		})
	}
	return keys, nil
}

func RandomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		return nil, fmt.Errorf("rand.Read failed: %w", err)
	}

	return data, nil
}

func CalculateSHA256Hmac(secret, data []byte) []byte {
	// Create a new HMAC by defining the hash type and the secret
	hash := hmac.New(sha256.New, secret)

	// compute the HMAC
	hash.Write(data)
	dataHmac := hash.Sum(nil)

	return dataHmac
}

func (s Standard) CreateKeyAccessObject(url string, kid KeyIdentifier, pk string, po sdk.PolicyObject) ([]byte, *sdk.KeyAccess, error) {
	dek, err := RandomBytes(32) //nolint:mnd // 256 bits, standard for AES keys
	if err != nil {
		slog.Error("ocrypto.RandomBytes failed", "err", err)
		return nil, nil, fmt.Errorf("ocrypto.RandomBytes failed:%w", err)
	}

	pos, err := json.Marshal(po)
	if err != nil {
		slog.Error("json.Marshal failed", "err", err)
		return nil, nil, fmt.Errorf("json.Marshal failed:%w", err)
	}
	pob := make([]byte, base64.StdEncoding.EncodedLen(len(pos)))
	base64.StdEncoding.Encode(pob, pos)

	policyBinding := sdk.PolicyBinding{
		Alg: "HS256",
		// FIXME this is encoded AGAIN into base64 in current code. Choose one or the other, or both?
		Hash: hex.EncodeToString(CalculateSHA256Hmac(dek, pob)),
	}

	a, err := ocrypto.NewAsymEncryption(pk)
	if err != nil {
		slog.Error("ocrypto.NewAsymEncryption failed", "err", err)
		return nil, nil, fmt.Errorf("ocrypto.NewAsymEncryption failed:%w", err)
	}
	wk, err := a.Encrypt(dek)
	if err != nil {
		slog.Error("ocrypto.AsymEncryption.encrypt failed", "err", err)
		return nil, nil, fmt.Errorf("ocrypto.AsymEncryption.encrypt failed:%w", err)
	}
	return dek, &sdk.KeyAccess{
		KeyType:       "wrapped",
		KasURL:        url,
		KID:           string(kid),
		Protocol:      "kas",
		PolicyBinding: policyBinding,
		WrappedKey:    string(ocrypto.Base64Encode(wk)),
	}, nil
}

func versionSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("L1L"))
	return digest.Sum(nil)
}

func NewECKeyPair() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ec.GenerateKey failed: %w", err)
	}
	return privateKey, nil
}

type aesUnwrappedKey struct {
	h     Standard
	value []byte
}

func NewAESUnwrappedKey(value []byte) UnwrappedKey {
	return aesUnwrappedKey{value: value}
}

func (k aesUnwrappedKey) Digest(msg []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k.value)
	_, err := mac.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("user input invalid policy hmac")
	}
	return mac.Sum(nil), nil
}

func (k aesUnwrappedKey) Wrap(within ocrypto.AsymEncryption) ([]byte, error) {
	return within.Encrypt(k.value)
}

func (k aesUnwrappedKey) generateEphemeralKasKeys() (any, []byte, error) {
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

func (k aesUnwrappedKey) generateNanoTDFSessionKey(privateKey any, ephemeralPublicKeyPEM []byte) ([]byte, error) {
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

func wrapKeyAES(sessionKey, dek []byte) ([]byte, error) {
	gcm, err := ocrypto.NewAESGcm(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewAESGcm:%w", err)
	}

	cipherText, err := gcm.Encrypt(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto.AsymEncryption.encrypt:%w", err)
	}

	return cipherText, nil
}

func (k aesUnwrappedKey) NanoWrap(within []byte) (*NanoWrapResponse, error) {
	privateKeyHandle, publicKeyHandle, err := k.generateEphemeralKasKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	sessionKey, err := k.generateNanoTDFSessionKey(privateKeyHandle, within)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session key: %w", err)
	}

	cipherText, err := wrapKeyAES(sessionKey, k.value)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	return &NanoWrapResponse{
		EntityWrappedKey: cipherText,
		SessionPublicKey: string(publicKeyHandle),
	}, nil
}

func (k aesUnwrappedKey) DecryptNanoPolicy(cipherText []byte, tagSize int) ([]byte, error) {
	gcm, err := ocrypto.NewAESGcm(k.value)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewAESGcm:%w", err)
	}

	const (
		kIvLen = 12
	)
	iv := make([]byte, kIvLen)
	policyData, err := gcm.DecryptWithIVAndTagSize(iv, cipherText, tagSize)
	return policyData, err
}
