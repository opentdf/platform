package ocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // used for padding which is safe
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

type SchemeType string

const (
	RSA    SchemeType = "wrapped"
	EC     SchemeType = "ec-wrapped"
	MLKEM  SchemeType = "mlkem-wrapped"
	Hybrid SchemeType = "hybrid"
)

type PublicKeyEncryptor interface {
	// Encrypt encrypts data with public key.
	Encrypt(data []byte) ([]byte, error)

	// PublicKeyInPemFormat Returns public key in pem format, or the empty string if not present
	PublicKeyInPemFormat() (string, error)

	// Type required to use the scheme for encryption - notably, if it procduces extra metadata.
	Type() SchemeType

	// KeyType returns the key type, e.g. RSA or EC.
	KeyType() KeyType

	// For EC schemes, this method returns the public part of the ephemeral key.
	// Otherwise, it returns nil.
	EphemeralKey() []byte

	// Any extra metadata, e.g. the ephemeral public key for EC scheme keys.
	Metadata() (map[string]string, error)
}

type AsymEncryption struct {
	PublicKey *rsa.PublicKey
}

type ECEncryptor struct {
	pub  *ecdh.PublicKey
	ek   *ecdh.PrivateKey
	salt []byte
	info []byte
}

type MLKEMEncryptor768 struct {
	pub          *mlkem.EncapsulationKey768
	cipherText   []byte
	sharedSecret []byte
}

type MLKEMEncryptor1024 struct {
	pub          *mlkem.EncapsulationKey1024
	cipherText   []byte
	sharedSecret []byte
}

type XWingEncryptor struct {
	pk           []byte // 1216-byte X-Wing encapsulation key
	cipherText   []byte // 1120-byte X-Wing ciphertext (ct_M || ct_X)
	sharedSecret []byte // 32-byte combined shared secret
}

func FromPublicPEM(publicKeyInPem string) (PublicKeyEncryptor, error) {
	// TK Move salt and info out of library, into API option functions
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)

	return FromPublicPEMWithSalt(publicKeyInPem, salt, nil)
}

func FromPublicPEMWithSalt(publicKeyInPem string, salt, info []byte) (PublicKeyEncryptor, error) {
	pub, err := getPublicPart(publicKeyInPem)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return &AsymEncryption{pub}, nil
	case *ecdsa.PublicKey:
		e, err := pub.ECDH()
		if err != nil {
			return nil, err
		}
		return newECIES(e, salt, info)
	case *ecdh.PublicKey:
		return newECIES(pub, salt, info)
	case *mlkem.EncapsulationKey768:
		return newMLKEM768(pub), nil
	case *mlkem.EncapsulationKey1024:
		return newMLKEM1024(pub), nil
	case xwingPublicKey:
		return newXWingEncryptor([]byte(pub))
	default:
		break
	}

	return nil, errors.New("unsupported type of public key")
}

func newECIES(pub *ecdh.PublicKey, salt, info []byte) (ECEncryptor, error) {
	ek, err := pub.Curve().GenerateKey(rand.Reader)
	return ECEncryptor{pub, ek, salt, info}, err
}

func newMLKEM768(pub *mlkem.EncapsulationKey768) *MLKEMEncryptor768 {
	sharedSecret, cipherText := pub.Encapsulate()
	return &MLKEMEncryptor768{pub: pub, cipherText: cipherText, sharedSecret: sharedSecret}
}

func newMLKEM1024(pub *mlkem.EncapsulationKey1024) *MLKEMEncryptor1024 {
	sharedSecret, cipherText := pub.Encapsulate()
	return &MLKEMEncryptor1024{pub: pub, cipherText: cipherText, sharedSecret: sharedSecret}
}

// NewAsymEncryption creates and returns a new AsymEncryption.
//
// Deprecated: Use FromPublicPEM instead.
func NewAsymEncryption(publicKeyInPem string) (AsymEncryption, error) {
	pub, err := getPublicPart(publicKeyInPem)
	if err != nil {
		return AsymEncryption{}, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return AsymEncryption{pub}, nil
	default:
		break
	}

	return AsymEncryption{}, fmt.Errorf("unsupported public key type: %T", pub)
}

// xwingPublicKey is a wrapper type for the raw 1216-byte X-Wing public key
// used for type-switching in FromPublicPEMWithSalt.
type xwingPublicKey []byte

func getPublicPart(publicKeyInPem string) (any, error) {
	block, _ := pem.Decode([]byte(publicKeyInPem))
	if block == nil {
		return nil, errors.New("failed to parse PEM formatted public key")
	}

	var pub any
	switch {
	case strings.Contains(publicKeyInPem, "BEGIN CERTIFICATE"):
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
		}

		pub = cert.PublicKey
	case block.Type == "MLKEM ENCAPSULATOR":
		encap768, err := mlkem.NewEncapsulationKey768(block.Bytes)
		if err == nil {
			pub = encap768
			break
		}
		encap1024, err1024 := mlkem.NewEncapsulationKey1024(block.Bytes)
		if err1024 != nil {
			return nil, fmt.Errorf("mlkem.NewEncapsulationKey1024 failed after mlkem.NewEncapsulationKey768 failed: %w / %w", err, err1024)
		}
		pub = encap1024
	default:
		// Try X-Wing SubjectPublicKeyInfo first (has id-XWing OID)
		if pk, err := parseXWingPublicKeyFromDER(block.Bytes); err == nil {
			pub = xwingPublicKey(pk)
			break
		}
		var err error
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParsePKIXPublicKey failed: %w", err)
		}
	}
	return pub, nil
}

func (e AsymEncryption) Type() SchemeType {
	return RSA
}

func (e AsymEncryption) KeyType() KeyType {
	switch e.PublicKey.Size() {
	case RSA2048Size / 8: //nolint:mnd // standard key size in bytes
		return RSA2048Key
	case RSA4096Size / 8: //nolint:mnd // large key size in bytes
		return RSA4096Key
	default:
		bitlen := e.PublicKey.Size() * 8 //nolint:mnd // convert to bits
		return KeyType("rsa:" + strconv.Itoa(bitlen))
	}
}

func (e ECEncryptor) Type() SchemeType {
	return EC
}

func (e MLKEMEncryptor768) Type() SchemeType {
	return MLKEM
}

func (e MLKEMEncryptor1024) Type() SchemeType {
	return MLKEM
}

func (e ECEncryptor) KeyType() KeyType {
	switch e.pub.Curve() {
	case ecdh.P256():
		return EC256Key
	case ecdh.P384():
		return EC384Key
	case ecdh.P521():
		return EC521Key
	default:
		if n, ok := e.pub.Curve().(fmt.Stringer); ok {
			return KeyType("ec:" + n.String())
		}
		return KeyType("ec:[unknown]")
	}
}

func (e MLKEMEncryptor768) KeyType() KeyType {
	return MLKEM768Key
}

func (e MLKEMEncryptor1024) KeyType() KeyType {
	return MLKEM1024Key
}

func (e AsymEncryption) EphemeralKey() []byte {
	return nil
}

func (e ECEncryptor) EphemeralKey() []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(e.ek.PublicKey())
	if err != nil {
		return nil
	}
	return publicKeyBytes
}

func (e MLKEMEncryptor768) EphemeralKey() []byte {
	return e.cipherText
}

func (e MLKEMEncryptor1024) EphemeralKey() []byte {
	return e.cipherText
}

func (e AsymEncryption) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

func (e ECEncryptor) Metadata() (map[string]string, error) {
	m := make(map[string]string)
	m["ephemeralPublicKey"] = string(e.EphemeralKey())
	return m, nil
}

func (e MLKEMEncryptor768) Metadata() (map[string]string, error) {
	m := make(map[string]string)
	m["encapsulatedKey"] = string(e.EphemeralKey())
	return m, nil
}

func (e MLKEMEncryptor1024) Metadata() (map[string]string, error) {
	m := make(map[string]string)
	m["encapsulatedKey"] = string(e.EphemeralKey())
	return m, nil
}

func (e AsymEncryption) Encrypt(data []byte) ([]byte, error) {
	if e.PublicKey == nil {
		return nil, errors.New("failed to encrypt, public key is empty")
	}

	bytes, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, e.PublicKey, data, nil) //nolint:gosec // used for padding which is safe
	if err != nil {
		return nil, fmt.Errorf("rsa.EncryptOAEP failed: %w", err)
	}

	return bytes, nil
}

func publicKeyInPemFormat(pk any) (string, error) {
	if pk == nil {
		return "", errors.New("failed to generate PEM formatted public key")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("x509.MarshalPKIXPublicKey failed: %w", err)
	}

	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)

	return string(publicKeyPem), nil
}

func (e AsymEncryption) PublicKeyInPemFormat() (string, error) {
	return publicKeyInPemFormat(e.PublicKey)
}

// Encrypts the data with the EC public key.
func (e ECEncryptor) Encrypt(data []byte) ([]byte, error) {
	ikm, err := e.ek.ECDH(e.pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh failure: %w", err)
	}

	hkdfObj := hkdf.New(sha256.New, ikm, e.salt, e.info)

	derivedKey := make([]byte, 32) //nolint:mnd // AES-256 requires a 32-byte key
	if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failure: %w", err)
	}

	// Encrypt data with derived key using aes-gcm
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (e MLKEMEncryptor768) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (e MLKEMEncryptor1024) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// PublicKeyInPemFormat Returns public key in pem format.
func (e ECEncryptor) PublicKeyInPemFormat() (string, error) {
	return publicKeyInPemFormat(e.ek.Public())
}

func (e MLKEMEncryptor768) PublicKeyInPemFormat() (string, error) {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "MLKEM ENCAPSULATOR",
		Bytes: e.pub.Bytes(),
	})), nil
}

func (e MLKEMEncryptor1024) PublicKeyInPemFormat() (string, error) {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "MLKEM ENCAPSULATOR",
		Bytes: e.pub.Bytes(),
	})), nil
}

// --- XWingEncryptor ---

func newXWingEncryptor(pk []byte) (*XWingEncryptor, error) {
	ss, ct, err := xwingEncapsulate(pk)
	if err != nil {
		return nil, err
	}
	return &XWingEncryptor{
		pk:           pk,
		cipherText:   ct[:],
		sharedSecret: ss[:],
	}, nil
}

func (e XWingEncryptor) Type() SchemeType {
	return Hybrid
}

func (e XWingEncryptor) KeyType() KeyType {
	return HybridXWing
}

func (e XWingEncryptor) EphemeralKey() []byte {
	ct, err := marshalXWingCiphertext(e.cipherText)
	if err != nil {
		return nil
	}
	return ct
}

func (e XWingEncryptor) Metadata() (map[string]string, error) {
	m := make(map[string]string)
	m["encapsulatedKey"] = string(e.EphemeralKey())
	return m, nil
}

func (e XWingEncryptor) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (e XWingEncryptor) PublicKeyInPemFormat() (string, error) {
	der, err := marshalXWingPublicKey(e.pk)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})), nil
}
