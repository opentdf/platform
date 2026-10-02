package ocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
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
	Hybrid SchemeType = "hybrid-wrapped"
	MLKEM  SchemeType = "mlkem-wrapped"
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

func FromPublicPEM(publicKeyInPem string) (PublicKeyEncryptor, error) {
	// TK Move salt and info out of library, into API option functions
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)

	return FromPublicPEMWithSalt(publicKeyInPem, salt, nil)
}

func FromPublicPEMWithSalt(publicKeyInPem string, salt, info []byte) (PublicKeyEncryptor, error) {
	block, _ := pem.Decode([]byte(publicKeyInPem))
	if block == nil {
		return nil, errors.New("failed to parse PEM formatted public key")
	}
	// Pure ML-KEM public keys are SPKI-wrapped under the NIST OIDs handled by
	// the unified kem path. Try these first so an ML-KEM key is never misrouted
	// into the hybrid OID dispatcher (which would treat an unknown OID as an
	// error rather than falling through).
	if block.Type == pemBlockPublicKey {
		switch oid, key, err := ParseKEMPublicSPKI(block.Bytes); {
		case err == nil:
			if k, ok := kemByOID(oid); ok {
				return newKEMEncryptor(k, key, salt, info)
			}
		case !errors.Is(err, errNotKEM):
			return nil, err
		}

		// Hybrid PQ/T public keys are SPKI-wrapped under our composite-KEM OIDs.
		// Peek at the AlgorithmIdentifier and route hybrids to their per-scheme
		// constructors; everything else (RSA, EC) falls through to the x509 path.
		if enc, matched, err := hybridEncryptorFromSPKI(block.Bytes, salt, info); matched {
			return enc, err
		}
	}
	// X.509 certificates carrying a hybrid SPKI are out of scope; reject them
	// with a clear message so operators don't see a confusing x509 parse error.
	if block.Type == pemBlockCertificate && containsHybridOID(block.Bytes) {
		return nil, errors.New("certificate-wrapped hybrid keys are not supported; provide a bare SPKI PUBLIC KEY")
	}

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
	default:
		break
	}

	return nil, errors.New("unsupported type of public key")
}

func newECIES(pub *ecdh.PublicKey, salt, info []byte) (ECEncryptor, error) {
	ek, err := pub.Curve().GenerateKey(rand.Reader)
	return ECEncryptor{pub, ek, salt, info}, err
}

func getPublicPart(publicKeyInPem string) (any, error) {
	block, _ := pem.Decode([]byte(publicKeyInPem))
	if block == nil {
		return nil, errors.New("failed to parse PEM formatted public key")
	}

	var pub any
	if strings.Contains(publicKeyInPem, "BEGIN CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
		}

		pub = cert.PublicKey
	} else {
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

func (e AsymEncryption) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

func (e ECEncryptor) Metadata() (map[string]string, error) {
	m := make(map[string]string)
	m["ephemeralPublicKey"] = string(e.EphemeralKey())
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
			Type:  pemBlockPublicKey,
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

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCMWithRandomNonce failed: %w", err)
	}

	ciphertext := gcm.Seal(nil, nil, data, nil)
	return ciphertext, nil
}

// PublicKeyInPemFormat Returns public key in pem format.
func (e ECEncryptor) PublicKeyInPemFormat() (string, error) {
	return publicKeyInPemFormat(e.ek.Public())
}

// hybridEncryptorFromSPKI tries to decode `der` as a hybrid PQ/T
// SubjectPublicKeyInfo. The `matched` return reports whether the dispatcher
// owns the result: when true, the caller MUST return whatever this function
// returns (encryptor or error) without trying the legacy x509 path. When
// false, the caller falls through to the standard RSA/EC handling.
// Salt/info are honoured only for X-Wing (the NIST composite-KEM hybrids
// derive their wrap key without them).
func hybridEncryptorFromSPKI(der, salt, info []byte) (PublicKeyEncryptor, bool, error) {
	oid, raw, parseErr := parseHybridSPKI(der)
	if parseErr != nil {
		// Structurally not an SPKI envelope. Fall through to the legacy path,
		// which handles PKCS#1 keys, certificates, and stdlib-recognised SPKI.
		return nil, false, nil //nolint:nilerr // intentional fall-through on non-envelope input
	}
	if k, ok := hybridKEMByOID(oid); ok {
		enc, err := newKEMEncryptor(k, raw, salt, info)
		return enc, true, err
	}
	// Valid SPKI envelope with a non-hybrid OID. If the stdlib recognises it,
	// fall through so the legacy RSA/EC path can handle it. Otherwise, surface
	// a precise error rather than letting x509 return its generic message —
	// that prevents an unknown OID from being silently retried as RSA/EC.
	if _, x509Err := x509.ParsePKIXPublicKey(der); x509Err == nil {
		return nil, false, nil
	}
	return nil, true, fmt.Errorf("unsupported public-key algorithm OID %s: not a known hybrid scheme and not recognised by crypto/x509", oid)
}
