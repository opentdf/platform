package ocrypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

type AsymDecryption struct {
	PrivateKey *rsa.PrivateKey
}

type PrivateKeyDecryptor interface {
	// Decrypt decrypts ciphertext with private key.
	Decrypt(data []byte) ([]byte, error)

	// PrivateKeyInPemFormat returns the private key in PEM format.
	PrivateKeyInPemFormat() (string, error)

	// Public returns the corresponding public-key encryptor.
	Public() (PublicKeyEncryptor, error)

	// KeyType returns the key type, e.g. RSA or EC.
	KeyType() KeyType
}

func NewPrivateKeyDecryptor(kt KeyType) (PrivateKeyDecryptor, error) {
	switch {
	case IsRSAKeyType(kt):
		bits, err := RSAKeyTypeToBits(kt)
		if err != nil {
			return nil, err
		}
		keyPair, err := NewRSAKeyPair(bits)
		if err != nil {
			return nil, err
		}
		return keyPair, nil
	case IsECKeyType(kt):
		mode, err := ECKeyTypeToMode(kt)
		if err != nil {
			return nil, err
		}
		return NewECPrivateKey(mode)
	default:
		return nil, fmt.Errorf("unsupported key type: %v", kt)
	}
}

// FromPrivatePEM creates and returns a new AsymDecryption.
func FromPrivatePEM(privateKeyInPem string) (PrivateKeyDecryptor, error) {
	// TK Move salt and info out of library, into API option functions
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)

	return FromPrivatePEMWithSalt(privateKeyInPem, salt, nil)
}

func FromPrivatePEMWithSalt(privateKeyInPem string, salt, info []byte) (PrivateKeyDecryptor, error) {
	block, _ := pem.Decode([]byte(privateKeyInPem))
	if block == nil {
		return AsymDecryption{}, errors.New("failed to parse PEM formatted private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	switch {
	case err == nil:
		break
	case strings.Contains(err.Error(), "use ParsePKCS1PrivateKey instead"):
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return AsymDecryption{}, fmt.Errorf("x509.ParsePKCS1PrivateKey failed: %w", err)
		}
	case strings.Contains(err.Error(), "use ParseECPrivateKey instead"):
		priv, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return AsymDecryption{}, fmt.Errorf("x509.ParseECPrivateKey failed: %w", err)
		}
	default:
		return AsymDecryption{}, fmt.Errorf("x509.ParsePKCS8PrivateKey failed: %w", err)
	}

	switch privateKey := priv.(type) {
	case *ecdsa.PrivateKey:
		sk, err := privateKey.ECDH()
		if err != nil {
			return nil, fmt.Errorf("unable to create ECDH key: %w", err)
		}
		return NewSaltedECDecryptor(sk, salt, info)
	case *ecdh.PrivateKey:
		return NewSaltedECDecryptor(privateKey, salt, info)
	case *rsa.PrivateKey:
		return AsymDecryption{privateKey}, nil
	default:
		break
	}

	return nil, errors.New("not a supported PEM formatted private key")
}

func NewAsymDecryption(privateKeyInPem string) (AsymDecryption, error) {
	d, err := FromPrivatePEMWithSalt(privateKeyInPem, nil, nil)
	if err != nil {
		return AsymDecryption{}, err
	}
	switch d := d.(type) {
	case AsymDecryption:
		return d, nil
	default:
		return AsymDecryption{}, errors.New("not an RSA private key")
	}
}

// Decrypt decrypts ciphertext with private key.
func (asymDecryption AsymDecryption) Decrypt(data []byte) ([]byte, error) {
	if asymDecryption.PrivateKey == nil {
		return nil, errors.New("failed to decrypt, private key is empty")
	}

	bytes, err := asymDecryption.PrivateKey.Decrypt(nil,
		data,
		&rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt failed: %w", err)
	}

	return bytes, nil
}

func (asymDecryption AsymDecryption) PrivateKeyInPemFormat() (string, error) {
	return privateKeyInPemFormat(asymDecryption.PrivateKey)
}

func (asymDecryption AsymDecryption) Public() (PublicKeyEncryptor, error) {
	if asymDecryption.PrivateKey == nil {
		return nil, errors.New("failed to generate public key encryptor, private key is empty")
	}

	return &AsymEncryption{PublicKey: &asymDecryption.PrivateKey.PublicKey}, nil
}

func (asymDecryption AsymDecryption) KeyType() KeyType {
	if asymDecryption.PrivateKey == nil {
		return KeyType("rsa:[unknown]")
	}

	switch asymDecryption.PrivateKey.Size() {
	case RSA2048Size / 8: //nolint:mnd // standard key size in bytes
		return RSA2048Key
	case RSA4096Size / 8: //nolint:mnd // large key size in bytes
		return RSA4096Key
	default:
		return KeyType(fmt.Sprintf("rsa:%d", asymDecryption.PrivateKey.Size()*8)) //nolint:mnd // convert to bits
	}
}

type ECDecryptor struct {
	sk   *ecdh.PrivateKey
	salt []byte
	info []byte
}

func NewECDecryptor(sk *ecdh.PrivateKey) (ECDecryptor, error) {
	// TK Move salt and info out of library, into API option functions
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)

	return ECDecryptor{sk, salt, nil}, nil
}

func NewECPrivateKey(mode ECCMode) (ECDecryptor, error) {
	curve, err := curveFromECCMode(mode)
	if err != nil {
		return ECDecryptor{}, err
	}

	sk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return ECDecryptor{}, fmt.Errorf("ecdh.GenerateKey failed: %w", err)
	}

	return NewECDecryptor(sk)
}

func NewSaltedECDecryptor(sk *ecdh.PrivateKey, salt, info []byte) (ECDecryptor, error) {
	return ECDecryptor{sk, salt, info}, nil
}

func (e ECDecryptor) Decrypt(_ []byte) ([]byte, error) {
	// TK How to get the ephmeral key into here?
	return nil, errors.New("ecdh standard decrypt unimplemented")
}

func (e ECDecryptor) PrivateKeyInPemFormat() (string, error) {
	return privateKeyInPemFormat(e.sk)
}

func (e ECDecryptor) Public() (PublicKeyEncryptor, error) {
	if e.sk == nil {
		return nil, errors.New("failed to generate public key encryptor, private key is empty")
	}

	return newECIES(e.sk.PublicKey(), e.salt, e.info)
}

func (e ECDecryptor) KeyType() KeyType {
	if e.sk == nil {
		return KeyType("ec:[unknown]")
	}

	return keyTypeFromECDHCurve(e.sk.Curve())
}

func (e ECDecryptor) deriveSharedKey(publicKeyInPem string) ([]byte, error) {
	if e.sk == nil {
		return nil, errors.New("failed to derive shared key, private key is empty")
	}

	pub, err := getPublicPart(publicKeyInPem)
	if err != nil {
		return nil, err
	}

	ecdhPublicKey, err := ConvertToECDHPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("unsupported public key type: %w", err)
	}

	sharedKey, err := e.sk.ECDH(ecdhPublicKey)
	if err != nil {
		return nil, fmt.Errorf("there was a problem deriving a shared ECDH key: %w", err)
	}

	return sharedKey, nil
}

func (e ECDecryptor) DecryptWithEphemeralKey(data, ephemeral []byte) ([]byte, error) {
	ek, err := e.parseEphemeralPublicKey(ephemeral)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	ikm, err := e.sk.ECDH(ek)
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
		return nil, fmt.Errorf("aes.NewCipher failure: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failure: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open failure: %w", err)
	}

	return plaintext, nil
}

// parseEphemeralPublicKey parses an ephemeral public key from DER (PKIX) or compressed EC point bytes.
func (e ECDecryptor) parseEphemeralPublicKey(ephemeral []byte) (*ecdh.PublicKey, error) {
	if pub, err := x509.ParsePKIXPublicKey(ephemeral); err == nil {
		switch pub := pub.(type) {
		case *ecdsa.PublicKey:
			return ConvertToECDHPublicKey(pub)
		case *ecdh.PublicKey:
			return pub, nil
		default:
			return nil, fmt.Errorf("unsupported public key of type: %T", pub)
		}
	}
	curve, err := convCurve(e.sk.Curve())
	if err != nil {
		return nil, err
	}
	ekDSA, err := UncompressECPubKey(curve, ephemeral)
	if err != nil {
		return nil, err
	}
	return ekDSA.ECDH()
}

func convCurve(c ecdh.Curve) (elliptic.Curve, error) {
	switch c {
	case ecdh.P256():
		return elliptic.P256(), nil
	case ecdh.P384():
		return elliptic.P384(), nil
	case ecdh.P521():
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDH curve: %v", c)
	}
}
