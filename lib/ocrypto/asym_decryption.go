package ocrypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
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

	// Hybrid PQ/T private keys are PKCS#8-wrapped under one of our known OIDs.
	// Peek at the AlgorithmIdentifier and route hybrids to their constructors;
	// everything else (RSA, EC, EC PRIVATE KEY) falls through to x509.
	if block.Type == pemBlockPrivateKey {
		if dec, matched, err := hybridDecryptorFromPKCS8(block.Bytes, salt, info); matched {
			return dec, err
		}
	}
	// Reject CERTIFICATE blocks containing a hybrid SPKI: certificates are not
	// supported as a private-key transport, but operators sometimes paste them
	// here by mistake. Symmetric with the public-key path.
	if block.Type == pemBlockCertificate && containsHybridOID(block.Bytes) {
		return AsymDecryption{}, errors.New("certificate-wrapped hybrid keys are not supported; provide a bare PKCS#8 PRIVATE KEY")
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

func NewSaltedECDecryptor(sk *ecdh.PrivateKey, salt, info []byte) (ECDecryptor, error) {
	return ECDecryptor{sk, salt, info}, nil
}

func (e ECDecryptor) Decrypt(_ []byte) ([]byte, error) {
	// TK How to get the ephmeral key into here?
	return nil, errors.New("ecdh standard decrypt unimplemented")
}

func (e ECDecryptor) DecryptWithEphemeralKey(data, ephemeral []byte) ([]byte, error) {
	var ek *ecdh.PublicKey

	if pubFromDSN, err := x509.ParsePKIXPublicKey(ephemeral); err == nil {
		switch pubFromDSN := pubFromDSN.(type) {
		case *ecdsa.PublicKey:
			ek, err = ConvertToECDHPublicKey(pubFromDSN)
			if err != nil {
				return nil, fmt.Errorf("ecdh conversion failure: %w", err)
			}
		case *ecdh.PublicKey:
			ek = pubFromDSN
		default:
			return nil, fmt.Errorf("unsupported public key of type: %T", pubFromDSN)
		}
	} else {
		ekDSA, err := UncompressECPubKey(convCurve(e.sk.Curve()), ephemeral)
		if err != nil {
			return nil, err
		}
		ek, err = ekDSA.ECDH()
		if err != nil {
			return nil, fmt.Errorf("ecdh failure: %w", err)
		}
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

	if len(data) < GcmStandardNonceSize+aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	// Decrypt data with derived key using AES-GCM.
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failure: %w", err)
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCMWithRandomNonce failure: %w", err)
	}

	plaintext, err := gcm.Open(nil, nil, data, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open failure: %w", err)
	}

	return plaintext, nil
}

// hybridDecryptorFromPKCS8 mirrors hybridEncryptorFromSPKI for PKCS#8 private
// keys. The `matched` return reports whether the dispatcher owns the result:
// when true, the caller MUST return whatever this function returns. When
// false, the caller falls through to the legacy RSA/EC PKCS#8 / PKCS#1 path.
// Salt/info are honoured only for X-Wing.
func hybridDecryptorFromPKCS8(der, salt, info []byte) (PrivateKeyDecryptor, bool, error) {
	oid, raw, parseErr := parseHybridPKCS8(der)
	if parseErr != nil {
		// Structurally not a PKCS#8 envelope (e.g. PKCS#1 RSA or EC PRIVATE
		// KEY). Fall through to the legacy decoder.
		return nil, false, nil //nolint:nilerr // intentional fall-through on non-envelope input
	}
	switch {
	case oid.Equal(oidXWing):
		dec, err := NewSaltedXWingDecryptor(raw, salt, info)
		return dec, true, err
	case oid.Equal(oidCompositeMLKEM768P256):
		dec, err := NewP256MLKEM768Decryptor(raw)
		return dec, true, err
	case oid.Equal(oidCompositeMLKEM1024P384):
		dec, err := NewP384MLKEM1024Decryptor(raw)
		return dec, true, err
	}
	// Valid PKCS#8 envelope with a non-hybrid OID. If the stdlib recognises it,
	// fall through. Otherwise surface a precise "unknown OID" error so the
	// caller doesn't end up reporting a confusing PKCS#1/EC-Private-Key error.
	if _, x509Err := x509.ParsePKCS8PrivateKey(der); x509Err == nil {
		return nil, false, nil
	}
	return nil, true, fmt.Errorf("unsupported private-key algorithm OID %s: not a known hybrid scheme and not recognised by crypto/x509", oid)
}

func convCurve(c ecdh.Curve) elliptic.Curve {
	switch c {
	case ecdh.P256():
		return elliptic.P256()
	case ecdh.P384():
		return elliptic.P384()
	case ecdh.P521():
		return elliptic.P521()
	default:
		return nil
	}
}
