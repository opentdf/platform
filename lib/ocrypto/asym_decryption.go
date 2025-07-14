package ocrypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
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

	return FromPrivatePEMWithSalt(privateKeyInPem, salt, "")
}

func FromPrivatePEMWithSalt(privateKeyInPem string, salt []byte, info string) (PrivateKeyDecryptor, error) {
	block, _ := pem.Decode([]byte(privateKeyInPem))
	if block == nil {
		return AsymDecryption{}, errors.New("failed to parse PEM formatted private key")
	}

	if block.Type == "MLKEM DECAPSULATION KEY" {
		// TK Handle ML-KEM decapsulation key
		decap, err := mlkem.NewDecapsulationKey768(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("mlkem.NewDecapsulationKey768 failed: %w", err)
		}
		return NewMLKEMDecryptor768(decap)
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
	d, err := FromPrivatePEMWithSalt(privateKeyInPem, nil, "")
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
	info string
}

func NewECDecryptor(sk *ecdh.PrivateKey) (ECDecryptor, error) {
	// TK Move salt and info out of library, into API option functions
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)

	return ECDecryptor{sk, salt, ""}, nil
}

func NewSaltedECDecryptor(sk *ecdh.PrivateKey, salt []byte, info string) (ECDecryptor, error) {
	return ECDecryptor{sk, salt, info}, nil
}

type MLKEMDecryptor768 struct {
	decap *mlkem.DecapsulationKey768
}

func NewMLKEMDecryptor768(decap *mlkem.DecapsulationKey768) (*MLKEMDecryptor768, error) {
	if decap == nil {
		return nil, errors.New("decapsulation key is nil")
	}

	return &MLKEMDecryptor768{decap}, nil
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

	derivedKey, err := hkdf.Key(sha256.New, ikm, e.salt, e.info, 32) //nolint:mnd // AES-256 requires a 32-byte key
	if err != nil {
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

func (d *MLKEMDecryptor768) Decrypt(data []byte) ([]byte, error) {
	return nil, errors.New("decapsulation key requires ciphertext (ephemeral key) to decrypt")
}

func (d *MLKEMDecryptor768) DecryptWithEphemeralKey(data, cipherText []byte) ([]byte, error) {
	if d.decap == nil {
		return nil, errors.New("mlkem.DecryptWithEphemeralKey - decapsulation key is nil")
	}

	sharedSecret, err := d.decap.Decapsulate(cipherText)
	if err != nil {
		return nil, fmt.Errorf("mlkem.DecryptWithEphemeralKey - decap failed: %w", err)
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("mlkem.DecryptWithEphemeralKey - aes.NewCipher failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mlkem.DecryptWithEphemeralKey - cipher.NewGCM failure: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("mlkem.DecryptWithEphemeralKey - ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("mlkem.DecryptWithEphemeralKey - gcm.Open failure: %w", err)
	}

	return plaintext, nil
}
