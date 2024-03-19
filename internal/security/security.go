package security

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Using generic types here since it could be one of an HSM reference to a key, or an actual key.
type RSAPrivateKey interface{}
type RSAPublicKey interface{}
type ECPrivateKey interface{}
type ECPublicKey interface{}

type CryptoSession struct {
	RSA *StandardRSAKeyPair
	EC  *StandardECKeyPair
}

type StandardRSAKeyPair struct {
	PrivateKey  *rsa.PrivateKey
	PublicKey   *rsa.PublicKey
	Certificate *x509.Certificate
}

type StandardECKeyPair struct {
	PrivateKey  *ecdh.PrivateKey
	PublicKey   *ecdh.PublicKey
	Certificate *x509.Certificate
}

func New() (*CryptoSession, error) {
	rsaPrivateKey, err := loadRSAPrivateKey("private.pem")
	if err != nil {
		panic(err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	ecPrivateKey, err := loadECPrivateKey("ec-private.pem")
	if err != nil {
		panic(err)
	}
	ecPublicKey, err := loadECPublicKey("ec-public.pem")

	if err != nil {
		panic(err)
	}

	rsaKeyPair := &StandardRSAKeyPair{
		PrivateKey: rsaPrivateKey,
		PublicKey:  rsaPublicKey,
	}

	ecKeyPair := &StandardECKeyPair{
		PrivateKey: ecPrivateKey,
		PublicKey:  ecPublicKey,
	}

	return &CryptoSession{
		RSA: rsaKeyPair,
		EC:  ecKeyPair,
	}, nil
}

func loadRSAPrivateKey(fileName string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadECPrivateKey(filePath string) (*ecdh.PrivateKey, error) {
	pemData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, err
	}

	ecdaKey, err := x509.ParseECPrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	return ecdaKey.ECDH()
}

func loadECPublicKey(filePath string) (*ecdh.PublicKey, error) {
	pemData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, err
	}

	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := genericPublicKey.(*ecdh.PublicKey)
	if !ok {
		return nil, err
	}

	return publicKey, nil
}

func (s *CryptoSession) DecryptOAEP(privateKey RSAPrivateKey, cipherText []byte, hashFunction crypto.Hash, label []byte) ([]byte, error) {
	bytes, err := privateKey.(*rsa.PrivateKey).Decrypt(
		nil,
		cipherText,
		&rsa.OAEPOptions{Hash: hashFunction},
	)

	if err != nil {
		return nil, fmt.Errorf("Unable to unwrap symmetric key: %w", err)
	}

	return bytes, nil
}

func (s *CryptoSession) GenerateNanoTDFSymmetricKey(ephemeralPublicKey *ecdh.PublicKey, privateKey *ecdh.PrivateKey) ([]byte, error) {

	ecdhPrivateKey, err := convertToECDHPrivateKey(privateKey)

	if err != nil {
		return nil, fmt.Errorf("There was a problem converting the ECDSA private key, to the ECDH equivelant: %w", err)
	}

	ecdhPublicKey, err := convertToECDHPublicKey(ephemeralPublicKey)

	if err != nil {
		return nil, fmt.Errorf("There was a problem converting the ECDSA public key, to the ECDH equivelant: %w", err)
	}

	sharedKey, err := ecdhPrivateKey.ECDH(ecdhPublicKey)

	if err != nil {
		return nil, fmt.Errorf("There was a problem deriving a shared ECDH key: %w", err)
	}

	return sharedKey, nil
}

func (s *CryptoSession) GenerateNanoTDFSessionKey(privateKey *ecdh.PrivateKey, ephemeralPublicKey *ecdh.PublicKey) ([]byte, error) {

	ecdhPrivateKey, err := convertToECDHPrivateKey(privateKey)

	if err != nil {
		return nil, fmt.Errorf("There was a problem converting the ECDSA private key, to the ECDH equivelant: %w", err)
	}

	ecdhPublicKey, err := convertToECDHPublicKey(ephemeralPublicKey)

	if err != nil {
		return nil, fmt.Errorf("There was a problem converting the ECDSA public key, to the ECDH equivelant: %w", err)
	}

	sharedKey, err := ecdhPrivateKey.ECDH(ecdhPublicKey)

	if err != nil {
		return nil, fmt.Errorf("There was a problem deriving a shared ECDH key: %w", err)
	}

	return sharedKey, nil
}

func (s *CryptoSession) GenerateEphemeralKasKeys() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.P256()

	privateKey, err := curve.GenerateKey(rand.Reader)

	if err != nil {
		return nil, nil, fmt.Errorf("There was a problem genrating an ephemeral kas key pair: %w", err)
	}

	publicKey := privateKey.PublicKey()

	return privateKey, publicKey, nil
}

func convertToECDHPublicKey(key interface{}) (*ecdh.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		// Convert from ecdsa.PublicKey to ECDHPublicKey
		return k.ECDH()
	case *ecdh.PublicKey:
		// No conversion needed
		return k, nil
	default:
		return nil, fmt.Errorf("Unsupported public key type")
	}
}

func convertToECDHPrivateKey(key interface{}) (*ecdh.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		// Convert from ecdsa.PublicKey to ECDHPublicKey
		return k.ECDH()
	case *ecdh.PrivateKey:
		// No conversion needed
		return k, nil
	default:
		return nil, fmt.Errorf("Unsupported private key type")
	}
}
