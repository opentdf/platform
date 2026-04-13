package ocrypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// HybridXWingKeyPair combines X25519 and ML-KEM-768
type HybridXWingKeyPair struct {
	X25519   *ecdh.PrivateKey
	MLKEM768 *mlkem.DecapsulationKey768
}

type hybridXWingPublicKeyASN1 struct {
	X25519   []byte
	MLKEM768 []byte
}

type hybridXWingPrivateKeyASN1 struct {
	X25519   []byte
	MLKEM768 []byte
}

type hybridXWingCiphertextASN1 struct {
	X25519   []byte
	MLKEM768 []byte
}

func NewHybridXWingKeyPair() (*HybridXWingKeyPair, error) {
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdh.X25519.GenerateKey failed: %w", err)
	}

	mlkem768, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("mlkem.GenerateKey768 failed: %w", err)
	}

	return &HybridXWingKeyPair{
		X25519:   x25519,
		MLKEM768: mlkem768,
	}, nil
}

func (kp *HybridXWingKeyPair) GetKeyType() KeyType {
	return HybridXWingKey
}

func (kp *HybridXWingKeyPair) PublicKeyInPemFormat() (string, error) {
	pk := hybridXWingPublicKeyASN1{
		X25519:   kp.X25519.PublicKey().Bytes(),
		MLKEM768: kp.MLKEM768.EncapsulationKey().Bytes(),
	}

	bytes, err := asn1.Marshal(pk)
	if err != nil {
		return "", fmt.Errorf("failed to marshal hybrid public key: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "HYBRID X-WING PUBLIC KEY",
		Bytes: bytes,
	})), nil
}

func (kp *HybridXWingKeyPair) PrivateKeyInPemFormat() (string, error) {
	sk := hybridXWingPrivateKeyASN1{
		X25519:   kp.X25519.Bytes(),
		MLKEM768: kp.MLKEM768.Bytes(),
	}

	bytes, err := asn1.Marshal(sk)
	if err != nil {
		return "", fmt.Errorf("failed to marshal hybrid private key: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "HYBRID X-WING PRIVATE KEY",
		Bytes: bytes,
	})), nil
}

// X-Wing KEM Shared Secret computation as per draft-connolly-cfrg-xwing-kem-10
// Shared Secret: SHA3-256("\X-Wing" || ss_X || ss_M || X25519_pk || ML-KEM-768_pk || X25519_ct || ML-KEM-768_ct)
func computeXWingSharedSecret(ssX, ssM, pkX, pkM, ctX, ctM []byte) []byte {
	h := sha3.New256()
	h.Write([]byte("\\X-Wing"))
	h.Write(ssX)
	h.Write(ssM)
	h.Write(pkX)
	h.Write(pkM)
	h.Write(ctX)
	h.Write(ctM)
	return h.Sum(nil)
}

type HybridXWingEncryptor struct {
	pkX []byte
	pkM *mlkem.EncapsulationKey768
}

func NewHybridXWingEncryptor(pk []byte) (*HybridXWingEncryptor, error) {
	var pkASN hybridXWingPublicKeyASN1
	if _, err := asn1.Unmarshal(pk, &pkASN); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hybrid public key: %w", err)
	}

	pkM, err := mlkem.NewEncapsulationKey768(pkASN.MLKEM768)
	if err != nil {
		return nil, fmt.Errorf("failed to create MLKEM encapsulation key: %w", err)
	}

	return &HybridXWingEncryptor{
		pkX: pkASN.X25519,
		pkM: pkM,
	}, nil
}

func (e *HybridXWingEncryptor) Encapsulate() ([]byte, []byte, error) {
	// X25519 encapsulation
	ekX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pkX, err := ecdh.X25519().NewPublicKey(e.pkX)
	if err != nil {
		return nil, nil, err
	}
	ssX, err := ekX.ECDH(pkX)
	if err != nil {
		return nil, nil, err
	}
	ctX := ekX.PublicKey().Bytes()

	// ML-KEM-768 encapsulation
	ssM, ctM := e.pkM.Encapsulate()

	// Compute combined shared secret
	sharedSecret := computeXWingSharedSecret(ssX, ssM, e.pkX, e.pkM.Bytes(), ctX, ctM)

	// Marshal ciphertext into ASN.1
	ctASN := hybridXWingCiphertextASN1{
		X25519:   ctX,
		MLKEM768: ctM,
	}
	ciphertext, err := asn1.Marshal(ctASN)
	if err != nil {
		return nil, nil, err
	}

	return sharedSecret, ciphertext, nil
}

type HybridXWingDecryptor struct {
	skX *ecdh.PrivateKey
	skM *mlkem.DecapsulationKey768
}

func NewHybridXWingDecryptor(sk []byte) (*HybridXWingDecryptor, error) {
	var skASN hybridXWingPrivateKeyASN1
	if _, err := asn1.Unmarshal(sk, &skASN); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hybrid private key: %w", err)
	}

	skX, err := ecdh.X25519().NewPrivateKey(skASN.X25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 private key: %w", err)
	}

	skM, err := mlkem.NewDecapsulationKey768(skASN.MLKEM768)
	if err != nil {
		return nil, fmt.Errorf("failed to create MLKEM decapsulation key: %w", err)
	}

	return &HybridXWingDecryptor{
		skX: skX,
		skM: skM,
	}, nil
}

func (d *HybridXWingDecryptor) Decapsulate(ciphertext []byte) ([]byte, error) {
	var ctASN hybridXWingCiphertextASN1
	if _, err := asn1.Unmarshal(ciphertext, &ctASN); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hybrid ciphertext: %w", err)
	}

	// X25519 decapsulation
	pkX, err := ecdh.X25519().NewPublicKey(ctASN.X25519)
	if err != nil {
		return nil, err
	}
	ssX, err := d.skX.ECDH(pkX)
	if err != nil {
		return nil, err
	}

	// ML-KEM-768 decapsulation
	ssM, err := d.skM.Decapsulate(ctASN.MLKEM768)
	if err != nil {
		return nil, err
	}

	// Compute combined shared secret
	sharedSecret := computeXWingSharedSecret(ssX, ssM, d.skX.PublicKey().Bytes(), d.skM.EncapsulationKey().Bytes(), ctASN.X25519, ctASN.MLKEM768)

	return sharedSecret, nil
}

// Convert from PEM format to internal encryptor/decryptor
func HybridEncryptorFromPEM(publicKeyInPem string) (*HybridXWingEncryptor, error) {
	block, _ := pem.Decode([]byte(publicKeyInPem))
	if block == nil || block.Type != "HYBRID X-WING PUBLIC KEY" {
		return nil, errors.New("failed to parse HYBRID X-WING PUBLIC KEY")
	}

	return NewHybridXWingEncryptor(block.Bytes)
}

func HybridDecryptorFromPEM(privateKeyInPem string) (*HybridXWingDecryptor, error) {
	block, _ := pem.Decode([]byte(privateKeyInPem))
	if block == nil || block.Type != "HYBRID X-WING PRIVATE KEY" {
		return nil, errors.New("failed to parse HYBRID X-WING PRIVATE KEY")
	}

	return NewHybridXWingDecryptor(block.Bytes)
}
