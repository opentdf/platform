package ocrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/hkdf"
)

// Sizes for P-256 + ML-KEM-768 hybrid.
const (
	P256MLKEM768ECPublicKeySize  = 65   // uncompressed P-256 point
	P256MLKEM768ECPrivateKeySize = 32   // P-256 scalar
	P256MLKEM768MLKEMPubKeySize  = 1184 // mlkem768.PublicKeySize
	P256MLKEM768MLKEMPrivKeySize = 2400 // mlkem768.PrivateKeySize
	P256MLKEM768MLKEMCtSize      = 1088 // mlkem768.CiphertextSize

	P256MLKEM768PublicKeySize  = P256MLKEM768ECPublicKeySize + P256MLKEM768MLKEMPubKeySize   // 1249
	P256MLKEM768PrivateKeySize = P256MLKEM768ECPrivateKeySize + P256MLKEM768MLKEMPrivKeySize // 2432
	P256MLKEM768CiphertextSize = P256MLKEM768ECPublicKeySize + P256MLKEM768MLKEMCtSize       // 1153

	PEMBlockP256MLKEM768PublicKey  = "SECP256R1 MLKEM768 PUBLIC KEY"
	PEMBlockP256MLKEM768PrivateKey = "SECP256R1 MLKEM768 PRIVATE KEY"
)

// Sizes for P-384 + ML-KEM-1024 hybrid.
const (
	P384MLKEM1024ECPublicKeySize  = 97   // uncompressed P-384 point
	P384MLKEM1024ECPrivateKeySize = 48   // P-384 scalar
	P384MLKEM1024MLKEMPubKeySize  = 1568 // mlkem1024.PublicKeySize
	P384MLKEM1024MLKEMPrivKeySize = 3168 // mlkem1024.PrivateKeySize
	P384MLKEM1024MLKEMCtSize      = 1568 // mlkem1024.CiphertextSize

	P384MLKEM1024PublicKeySize  = P384MLKEM1024ECPublicKeySize + P384MLKEM1024MLKEMPubKeySize   // 1665
	P384MLKEM1024PrivateKeySize = P384MLKEM1024ECPrivateKeySize + P384MLKEM1024MLKEMPrivKeySize // 3216
	P384MLKEM1024CiphertextSize = P384MLKEM1024ECPublicKeySize + P384MLKEM1024MLKEMCtSize       // 1665

	PEMBlockP384MLKEM1024PublicKey  = "SECP384R1 MLKEM1024 PUBLIC KEY"
	PEMBlockP384MLKEM1024PrivateKey = "SECP384R1 MLKEM1024 PRIVATE KEY"
)

// AES-256 key size used for wrap key derivation.
const hybridNISTWrapKeySize = 32

// HybridNISTWrappedKey is the ASN.1 envelope stored in wrapped_key.
type HybridNISTWrappedKey struct {
	HybridCiphertext []byte `asn1:"tag:0"`
	EncryptedDEK     []byte `asn1:"tag:1"`
}

// hybridNISTParams captures the curve-specific parameters for a NIST hybrid scheme.
type hybridNISTParams struct {
	curve            ecdh.Curve
	ecPubSize        int
	ecPrivSize       int
	mlkemPubSize     int
	mlkemPrivSize    int
	mlkemCtSize      int
	pubPEMBlock      string
	privPEMBlock     string
	keyType          KeyType
	mlkemEncapsulate func(pubKey []byte) (sharedSecret, ciphertext []byte, err error)
	mlkemDecapsulate func(privKey, ciphertext []byte) (sharedSecret []byte, err error)
}

var p256mlkem768Params = hybridNISTParams{
	curve:         ecdh.P256(),
	ecPubSize:     P256MLKEM768ECPublicKeySize,
	ecPrivSize:    P256MLKEM768ECPrivateKeySize,
	mlkemPubSize:  P256MLKEM768MLKEMPubKeySize,
	mlkemPrivSize: P256MLKEM768MLKEMPrivKeySize,
	mlkemCtSize:   P256MLKEM768MLKEMCtSize,
	pubPEMBlock:   PEMBlockP256MLKEM768PublicKey,
	privPEMBlock:  PEMBlockP256MLKEM768PrivateKey,
	keyType:       HybridSecp256r1MLKEM768Key,
	mlkemEncapsulate: func(pubKey []byte) ([]byte, []byte, error) {
		var pk mlkem768.PublicKey
		if err := pk.Unpack(pubKey); err != nil {
			return nil, nil, fmt.Errorf("mlkem768 public key unpack: %w", err)
		}
		ct := make([]byte, mlkem768.CiphertextSize)
		ss := make([]byte, mlkem768.SharedKeySize)
		pk.EncapsulateTo(ct, ss, nil)
		return ss, ct, nil
	},
	mlkemDecapsulate: func(privKey, ciphertext []byte) ([]byte, error) {
		var sk mlkem768.PrivateKey
		if err := sk.Unpack(privKey); err != nil {
			return nil, fmt.Errorf("mlkem768 private key unpack: %w", err)
		}
		ss := make([]byte, mlkem768.SharedKeySize)
		sk.DecapsulateTo(ss, ciphertext)
		return ss, nil
	},
}

var p384mlkem1024Params = hybridNISTParams{
	curve:         ecdh.P384(),
	ecPubSize:     P384MLKEM1024ECPublicKeySize,
	ecPrivSize:    P384MLKEM1024ECPrivateKeySize,
	mlkemPubSize:  P384MLKEM1024MLKEMPubKeySize,
	mlkemPrivSize: P384MLKEM1024MLKEMPrivKeySize,
	mlkemCtSize:   P384MLKEM1024MLKEMCtSize,
	pubPEMBlock:   PEMBlockP384MLKEM1024PublicKey,
	privPEMBlock:  PEMBlockP384MLKEM1024PrivateKey,
	keyType:       HybridSecp384r1MLKEM1024Key,
	mlkemEncapsulate: func(pubKey []byte) ([]byte, []byte, error) {
		var pk mlkem1024.PublicKey
		if err := pk.Unpack(pubKey); err != nil {
			return nil, nil, fmt.Errorf("mlkem1024 public key unpack: %w", err)
		}
		ct := make([]byte, mlkem1024.CiphertextSize)
		ss := make([]byte, mlkem1024.SharedKeySize)
		pk.EncapsulateTo(ct, ss, nil)
		return ss, ct, nil
	},
	mlkemDecapsulate: func(privKey, ciphertext []byte) ([]byte, error) {
		var sk mlkem1024.PrivateKey
		if err := sk.Unpack(privKey); err != nil {
			return nil, fmt.Errorf("mlkem1024 private key unpack: %w", err)
		}
		ss := make([]byte, mlkem1024.SharedKeySize)
		sk.DecapsulateTo(ss, ciphertext)
		return ss, nil
	},
}

// HybridNISTKeyPair holds a hybrid EC + ML-KEM keypair as raw bytes.
type HybridNISTKeyPair struct {
	publicKey  []byte
	privateKey []byte
	params     *hybridNISTParams
}

// HybridNISTEncryptor implements PublicKeyEncryptor for NIST hybrid schemes.
type HybridNISTEncryptor struct {
	publicKey []byte
	salt      []byte
	info      []byte
	params    *hybridNISTParams
}

// HybridNISTDecryptor implements PrivateKeyDecryptor for NIST hybrid schemes.
type HybridNISTDecryptor struct {
	privateKey []byte
	salt       []byte
	info       []byte
	params     *hybridNISTParams
}

// --- KeyPair generation ---

func NewP256MLKEM768KeyPair() (HybridNISTKeyPair, error) {
	return newHybridNISTKeyPair(&p256mlkem768Params, func() ([]byte, []byte, error) {
		pk, sk, err := mlkem768.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub := make([]byte, mlkem768.PublicKeySize)
		priv := make([]byte, mlkem768.PrivateKeySize)
		pk.Pack(pub)
		sk.Pack(priv)
		return pub, priv, nil
	})
}

func NewP384MLKEM1024KeyPair() (HybridNISTKeyPair, error) {
	return newHybridNISTKeyPair(&p384mlkem1024Params, func() ([]byte, []byte, error) {
		pk, sk, err := mlkem1024.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub := make([]byte, mlkem1024.PublicKeySize)
		priv := make([]byte, mlkem1024.PrivateKeySize)
		pk.Pack(pub)
		sk.Pack(priv)
		return pub, priv, nil
	})
}

func newHybridNISTKeyPair(p *hybridNISTParams, genMLKEM func() (pub, priv []byte, err error)) (HybridNISTKeyPair, error) {
	ecPriv, err := p.curve.GenerateKey(rand.Reader)
	if err != nil {
		return HybridNISTKeyPair{}, fmt.Errorf("ECDH key generation failed: %w", err)
	}
	ecPub := ecPriv.PublicKey().Bytes() // uncompressed point
	ecPrivBytes := ecPriv.Bytes()       // raw scalar

	mlkemPub, mlkemPriv, err := genMLKEM()
	if err != nil {
		return HybridNISTKeyPair{}, fmt.Errorf("ML-KEM key generation failed: %w", err)
	}

	pubKey := make([]byte, 0, p.ecPubSize+p.mlkemPubSize)
	pubKey = append(pubKey, ecPub...)
	pubKey = append(pubKey, mlkemPub...)

	privKey := make([]byte, 0, p.ecPrivSize+p.mlkemPrivSize)
	privKey = append(privKey, ecPrivBytes...)
	privKey = append(privKey, mlkemPriv...)

	return HybridNISTKeyPair{
		publicKey:  pubKey,
		privateKey: privKey,
		params:     p,
	}, nil
}

func (k HybridNISTKeyPair) PublicKeyInPemFormat() (string, error) {
	return xwingRawToPEM(k.params.pubPEMBlock, k.publicKey, k.params.ecPubSize+k.params.mlkemPubSize)
}

func (k HybridNISTKeyPair) PrivateKeyInPemFormat() (string, error) {
	return xwingRawToPEM(k.params.privPEMBlock, k.privateKey, k.params.ecPrivSize+k.params.mlkemPrivSize)
}

func (k HybridNISTKeyPair) GetKeyType() KeyType {
	return k.params.keyType
}

// --- PEM decode helpers ---

func P256MLKEM768PubKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockP256MLKEM768PublicKey, P256MLKEM768PublicKeySize)
}

func P256MLKEM768PrivateKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockP256MLKEM768PrivateKey, P256MLKEM768PrivateKeySize)
}

func P384MLKEM1024PubKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockP384MLKEM1024PublicKey, P384MLKEM1024PublicKeySize)
}

func P384MLKEM1024PrivateKeyFromPem(data []byte) ([]byte, error) {
	return decodeSizedPEMBlock(data, PEMBlockP384MLKEM1024PrivateKey, P384MLKEM1024PrivateKeySize)
}

// --- Encryptor ---

func NewP256MLKEM768Encryptor(publicKey, salt, info []byte) (*HybridNISTEncryptor, error) {
	return newHybridNISTEncryptor(&p256mlkem768Params, publicKey, salt, info)
}

func NewP384MLKEM1024Encryptor(publicKey, salt, info []byte) (*HybridNISTEncryptor, error) {
	return newHybridNISTEncryptor(&p384mlkem1024Params, publicKey, salt, info)
}

func newHybridNISTEncryptor(p *hybridNISTParams, publicKey, salt, info []byte) (*HybridNISTEncryptor, error) {
	expectedSize := p.ecPubSize + p.mlkemPubSize
	if len(publicKey) != expectedSize {
		return nil, fmt.Errorf("invalid %s public key size: got %d want %d", p.keyType, len(publicKey), expectedSize)
	}
	return &HybridNISTEncryptor{
		publicKey: append([]byte(nil), publicKey...),
		salt:      cloneOrNil(salt),
		info:      cloneOrNil(info),
		params:    p,
	}, nil
}

func (e *HybridNISTEncryptor) Encrypt(data []byte) ([]byte, error) {
	return hybridNISTWrapDEK(e.params, e.publicKey, data, e.salt, e.info)
}

func (e *HybridNISTEncryptor) PublicKeyInPemFormat() (string, error) {
	return xwingRawToPEM(e.params.pubPEMBlock, e.publicKey, e.params.ecPubSize+e.params.mlkemPubSize)
}

func (e *HybridNISTEncryptor) Type() SchemeType     { return Hybrid }
func (e *HybridNISTEncryptor) KeyType() KeyType     { return e.params.keyType }
func (e *HybridNISTEncryptor) EphemeralKey() []byte { return nil }

func (e *HybridNISTEncryptor) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

// --- Decryptor ---

func NewP256MLKEM768Decryptor(privateKey []byte) (*HybridNISTDecryptor, error) {
	return NewSaltedP256MLKEM768Decryptor(privateKey, defaultXWingSalt(), nil)
}

func NewSaltedP256MLKEM768Decryptor(privateKey, salt, info []byte) (*HybridNISTDecryptor, error) {
	return newHybridNISTDecryptor(&p256mlkem768Params, privateKey, salt, info)
}

func NewP384MLKEM1024Decryptor(privateKey []byte) (*HybridNISTDecryptor, error) {
	return NewSaltedP384MLKEM1024Decryptor(privateKey, defaultXWingSalt(), nil)
}

func NewSaltedP384MLKEM1024Decryptor(privateKey, salt, info []byte) (*HybridNISTDecryptor, error) {
	return newHybridNISTDecryptor(&p384mlkem1024Params, privateKey, salt, info)
}

func newHybridNISTDecryptor(p *hybridNISTParams, privateKey, salt, info []byte) (*HybridNISTDecryptor, error) {
	expectedSize := p.ecPrivSize + p.mlkemPrivSize
	if len(privateKey) != expectedSize {
		return nil, fmt.Errorf("invalid %s private key size: got %d want %d", p.keyType, len(privateKey), expectedSize)
	}
	return &HybridNISTDecryptor{
		privateKey: append([]byte(nil), privateKey...),
		salt:       cloneOrNil(salt),
		info:       cloneOrNil(info),
		params:     p,
	}, nil
}

func (d *HybridNISTDecryptor) Decrypt(data []byte) ([]byte, error) {
	return hybridNISTUnwrapDEK(d.params, d.privateKey, data, d.salt, d.info)
}

// --- Public WrapDEK / UnwrapDEK ---

func P256MLKEM768WrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return hybridNISTWrapDEK(&p256mlkem768Params, publicKeyRaw, dek, defaultXWingSalt(), nil)
}

func P256MLKEM768UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return hybridNISTUnwrapDEK(&p256mlkem768Params, privateKeyRaw, wrappedDER, defaultXWingSalt(), nil)
}

func P384MLKEM1024WrapDEK(publicKeyRaw, dek []byte) ([]byte, error) {
	return hybridNISTWrapDEK(&p384mlkem1024Params, publicKeyRaw, dek, defaultXWingSalt(), nil)
}

func P384MLKEM1024UnwrapDEK(privateKeyRaw, wrappedDER []byte) ([]byte, error) {
	return hybridNISTUnwrapDEK(&p384mlkem1024Params, privateKeyRaw, wrappedDER, defaultXWingSalt(), nil)
}

// --- Core wrap/unwrap ---

func hybridNISTWrapDEK(p *hybridNISTParams, publicKeyRaw, dek, salt, info []byte) ([]byte, error) {
	expectedPubSize := p.ecPubSize + p.mlkemPubSize
	if len(publicKeyRaw) != expectedPubSize {
		return nil, fmt.Errorf("invalid %s public key size: got %d want %d", p.keyType, len(publicKeyRaw), expectedPubSize)
	}

	ecPubBytes := publicKeyRaw[:p.ecPubSize]
	mlkemPubBytes := publicKeyRaw[p.ecPubSize:]

	// ECDH: generate ephemeral key, compute shared secret
	ecPub, err := p.curve.NewPublicKey(ecPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid EC public key: %w", err)
	}
	ephemeral, err := p.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ECDH ephemeral key generation failed: %w", err)
	}
	ecdhSecret, err := ephemeral.ECDH(ecPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}
	ephemeralPub := ephemeral.PublicKey().Bytes()

	// ML-KEM: encapsulate
	mlkemSecret, mlkemCt, err := p.mlkemEncapsulate(mlkemPubBytes)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM encapsulate failed: %w", err)
	}

	// Combine secrets: ECDH || ML-KEM
	combinedSecret := make([]byte, 0, len(ecdhSecret)+len(mlkemSecret))
	combinedSecret = append(combinedSecret, ecdhSecret...)
	combinedSecret = append(combinedSecret, mlkemSecret...)

	// Derive AES-256 wrap key via HKDF
	wrapKey, err := deriveHybridNISTWrapKey(combinedSecret, salt, info)
	if err != nil {
		return nil, err
	}

	// AES-GCM encrypt DEK
	gcm, err := NewAESGcm(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("NewAESGcm failed: %w", err)
	}
	encryptedDEK, err := gcm.Encrypt(dek)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encrypt failed: %w", err)
	}

	// Build hybrid ciphertext: ephemeral EC point || ML-KEM ciphertext
	hybridCt := make([]byte, 0, len(ephemeralPub)+len(mlkemCt))
	hybridCt = append(hybridCt, ephemeralPub...)
	hybridCt = append(hybridCt, mlkemCt...)

	wrappedDER, err := asn1.Marshal(HybridNISTWrappedKey{
		HybridCiphertext: hybridCt,
		EncryptedDEK:     encryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("asn1.Marshal failed: %w", err)
	}

	return wrappedDER, nil
}

func hybridNISTUnwrapDEK(p *hybridNISTParams, privateKeyRaw, wrappedDER, salt, info []byte) ([]byte, error) {
	expectedPrivSize := p.ecPrivSize + p.mlkemPrivSize
	if len(privateKeyRaw) != expectedPrivSize {
		return nil, fmt.Errorf("invalid %s private key size: got %d want %d", p.keyType, len(privateKeyRaw), expectedPrivSize)
	}

	var wrapped HybridNISTWrappedKey
	rest, err := asn1.Unmarshal(wrappedDER, &wrapped)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("asn1.Unmarshal left %d trailing bytes", len(rest))
	}

	expectedCtSize := p.ecPubSize + p.mlkemCtSize
	if len(wrapped.HybridCiphertext) != expectedCtSize {
		return nil, fmt.Errorf("invalid %s ciphertext size: got %d want %d",
			p.keyType, len(wrapped.HybridCiphertext), expectedCtSize)
	}

	// Split hybrid ciphertext
	ephemeralPubBytes := wrapped.HybridCiphertext[:p.ecPubSize]
	mlkemCtBytes := wrapped.HybridCiphertext[p.ecPubSize:]

	// Split private key
	ecPrivBytes := privateKeyRaw[:p.ecPrivSize]
	mlkemPrivBytes := privateKeyRaw[p.ecPrivSize:]

	// ECDH: reconstruct shared secret
	ecPriv, err := p.curve.NewPrivateKey(ecPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid EC private key: %w", err)
	}
	ephemeralPub, err := p.curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral EC public key: %w", err)
	}
	ecdhSecret, err := ecPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// ML-KEM: decapsulate
	mlkemSecret, err := p.mlkemDecapsulate(mlkemPrivBytes, mlkemCtBytes)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulate failed: %w", err)
	}

	// Combine secrets: ECDH || ML-KEM
	combinedSecret := make([]byte, 0, len(ecdhSecret)+len(mlkemSecret))
	combinedSecret = append(combinedSecret, ecdhSecret...)
	combinedSecret = append(combinedSecret, mlkemSecret...)

	// Derive AES-256 wrap key via HKDF
	wrapKey, err := deriveHybridNISTWrapKey(combinedSecret, salt, info)
	if err != nil {
		return nil, err
	}

	// AES-GCM decrypt DEK
	gcm, err := NewAESGcm(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("NewAESGcm failed: %w", err)
	}
	plaintext, err := gcm.Decrypt(wrapped.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt failed: %w", err)
	}

	return plaintext, nil
}

func deriveHybridNISTWrapKey(combinedSecret, salt, info []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = defaultXWingSalt()
	}

	hkdfObj := hkdf.New(sha256.New, combinedSecret, salt, info)
	derivedKey := make([]byte, hybridNISTWrapKeySize)
	if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failure: %w", err)
	}

	return derivedKey, nil
}
